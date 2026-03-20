"""Report Quality Assurance — programmatic checks + Haiku plausibility.

Hybrid approach: deterministic checks are done in code (free, fast),
only judgment questions go to Haiku.

Programmatic checks:
1. CVSS vector calculation (divergence > 0.1 → correct)
2. CWE format validation
3. Severity consistency (CVSS score ↔ severity label)
4. Duplicate detection (fuzzy title match)
5. Required field check (HIGH/CRITICAL findings need recommendations)
6. EPSS reference check (if enrichment data present)
7. NIS2 mapping check (compliance package only)

Haiku check:
- Only for findings where programmatic checks found anomalies
- Plausibility: CWE↔finding match, recommendation↔finding match
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import structlog

log = structlog.get_logger()

HAIKU_MODEL = "claude-haiku-4-5-20251001"


# ---------------------------------------------------------------------------
# Programmatic checks
# ---------------------------------------------------------------------------

def _check_cvss_consistency(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Check 1+3: CVSS vector ↔ score consistency and severity alignment."""
    from reporter.claude_client import compute_cvss_score, _severity_for_score

    issues: list[dict[str, Any]] = []
    for f in findings:
        fid = f.get("id", "?")
        vector = f.get("cvss_vector", "")
        score_str = f.get("cvss_score", "")
        severity = f.get("severity", "")

        if not vector or not vector.startswith("CVSS:3.1/"):
            continue

        # Check score matches vector
        computed = compute_cvss_score(vector)
        if computed is None:
            issues.append({
                "finding_id": fid,
                "check": "cvss_vector",
                "issue": f"Invalid CVSS vector: {vector}",
                "auto_fix": False,
            })
            continue

        try:
            reported = float(score_str)
        except (ValueError, TypeError):
            reported = 0.0

        if abs(computed - reported) > 0.1:
            issues.append({
                "finding_id": fid,
                "check": "cvss_score",
                "issue": f"Score {reported} doesn't match vector (computed: {computed})",
                "auto_fix": True,
                "corrected_score": computed,
            })

        # Check severity matches score
        expected_sev = _severity_for_score(computed)
        if severity.upper() != expected_sev:
            issues.append({
                "finding_id": fid,
                "check": "severity_consistency",
                "issue": f"Severity {severity} doesn't match CVSS {computed} (expected: {expected_sev})",
                "auto_fix": True,
                "corrected_severity": expected_sev,
            })

    return issues


def _check_cwe_format(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Check 2: CWE format validation."""
    from reporter.cwe_reference import KNOWN_CWES

    issues: list[dict[str, Any]] = []
    valid_pattern = re.compile(r"^CWE-\d{1,4}$")

    for f in findings:
        cwe = f.get("cwe", "")
        if not cwe or cwe in ("", "—", "N/A"):
            continue
        if not valid_pattern.match(cwe):
            issues.append({
                "finding_id": f.get("id", "?"),
                "check": "cwe_format",
                "issue": f"Invalid CWE format: {cwe}",
                "auto_fix": True,
                "corrected_value": "",
            })

    return issues


def _check_duplicates(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Check 4: Duplicate detection via title similarity."""
    issues: list[dict[str, Any]] = []
    titles: list[tuple[str, str]] = []  # (finding_id, normalized_title)

    for f in findings:
        fid = f.get("id", "?")
        title = f.get("title", "").lower().strip()
        # Simple word-set similarity
        title_words = set(title.split())

        for other_id, other_title in titles:
            other_words = set(other_title.split())
            if not title_words or not other_words:
                continue
            # Jaccard similarity
            intersection = title_words & other_words
            union = title_words | other_words
            similarity = len(intersection) / len(union) if union else 0

            if similarity > 0.8:
                issues.append({
                    "finding_id": fid,
                    "check": "duplicate",
                    "issue": f"Possible duplicate of {other_id} (similarity: {similarity:.0%})",
                    "auto_fix": False,
                    "related_finding": other_id,
                })
                break

        titles.append((fid, title))

    return issues


def _check_required_fields(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Check 5: HIGH/CRITICAL findings must have recommendations."""
    issues: list[dict[str, Any]] = []

    for f in findings:
        severity = f.get("severity", "").upper()
        if severity not in ("HIGH", "CRITICAL"):
            continue

        rec = f.get("recommendation", "")
        if not rec or len(rec.strip()) < 10:
            issues.append({
                "finding_id": f.get("id", "?"),
                "check": "required_field",
                "issue": f"{severity} finding missing meaningful recommendation",
                "auto_fix": False,
            })

    return issues


def _check_severity_evidence(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Check 8: HIGH/CRITICAL findings without CVE or strong evidence → cap to MEDIUM.

    Prevents alarmist reports where AI speculates severity without proof.
    A finding is only HIGH/CRITICAL if it has:
    - A CVE reference, OR
    - A CVSS vector with AV:N + C:H or I:H, OR
    - Evidence of active exploitation or direct data access

    Common false-HIGH patterns that get capped:
    - "Öffentlich erreichbar" without exploit → MEDIUM
    - "Unvollständige Zertifikatskette" → MEDIUM (browsers handle gracefully)
    - "Veraltete Software" without CVE → MEDIUM
    """
    import re

    issues: list[dict[str, Any]] = []

    # Patterns that are typically overrated as HIGH
    _MAX_MEDIUM_PATTERNS = re.compile(
        r"zertifikatskette|certificate.chain|chain.of.trust|"
        r"öffentlich.erreichbar|publicly.accessible|publicly.exposed|"
        r"exponiert.im.internet|internet.exponiert|direkt.erreichbar|"
        r"veraltete?.software|outdated.software|eol|end.of.life|"
        r"server.banner|version.disclosure|versionsinformation|"
        r"fehlende?.security.header|missing.header|"
        r"weak.cipher|schwache?.cipher|cbc.cipher|"
        r"session.id.in.url|url.rewriting",
        re.IGNORECASE,
    )

    for f in findings:
        severity = f.get("severity", "").upper()
        if severity not in ("HIGH", "CRITICAL"):
            continue

        title = f.get("title", "")
        description = f.get("description", "")
        cvss_score = f.get("cvss_score", "")
        cve = f.get("cve", "") or ""
        evidence = f.get("evidence", "")

        # Has strong evidence?
        has_cve = bool(re.search(r"CVE-\d{4}-\d+", cve + " " + title + " " + description))
        has_cvss_high = False
        try:
            score = float(cvss_score)
            has_cvss_high = score >= 7.0
        except (ValueError, TypeError):
            pass

        combined = f"{title} {description}"

        # Pattern-based cap: known overrated findings → MEDIUM
        if _MAX_MEDIUM_PATTERNS.search(combined) and not has_cve:
            issues.append({
                "finding_id": f.get("id", "?"),
                "check": "severity_evidence",
                "issue": f"{severity} → MEDIUM (pattern match, no CVE: {title[:60]})",
                "auto_fix": True,
                "corrected_severity": "MEDIUM",
                "corrected_score": "5.3",
            })
            continue

        # Generic check: HIGH/CRITICAL without CVE and without high CVSS → MEDIUM
        if not has_cve and not has_cvss_high:
            issues.append({
                "finding_id": f.get("id", "?"),
                "check": "severity_evidence",
                "issue": f"{severity} finding without CVE or CVSS ≥7.0: {title[:60]}",
                "auto_fix": True,
                "corrected_severity": "MEDIUM",
                "corrected_score": "5.3",
            })

    return issues


def _check_epss_reference(
    findings: list[dict[str, Any]],
    enrichment: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Check 6: If EPSS data is available, it should be referenced in high-EPSS findings."""
    if not enrichment:
        return []

    issues: list[dict[str, Any]] = []
    for f in findings:
        # Check if finding has a CVE that's in EPSS data
        cve = f.get("cve", "")
        if not cve:
            continue
        epss_data = enrichment.get(cve, {}).get("epss", {})
        if not epss_data:
            continue
        epss_score = epss_data.get("epss", 0)
        if epss_score > 0.5:
            # High EPSS — should be mentioned somewhere in the finding
            desc = f.get("description", "").lower()
            impact = f.get("impact", "").lower()
            if "epss" not in desc and "exploit" not in desc and "epss" not in impact:
                issues.append({
                    "finding_id": f.get("id", "?"),
                    "check": "epss_reference",
                    "issue": f"CVE {cve} has EPSS {epss_score:.0%} but not referenced in finding",
                    "auto_fix": False,
                })

    return issues


def _check_nis2_mapping(
    findings: list[dict[str, Any]],
    package: str,
) -> list[dict[str, Any]]:
    """Check 7: NIS2/Compliance package — all §30 BSIG sections should be mapped."""
    if package not in ("compliance", "nis2"):
        return []

    issues: list[dict[str, Any]] = []
    mapped_refs: set[str] = set()
    for f in findings:
        ref = f.get("nis2_ref", "")
        if ref:
            mapped_refs.add(ref)

    # Check that at least nr5 and nr8 are covered (most common for external scans)
    expected = {"Nr. 5", "Nr. 8"}
    for exp in expected:
        if not any(exp in ref for ref in mapped_refs):
            issues.append({
                "finding_id": "global",
                "check": "nis2_mapping",
                "issue": f"§30 BSIG {exp} not referenced in any finding",
                "auto_fix": False,
            })

    return issues


# ---------------------------------------------------------------------------
# Apply auto-fixes
# ---------------------------------------------------------------------------

def _apply_auto_fixes(
    result: dict[str, Any],
    issues: list[dict[str, Any]],
) -> int:
    """Apply auto-fixes from QA issues to the Claude result.

    Returns number of fixes applied.
    """
    fixes_applied = 0
    findings_by_id = {f.get("id"): f for f in result.get("findings", [])}

    for issue in issues:
        if not issue.get("auto_fix"):
            continue

        fid = issue["finding_id"]
        finding = findings_by_id.get(fid)
        if not finding:
            continue

        check = issue["check"]
        if check == "cvss_score" and "corrected_score" in issue:
            finding["cvss_score"] = str(issue["corrected_score"])
            fixes_applied += 1
        elif check == "severity_consistency" and "corrected_severity" in issue:
            finding["severity"] = issue["corrected_severity"]
            fixes_applied += 1
        elif check == "severity_evidence" and "corrected_severity" in issue:
            log.info("severity_capped", finding_id=fid,
                     old=finding.get("severity"), new=issue["corrected_severity"],
                     reason=issue.get("issue", ""))
            finding["severity"] = issue["corrected_severity"]
            if "corrected_score" in issue:
                finding["cvss_score"] = str(issue["corrected_score"])
            fixes_applied += 1
        elif check == "cwe_format" and "corrected_value" in issue:
            finding["cwe"] = issue["corrected_value"]
            fixes_applied += 1

    return fixes_applied


# ---------------------------------------------------------------------------
# Haiku plausibility check (only for anomalies)
# ---------------------------------------------------------------------------

def _haiku_plausibility_check(
    anomaly_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Call Haiku to check plausibility of flagged findings.

    Only called when programmatic checks found anomalies.
    Returns QA assessment dict.
    """
    if not anomaly_findings:
        return {"haiku_checked": False}

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {"haiku_checked": False, "reason": "no_api_key"}

    system_prompt = """Du bist ein QA-Reviewer für Security-Assessment-Reports.
Prüfe die folgenden Findings auf Plausibilität:
1. Passt die CWE-Zuordnung zum beschriebenen Problem?
2. Passt die Empfehlung zum Finding?
3. Ist der CVSS-Score plausibel für das beschriebene Problem?
4. Sind positive Findings tatsächlich positiv?

Antworte NUR mit validem JSON:
{
  "plausibility_issues": [
    {"finding_id": "...", "issue": "...", "suggestion": "..."}
  ],
  "overall_quality": "good|acceptable|needs_review"
}"""

    user_prompt = f"""Prüfe diese {len(anomaly_findings)} Findings auf Plausibilität:

{json.dumps(anomaly_findings, indent=2, ensure_ascii=False)}"""

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)

        start = time.monotonic()
        response = client.messages.create(
            model=HAIKU_MODEL,
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        duration_ms = int((time.monotonic() - start) * 1000)

        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
        if raw.endswith("```"):
            raw = raw.rsplit("```", 1)[0]

        result = json.loads(raw.strip())
        result["haiku_checked"] = True
        result["duration_ms"] = duration_ms
        log.info("qa_haiku_complete", duration_ms=duration_ms,
                 issues=len(result.get("plausibility_issues", [])))
        return result

    except Exception as e:
        log.warning("qa_haiku_failed", error=str(e))
        return {"haiku_checked": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Main QA pipeline
# ---------------------------------------------------------------------------

def run_qa_checks(
    claude_result: dict[str, Any],
    package: str = "perimeter",
    enrichment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the full QA pipeline on Claude's report output.

    Args:
        claude_result: Parsed JSON from Claude API.
        package: Scan package name.
        enrichment: Phase 3 enrichment data (optional).

    Returns:
        QA report dict with quality_score, issues, and fixes applied.
    """
    findings = claude_result.get("findings", [])

    # Run all programmatic checks
    all_issues: list[dict[str, Any]] = []
    all_issues.extend(_check_cvss_consistency(findings))
    all_issues.extend(_check_cwe_format(findings))
    all_issues.extend(_check_duplicates(findings))
    all_issues.extend(_check_required_fields(findings))
    all_issues.extend(_check_severity_evidence(findings))
    all_issues.extend(_check_epss_reference(findings, enrichment))
    all_issues.extend(_check_nis2_mapping(findings, package))

    # Apply auto-fixes
    auto_fixes = _apply_auto_fixes(claude_result, all_issues)

    # Haiku plausibility check for non-auto-fixable anomalies
    manual_issues = [i for i in all_issues if not i.get("auto_fix")]
    haiku_result: dict[str, Any] = {}
    if manual_issues and len(manual_issues) <= 10:
        # Collect the actual findings that have issues
        issue_finding_ids = {i["finding_id"] for i in manual_issues}
        anomaly_findings = [f for f in findings if f.get("id") in issue_finding_ids]
        if anomaly_findings:
            haiku_result = _haiku_plausibility_check(anomaly_findings[:5])

    # Calculate quality score
    total_findings = max(len(findings), 1)
    issue_count = len([i for i in all_issues if not i.get("auto_fix")])
    quality_score = max(0.0, 1.0 - (issue_count / total_findings) * 0.2)

    qa_report = {
        "quality_score": round(quality_score, 2),
        "issues": all_issues,
        "auto_fixes_applied": auto_fixes,
        "manual_review_needed": issue_count > 3,
        "haiku_check": haiku_result,
        "checks_run": [
            "cvss_consistency",
            "cwe_format",
            "duplicate_detection",
            "required_fields",
            "epss_reference",
            "nis2_mapping",
        ],
    }

    log.info("qa_complete",
             quality_score=qa_report["quality_score"],
             total_issues=len(all_issues),
             auto_fixes=auto_fixes,
             manual_review=qa_report["manual_review_needed"])

    return qa_report
