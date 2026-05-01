"""Claude API Client — Aufruf + JSON-Parsing der Antwort."""

import json
import math
import os
import re
import time
from typing import Any

import anthropic
import structlog

from reporter.ai_cache import (
    cache_key as build_cache_key,
    delete_cached,
    get_cached_response,
    set_cached_response,
    stats_from_cache_entry,
)
from reporter.cwe_reference import correct_cwe_mappings
from reporter.prompts import get_system_prompt

# Cache-TTL fuer Reporter-Calls (Spec 03-ai-determinism.md §5: 1 Tag).
REPORTER_CACHE_TTL_SECONDS = 24 * 3600
REPORTER_CACHE_NAMESPACE = "reporter_v1"

log = structlog.get_logger()

# Model selection by package — Opus for complex reports, Sonnet for simple ones
REPORT_MODELS: dict[str, str] = {
    "webcheck": "claude-sonnet-4-6",
    "basic": "claude-sonnet-4-6",
    "perimeter": "claude-opus-4-6",
    "professional": "claude-opus-4-6",
    "compliance": "claude-opus-4-6",
    "nis2": "claude-opus-4-6",
    "supplychain": "claude-opus-4-6",
    "insurance": "claude-opus-4-6",
    "tlscompliance": "claude-sonnet-4-6",
}

MAX_TOKENS_BY_MODEL: dict[str, int] = {
    "claude-sonnet-4-6": 16384,
    "claude-opus-4-6": 32000,
    "claude-haiku-4-5-20251001": 4096,
}

AI_PRICING: dict[str, dict[str, float]] = {
    "claude-haiku-4-5-20251001": {"input": 1.0, "output": 5.0},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-opus-4-6": {"input": 15.0, "output": 75.0},
}

# System prompt from docs/architecture.md — copy VERBATIM
SYSTEM_PROMPT = """
Du bist ein erfahrener Penetration Tester, der Scan-Rohdaten in professionelle
Befunde umwandelt. Du arbeitest nach dem PTES-Standard.

REGELN FÜR CVSS-SCORING:
- Score was du beweisen kannst, nicht was du dir vorstellst
- Exponierter Port MIT Auth = NICHT dasselbe wie OHNE Auth
- Scope Change (S:C) erfordert Nachweis
- Information Disclosure ist fast nie über LOW (3.0-3.9)
- Immer den vollständigen CVSS-Vektorstring angeben
- Der numerische cvss_score MUSS exakt zum CVSS-Vektor passen

CVSS-REFERENZWERTE (häufige Findings):
- DB-Port exponiert, KEINE Auth (anonym/root ohne Passwort): CRITICAL (9.8)
- DB-Port exponiert, Auth aktiv aber Default-Credentials nachgewiesen: HIGH (7.5-8.0)
- DB-Port exponiert, Auth aktiv (Credentials unbekannt/nicht getestet): MEDIUM (5.3-6.5)
  → Empfehlung: Firewall-Regel oder SSH-Tunnel, nicht pauschal CRITICAL
  → 3,6 Mio MySQL-Server sind öffentlich erreichbar — bei vielen Hostern Standardconfig
- Admin-Panel/Webmin exponiert ohne MFA: HIGH (7.0-7.5)
- Admin-Panel exponiert mit Auth: MEDIUM (5.0-6.0)
- Stark veraltete Software (EOL, keine Patches): HIGH (7.0-8.0)
- Mail-Services auf Prod-Server: MEDIUM (5.0-6.5)
- FTP exponiert mit SSL: MEDIUM (4.0-5.5)
- SSH ohne fail2ban: LOW (3.0-4.0)
- Info Disclosure (robots.txt, Banner): LOW (2.0-3.5)
- Gute Security-Header: INFORMATIONAL (positiver Befund)

CVSS-REFERENZWERTE FÜR DNS-FINDINGS:
- Kein DKIM konfiguriert (SPF und DMARC vorhanden):
  → MEDIUM 4.3, CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N
  → E-Mail-Authentifizierung ist geschwächt, Phishing-Risiko erhöht
- DMARC-Policy auf 'none' (kein Enforcement):
  → MEDIUM 5.3, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N
  → Keine Durchsetzung, Spoofing ungehindert möglich
- DMARC-Policy auf 'quarantine' statt 'reject':
  → LOW 3.7, CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N
  → Teilweise Durchsetzung, aber nicht vollständig blockiert
- Kein SPF-Record vorhanden:
  → MEDIUM 5.3, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N
- SPF mit ~all (Softfail) statt -all (Hardfail):
  → LOW 3.7, CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N
- Zone Transfer (AXFR) möglich:
  → HIGH 7.5, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
  → Vollständige DNS-Zone kann abgerufen werden
- Dangling CNAME — Bewertung nach Risiko:
  Wenn "[TAKEOVER MÖGLICH]": → HIGH 8.2, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L
  Wenn "[Verwaist]": → LOW 2.0, CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N (aufräumen empfohlen)
  Wenn "[Kein Risiko]": → INFO, CVSS 0.0 (z.B. Microsoft Lync, veralteter Dienst, kein Takeover möglich)

WICHTIG: Jeder Finding MUSS einen cvss_score und cvss_vector haben.
Nur bei INFO-Severity (Score 0.0) darf der Vektor "N/A" sein.

CNAME-BASIERTE CLOUD-DIENSTE — TLS-Zertifikat-Mismatch:
Wenn ein Hostname per CNAME auf einen Cloud-Dienst zeigt (z.B. enterpriseenrollment.heuel.com
→ enterpriseenrollment.manage.microsoft.com), präsentiert der Cloud-Provider sein EIGENES
Zertifikat (z.B. *.manage.microsoft.com). Das ist KEIN Sicherheitsproblem, sondern erwartetes
Verhalten. Bekannte Muster:
- enterpriseenrollment.*.com → manage.microsoft.com (Microsoft Intune MDM)
- enterpriseregistration.*.com → enterpriseregistration.windows.net (Microsoft Entra ID)
- autodiscover.*.com → autodiscover.outlook.com (Microsoft 365)
- lyncdiscover.*.com → webdir.online.lync.com (Skype for Business, abgeschaltet)
- sip.*.com → sipdir.online.lync.com (Skype for Business, abgeschaltet)
→ Bewertung: INFO, CVSS 0.0 — "Erwartetes Verhalten bei CNAME-basiertem Cloud-Dienst"
→ Empfehlung: "DNS-Eintrag aufräumen falls Dienst nicht mehr genutzt wird"
→ NICHT als HIGH/CRITICAL bewerten, KEINE Zertifikatsempfehlung geben (nicht vom Kunden kontrollierbar)

HÄUFIG FALSCH BEWERTETE FINDINGS — Korrekte Scores:
- SSH Port 22 offen, Key-Auth konfiguriert, Passwort-Auth deaktiviert:
  → INFO, CVSS 0.0, kein Vektor nötig — das ist Standard-Konfiguration
- SSH Port 22 offen, Passwort-Auth erlaubt, kein fail2ban:
  → LOW 3.1, CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
- robots.txt enthält /admin oder /backup Pfade:
  → LOW 2.5 — reine Information Disclosure ohne direkten Zugriff
  → NICHT MEDIUM — robots.txt verrät nur Pfadnamen, kein Exploit
- MySQL/PostgreSQL Port offen, Connection refused oder Auth required:
  → INFO — Port ist erreichbar aber kein unautorisierter Zugriff möglich
  → NICHT HIGH — Connection refused = kein Risiko
- HTTP statt HTTPS ohne Redirect (kein Login-Formular):
  → LOW 3.7, CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N
- Server-Version im Banner sichtbar (z.B. "nginx/1.24"):
  → INFO — reine Information, kein direkter Angriff
  → NICHT LOW — Version im Banner allein ist kein Risiko
- Port offen aber Service antwortet nicht oder lehnt ab:
  → INFO — offener Port allein ohne erreichbaren Dienst ist kein Befund

REGELN FÜR TONALITÄT:
- Professionell und sachlich, nicht alarmistisch
- Keine Superlative ("katastrophal", "existenziell")
- Positive Befunde immer einschließen
- Empfehlungen müssen konkret und umsetzbar sein
- Dringlichkeit an tatsächlichen Schweregrad koppeln:
  CRITICAL: "Sofortige Behebung (24-48 Stunden)"
  HIGH: "Behebung innerhalb weniger Tage"
  MEDIUM: "Empfohlen innerhalb 2-4 Wochen"
  LOW: "Empfohlen innerhalb 1-3 Monaten"
  INFO: "Für kontinuierliche Verbesserung berücksichtigen"

OUTPUT-FORMAT:
Antworte ausschließlich in JSON nach folgendem Schema:
{
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "overall_description": "2-3 Sätze Gesamtbewertung",
  "findings": [
    {
      "id": "VS-2026-001",
      "title": "Kurzer, präziser Titel",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "cvss_score": "8.6",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
      "cwe": "CWE-284",
      "affected": "88.99.35.112:3306 (beispiel.de)",
      "description": "Was wurde gefunden. Sachlich und präzise.",
      "evidence": "$ nmap -sV 88.99.35.112\\n3306/tcp open mysql MariaDB 10.11.6",
      "impact": "Mögliche Auswirkung bei Ausnutzung. Business-Kontext.",
      "recommendation": "<b>Kurzfristig (Tage):</b> Konkrete Maßnahme.\\n<b>Mittelfristig:</b> Strategische Verbesserung."
    }
  ],
  "positive_findings": [
    {
      "title": "Korrekte TLS-Konfiguration",
      "description": "Alle Hosts nutzen TLS 1.2+, keine veralteten Cipher-Suites."
    }
  ],
  "recommendations": [
    {
      "timeframe": "Sofort|Tag 1-3|Woche 1|Monat 1",
      "action": "Konkrete Maßnahme",
      "finding_refs": ["001"],
      "effort": "2-4 h"
    }
  ]
}
"""

MAX_TOKENS_BY_PACKAGE: dict[str, int] = {
    # Derived from REPORT_MODELS + MAX_TOKENS_BY_MODEL:
    # Sonnet packages → 16384, Opus packages → 32000
    "webcheck": 16384,
    "perimeter": 32000,
    "compliance": 32000,
    "supplychain": 32000,
    "insurance": 32000,
    # Legacy aliases
    "basic": 16384,
    "professional": 32000,
    "nis2": 32000,
}


# ---------------------------------------------------------------------------
# CVSS 3.1 score calculation from vector string
# ---------------------------------------------------------------------------

# Metric value weights per CVSS 3.1 specification
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # Scope Unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}  # Scope Changed
_UI = {"N": 0.85, "R": 0.62}
_C = {"H": 0.56, "L": 0.22, "N": 0.0}
_I = {"H": 0.56, "L": 0.22, "N": 0.0}
_A = {"H": 0.56, "L": 0.22, "N": 0.0}

_SEVERITY_RANGES = [
    (0.0, 0.0, "INFO"),
    (0.1, 3.9, "LOW"),
    (4.0, 6.9, "MEDIUM"),
    (7.0, 8.9, "HIGH"),
    (9.0, 10.0, "CRITICAL"),
]


def _roundup(x: float) -> float:
    """CVSS 3.1 roundup function: smallest tenth >= x."""
    return math.ceil(x * 10) / 10


def compute_cvss_score(vector: str) -> float | None:
    """Compute CVSS 3.1 base score from a vector string.

    Returns None if the vector is malformed or cannot be parsed.
    """
    if not vector or not vector.startswith("CVSS:3.1/"):
        return None

    try:
        parts = {}
        for segment in vector.split("/")[1:]:  # skip "CVSS:3.1"
            key, val = segment.split(":")
            parts[key] = val

        scope_changed = parts["S"] == "C"
        pr_table = _PR_C if scope_changed else _PR_U

        iss = 1 - (1 - _C[parts["C"]]) * (1 - _I[parts["I"]]) * (1 - _A[parts["A"]])

        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss

        exploitability = (
            8.22 * _AV[parts["AV"]] * _AC[parts["AC"]]
            * pr_table[parts["PR"]] * _UI[parts["UI"]]
        )

        if impact <= 0:
            return 0.0

        if scope_changed:
            score = _roundup(min(1.08 * (impact + exploitability), 10.0))
        else:
            score = _roundup(min(impact + exploitability, 10.0))

        return score
    except (KeyError, ValueError, IndexError):
        return None


def _severity_for_score(score: float) -> str:
    """Return severity label for a CVSS score."""
    for low, high, label in _SEVERITY_RANGES:
        if low <= score <= high:
            return label
    return "CRITICAL"


_VALID_CVSS_METRICS = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"H", "L", "N"},
    "I": {"H", "L", "N"},
    "A": {"H", "L", "N"},
}

_REQUIRED_METRICS = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}


def validate_cvss_vector(vector: str) -> str | None:
    """Validate CVSS 3.1 vector syntax.

    Returns None if valid, or an error description if invalid.
    """
    if not vector or not vector.startswith("CVSS:3.1/"):
        return "missing CVSS:3.1/ prefix"

    try:
        parts = {}
        for segment in vector.split("/")[1:]:
            key, val = segment.split(":")
            parts[key] = val
    except ValueError:
        return "malformed metric segment"

    # Check all required metrics are present
    missing = _REQUIRED_METRICS - set(parts.keys())
    if missing:
        return f"missing metrics: {', '.join(sorted(missing))}"

    # Check for unexpected metrics
    extra = set(parts.keys()) - _REQUIRED_METRICS
    if extra:
        return f"unexpected metrics: {', '.join(sorted(extra))}"

    # Check each metric value is valid
    for metric, value in parts.items():
        valid_values = _VALID_CVSS_METRICS.get(metric)
        if valid_values and value not in valid_values:
            return f"invalid value {metric}:{value}"

    return None


def validate_cwe_mappings(result: dict[str, Any]) -> dict[str, Any]:
    """Validate CWE identifiers — remove invalid, verify unknown via MITRE API."""
    import re
    from reporter.cwe_reference import KNOWN_CWES

    valid_pattern = re.compile(r'^CWE-\d{1,4}$')
    unknown_cwes: list[str] = []

    for finding in result.get("findings", []):
        cwe = finding.get("cwe", "")
        if not cwe or cwe in ("", "—", "N/A"):
            finding["cwe"] = ""
            continue
        if not valid_pattern.match(cwe):
            log.warning("cwe_invalid_format", cwe=cwe, finding_id=finding.get("id"))
            finding["cwe"] = ""
            continue
        if cwe not in KNOWN_CWES:
            unknown_cwes.append(cwe)

    # Live-validate unknown CWEs via MITRE API (graceful degradation)
    if unknown_cwes:
        try:
            from reporter.cwe_api_client import CWEAPIClient
            client = CWEAPIClient()
            api_results = client.lookup_batch(list(set(unknown_cwes)))
            for finding in result.get("findings", []):
                cwe = finding.get("cwe", "")
                if cwe in api_results:
                    if not api_results[cwe].get("exists", False):
                        log.warning("cwe_nonexistent", cwe=cwe,
                                    finding_id=finding.get("id"))
                        finding["cwe"] = ""
                    else:
                        log.info("cwe_verified_via_api", cwe=cwe,
                                 name=api_results[cwe].get("name", ""))
        except Exception as e:
            log.warning("cwe_api_fallback_to_static", error=str(e))
            # Keep unknown CWEs as-is (previous behavior)

    return result


def cap_implausible_scores(result: dict[str, Any]) -> dict[str, Any]:
    """Cap CVSS scores that are implausibly high for certain finding types."""
    # keyword in title/description → maximum plausible CVSS score
    score_limits = {
        # Info-Disclosure-Findings — niemals HIGH
        "robots.txt": 3.5,
        "server banner": 2.5,
        "server-version": 2.5,
        "version im banner": 2.5,
        "versionsinformation": 2.5,
        "information disclosure": 4.0,
        "banner": 2.5,
        # Security-Header — maximal MEDIUM
        "security header": 5.5,
        "security-header": 5.5,
        "x-frame-options": 5.5,
        "content-security-policy": 5.5,
        # DNS-/Mail-Config — maximal MEDIUM
        "spf": 5.5,
        "dmarc": 5.5,
        "dkim": 4.5,
        # Directory Listing — maximal MEDIUM
        "directory listing": 5.5,
        "verzeichnislisting": 5.5,
        # TLS-Konfiguration — maximal MEDIUM
        "zertifikatskette": 5.5,
        "certificate chain": 5.5,
        "chain of trust": 5.5,
        "cbc cipher": 5.5,
        "weak cipher": 5.5,
        # Sonstige
        "session id in url": 5.5,
        "url rewriting": 5.5,
        "connection refused": 0.0,
        # ENTFERNT: "öffentlich erreichbar", "publicly accessible",
        # "publicly exposed", "exponiert im internet" — zu breit,
        # matchen auch DB-Ports ohne Auth, EOL-Server, Admin-Panels.
        # Claude wird per Prompt-Regeln (CVSS-Referenzwerte) gesteuert.
    }

    capped = 0
    for finding in result.get("findings", []):
        text = (finding.get("title", "") + " " + finding.get("description", "")).lower()
        try:
            score = float(finding.get("cvss_score", "0") or "0")
        except (ValueError, TypeError):
            continue

        for keyword, max_score in score_limits.items():
            if keyword in text and score > max_score:
                log.warning("cvss_score_capped",
                    finding_id=finding.get("id"),
                    original=score, capped=max_score,
                    keyword=keyword)
                finding["cvss_score"] = str(max_score)
                # Re-align severity
                if max_score == 0.0:
                    finding["severity"] = "INFO"
                elif max_score < 4.0:
                    finding["severity"] = "LOW"
                elif max_score < 7.0:
                    finding["severity"] = "MEDIUM"
                capped += 1
                break

    if capped:
        log.info("cvss_scores_capped", count=capped)
    return result


def validate_cvss_scores(result: dict[str, Any]) -> dict[str, Any]:
    """Validate and correct CVSS scores in Claude's response.

    For each finding with a cvss_vector:
    - Validate vector syntax (all 8 metrics, valid values)
    - Compute the correct score from the vector
    - If the reported score diverges by > 0.1, replace it with the computed score
    - Ensure severity label matches the computed score
    """
    findings = result.get("findings", [])
    corrected_count = 0

    for finding in findings:
        vector = finding.get("cvss_vector", "")
        reported_score_str = finding.get("cvss_score", "0")

        try:
            reported_score = float(reported_score_str)
        except (ValueError, TypeError):
            reported_score = 0.0

        # Normalize "N/A" vectors to empty string
        if vector == "N/A":
            finding["cvss_vector"] = ""
            vector = ""

        # Skip findings without CVSS (e.g. INFO findings, basic package)
        if not vector:
            continue

        # Validate vector syntax
        vector_error = validate_cvss_vector(vector)
        if vector_error:
            log.warning(
                "cvss_vector_invalid",
                finding_id=finding.get("id"),
                vector=vector,
                error=vector_error,
            )
            # Cannot compute score from invalid vector — keep as-is
            continue

        computed = compute_cvss_score(vector)
        if computed is None:
            continue

        if abs(computed - reported_score) > 0.1:
            log.warning(
                "cvss_score_corrected",
                finding_id=finding.get("id"),
                reported=reported_score,
                computed=computed,
                vector=vector,
            )
            finding["cvss_score"] = str(computed)
            corrected_count += 1

        # Always ensure severity matches the (possibly corrected) score
        actual_score = float(finding["cvss_score"])
        correct_severity = _severity_for_score(actual_score)
        if finding.get("severity") != correct_severity:
            log.warning(
                "cvss_severity_corrected",
                finding_id=finding.get("id"),
                old_severity=finding.get("severity"),
                new_severity=correct_severity,
                score=actual_score,
            )
            finding["severity"] = correct_severity

    if corrected_count:
        log.info("cvss_validation_complete", corrected=corrected_count)

    return result


def _repair_json(text: str) -> str:
    """Repair common JSON issues in Claude API responses.

    Handles: markdown fences, JS comments, trailing commas, control chars.
    """
    text = text.strip()

    # 1. Remove markdown code fences (```json ... ```)
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1])

    # 2. Remove JavaScript-style comments (only outside of JSON strings)
    #    Line comments: // ... (but not inside URLs like https://)
    text = re.sub(r'(?<![:"\\])//[^\n]*', '', text)
    #    Block comments: /* ... */
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)

    # 3. Trailing commas before } or ]
    text = re.sub(r',\s*([\]}])', r'\1', text)

    # 4. Fix control characters (literal tabs)
    text = text.replace('\t', '\\t')

    return text


def _try_escape_inner_quote(text: str, error_pos: int) -> str:
    """Try to fix an unescaped double quote inside a JSON string value.

    Scans backward from *error_pos* looking for a ``"`` that is likely an
    inner quote (not a JSON structural delimiter) and escapes it.
    Returns the modified text, or the original text unchanged if no fix found.
    """
    # JSON structural chars that legitimately precede a closing "
    STRUCT_BEFORE_CLOSE = set(':,[{')

    search_start = max(0, error_pos - 80)
    for i in range(error_pos - 1, search_start, -1):
        ch = text[i]
        if ch != '"' or (i > 0 and text[i - 1] == '\\'):
            continue
        # Found an unescaped " — check if it looks like an inner quote
        # (i.e. the previous non-whitespace char is NOT a JSON delimiter)
        j = i - 1
        while j >= 0 and text[j] in ' \t\n\r':
            j -= 1
        if j >= 0 and text[j] not in STRUCT_BEFORE_CLOSE:
            # This " is likely an inner quote — escape it
            return text[:i] + '\\"' + text[i + 1:]
    return text  # no fix found


def _iterative_json_parse(text: str, max_fixes: int = 15) -> dict[str, Any]:
    """Parse JSON with iterative repair for unescaped inner quotes.

    On each ``JSONDecodeError``, attempts to escape the offending quote
    and retries.  Handles up to *max_fixes* broken quotes per response.
    """
    for _ in range(max_fixes):
        try:
            return json.loads(text, strict=False)
        except json.JSONDecodeError as e:
            if e.pos is None:
                raise
            fixed = _try_escape_inner_quote(text, e.pos)
            if fixed == text:
                raise  # couldn't fix — re-raise original error
            log.debug("json_inner_quote_fixed", pos=e.pos, error=e.msg)
            text = fixed
    raise json.JSONDecodeError("Max JSON fixes exceeded", text, 0)


def call_claude(
    domain: str,
    host_inventory: dict[str, Any],
    tech_profiles: list[dict[str, Any]],
    consolidated_findings: str,
    package: str = "professional",
    debug_info: dict[str, Any] | None = None,
    order_id: str | None = None,
) -> dict[str, Any]:
    """Call Claude API to analyze scan data and generate findings.

    Args:
        domain: Target domain
        host_inventory: Host inventory from phase 0
        tech_profiles: Tech profiles from phase 1
        consolidated_findings: Consolidated text from parser

    Returns:
        Parsed JSON dict with overall_risk, findings, positive_findings, recommendations

    Raises:
        RuntimeError: If Claude API call fails after retries
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY environment variable not set")

    client = anthropic.Anthropic(api_key=api_key)

    # Smart truncation — preserve complete host sections, prioritize variety
    MAX_FINDINGS_CHARS = 120000  # ~30K tokens, well within Opus 200K context

    if len(consolidated_findings) > MAX_FINDINGS_CHARS:
        log.warning("consolidated_findings_truncated",
                    original_len=len(consolidated_findings),
                    truncated_to=MAX_FINDINGS_CHARS,
                    domain=domain)
        # Split by host sections (marked by "HOST:" headers)
        host_sections = re.split(r'(={50,}[\s\S]*?HOST:)', consolidated_findings)

        # Reconstruct with per-host caps
        truncated = ""
        per_host_cap = MAX_FINDINGS_CHARS // max(len(host_sections) // 2, 1)

        for i, section in enumerate(host_sections):
            if len(truncated) + len(section) > MAX_FINDINGS_CHARS:
                remaining = MAX_FINDINGS_CHARS - len(truncated)
                if remaining > 500:
                    truncated += section[:remaining]
                truncated += f"\n\n--- GEKUERZT: weitere Daten im MinIO-Archiv ---"
                break
            truncated += section

        consolidated_findings = truncated

    # Build user prompt (from architecture.md)
    user_prompt = f"""
Analysiere die folgenden Scan-Rohdaten für {domain}.

HOST-INVENTAR:
{json.dumps(host_inventory, indent=2)}

TECHNOLOGIE-PROFILE (pro Host):
{json.dumps(tech_profiles, indent=2)}

SCAN-ERGEBNISSE:
{consolidated_findings}

Erstelle die Befunde auf Deutsch. Finding-ID-Prefix: VS
"""

    system_prompt = get_system_prompt(package)
    model = REPORT_MODELS.get(package, "claude-sonnet-4-6")
    max_tokens = MAX_TOKENS_BY_MODEL.get(model, 16384)
    messages_payload = [{"role": "user", "content": user_prompt}]

    # Cache-Key (M1, 2026-05-01): Order-Scope wenn order_id vorliegt — dann
    # haengt der Hash NICHT mehr am consolidated_findings-Text und Re-Scans /
    # regenerate-report derselben Order liefern garantiert byte-identisch.
    # Ohne order_id: legacy Inhalts-Hash (kommt praktisch nicht mehr vor).
    cache_k = build_cache_key(
        model=model,
        system=system_prompt,
        messages=messages_payload,
        temperature=0.0,
        max_tokens=max_tokens,
        namespace=REPORTER_CACHE_NAMESPACE,
        order_scope=order_id or None,
    )

    # Populate debug info (prompts are constant across retries)
    if debug_info is not None:
        debug_info["system_prompt"] = system_prompt
        debug_info["user_prompt"] = user_prompt
        debug_info["package"] = package
        debug_info["domain"] = domain
        debug_info["cache_key"] = cache_k[:24]

    # Retry logic: 5 attempts with exponential backoff for transient errors
    response_text: str | None = None
    json_text: str | None = None
    max_retries = 5
    cache_hit_consumed = False  # markiert dass aktueller Versuch ein Cache-Hit ist
    for attempt in range(max_retries):
        try:
            # Cache-Lookup nur beim ERSTEN Versuch — bei JSON-Parse-Fehler
            # invalidieren wir und greifen ab da live durch.
            cache_entry = (
                get_cached_response(cache_k)
                if attempt == 0 and not cache_hit_consumed
                else None
            )

            if cache_entry is not None:
                cache_hit_consumed = True
                response_text = cache_entry.get("response_text", "")
                stop_reason = "end_turn"  # gecachte Antworten waren komplett
                input_tokens = int(cache_entry.get("input_tokens", 0) or 0)
                output_tokens = int(cache_entry.get("output_tokens", 0) or 0)
                stats = stats_from_cache_entry(cache_entry, model)
                prices = AI_PRICING.get(model, {"input": 3.0, "output": 15.0})
                cost_info = {
                    "model": model,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "input_cost_usd": round((input_tokens / 1_000_000) * prices["input"], 4),
                    "output_cost_usd": round((output_tokens / 1_000_000) * prices["output"], 4),
                    "total_cost_usd": round(stats.cost_estimated_usd, 4),
                    "cache_hit": True,
                    "cache_age_seconds": stats.age_seconds,
                }
                log.info("claude_cache_hit", domain=domain, model=model,
                         age_s=round(stats.age_seconds or 0, 1))
            else:
                log.info("claude_api_call", attempt=attempt + 1, domain=domain,
                         cache_hit=False)

                # Opus needs more time for complex reports (32K tokens output)
                api_timeout = 600.0 if "opus" in model else 120.0

                response = client.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    system=system_prompt,
                    messages=messages_payload,
                    temperature=0.0,
                    timeout=api_timeout,
                )

                # Extract text from response
                response_text = response.content[0].text
                stop_reason = response.stop_reason  # "end_turn" or "max_tokens"

                # Token cost tracking
                input_tokens = response.usage.input_tokens
                output_tokens = response.usage.output_tokens
                prices = AI_PRICING.get(model, {"input": 3.0, "output": 15.0})
                cost_info = {
                    "model": model,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "input_cost_usd": round((input_tokens / 1_000_000) * prices["input"], 4),
                    "output_cost_usd": round((output_tokens / 1_000_000) * prices["output"], 4),
                    "total_cost_usd": round((input_tokens / 1_000_000) * prices["input"] + (output_tokens / 1_000_000) * prices["output"], 4),
                    "cache_hit": False,
                }
            log.info("claude_cost", **cost_info)

            if debug_info is not None:
                debug_info["cost"] = cost_info

            # Save raw response for debug
            if debug_info is not None:
                debug_info["raw_response"] = response_text
                debug_info["attempt"] = attempt + 1
                debug_info["stop_reason"] = stop_reason

            # Detect truncated response — retry is useless, need more tokens
            if stop_reason == "max_tokens":
                log.warning("claude_response_truncated",
                            attempt=attempt + 1,
                            max_tokens=max_tokens,
                            response_chars=len(response_text))
                raise json.JSONDecodeError(
                    f"Response truncated (max_tokens={max_tokens}, got {len(response_text)} chars)",
                    response_text, len(response_text) - 1,
                )

            # Parse JSON from response — repair common Claude issues
            json_text = _repair_json(response_text)

            try:
                result = _iterative_json_parse(json_text)
            except json.JSONDecodeError:
                # Last resort: extract the outermost JSON object
                match = re.search(r'\{[\s\S]*\}', json_text)
                if match:
                    json_text = _repair_json(match.group(0))
                    result = _iterative_json_parse(json_text)
                else:
                    raise
            log.info(
                "claude_api_success",
                findings=len(result.get("findings", [])),
                positive=len(result.get("positive_findings", [])),
            )
            # Cache-Write nur bei Live-Call und erfolgreichem Parse.
            if not cost_info.get("cache_hit") and response_text:
                set_cached_response(
                    cache_k,
                    response_text=response_text,
                    model=model,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cache_ttl_seconds=REPORTER_CACHE_TTL_SECONDS,
                )

            # Post-process validation pipeline:
            # 1. Cap implausible scores (e.g. robots.txt with CVSS 7.0)
            result = cap_implausible_scores(result)
            # 2. Validate/correct CVSS scores vs vectors
            result = validate_cvss_scores(result)
            # 3. Validate CWE mappings (check if CWE exists)
            result = validate_cwe_mappings(result)
            # 4. Correct CWE assignments (pattern-based, deterministic)
            result = correct_cwe_mappings(result)
            result["_cost"] = cost_info
            return result

        except anthropic.RateLimitError as e:
            if attempt < max_retries - 1:
                wait_time = min(120, 10 * (2 ** attempt))  # 10s, 20s, 40s, 80s
                log.warning("claude_rate_limit", attempt=attempt + 1, wait=wait_time)
                time.sleep(wait_time)
            else:
                raise RuntimeError(
                    f"Claude API rate limited after {max_retries} retries: {e}"
                )

        except anthropic.APITimeoutError as e:
            if attempt < max_retries - 1:
                log.warning("claude_timeout", attempt=attempt + 1)
                time.sleep(5)
            else:
                raise RuntimeError(
                    f"Claude API timeout after {max_retries} retries: {e}"
                )

        except json.JSONDecodeError as e:
            # Wenn der aktuelle Versuch ein Cache-Hit war, ist die gecachte
            # Antwort defekt — invalidieren und im naechsten Versuch live gehen.
            if cache_hit_consumed:
                log.warning("claude_cache_invalidate_corrupt",
                            attempt=attempt + 1, error=str(e))
                delete_cached(cache_k)
                cache_hit_consumed = False  # zwingt naechsten Versuch zu live
            # Log context around the parse error position for debugging
            err_ctx = ""
            if json_text and e.pos is not None:
                ctx_start = max(0, e.pos - 120)
                ctx_end = min(len(json_text), e.pos + 120)
                err_ctx = json_text[ctx_start:ctx_end]
            elif json_text:
                err_ctx = json_text[:300]
            # Save error in debug info
            if debug_info is not None:
                debug_info["error"] = str(e)
                debug_info["error_context"] = err_ctx
            if attempt < max_retries - 1:
                log.warning("claude_json_parse_error", attempt=attempt + 1, error=str(e),
                            error_context=err_ctx)
                time.sleep(3)
            else:
                log.error("claude_json_parse_final_failure", error=str(e),
                          error_context=err_ctx,
                          response_length=len(json_text) if json_text else 0)
                raise RuntimeError(f"Failed to parse Claude response as JSON: {e}")

        except anthropic.APIStatusError as e:
            # Retryable server errors: 429, 500, 502, 503, 529 (overloaded)
            if e.status_code in (429, 500, 502, 503, 529) and attempt < max_retries - 1:
                wait_time = min(120, 15 * (2 ** attempt))  # 15s, 30s, 60s, 120s
                log.warning("claude_api_retryable_error",
                            attempt=attempt + 1, status=e.status_code,
                            wait=wait_time, error=str(e)[:200])
                time.sleep(wait_time)
            else:
                if debug_info is not None:
                    debug_info["error"] = str(e)
                raise RuntimeError(f"Claude API error (HTTP {e.status_code}): {e}")

        except Exception as e:
            if debug_info is not None:
                debug_info["error"] = str(e)
            raise RuntimeError(f"Claude API error: {e}")

    raise RuntimeError("Claude API call failed after all retries")
