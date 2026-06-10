"""Post-Claude Determinismus-Pipeline.

Hooked nach call_claude() im worker.py: nimmt das Claude-extrahierte
findings-Array entgegen und ueberschreibt Severities + waehlt Top-N
deterministisch aus.

Ablauf:
    1. finding_type_mapper.annotate_finding_types  → finding_type pro finding
    2. _normalize_for_policy                         → in policy-kompatibles Schema
    3. severity_policy.apply_policy                  → severity, policy_id, provenance
    4. business_impact.recompute                     → business_impact_score
    5. selection.select_findings                     → Top-N + additional
    6. _writeback_to_claude_output                   → claude_output.findings ersetzen

Spec: docs/deterministic/02-severity-policy.md, 04-deterministic-selection.md.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog

from reporter import business_impact, selection, severity_policy
from reporter.finding_type_mapper import annotate_finding_types
from reporter.severity_policy import POLICY_VERSION

log = structlog.get_logger()


# ---------------------------------------------------------------------------
# Schema-Normalisierung
# ---------------------------------------------------------------------------

def _to_lower_severity(sev: Any) -> str:
    return (str(sev or "info")).lower()


def _to_upper_severity(sev: Any) -> str:
    return (str(sev or "INFO")).upper()


def _normalize_for_policy(claude_findings: list[dict]) -> list[dict]:
    """Konvertiert Claude-Findings ins von severity_policy erwartete Schema.

    Claude-Output hat: id, title, severity (UPPER), cvss_score (str), cwe (str),
                       affected, description, evidence, impact, recommendation
    Policy erwartet: finding_id, finding_type, severity (lower), cvss_score (float),
                     url, evidence (dict ist optional), tool_source.

    NICHT mutiert — gibt eine Liste neuer Dicts zurueck.
    """
    normalized: list[dict] = []
    for f in claude_findings:
        cvss = f.get("cvss_score")
        try:
            cvss_f = float(cvss) if cvss is not None else None
        except (ValueError, TypeError):
            cvss_f = None
        n = {
            "finding_id": f.get("id") or f.get("finding_id"),
            "title": f.get("title"),
            "severity": _to_lower_severity(f.get("severity")),
            "cvss_score": cvss_f,
            "cvss_vector": f.get("cvss_vector"),
            "cwe": f.get("cwe"),
            "affected": f.get("affected") or "",
            "url": f.get("affected") or "",  # Claude nutzt "affected" als URL/Host
            "description": f.get("description") or "",
            "impact": f.get("impact") or "",
            "evidence": f.get("evidence") or "",
            "recommendation": f.get("recommendation") or "",
            "tool_source": f.get("tool_source") or "claude_extraction",
            # Optionale Threat-Intel-Daten reichen wir durch
            "threat_intel": f.get("threat_intel") or {},
            "enrichment": f.get("enrichment") or {},
        }
        # finding_type wird gleich vom mapper gesetzt
        normalized.append(n)
    return normalized


def _merge_orig_with_policy(orig: dict, pf: dict) -> dict:
    """Mergt KI-original + policy-normalisiertes Finding zu einem Output-dict."""
    merged = dict(orig)  # preserve existing description/recommendation/impact
    merged["severity"] = _to_upper_severity(pf.get("severity") or orig.get("severity"))
    if pf.get("cvss_score") is not None:
        merged["cvss_score"] = str(pf["cvss_score"])
    if pf.get("cvss_vector"):
        merged["cvss_vector"] = pf["cvss_vector"]
    if pf.get("policy_id"):
        merged["policy_id"] = pf["policy_id"]
    if pf.get("severity_provenance"):
        merged["severity_provenance"] = pf["severity_provenance"]
    if pf.get("business_impact_score") is not None:
        merged["business_impact_score"] = pf["business_impact_score"]
    if pf.get("affected_hosts"):
        merged["affected_hosts"] = pf["affected_hosts"]
    ft = pf.get("finding_type") or orig.get("finding_type")
    if ft:
        merged["finding_type"] = ft
    if pf.get("_finding_type_source"):
        merged["_finding_type_source"] = pf["_finding_type_source"]
    return merged


def _writeback_to_claude(claude_findings_in: list[dict],
                         policy_findings: list[dict],
                         selected: list[dict]) -> list[dict]:
    """Mergt die Policy-Annotationen zurueck in das urspruengliche Claude-Format.

    Reihenfolge: selected first (Top-N nach business_impact), then any
    additional (in unveraenderter Order). Der existierende Mapper sortiert
    spaeter sowieso nach Severity.

    Wichtig: Severity wird auf UPPER zurueckgesetzt (PDF/Mapper-Erwartung).
    """
    # Index policy_findings by finding_id
    policy_by_id = {pf.get("finding_id"): pf for pf in policy_findings if pf.get("finding_id")}
    selected_ids = {sf.get("finding_id") for sf in selected if sf.get("finding_id")}

    out: list[dict] = []
    for orig in claude_findings_in:
        fid = orig.get("id") or orig.get("finding_id")
        if fid not in selected_ids:
            continue
        pf = policy_by_id.get(fid, {})
        out.append(_merge_orig_with_policy(orig, pf))
    return out


def _build_additional_findings_full_body(
    claude_findings_in: list[dict],
    additional_normalized: list[dict],
) -> list[dict]:
    """Baut Voll-Body-Dicts fuer die nicht-selektierten Findings.

    Migration 027: API/Frontend brauchen Voll-Body um "alle Befunde anzeigen"-
    Drilldown sinnvoll zu zeigen. Vorher nur id/title/severity/policy_id.
    """
    orig_by_id = {(f.get("id") or f.get("finding_id")): f for f in claude_findings_in}
    out: list[dict] = []
    for pf in additional_normalized:
        fid = pf.get("finding_id")
        orig = orig_by_id.get(fid, {})
        out.append(_merge_orig_with_policy(orig, pf))
    return out


# ---------------------------------------------------------------------------
# Hauptfunktion
# ---------------------------------------------------------------------------

def apply_deterministic_pipeline(claude_output: dict,
                                 *,
                                 package: str,
                                 domain: str = "",
                                 scan_context: dict | None = None) -> dict:
    """Wendet die Determinismus-Pipeline auf claude_output an.

    Modifiziert claude_output IN-PLACE:
      - claude_output["findings"] wird durch die Top-N-Liste ersetzt
        (Severity/CVSS/policy_id/provenance auf jedem Finding gesetzt)
      - claude_output["additional_findings"] enthaelt die nicht selektierten
      - claude_output["policy_version"] = aktueller POLICY_VERSION
      - claude_output["policy_id_distinct"] = sortierte distinct-Liste
      - claude_output["selection_stats"] = Stats aus SelectionResult

    Returns: das (mutierte) claude_output
    """
    findings_in = claude_output.get("findings") or []
    sc = scan_context or {}

    # C2 (Mai 2026): EOL-Detector laeuft VOR der KI-Liste — Pflicht-Findings
    # fuer EOL-Software (Exchange 2016, Win-Server 2012, OpenSSL 1.0, etc.)
    # plus kritische Build-CVE-Whitelist (ProxyShell, Heartbleed, ...).
    # Ergebnis wird mit Claude-Output dedupliziert (claude_findings wins
    # fuer bessere Beschreibung; eol_detector setzt _deterministic_source).
    try:
        from reporter.eol_detector import detect_eol_findings, merge_into_claude_findings
        tech_profiles = sc.get("tech_profiles") or sc.get("techProfiles") or []
        eol_findings = detect_eol_findings(tech_profiles)
        if eol_findings:
            findings_in = merge_into_claude_findings(
                findings_in, eol_findings, tech_profiles=tech_profiles,
            )
            claude_output["findings"] = findings_in
            log.info("eol_detector_findings_added", count=len(eol_findings),
                     total_after_merge=len(findings_in))
    except Exception as e:
        log.warning("eol_detector_failed", error=str(e))

    if not findings_in:
        log.info("deterministic_pipeline_skipped_empty",
                 package=package, reason="no findings")
        claude_output["policy_version"] = POLICY_VERSION
        claude_output["policy_id_distinct"] = []
        claude_output["selection_stats"] = {"original_count": 0,
                                            "selected_count": 0}
        return claude_output

    # 1. Normalisieren + finding_type ableiten (mit AI-Fallback bei Miss)
    normalized = _normalize_for_policy(findings_in)
    annotate_finding_types(normalized)

    # 2. severity_policy
    severity_policy.apply_policy(normalized, sc)

    # 3. business_impact
    business_impact.recompute(normalized, package=package, domain=domain)

    # 4. selection
    sel = selection.select_findings(normalized, package=package)

    log.info("deterministic_pipeline_applied",
             package=package,
             original=sel.original_count,
             consolidated_groups=sel.consolidation_groups,
             selected=len(sel.selected),
             additional=len(sel.additional))

    # 5. Schreibe zurueck in claude_output
    claude_output["findings"] = _writeback_to_claude(
        findings_in, normalized, sel.selected,
    )

    # 5a. Recommendations.finding_refs auf ueberlebende IDs prunen.
    # Ohne diesen Sync referenziert die Massnahmenplan-Tabelle Phantom-IDs
    # von Findings, die durch Konsolidierung oder Top-N-Cap gedroppt wurden.
    surviving_ids = {f.get("id") for f in claude_output["findings"] if f.get("id")}
    recs_in = claude_output.get("recommendations") or []
    if recs_in and surviving_ids:
        pruned_recs: list[dict] = []
        dropped_refs = 0
        for rec in recs_in:
            raw_refs = rec.get("finding_refs") or []
            valid = [r for r in raw_refs if r in surviving_ids]
            dropped_refs += len(raw_refs) - len(valid)
            if not valid and raw_refs:
                # Recommendation hatte Refs, alle wurden konsolidiert/gedroppt -> Massnahme orphan, drop.
                continue
            rec["finding_refs"] = valid
            pruned_recs.append(rec)
        if dropped_refs or len(pruned_recs) != len(recs_in):
            log.info("recommendation_refs_pruned",
                     dropped_refs=dropped_refs,
                     dropped_recs=len(recs_in) - len(pruned_recs),
                     surviving_findings=len(surviving_ids))
        claude_output["recommendations"] = pruned_recs

    # 5b. Title-Templates pro policy_id anwenden (Determinismus)
    # Eliminiert KI-Wording-Drift ueber wiederholte Scans.
    from reporter.title_policy import apply_titles
    title_overridden = apply_titles(
        claude_output["findings"],
        scan_context={"domain": domain, **sc},
    )
    if title_overridden:
        log.info("title_templates_applied", count=title_overridden,
                 total=len(claude_output["findings"]))

    # 5c. ID-Renumerierung (M1 / Doc 01 Phase F)
    # Vor M1 trugen Findings die Claude-vergebenen IDs (VS-YYYY-XXX), die
    # nach FP-Filter / Konsolidierung / Top-N-Cap Luecken hatten. Ab M1:
    #   - `policy_id` bleibt intern stabil (Audit-Trail)
    #   - `external_id` wird lueckenlos VS-YYYY-001..N vergeben
    #   - `id` (kundenseitig sichtbar) = external_id
    #   - `original_claude_id` haelt den Pre-Renumerierungs-Wert fuer Audit
    # WICHTIG: Nur claude_output["findings"] (Top-N) wird renumeriert;
    # sel.additional behaelt seine Original-IDs, weil diese im Anhang
    # "Methodisch ausgeschlossene Befunde" rein als Counts referenziert werden.
    from reporter.id_renumber import remap_recommendation_refs, renumber_findings
    id_remap = renumber_findings(
        claude_output["findings"], year=datetime.now().year,
    )
    if id_remap:
        refs_remapped = remap_recommendation_refs(
            claude_output.get("recommendations") or [], id_remap,
        )
        log.info("id_renumbering_applied",
                 findings_renumbered=len(id_remap),
                 recommendation_refs_remapped=refs_remapped)

    # Additional als separate Liste mit Voll-Body — Migration 027 (Mai 2026):
    # API + Frontend brauchen description/recommendation/impact/cvss_*/affected_hosts
    # damit "alle Befunde anzeigen"-Drilldown ohne Reporter-Re-Run funktioniert.
    # Title-Templates vorab anwenden fuer Konsistenz mit Top-N.
    apply_titles(sel.additional, scan_context={"domain": domain, **sc})
    claude_output["additional_findings_summary"] = _build_additional_findings_full_body(
        findings_in, sel.additional,
    )

    # 5d. CVE-Referenz-Guard (VEC-377): KI-genannte CVE-IDs gegen die
    # autoritative NVD/KEV/EPSS-Anreicherung + kuratierte Build-Tabellen
    # validieren. Nicht auflösbare (halluzinierte) CVE-IDs werden im Text
    # durch einen neutralen Marker ersetzt — die Vulnerability-Klasse bleibt
    # erhalten, nur die unbelegte CVE-Referenz wird zurueckgehalten.
    from reporter.cve_guard import apply_cve_guard
    cve_stats = apply_cve_guard(
        claude_output, enrichment=sc.get("enrichment"),
    )
    claude_output["cve_guard_stats"] = cve_stats
    if cve_stats["removed_count"]:
        log.info("cve_guard_applied",
                 removed=cve_stats["removed_count"],
                 distinct=cve_stats["distinct_removed"],
                 allowlist_size=cve_stats["allowlist_size"])

    # Audit-Felder
    claude_output["policy_version"] = POLICY_VERSION
    claude_output["policy_id_distinct"] = sorted({
        f.get("policy_id") for f in normalized if f.get("policy_id")
    })
    claude_output["selection_stats"] = {
        "original_count": sel.original_count,
        "consolidated_groups": sel.consolidation_groups,
        "selected_count": len(sel.selected),
        "additional_count": len(sel.additional),
        "top_n": sel.top_n,
    }
    return claude_output


__all__ = [
    "apply_deterministic_pipeline",
]
