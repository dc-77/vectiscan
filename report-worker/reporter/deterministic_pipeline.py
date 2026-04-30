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
        merged = dict(orig)  # preserve existing description/recommendation/impact
        # Override the deterministic-relevant fields
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
        out.append(merged)
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
    if not findings_in:
        log.info("deterministic_pipeline_skipped_empty",
                 package=package, reason="no findings")
        claude_output["policy_version"] = POLICY_VERSION
        claude_output["policy_id_distinct"] = []
        claude_output["selection_stats"] = {"original_count": 0,
                                            "selected_count": 0}
        return claude_output

    sc = scan_context or {}

    # 1. Normalisieren + finding_type ableiten
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
    # Additional als separate Liste behalten (fuer „weitere Befunde"-Anhang)
    claude_output["additional_findings_summary"] = [
        {
            "id": f.get("finding_id"),
            "title": f.get("title"),
            "severity": _to_upper_severity(f.get("severity")),
            "policy_id": f.get("policy_id"),
        }
        for f in sel.additional
    ]
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
