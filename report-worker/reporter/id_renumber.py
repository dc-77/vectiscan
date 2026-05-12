"""ID-Renumerierung nach Selection (M1 / Doc 01 Phase F).

Vergibt lueckenlose kundenseitige Befund-IDs (VS-YYYY-001..N), waehrend
`policy_id` als interner Audit-Trail-Anker stabil bleibt.

Sortierreihenfolge der Vergabe: identisch zur Render-Reihenfolge im
PDF — severity DESC (CRITICAL->INFO), dann cvss_score DESC, dann
policy_id/finding_id als Tiebreaker. Das ist deterministisch und passt
damit zur visuellen Reihenfolge im Befund-Block.

WICHTIG: Diese Funktion mutiert die Findings IN-PLACE und gibt zusaetzlich
ein `id_remap`-Dict zurueck (alte_id -> neue_external_id), damit Aufrufer
recommendations.finding_refs synchron remappen koennen.
"""

from __future__ import annotations

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _sort_key_for_render(finding: dict) -> tuple:
    """Sortier-Schluessel — gleich der Render-Sortierung im PDF.

    1. severity (CRITICAL first)
    2. cvss_score DESC
    3. policy_id/finding_id ASC (Tiebreaker fuer 100% Determinismus)
    """
    sev = (finding.get("severity") or "INFO").upper()
    try:
        cvss = float(finding.get("cvss_score") or 0)
    except (TypeError, ValueError):
        cvss = 0.0
    return (
        _SEVERITY_ORDER.get(sev, 5),
        -cvss,
        str(
            finding.get("policy_id")
            or finding.get("finding_id")
            or finding.get("id")
            or ""
        ),
    )


def renumber_findings(findings: list[dict], year: int) -> dict[str, str]:
    """Vergibt lueckenlose `external_id` (VS-YYYY-001..N) an alle Findings.

    Mutiert in-place:
      - finding["original_claude_id"] = vorheriger finding["id"]
      - finding["external_id"]        = "VS-YYYY-NNN"
      - finding["id"]                 = external_id (Kunden-sichtbare ID)
      - finding["policy_id"]          bleibt unveraendert (Audit-Trail)

    Returns:
        id_remap = {alte_id: neue_external_id} fuer recommendation-Sync.
    """
    if not findings:
        return {}

    # Sortieren nach Render-Reihenfolge — IDs werden in dieser Reihenfolge vergeben.
    # findings selbst wird NICHT umsortiert; nur die ID-Vergabe folgt dem Render-Key.
    findings_sorted = sorted(findings, key=_sort_key_for_render)

    id_remap: dict[str, str] = {}
    for idx, f in enumerate(findings_sorted, start=1):
        old_id = f.get("id")
        new_id = f"VS-{year}-{idx:03d}"
        if old_id and old_id != new_id:
            id_remap[old_id] = new_id
        # Audit-Felder
        f["original_claude_id"] = old_id
        f["external_id"] = new_id
        # Kunden-sichtbare ID = neue ID (id-Feld wird vom Reporter/PDF gelesen)
        f["id"] = new_id
        # policy_id bleibt unveraendert (intern stabiler Audit-Trail-Anker)

    return id_remap


def remap_recommendation_refs(
    recommendations: list[dict], id_remap: dict[str, str]
) -> int:
    """Mappt finding_refs in Recommendations auf die neuen external_ids.

    Returns:
        Anzahl der gemappten Refs.
    """
    mapped = 0
    if not recommendations or not id_remap:
        return 0
    for rec in recommendations:
        refs = rec.get("finding_refs") or []
        new_refs = []
        for r in refs:
            if r in id_remap:
                new_refs.append(id_remap[r])
                mapped += 1
            else:
                new_refs.append(r)
        rec["finding_refs"] = new_refs
    return mapped


__all__ = ["renumber_findings", "remap_recommendation_refs"]
