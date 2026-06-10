"""Deterministischer CVE-Referenz-Guard (VEC-377).

Verhindert, dass KI-halluzinierte CVE-IDs als verifizierte Referenzen in
Kunden-Reports landen. Hintergrund: Bei der D5-Korrektheits-Verifikation
(VEC-374) nannte ein Report eine Betheme-RCE mit einer CVE-ID, die nicht in
NVD/Mitre auffindbar war — die Vulnerability-Klasse war real, die konkrete
CVE-Referenz aber frei erfunden. Gleiche Halluzinations-Klasse wie VEC-373 (D4).

Jede in einem Finding-Text genannte CVE-ID wird gegen eine *autoritative*
Allowlist validiert:
  - Phase-3 Threat-Intel-Enrichment (NVD/EPSS/CISA-KEV/ExploitDB) — also genau
    die CVEs, die von Scan-Tools detektiert UND von einer autoritativen Quelle
    aufgeloest wurden. `NVDClient.lookup_cve` liefert fuer nicht-existente CVEs
    `None`, sie fehlen dann im enrichment-Dict (siehe scan-worker/phase3.py).
  - kuratierte Build-CVE-Tabellen (known_vuln_builds_generated +
    eol_detector.KNOWN_VULN_BUILDS_MANUAL/EOL_DATA_MANUAL). Diese werden vom
    EOL-Detector als Pflicht-Findings injiziert und sind handgepflegt/aus
    OSV+KEV generiert — also belegt.

CVE-IDs, die in keiner Quelle auflösbar sind, werden im Text durch einen
neutralen Marker ersetzt ("nicht verifizierte CVE-Referenz") und aus
title_vars entfernt. Die Vulnerability-Klasse (z.B. "Betheme RCE") bleibt im
Text erhalten — nur die unbelegte konkrete CVE-Referenz wird zurueckgehalten.

Deterministisch, KEINE KI — analog zum FP-Filter
(scan-worker/scanner/correlation/fp_filter.py).
"""

from __future__ import annotations

import re
from typing import Any

import structlog

log = structlog.get_logger()

# CVE-ID-Muster: CVE-JJJJ-NNNN(N...). Jahr 4-stellig, Sequenz >= 4 Ziffern
# (Mitre-Format seit 2014). Case-insensitive fuer robuste Erkennung.
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Ersetzungs-Marker fuer nicht auflösbare CVE-Referenzen. Bewusst neutral,
# damit er sowohl eingeklammert "(nicht verifizierte CVE-Referenz)" als auch
# nach Label "Referenz: nicht verifizierte CVE-Referenz" lesbar bleibt.
UNVERIFIED_MARKER = "nicht verifizierte CVE-Referenz"

# Textfelder eines Findings, die auf CVE-IDs geprueft werden. Bewusst breit:
# Claude bettet CVEs frei in jeden dieser Strings ein.
_FINDING_TEXT_FIELDS = (
    "title",
    "description",
    "recommendation",
    "impact",
    "evidence",
    "affected",
)


# ---------------------------------------------------------------------------
# Kuratierte CVE-Allowlist (Modul-Cache)
# ---------------------------------------------------------------------------

_curated_cache: set[str] | None = None


def _collect_curated_cves() -> set[str]:
    """Sammelt alle handgepflegten/generierten CVE-IDs aus den Build-Tabellen.

    Diese gelten als belegt (OSV+KEV-Sync bzw. manuell kuratiert) und duerfen
    nicht vom Guard gestrichen werden — sonst wuerde der Guard die vom
    EOL-Detector injizierten Pflicht-Findings ihrer eigenen CVE berauben.

    Cached, weil die Tabellen statisch sind. Defensiv gegen Import-Fehler.
    """
    global _curated_cache
    if _curated_cache is not None:
        return _curated_cache

    cves: set[str] = set()

    def _harvest(table: dict, key: str) -> None:
        for info in table.values():
            if isinstance(info, dict):
                for cve in info.get(key, []) or []:
                    if isinstance(cve, str) and CVE_RE.fullmatch(cve):
                        cves.add(cve.upper())

    try:
        from reporter.known_vuln_builds_generated import (
            KNOWN_VULN_BUILDS_GENERATED,
        )
        _harvest(KNOWN_VULN_BUILDS_GENERATED, "cves")
    except Exception as e:  # pragma: no cover - defensiv
        log.warning("cve_guard_curated_generated_failed", error=str(e))

    try:
        from reporter.eol_detector import (
            EOL_DATA_MANUAL,
            KNOWN_VULN_BUILDS_MANUAL,
        )
        _harvest(KNOWN_VULN_BUILDS_MANUAL, "cves")
        _harvest(EOL_DATA_MANUAL, "cves_post_eol")
    except Exception as e:  # pragma: no cover - defensiv
        log.warning("cve_guard_curated_manual_failed", error=str(e))

    _curated_cache = cves
    return cves


# ---------------------------------------------------------------------------
# Allowlist-Aufbau
# ---------------------------------------------------------------------------

def build_allowlist(enrichment: Any) -> set[str]:
    """Baut die autoritative CVE-Allowlist (UPPERCASE) fuer einen Report.

    Quellen:
      1. Keys des Phase-3-enrichment-Dicts — CVEs, die von Scan-Tools detektiert
         und von NVD/EPSS/KEV/ExploitDB aufgeloest wurden. Zusaetzlich werden
         die `cve_id`-Felder innerhalb der NVD-Subdicts mitgenommen (Robustheit
         gegen leicht abweichende Key-Formate).
      2. kuratierte Build-CVE-Tabellen (siehe _collect_curated_cves).
    """
    allow: set[str] = set(_collect_curated_cves())

    if isinstance(enrichment, dict):
        for key, entry in enrichment.items():
            if isinstance(key, str) and CVE_RE.fullmatch(key):
                allow.add(key.upper())
            if isinstance(entry, dict):
                nvd = entry.get("nvd")
                if isinstance(nvd, dict):
                    cid = nvd.get("cve_id")
                    if isinstance(cid, str) and CVE_RE.fullmatch(cid):
                        allow.add(cid.upper())
    return allow


# ---------------------------------------------------------------------------
# Text-Scrubbing
# ---------------------------------------------------------------------------

def _scrub_text(text: Any, allowlist: set[str], removed: list[str]) -> Any:
    """Ersetzt nicht-auflösbare CVE-IDs in `text` durch den neutralen Marker.

    Verifizierte CVE-IDs bleiben unveraendert (inkl. Original-Schreibweise).
    Gibt den (ggf. veraenderten) Text zurueck; sammelt gestrichene CVEs in
    `removed`. Nicht-Strings werden unveraendert durchgereicht.
    """
    if not isinstance(text, str) or "CVE-" not in text.upper():
        return text

    def _repl(m: re.Match) -> str:
        cve = m.group(0)
        if cve.upper() in allowlist:
            return cve  # belegt → unveraendert lassen
        removed.append(cve.upper())
        return UNVERIFIED_MARKER

    return CVE_RE.sub(_repl, text)


def _scrub_finding(finding: dict, allowlist: set[str], removed: list[str]) -> None:
    """Scrubbt alle Textfelder + title_vars.cve_id eines Findings in-place."""
    if not isinstance(finding, dict):
        return
    for field in _FINDING_TEXT_FIELDS:
        if field in finding:
            finding[field] = _scrub_text(finding[field], allowlist, removed)

    # title_vars.cve_id: wenn unbelegt → entfernen, damit Title-Templates
    # keine halluzinierte CVE rendern. (SP-CVE-Templates feuern nur mit
    # KEV-Enrichment, deren CVE ist immer in der Allowlist — also nie betroffen.)
    tv = finding.get("title_vars")
    if isinstance(tv, dict):
        cid = tv.get("cve_id")
        if isinstance(cid, str) and CVE_RE.fullmatch(cid) and cid.upper() not in allowlist:
            removed.append(cid.upper())
            tv.pop("cve_id", None)


# ---------------------------------------------------------------------------
# Hauptfunktion
# ---------------------------------------------------------------------------

def apply_cve_guard(claude_output: dict, *, enrichment: Any = None) -> dict[str, Any]:
    """Validiert alle CVE-Referenzen im Report gegen die autoritative Allowlist.

    Mutiert `claude_output` in-place:
      - findings[] (Top-N) + additional_findings_summary[]: Textfelder +
        title_vars.cve_id gescrubbt
      - overall_description: gescrubbt

    Returns Stats-Dict::

        {"removed_count": int, "distinct_removed": [..], "allowlist_size": int}
    """
    allowlist = build_allowlist(enrichment)
    removed: list[str] = []

    for finding in claude_output.get("findings") or []:
        _scrub_finding(finding, allowlist, removed)

    for finding in claude_output.get("additional_findings_summary") or []:
        _scrub_finding(finding, allowlist, removed)

    od = claude_output.get("overall_description")
    if isinstance(od, str):
        claude_output["overall_description"] = _scrub_text(od, allowlist, removed)

    distinct = sorted(set(removed))
    if removed:
        log.warning(
            "cve_guard_unverified_stripped",
            removed_count=len(removed),
            distinct_removed=distinct,
            allowlist_size=len(allowlist),
        )
    else:
        log.info("cve_guard_clean", allowlist_size=len(allowlist))

    return {
        "removed_count": len(removed),
        "distinct_removed": distinct,
        "allowlist_size": len(allowlist),
    }


__all__ = [
    "apply_cve_guard",
    "build_allowlist",
    "CVE_RE",
    "UNVERIFIED_MARKER",
]
