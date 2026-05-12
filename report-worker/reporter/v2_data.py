"""v2-Daten-Aggregierungen, die Doc 02 Seite 1-9 versorgen.

Dieses Modul buendelt die "leichten" Aggregationen direkt fuer den
Renderer — schwerere/separate Aggregationen liegen in eigenen Modulen
(layer1_aggregator, business_context, posture_v2, befund_landschaft).

Bewusst getrennt von ``report_mapper.py``, weil ``_augment_for_v2`` dort
nur orchestriert. Hier liegt die fachliche Logik fuer:
  - Scope-Meta (Hosts, Subdomain-Count, Scan-Datum)
  - Methodik-Stats (FP-Filter-Rate, Tool-Versionen, KI-Modelle)
  - Compliance-Indikatoren (DSGVO/BSI/Branchen — fuer Frontpage)
  - Tech-Table v2 (Pro-Host-Tabelle mit Patch-Status + Top-CVE)
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


# ====================================================================
# SCOPE-META (Doc 02 Seite 4)
# ====================================================================
def build_scope_meta(
    scan_meta: dict[str, Any] | None,
    host_inventory: dict[str, Any] | None,
    claude_output: dict[str, Any] | None,
) -> dict[str, Any]:
    """Numerische und kontextuelle Scope-Daten fuer Doc 02 Seite 4.

    Returns dict mit:
        ``domain``            — primaere Domain
        ``hosts_count``       — aktive Hosts in der Pruefung
        ``subdomains_count``  — Anzahl identifizierter Subdomains (kann hoeher
                                sein als hosts_count, weil Discovery >
                                Liveness)
        ``scan_date``         — ISO-Date
        ``started_at``        — full ISO timestamp
        ``finished_at``       — full ISO timestamp oder None
        ``package``           — package-Key
        ``out_of_scope``      — fixe Aufzaehlung (Doc 02 Seite 4 Boilerplate)
    """
    scan_meta = scan_meta or {}
    host_inventory = host_inventory or {}

    domain = scan_meta.get("domain") or host_inventory.get("domain") or "unknown"
    hosts = host_inventory.get("hosts") or []
    hosts_count = len(hosts)

    # Subdomains: aus host_inventory.subdomains (falls vorhanden) oder
    # aus den FQDNs-Listen pro Host.
    subdomains: set[str] = set()
    for sub in host_inventory.get("subdomains") or []:
        if isinstance(sub, str):
            subdomains.add(sub.strip().lower())
        elif isinstance(sub, dict) and sub.get("fqdn"):
            subdomains.add(str(sub["fqdn"]).strip().lower())
    for h in hosts:
        for fq in h.get("fqdns") or []:
            subdomains.add(str(fq).strip().lower())
    subdomains.discard("")
    subdomains_count = len(subdomains)

    started_raw = scan_meta.get("startedAt") or datetime.now().isoformat()
    finished_raw = scan_meta.get("completedAt") or None
    scan_date = str(started_raw)[:10]

    return {
        "domain": domain,
        "hosts_count": hosts_count,
        "subdomains_count": subdomains_count,
        "scan_date": scan_date,
        "started_at": str(started_raw),
        "finished_at": str(finished_raw) if finished_raw else None,
        "package": scan_meta.get("package") or "perimeter",
        "out_of_scope": (
            "interne Netzsegmente",
            "mitarbeiterseitige Authentifizierungssysteme",
            "mobile Endgeraete",
            "Social-Engineering-Versuche",
            "physische Sicherheit",
        ),
    }


# ====================================================================
# METHODIK-STATS (Doc 02 Seite 5)
# ====================================================================
def build_methodology_stats(
    scan_meta: dict[str, Any] | None,
    claude_output: dict[str, Any] | None,
) -> dict[str, Any]:
    """Liefert die Zahlen fuer die "Methodik"-Sektion Seite 5.

    Felder:
        ``filtered_count``   — Anzahl ``additional_findings`` (raw -> nicht
                               verstoffwechselt zum Befund)
        ``selected_count``   — Anzahl finaler Befunde im Report
        ``filter_rate_pct``  — selected / (selected + filtered) * 100
        ``policy_version``   — aktueller POLICY_VERSION-String
        ``ai_models``        — Liste von Mini-Beschreibungen (Sonnet 4.6, Haiku 4.5)
        ``tool_versions``    — Liste mit (tool, version) — best effort
        ``phases``           — Liste mit Phase-Beschreibungen (Doc 02 Seite 5)
    """
    scan_meta = scan_meta or {}
    claude_output = claude_output or {}

    findings = claude_output.get("findings") or []
    additional = claude_output.get("additional_findings") or []
    selected_count = len(findings)
    filtered_count = len(additional)
    total_raw = selected_count + filtered_count
    if total_raw > 0:
        filter_rate_pct = round(filtered_count / total_raw * 100, 1)
    else:
        filter_rate_pct = 0.0

    policy_version = os.environ.get(
        "VECTISCAN_POLICY_VERSION",
        # gleicher Default wie severity_policy.POLICY_VERSION
        "2026-06-01.1",
    )

    ai_models = [
        {
            "name": "Sonnet 4.6",
            "role": (
                "Cross-Tool-Confidence-Boost (Phase 3) und "
                "Klassifizierung neu beobachteter Finding-Pattern."
            ),
            "model_id": "claude-sonnet-4-6",
        },
        {
            "name": "Haiku 4.5",
            "role": (
                "Host-Strategie (Phase 0b), Phase-2-Tool-Konfiguration "
                "und Title-Type-Fallback. Deterministisch durch "
                "temperature=0 + Redis-Cache."
            ),
            "model_id": "claude-haiku-4-5-20251001",
        },
        {
            "name": f"VECTISCAN-Severity-Policy {policy_version}",
            "role": (
                "Deterministische Severity-Vergabe ueberschreibt die "
                "Tool-Severities. KEINE KI im Severity-Pfad."
            ),
            "model_id": "deterministic",
        },
    ]

    tool_versions = []
    for tv in scan_meta.get("toolVersions") or []:
        if isinstance(tv, dict) and tv.get("tool"):
            tool_versions.append((tv["tool"], tv.get("version", "?")))
        elif isinstance(tv, (list, tuple)) and len(tv) >= 2:
            tool_versions.append((str(tv[0]), str(tv[1])))

    phases = [
        {
            "name": "Phase 0 - Reconnaissance",
            "description": (
                "Passive Intelligence (Shodan, AbuseIPDB, WHOIS), "
                "Subdomain-Discovery (subfinder, amass, crt.sh, certspotter) "
                "und Web-Probe (httpx). KI-gestuetzte Host-Strategie "
                "priorisiert die Tiefe pro Host."
            ),
        },
        {
            "name": "Phase 1 - Technologie-Erkennung",
            "description": (
                "Port-Scanning (nmap), Web-Tech-Identifikation "
                "(webtech, wafw00f) pro Host. KI-gestuetzte CMS-Korrektur "
                "und Phase-2-Tool-Konfiguration."
            ),
        },
        {
            "name": "Phase 2 - Tiefer Scan",
            "description": (
                "TLS-Analyse (testssl.sh), Schwachstellen-Scan (nuclei + ZAP), "
                "Directory-Enumeration (ffuf, feroxbuster), Header-Pruefung, "
                "WordPress-Scan (wpscan). Multi-VHost-Probe wenn mehrere "
                "Hostnamen auf eine IP zeigen."
            ),
        },
        {
            "name": "Phase 3 - Korrelation + Threat-Intelligence",
            "description": (
                "Cross-Tool-Korrelation, False-Positive-Filterung, "
                "Anreicherung aus NVD / EPSS / CISA-KEV / ExploitDB. "
                "KI-gestuetzter Confidence-Boost, deterministische "
                "Severity-Policy schreibt die finale Bewertung."
            ),
        },
    ]

    return {
        "filtered_count": filtered_count,
        "selected_count": selected_count,
        "filter_rate_pct": filter_rate_pct,
        "policy_version": policy_version,
        "ai_models": ai_models,
        "tool_versions": tool_versions,
        "phases": phases,
        "out_of_scope_note": (
            "Was leistet dieser Scan nicht? Ein externer automatischer "
            "Scan zeigt die erreichbare Angriffsflaeche und bekannte "
            "Schwachstellenmuster. Er ersetzt nicht: Code-Reviews, interne "
            "Audits, Konfigurations-Audits mit privilegiertem Zugang, "
            "manuelle Penetrationstests. Empfohlene Ergaenzung bei "
            "kritischen Befunden: gezielter manueller Pentest in den "
            "betroffenen Komponenten."
        ),
    }


# ====================================================================
# COMPLIANCE-INDIKATOREN (Doc 02 Seite 2)
# ====================================================================
# Drei Indikatoren auf der Frontpage:
#   - DSGVO Art. 32 (Datensicherheit)
#   - BSI IT-Grundschutz (Basisabsicherung)
#   - Branchen-Empfehlungen (cluster-spezifisch)
#
# Mapping:
#   keine HIGH/CRITICAL Findings              -> "Konform"
#   nur MEDIUM oder LOW                       -> "Teilerfuellt"
#   HIGH oder CRITICAL Findings vorhanden     -> "Handlungsbedarf"

_SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _global_status(findings: list[dict]) -> str:
    max_sev = "INFO"
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(max_sev, 0):
            max_sev = sev
    if max_sev in ("CRITICAL", "HIGH"):
        return "Handlungsbedarf"
    if max_sev in ("MEDIUM", "LOW"):
        return "Teilerfuellt"
    return "Konform"


def build_compliance_indicators(
    claude_output: dict[str, Any] | None,
    business_context: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Drei Indikatoren fuer Doc 02 Seite 2.

    Die Logik ist bewusst grob — die genaue Compliance-Mapping-Tabelle
    landet in Anhang D (Track 5c). Auf der Frontpage geht es um den
    'Ueberblicks-Status', nicht um Einzelnachweise.
    """
    findings = (claude_output or {}).get("findings") or []
    status = _global_status(findings)
    business_context = business_context or {}
    cluster_label = business_context.get("cluster_label") or "Branchen-Empfehlungen"

    return [
        {
            "label": "DSGVO Art. 32 (Datensicherheit)",
            "status": status,
        },
        {
            "label": "BSI IT-Grundschutz (Basisabsicherung)",
            "status": status,
        },
        {
            "label": f"Branchen-Empfehlungen: {cluster_label}",
            "status": status,
        },
    ]


# ====================================================================
# TECH-TABLE v2 (Doc 02 Seite 6)
# ====================================================================
def build_tech_table_v2(
    host_inventory: dict[str, Any] | None,
    tech_profiles: list[dict] | None,
) -> list[dict[str, Any]]:
    """Pro Host eine Tech-Tabelle v2.

    Quelle ist M2 Track 2c (``tech_table_builder.build_tech_table_for_host``).
    Erkennung/Patch-Status sind in der Quelle bereits getrennt, Top-CVE
    nach EPSS ist mit ausgewertet.

    Returns: List[{host_label, ip, rows: list[dict]}]
        wobei rows die direkte Ausgabe von build_tech_table_for_host ist.
    """
    from reporter.tech_table_builder import build_tech_table_for_host

    host_inventory = host_inventory or {}
    tech_profiles = tech_profiles or []
    hosts = host_inventory.get("hosts") or []

    profile_by_ip: dict[str, dict] = {}
    for p in tech_profiles:
        if not isinstance(p, dict):
            continue
        ip = p.get("ip")
        if ip:
            profile_by_ip[ip] = p

    tables: list[dict[str, Any]] = []
    for h in hosts:
        ip = h.get("ip") or ""
        fqdns = h.get("fqdns") or []
        host_label = f"{(fqdns[0] if fqdns else ip)} - {ip}".strip(" -")
        profile = profile_by_ip.get(ip)
        if not profile:
            continue
        try:
            rows = build_tech_table_for_host(profile)
        except Exception as e:  # pragma: no cover
            logger.warning(
                "tech_table_v2_failed_for_host",
                extra={"ip": ip, "err": str(e)},
            )
            rows = []
        if not rows:
            continue
        tables.append({
            "host_label": host_label,
            "ip": ip,
            "rows": rows,
        })
    return tables


__all__ = [
    "build_scope_meta",
    "build_methodology_stats",
    "build_compliance_indicators",
    "build_tech_table_v2",
]
