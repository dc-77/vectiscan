"""Befund-Landschaft + Service-Karte fuer Doc 02 Seite 8-9 + 6-7.

Doc 02 Leitsatz: "Uebersicht aller Befunde — gruppiert nach Massnahmen-
kategorie, nicht nach CVSS-Score." Kategorisierung deterministisch ueber
``policy_id``-Praefixe.

Plus: Service-Karte (Doc 02 Seite 6-7) — pro Host eine kompakte
visuelle Port-Liste mit Ampelfarben.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)


# ====================================================================
# KATEGORIEN — Doc 02 Seite 8-9
# ====================================================================
# Reihenfolge ist die Anzeige-Reihenfolge im Report (oben = wichtigster
# Massnahmenbereich). Doc 02 nennt explizit:
#   A — Exponierte Infrastrukturdienste (DB, FTP, RDP, Dev-Umgebung)
#   B — Veraltete Software (EOL, WordPress-veraltet)
#   C — E-Mail-Authentifizierung (SPF/DKIM/DMARC)
#   D — Informationspreisgabe (Server-Banner, Generator-Tags)
#   E — Web-Hygiene (Header, Cookies, CSP)
#   F — TLS/Krypto
#   G — Sonstiges (Auffang)

CATEGORIES: tuple[dict[str, Any], ...] = (
    {
        "key": "exposed_services",
        "label": "Kategorie A - Exponierte Infrastrukturdienste",
        "prefixes": ("SP-DB", "SP-RDP", "SP-FTP", "SP-SSH"),
        "finding_types": (
            "database_port_exposed", "rdp_exposed", "ftp_cleartext",
            "ssh_weak", "dev_environment_exposed",
        ),
    },
    {
        "key": "outdated_software",
        "label": "Kategorie B - Veraltete Software / EOL",
        "prefixes": ("SP-EOL", "SP-CVE", "SP-WP", "SP-CMS", "SP-JS"),
        "finding_types": (
            "software_eol", "outdated_software", "cve_finding",
            "wordpress_plugin_vulnerability",
        ),
    },
    {
        "key": "mail_authenticity",
        "label": "Kategorie C - E-Mail-Authentifizierung",
        "prefixes": ("SP-DNS",),
        "finding_types": (
            "mail_security_missing", "mail_security_missing_spf",
            "mail_security_missing_dkim", "mail_security_missing_dmarc",
            "mail_security_dmarc_none",
        ),
    },
    {
        "key": "info_disclosure",
        "label": "Kategorie D - Informationspreisgabe",
        "prefixes": ("SP-DISC", "SP-INFO"),
        "finding_types": (
            "info_disclosure_banner", "info_disclosure_meta_generator",
            "tech_detection_artefact",
        ),
    },
    {
        "key": "web_hygiene",
        "label": "Kategorie E - Web-Hygiene (Header, Cookies, CSP)",
        "prefixes": ("SP-HDR", "SP-CSP", "SP-COOK", "SP-CSRF", "SP-WEB"),
        "finding_types": (),
    },
    {
        "key": "tls_crypto",
        "label": "Kategorie F - TLS / Krypto",
        "prefixes": ("SP-TLS",),
        "finding_types": ("tls_weak_cipher", "tls_obsolete_version", "cleartext_login"),
    },
    {
        "key": "other",
        "label": "Kategorie G - Sonstiges",
        "prefixes": (),
        "finding_types": (),
    },
)


# Severity -> Schwerpunkt-Label (Doc 02: "Schwerpunkt HOCH/MITTEL/NIEDRIG")
_SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _schwerpunkt_label(findings: list[dict]) -> str:
    if not findings:
        return "—"
    max_sev = "INFO"
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(max_sev, 0):
            max_sev = sev
    return {
        "CRITICAL": "kritisch",
        "HIGH": "hoch",
        "MEDIUM": "mittel",
        "LOW": "niedrig",
        "INFO": "info",
    }.get(max_sev, "info")


def _classify_finding(finding: dict) -> str:
    """Welche Kategorie passt? Erste passende Kategorie gewinnt (deterministisch)."""
    pid = (finding.get("policy_id") or "").upper().strip()
    ft = (finding.get("finding_type") or "").lower().strip()
    for cat in CATEGORIES:
        if cat["key"] == "other":
            continue
        if pid and any(pid.startswith(p) for p in cat["prefixes"]):
            return cat["key"]
        if ft and ft in cat["finding_types"]:
            return cat["key"]
    return "other"


def build_befund_landschaft(
    findings: list[dict],
    positive_findings: list[dict] | None = None,
) -> dict[str, Any]:
    """Doc 02 Seite 8-9: Kategorisierung der Befunde + positive Findings.

    Returns Dict mit:
        ``categories``:        Liste pro Kategorie mit (label, count, schwerpunkt, findings)
        ``positive_findings``: Liste der positiven Befunde (verkuerzte Form)
        ``total_count``:       Summe ueber alle Befunde
    """
    findings = findings or []
    positive_findings = positive_findings or []

    bucket: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        # Positive Findings sollen nicht in den negativen Kategorien landen
        if f.get("is_positive_finding"):
            continue
        cat_key = _classify_finding(f)
        bucket[cat_key].append(f)

    result_categories: list[dict[str, Any]] = []
    for cat in CATEGORIES:
        fs = bucket.get(cat["key"], [])
        if not fs:
            continue
        # Stable Sort innerhalb der Kategorie: Severity DESC, dann ID ASC
        fs_sorted = sorted(
            fs,
            key=lambda f: (
                -_SEV_RANK.get((f.get("severity") or "INFO").upper(), 0),
                f.get("id") or f.get("external_id") or "",
            ),
        )
        result_categories.append({
            "key": cat["key"],
            "label": cat["label"],
            "count": len(fs_sorted),
            "schwerpunkt": _schwerpunkt_label(fs_sorted),
            "findings": [
                {
                    "id": (f.get("external_id") or f.get("id") or "?"),
                    "title": f.get("title") or "(ohne Titel)",
                    "severity": (f.get("severity") or "INFO").upper(),
                }
                for f in fs_sorted
            ],
        })

    positive_block = [
        {
            "id": (f.get("external_id") or f.get("id") or "POS"),
            "title": f.get("title") or "(ohne Titel)",
        }
        for f in positive_findings
    ]

    return {
        "categories": result_categories,
        "positive_findings": positive_block,
        "total_count": sum(c["count"] for c in result_categories),
    }


# ====================================================================
# SERVICE-KARTE (Doc 02 Seite 6-7)
# ====================================================================
# Doc 02-Spezifikation:
#   "Eine kompakte visuelle Darstellung der erreichbaren Ports pro Host"
#   Mit Ampelfarben (rot = direkt riskant, orange = klartext, gruen = okay).

# Direkt riskante Ports — generell ungewollt aus dem Internet erreichbar
RED_PORTS: dict[int, str] = {
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    3389: "RDP",
    23: "Telnet",
    111: "RPC",
    445: "SMB",
    139: "NetBIOS",
    1433: "MSSQL",
    1521: "Oracle",
    9200: "Elasticsearch",
    11211: "Memcached",
    5900: "VNC",
    5984: "CouchDB",
}

# Klartext-Protokolle — funktional ok, aber sicherheits-bedenklich
ORANGE_PORTS: dict[int, str] = {
    21: "FTP",
    80: "HTTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    143: "IMAP",
    389: "LDAP",
}

# Service-Name-Hints fuer Anzeige (Default: nmap-service-name)
SERVICE_LABELS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 465: "SMTPS", 587: "SUBM", 993: "IMAPS",
    995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PgSQL",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
    6379: "Redis", 9200: "ES", 11211: "Memcache",
}


def _port_color(port: int) -> str:
    if port in RED_PORTS:
        return "#DC2626"   # red-600
    if port in ORANGE_PORTS:
        return "#F97316"   # orange-500
    return "#22C55E"       # green-500


def _port_service_label(port: int, fallback: str | None) -> str:
    if port in SERVICE_LABELS:
        return SERVICE_LABELS[port]
    if fallback:
        return fallback[:8]
    return "?"


def build_service_cards(
    host_inventory: dict[str, Any] | None,
    tech_profiles: list[dict] | None,
) -> list[dict[str, Any]]:
    """Doc 02 Seite 6-7: pro Host eine Service-Karte.

    Quelle ist primaer ``tech_profile["nmap"]["open_ports"]``, mit Fallback
    auf ``tech_profile["exposed_services"]`` (Shodan).

    Returns Liste pro Host mit ``host_label``, ``ports`` (List[(port, service, color)]).
    """
    host_inventory = host_inventory or {}
    tech_profiles = tech_profiles or []
    hosts = host_inventory.get("hosts") or []

    # tech_profile per IP
    profile_by_ip: dict[str, dict] = {}
    for p in tech_profiles:
        if not isinstance(p, dict):
            continue
        ip = p.get("ip")
        if ip:
            profile_by_ip[ip] = p

    cards: list[dict[str, Any]] = []
    for h in hosts:
        ip = h.get("ip") or ""
        fqdns = h.get("fqdns") or []
        host_label = f"{(fqdns[0] if fqdns else ip)} - {ip}".strip(" -")
        profile = profile_by_ip.get(ip, {})

        ports_seen: set[int] = set()
        port_entries: list[tuple[int, str, str]] = []

        def _add_port(p: Any, svc: str | None = None) -> None:
            """Akzeptiert int, str, oder dict mit 'port'-Key."""
            try:
                if isinstance(p, dict):
                    port = int(p.get("port"))
                    svc_in = svc or p.get("service") or p.get("name")
                else:
                    port = int(p)
                    svc_in = svc
            except (TypeError, ValueError):
                return
            if port in ports_seen:
                return
            ports_seen.add(port)
            port_entries.append((
                port,
                _port_service_label(port, svc_in),
                _port_color(port),
            ))

        # 1. tech_profile["open_ports"] TOP-LEVEL — Prod-Format aus
        #    scan-worker/scanner/phase1.py:663 (flache list[int]).
        for entry in profile.get("open_ports") or []:
            _add_port(entry)

        # 2. tech_profile["services"] (falls vorhanden, dann mit Service-Namen)
        for entry in profile.get("services") or []:
            _add_port(entry)

        # 3. tech_profile["nmap"]["open_ports"] — Test-Fixture-Format
        nmap = profile.get("nmap") or {}
        for entry in nmap.get("open_ports") or []:
            _add_port(entry)

        # 4. Shodan-exposed_services Fallback
        for entry in profile.get("exposed_services") or []:
            try:
                port = int(entry.get("port"))
                svc = (entry.get("service") or "").split(" ")[0] or None
            except (TypeError, ValueError, AttributeError):
                continue
            _add_port(port, svc)

        # 5. host_inventory.hosts[*].open_ports (Last-Ditch-Fallback)
        for entry in h.get("open_ports") or []:
            _add_port(entry)

        # Stable Sort: Risk-Color first (rot oben), dann Port-Number
        _color_order = {"#DC2626": 0, "#F97316": 1, "#22C55E": 2}
        port_entries.sort(
            key=lambda t: (_color_order.get(t[2], 9), t[0]),
        )
        cards.append({
            "host_label": host_label,
            "ip": ip,
            "ports": port_entries,
            "port_count": len(port_entries),
        })

    return cards


__all__ = [
    "CATEGORIES",
    "build_befund_landschaft",
    "build_service_cards",
]
