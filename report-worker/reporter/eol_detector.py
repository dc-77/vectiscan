"""Deterministischer EOL-Detector — generiert Pflicht-Findings fuer
Software-Produkte deren End-of-Life-Datum erreicht/ueberschritten ist.

Hintergrund (securess.de Mai 2026): KI #5 entscheidet ad-hoc ob ein
EOL-Risk in den Report kommt. Resultat: Exchange 2016 wurde nur in 1 von
3 Reports erwaehnt. Fix: tool-side Detection garantiert das Finding.

Workflow:
1. `detect_eol_findings(tech_profiles, scan_date)` iteriert tech_profiles
2. Match (vendor, product, version) gegen EOL_DATA + KNOWN_VULN_BUILDS
3. Erzeugt deterministische Finding-Dicts mit:
   - `finding_type="software_eol"` (severity_policy SP-EOL-001 greift)
   - `policy_id="SP-EOL-001"` direkt gesetzt
   - `_deterministic_source="eol_detector"` (Audit-Marker)
   - `title_vars` mit tech/version/host/days

Hook in deterministic_pipeline VOR severity_policy: Findings werden mit
KI-Output gemerged (Dedup nach (host_ip, finding_type, version)).

Datenbank ist hier hardcoded — uebersichtlich, version-controlled. Bei
neuen EOL-Daten: PR mit Erweiterung von EOL_DATA/KNOWN_VULN_BUILDS.
"""

from __future__ import annotations

import logging
import re
from datetime import date, datetime
from typing import Any

log = logging.getLogger(__name__)


def _load_eol_union() -> dict[tuple[str, str, str], dict[str, Any]]:
    """Vereint EOL_DATA_GENERATED (von scripts/sync-eol-data.py) mit
    EOL_DATA_MANUAL (lokale Overrides / Spezial-Eintraege mit CVE-Listen).

    Manual-Eintraege ueberschreiben Generated bei gleichem Schluessel —
    so koennen wir z.B. Exchange 2016 mit handgepflegten cves_post_eol
    behalten, auch wenn endoflife.date dasselbe Datum liefert.
    """
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    try:
        from reporter.eol_data_generated import EOL_DATA_GENERATED
        merged.update(EOL_DATA_GENERATED)
    except Exception:
        pass  # generated-File noch nicht erzeugt → nur Manual nutzen
    return merged


# Schluessel: (vendor_lower, product_lower, version_prefix)
# product=None matcht jeden product des vendors mit dieser version
# Werte:
#   date         — EOL-Datum (ISO)
#   severity     — explizite Severity (default LOW falls nicht gesetzt)
#   cves_post_eol — bekannte schwerwiegende CVEs nach EOL
EOL_DATA_MANUAL: dict[tuple[str, str, str], dict[str, Any]] = {
    # Microsoft Exchange — Build-Versionen: 15.1.x=2016, 15.0.x=2013,
    # 14.x=2010, 15.2.x=2019. Schluessel ist Build-Prefix.
    ("microsoft", "exchange", "15.1"): {
        "date": "2025-10-14", "severity": "HIGH",
        "label": "Exchange Server 2016",
        "cves_post_eol": ["CVE-2021-26855", "CVE-2021-34473", "CVE-2022-41040"],
    },
    ("microsoft", "exchange", "15.0"): {
        "date": "2023-04-11", "severity": "HIGH",
        "label": "Exchange Server 2013",
        "cves_post_eol": ["CVE-2021-26855"],
    },
    ("microsoft", "exchange", "14"): {
        "date": "2020-10-13", "severity": "CRITICAL",
        "label": "Exchange Server 2010",
        "cves_post_eol": ["CVE-2020-0688"],
    },
    # Microsoft Windows Server
    ("microsoft", "windows-server", "2012"): {
        "date": "2023-10-10", "severity": "HIGH",
    },
    ("microsoft", "windows-server", "2008"): {
        "date": "2020-01-14", "severity": "CRITICAL",
    },
    ("microsoft", "windows-server", "2003"): {
        "date": "2015-07-14", "severity": "CRITICAL",
    },
    # Webserver
    ("nginx", "", "1.20"):  {"date": "2022-04-19", "severity": "MEDIUM"},
    ("nginx", "", "1.18"):  {"date": "2021-04-20", "severity": "MEDIUM"},
    ("nginx", "", "1.16"):  {"date": "2020-04-21", "severity": "MEDIUM"},
    ("apache", "httpd", "2.2"):  {"date": "2017-07-11", "severity": "HIGH"},
    ("apache", "httpd", "2.4.49"): {"date": "2021-10-04", "severity": "CRITICAL",
                                     "cves_post_eol": ["CVE-2021-41773"]},
    ("apache", "httpd", "2.4.50"): {"date": "2021-10-07", "severity": "CRITICAL",
                                     "cves_post_eol": ["CVE-2021-42013"]},
    ("microsoft", "iis", "7.0"):  {"date": "2020-01-14", "severity": "HIGH"},
    ("microsoft", "iis", "7.5"):  {"date": "2020-01-14", "severity": "HIGH"},
    # Crypto-Libraries
    ("openssl", "", "1.0"): {"date": "2019-12-31", "severity": "CRITICAL"},
    ("openssl", "", "1.0.1"): {"date": "2016-12-31", "severity": "CRITICAL",
                                "cves_post_eol": ["CVE-2014-0160"]},  # Heartbleed
    ("openssl", "", "1.0.2"): {"date": "2019-12-31", "severity": "HIGH"},
    ("openssl", "", "1.1.0"): {"date": "2019-09-11", "severity": "HIGH"},
    ("openssl", "", "1.1.1"): {"date": "2023-09-11", "severity": "MEDIUM"},
    # PHP
    ("php", "", "5.6"):  {"date": "2018-12-31", "severity": "HIGH"},
    ("php", "", "7.0"):  {"date": "2018-12-03", "severity": "HIGH"},
    ("php", "", "7.1"):  {"date": "2019-12-01", "severity": "HIGH"},
    ("php", "", "7.2"):  {"date": "2020-11-30", "severity": "HIGH"},
    ("php", "", "7.3"):  {"date": "2021-12-06", "severity": "HIGH"},
    ("php", "", "7.4"):  {"date": "2022-11-28", "severity": "HIGH"},
    ("php", "", "8.0"):  {"date": "2023-11-26", "severity": "MEDIUM"},
    # Python
    ("python", "", "2.7"): {"date": "2020-01-01", "severity": "HIGH"},
    ("python", "", "3.6"): {"date": "2021-12-23", "severity": "HIGH"},
    ("python", "", "3.7"): {"date": "2023-06-27", "severity": "MEDIUM"},
    ("python", "", "3.8"): {"date": "2024-10-07", "severity": "MEDIUM"},
    # Datenbanken
    ("mysql", "", "5.7"): {"date": "2023-10-31", "severity": "HIGH"},
    ("mysql", "", "5.6"): {"date": "2021-02-05", "severity": "HIGH"},
    ("postgresql", "", "11"): {"date": "2023-11-09", "severity": "MEDIUM"},
    ("postgresql", "", "10"): {"date": "2022-11-10", "severity": "MEDIUM"},
}


# Final EOL_DATA: Union (Generated ∪ Manual), Manual hat Vorrang.
# scripts/sync-eol-data.py erzeugt eol_data_generated.py — bei fehlendem
# Sync (z.B. fresh checkout) bleibt nur EOL_DATA_MANUAL aktiv.
EOL_DATA: dict[tuple[str, str, str], dict[str, Any]] = {
    **_load_eol_union(),
    **EOL_DATA_MANUAL,  # Manual gewinnt bei gleichem Schluessel
}


# C3: Build-spezifische CVE-Maps. Schluessel: (vendor_lower, product_lower,
# version_oder_build_pattern). Werte: Liste konkreter CVE-IDs mit Schwere.
# Wird genutzt wenn nmap-Banner einen kritischen Build matcht — Pflicht-
# Finding fuer ProxyShell, Heartbleed, Path-Traversal etc.
KNOWN_VULN_BUILDS: dict[tuple[str, str, str], dict[str, Any]] = {
    # Exchange ProxyShell (Builds vor CU22 ohne Patches)
    ("microsoft", "exchange", "15.1.2375"):  # CU21 ohne KB5005076
        {"cves": ["CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207"],
         "severity": "CRITICAL", "name": "ProxyShell"},
    ("microsoft", "exchange", "15.1.2308"):  # CU20 ungepatcht
        {"cves": ["CVE-2021-26855", "CVE-2021-26857"],
         "severity": "CRITICAL", "name": "ProxyLogon"},
    # OpenSSL Heartbleed
    ("openssl", "", "1.0.1"):
        {"cves": ["CVE-2014-0160"], "severity": "CRITICAL", "name": "Heartbleed"},
    # Apache Path-Traversal
    ("apache", "httpd", "2.4.49"):
        {"cves": ["CVE-2021-41773"], "severity": "CRITICAL",
         "name": "Apache Path Traversal"},
    ("apache", "httpd", "2.4.50"):
        {"cves": ["CVE-2021-42013"], "severity": "CRITICAL",
         "name": "Apache RCE"},
}


def _parse_version(version_str: str) -> tuple[int, ...]:
    """'1.22.1' → (1,22,1). 'CU23' → (23,)."""
    if not version_str:
        return ()
    m = re.findall(r"\d+", version_str)
    return tuple(int(x) for x in m) if m else ()


def _version_starts_with(actual: str, prefix: str) -> bool:
    """'1.22.1' starts with '1.22'? '7.4.3' starts with '7.4'? Stricter than
    string-startswith — vergleicht semver-tuples per Tuple-prefix.
    """
    a = _parse_version(actual)
    p = _parse_version(prefix)
    if not p:
        return False
    return a[:len(p)] == p


def _normalize_vendor_product(tech_str: str) -> tuple[str, str, str]:
    """Splitter: 'nginx/1.22.1' → ('nginx', '', '1.22.1'),
    'Microsoft-IIS/10.0' → ('microsoft', 'iis', '10.0'),
    'Apache/2.4.49' → ('apache', 'httpd', '2.4.49').
    """
    if not tech_str:
        return ("", "", "")
    s = tech_str.strip()
    # Trenne Vendor/Produkt von Version
    m = re.match(r"^([A-Za-z][\w\s./-]*?)[\s/]+(\d[\d.\w-]*)\s*$", s)
    if m:
        name = m.group(1).strip().lower()
        version = m.group(2).strip()
    else:
        name = s.lower()
        version = ""

    # Vendor/Product-Mapping
    if "iis" in name or "internet information" in name or name.startswith("microsoft-iis"):
        return ("microsoft", "iis", version)
    if "exchange" in name:
        return ("microsoft", "exchange", version)
    if "windows" in name and "server" in name:
        return ("microsoft", "windows-server", version)
    if "apache" in name or name == "httpd":
        return ("apache", "httpd", version)
    if "nginx" in name:
        return ("nginx", "", version)
    if name.startswith("php"):
        return ("php", "", version)
    if name.startswith("python"):
        return ("python", "", version)
    if "openssl" in name:
        return ("openssl", "", version)
    if "mysql" in name:
        return ("mysql", "", version)
    if "postgres" in name:
        return ("postgresql", "", version)
    return (name, "", version)


def _days_since(eol_date_iso: str, scan_date: date) -> int:
    try:
        eol = datetime.fromisoformat(eol_date_iso).date()
    except Exception:
        return 0
    return (scan_date - eol).days


def _build_finding(
    *, host_ip: str, host: str, vendor: str, product: str, version: str,
    eol_date: str, severity: str, days_since: int,
    cves: list[str] | None = None, vuln_name: str | None = None,
    source: str = "eol_detector", label_override: str | None = None,
) -> dict[str, Any]:
    if label_override:
        tech_label = label_override
    else:
        tech_label = f"{vendor.title()} {product.upper() if product == 'iis' else product.title()}".strip()
        if not product:
            tech_label = vendor.title()
    if vuln_name:
        title = f"{tech_label} {version} betroffen von {vuln_name} auf {host}"
    elif days_since > 0:
        title = f"{tech_label} {version} ist End-of-Life seit {days_since} Tagen auf {host}"
    else:
        title = f"{tech_label} {version} naehert sich End-of-Life auf {host}"

    finding: dict[str, Any] = {
        "id": "",  # wird vom Mapper befuellt
        "title": title,
        "title_vars": {
            "tech": tech_label, "version": version, "host": host,
            "days": str(abs(days_since)),
        },
        "severity": severity,
        "finding_type": "software_eol",
        "policy_id": "SP-EOL-001",
        "host_ip": host_ip,
        "fqdn": host,
        "vhost": host,
        "affected": f"{host_ip} ({host})" if host != host_ip else host_ip,
        "cwe": "CWE-1104",  # Use of Unmaintained Third Party Components
        "description": (
            f"Die eingesetzte {tech_label}-Version {version} hat ihr End-of-Life "
            f"am {eol_date} erreicht. Microsoft/Hersteller stellt keine "
            f"Sicherheitsupdates mehr bereit. "
            + (f"Bekannte schwerwiegende CVEs nach EOL: {', '.join(cves)}. "
               if cves else "")
        ),
        "impact": (
            "Ohne Sicherheitsupdates entstehen mit jeder neuen entdeckten "
            "Schwachstelle ungepatchte Angriffspunkte. Besonders kritisch "
            "fuer Internet-exponierte Dienste."
        ),
        "recommendation": (
            f"Migration auf eine aktuelle, supportete Version von {tech_label} "
            f"einplanen. Bis Migration: Internet-Exposition pruefen, "
            f"Web Application Firewall (WAF) und Monitoring einsetzen."
        ),
        "_deterministic_source": source,
    }
    if cves:
        finding["cve"] = cves[0]
        finding["cve_id"] = cves[0]
    return finding


def detect_eol_findings(
    tech_profiles: list[dict[str, Any]] | None,
    scan_date: date | None = None,
) -> list[dict[str, Any]]:
    """Deterministische EOL-Detection ueber alle tech_profiles.

    Returns: Liste von Finding-Dicts (kann leer sein).
    """
    if not tech_profiles:
        return []
    today = scan_date or date.today()

    out: list[dict[str, Any]] = []
    for tp in tech_profiles:
        host_ip = tp.get("ip", "")
        fqdns = tp.get("fqdns") or []
        host = fqdns[0] if fqdns else host_ip

        # Tech-Strings sammeln aus server, cms, technologies[]
        tech_strings: list[str] = []
        if tp.get("server"):
            tech_strings.append(str(tp["server"]))
        if tp.get("cms") and tp.get("cms_version"):
            tech_strings.append(f"{tp['cms']}/{tp['cms_version']}")
        for t in tp.get("technologies") or []:
            if isinstance(t, dict):
                name = t.get("name", "")
                ver = t.get("version", "")
                if name:
                    tech_strings.append(f"{name}/{ver}" if ver else name)
            elif isinstance(t, str):
                tech_strings.append(t)
        # Exchange-Build aus vhost_results.cms_details (Phase 1 setzt das)
        for vh, vinfo in (tp.get("vhost_results") or {}).items():
            if vinfo.get("cms") and vinfo.get("cms_version"):
                tech_strings.append(f"{vinfo['cms']}/{vinfo['cms_version']}")

        for tech_str in tech_strings:
            vendor, product, version = _normalize_vendor_product(tech_str)
            if not vendor or not version:
                continue

            # 1. EOL_DATA
            for (v, p, prefix), info in EOL_DATA.items():
                if v != vendor:
                    continue
                if p and p != product:
                    continue
                if not _version_starts_with(version, prefix):
                    continue
                days = _days_since(info["date"], today)
                if days < 0 and abs(days) > 60:
                    continue  # weiter als 60 Tage in der Zukunft → noch nicht relevant
                out.append(_build_finding(
                    host_ip=host_ip, host=host,
                    vendor=vendor, product=product, version=version,
                    eol_date=info["date"], severity=info.get("severity", "MEDIUM"),
                    days_since=days, cves=info.get("cves_post_eol"),
                    label_override=info.get("label"),
                ))
                break  # nur ersten Match pro tech_string

            # 2. KNOWN_VULN_BUILDS (genau Build-Match)
            for (v, p, build), vuln in KNOWN_VULN_BUILDS.items():
                if v != vendor:
                    continue
                if p and p != product:
                    continue
                if not _version_starts_with(version, build):
                    continue
                out.append(_build_finding(
                    host_ip=host_ip, host=host,
                    vendor=vendor, product=product, version=version,
                    eol_date="", severity=vuln.get("severity", "HIGH"),
                    days_since=0, cves=vuln.get("cves"),
                    vuln_name=vuln.get("name"),
                    source="cve_whitelist",
                ))
                break

    if out:
        log.info("eol_detector_findings count=%d", len(out))
    return out


_VERSION_PAT = re.compile(r"\b(\d+(?:\.\d+){1,3}(?:[a-z]\d?)?)\b")


def merge_into_claude_findings(
    claude_findings: list[dict[str, Any]],
    eol_findings: list[dict[str, Any]],
    *,
    tech_profiles: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Merged EOL-Findings in Claude-Output. Dedup-Key:
    (normalized_host, finding_type, version).

    F-RPT-007: Host-Resolution + Version-Recovery.

    Vorher: dedup auf (host_ip, finding_type, version) — Claude-Findings
    haben aber oft keinen host_ip (KI sieht nur FQDN/affected). Resultat:
    Doppel-Findings im Report.

    Jetzt:
    - normalized_host = primary FQDN aus tech_profiles (FQDN > host > host_ip).
      Cross-Mapping IP↔FQDN ueber tech_profiles[].fqdns.
    - version = title_vars.version, fallback Title-Regex (Apache 2.2, etc.)

    `tech_profiles=None` faellt auf altes Verhalten zurueck (kein Cross-Mapping).
    """
    # ip_to_fqdn-Map aus tech_profiles
    ip_to_fqdn: dict[str, str] = {}
    for tp in tech_profiles or []:
        ip = tp.get("ip", "")
        fqdns = tp.get("fqdns") or []
        if ip and fqdns:
            # primary fqdn = erster Eintrag, lowercase
            ip_to_fqdn[ip] = str(fqdns[0]).lower().strip()

    def _normalize_host(f: dict) -> str:
        """Bevorzugt FQDN > host > host_ip-mapped-zu-FQDN > host_ip."""
        fqdn = (f.get("fqdn") or f.get("host") or "").lower().strip()
        host_ip = f.get("host_ip") or ""
        if not fqdn and host_ip in ip_to_fqdn:
            fqdn = ip_to_fqdn[host_ip]
        if fqdn:
            return fqdn
        return host_ip

    def _extract_version(f: dict) -> str:
        """Erst title_vars.version, dann Title-Regex-Fallback."""
        tv = f.get("title_vars") or {}
        if isinstance(tv, dict) and tv.get("version"):
            return str(tv["version"])
        title = f.get("title") or ""
        m = _VERSION_PAT.search(title)
        return m.group(1) if m else ""

    by_key: dict[tuple, dict] = {}
    for f in claude_findings or []:
        key = (
            _normalize_host(f),
            f.get("finding_type", ""),
            _extract_version(f),
        )
        by_key[key] = f

    merged = list(claude_findings or [])
    added = 0
    for ef in eol_findings:
        key = (
            _normalize_host(ef),
            ef.get("finding_type", ""),
            _extract_version(ef),
        )
        if key in by_key:
            # Markiere bestehenden Claude-Eintrag als deterministic-bestaetigt
            by_key[key]["_deterministic_source"] = ef.get(
                "_deterministic_source", "eol_detector",
            )
            continue
        merged.append(ef)
        added += 1
    if added:
        log.info("eol_detector_added_to_findings count=%d", added)
    return merged
