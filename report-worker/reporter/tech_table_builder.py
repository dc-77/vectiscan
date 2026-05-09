"""Tech-Table-Builder: aus tech_profile + EOL-Daten + KNOWN_VULN_BUILDS pro Host
eine Liste von Zeilen (Technologie/Version/Status/EOL/Stable/CVEs) bauen.

Single Source of Truth:
- gleiche Logik wird in PDF (`report_mapper._build_scope`) und API-Response
  (`/api/orders/:id/findings`) genutzt
- Re-uses existing helpers in `eol_detector.py`:
  - `_load_eol_union()` + `EOL_DATA_MANUAL` -> EOL-Daten-Quelle
  - `KNOWN_VULN_BUILDS` -> KEV-CVEs
  - `_normalize_vendor_product()` -> Banner-Parsing
  - `_version_in_range()` -> Range-Match
  - `_version_starts_with()` -> Prefix-Match
  - `_days_since()` -> EOL-Distanz

Status (drei sich-ausschliessende Zustaende):
- "eol"      -> 🔴 EOL (eol_data.date < scan_date)
- "outdated" -> 🟠 veraltet (version < latest_patch, aber nicht EOL)
- "current"  -> 🟢 aktuell (>= latest_patch oder kein eol_data-Eintrag)

Plus orthogonaler Flag:
- is_mega_cve -> ⚠️ KNOWN_VULN_BUILDS-Match (kann zusaetzlich zu eol/outdated/current gelten)

UI/PDF kombiniert: Apache 2.2.34 -> "EOL + Mega-CVE", Apache 2.4.49 -> "veraltet + Mega-CVE",
Apache 2.4.62 -> "aktuell".

Mai 2026 — Test-Session-Folge.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from reporter.eol_detector import (
    EOL_DATA_MANUAL,
    KNOWN_VULN_BUILDS,
    _days_since,
    _load_eol_union,
    _normalize_vendor_product,
    _parse_version,
    _version_in_range,
    _version_starts_with,
)


def _major_compatible(actual_version: str, range_spec: str) -> bool:
    """Defensiver Filter gegen CPE-Noise im KNOWN_VULN_BUILDS_GENERATED.

    Hintergrund: OSV-CVE-Source-Conversion liefert pro CVE oft mehrere
    `affected[]`-Eintraege fuer Oracle/Ubuntu/IBM-Distros die das
    Upstream-Produkt einbetten — z.B. CVE-2024-38475 hat Apache-Eintrag
    "<2.4.60" und parallel "<10.2.1.14-75sv" (Oracle-Linux-Apache-Modul).
    Beide kommen mit (vendor=apache, product=httpd) in KNOWN_VULN_BUILDS_
    GENERATED und matchen damit JEDE Apache-Version <10 — auch 2.4.62
    (=current).

    Fix: nur Range-Specs zulassen deren Target-Version-Major mit der
    actual-Version-Major matcht. Apache 2.4.62 vs "<10..." → 2 != 10 → skip.
    """
    if not range_spec or not actual_version:
        return False
    # Operator stripping (synchron mit _version_in_range)
    spec = range_spec
    if spec.startswith(("<=", ">=")):
        spec = spec[2:].strip()
    elif spec.startswith(("<", ">")):
        spec = spec[1:].strip()
    a = _parse_version(actual_version)
    s = _parse_version(spec)
    if not a or not s:
        # Kein parsebar → sei tolerant (lass _version_in_range entscheiden)
        return True
    return a[0] == s[0]


# Heuristik: Kategorie-Mapping aus vendor/product (oder Name-Substring).
# Wird sowohl in UI als auch im PDF angezeigt — hilft bei vielen Eintraegen
# pro Host die Sortierung/Gruppierung.
_CATEGORY_MAP: dict[tuple[str, str], str] = {
    ("apache",      "httpd"):          "Web-Server",
    ("nginx",       ""):                "Web-Server",
    ("microsoft",   "iis"):             "Web-Server",
    ("microsoft",   "exchange"):        "Mail",
    ("microsoft",   "windows-server"):  "OS",
    ("openssl",     ""):                "Krypto-Bibliothek",
    ("openssh",     ""):                "Remote-Access",
    ("php",         ""):                "Sprache",
    ("python",      ""):                "Sprache",
    ("nodejs",      ""):                "Sprache",
    ("mysql",       ""):                "Datenbank",
    ("postgresql",  ""):                "Datenbank",
    ("mongodb",     ""):                "Datenbank",
    ("redis",       ""):                "Datenbank",
    ("atlassian",   "confluence"):      "Wiki/Collab",
    ("atlassian",   "jira"):            "Wiki/Collab",
    ("atlassian",   "bitbucket"):       "Code-Hosting",
    ("gitlab",      ""):                "Code-Hosting",
    ("jetbrains",   "teamcity"):        "CI",
    ("citrix",      "netscaler"):       "Network-Appliance",
    ("citrix",      "adc"):             "Network-Appliance",
    ("fortinet",    "fortigate"):       "Network-Appliance",
    ("ivanti",      "connect-secure"):  "VPN-Appliance",
    ("connectwise", "screenconnect"):   "Remote-Access",
    ("progress",    "moveit"):          "File-Transfer",
    ("progress",    "ws_ftp"):          "File-Transfer",
    ("vmware",      "vcenter"):         "Virtualisierung",
    ("vmware",      "esxi"):            "Virtualisierung",
}


def _category_for(vendor: str, product: str, name_hint: str) -> str:
    """Mappt vendor/product auf Kategorie. Fallback: 'Sonstiges'."""
    cat = _CATEGORY_MAP.get((vendor.lower(), (product or "").lower()))
    if cat:
        return cat
    # CMS-Heuristik (vendor leer, name_hint hat CMS-Namen)
    name_lower = (name_hint or "").lower()
    cms_keywords = ("wordpress", "neos", "pimcore", "sulu", "plone", "silverstripe",
                    "statamic", "typo3", "drupal", "joomla", "shopware", "ghost",
                    "craft", "magento", "shopify", "webflow", "wix", "squarespace",
                    "hubspot")
    if any(k in name_lower for k in cms_keywords):
        return "CMS"
    framework_keywords = ("flow", "laravel", "symfony", "django", "rails", "express",
                          "spring", "react", "vue", "angular", "next.js")
    if any(k in name_lower for k in framework_keywords):
        return "Framework"
    return "Sonstiges"


def _classify_status(
    vendor: str, product: str, version: str,
    eol_data: dict, known_vuln_builds: dict, scan_date: date,
) -> tuple[str, bool, dict[str, Any]]:
    """Klassifiziert (vendor, product, version).

    Returns (status, is_mega_cve, info):
      status:       "eol" | "outdated" | "current"  — sich ausschliessende Zustaende
      is_mega_cve:  bool — orthogonal, kann zusaetzlich zu jedem status gelten
      info: dict mit Feldern eol_date, latest_patch, cves, vuln_name
    """
    info: dict[str, Any] = {"eol_date": "", "latest_patch": "", "cves": [], "vuln_name": ""}
    if not version:
        return ("current", False, info)

    # 1. KNOWN_VULN_BUILDS-Match → Mega-CVE-Flag (orthogonal zu eol/outdated/current)
    is_mega_cve = False
    for (kvb_vendor, kvb_product, range_spec), kvb_data in known_vuln_builds.items():
        if kvb_vendor.lower() != vendor.lower():
            continue
        if (kvb_product or "").lower() != (product or "").lower():
            continue
        # CPE-Noise-Filter: Range-Spec muss in derselben Major-Version-Familie sein
        if not _major_compatible(version, range_spec):
            continue
        if _version_in_range(version, range_spec):
            is_mega_cve = True
            info["cves"] = list(kvb_data.get("cves") or [])
            info["vuln_name"] = kvb_data.get("name", "") or ""
            break

    # 2. EOL_DATA-Match → date < today = EOL
    matched_eol = None
    for (eol_vendor, eol_product, version_prefix), eol_entry in eol_data.items():
        if eol_vendor.lower() != vendor.lower():
            continue
        # Manche EOL-Eintraege haben product="" als wildcard fuer den Vendor
        if eol_product and eol_product.lower() != (product or "").lower():
            continue
        if _version_starts_with(version, version_prefix):
            matched_eol = eol_entry
            info["eol_date"] = eol_entry.get("date", "") or ""
            info["latest_patch"] = eol_entry.get("latest_patch", "") or ""
            break

    if matched_eol:
        eol_date_iso = matched_eol.get("date")
        if eol_date_iso:
            days = _days_since(eol_date_iso, scan_date)
            if days > 0:
                return ("eol", is_mega_cve, info)
            # Nicht EOL aber moeglicherweise outdated wenn latest_patch != version
            if matched_eol.get("latest_patch"):
                if not _version_starts_with(version, matched_eol["latest_patch"]):
                    return ("outdated", is_mega_cve, info)

    return ("current", is_mega_cve, info)


def build_tech_table_for_host(
    tech_profile: dict[str, Any],
    *,
    scan_date: date | None = None,
    eol_data: dict | None = None,
    known_vuln_builds: dict | None = None,
) -> list[dict[str, Any]]:
    """Baut die Tech-Tabelle fuer einen Host.

    Args:
        tech_profile: einzelnes Phase-1-Profile-Dict (siehe phase1.build_tech_profile)
        scan_date: Datum des Scans fuer EOL-Vergleich (default: today)
        eol_data: Override fuer Tests; default kombiniert EOL_DATA_GENERATED + MANUAL
        known_vuln_builds: Override fuer Tests; default ist die globale Konstante

    Returns:
        Liste von Zeilen-Dicts mit Feldern:
          name        : str   — z.B. "Apache HTTP Server"
          version     : str   — z.B. "2.4.49"
          category    : str   — z.B. "Web-Server"
          status      : str   — "eol" | "outdated" | "current" (sich ausschliessend)
          is_mega_cve : bool  — KNOWN_VULN_BUILDS-Match (orthogonal zu status)
          eol_date    : str   — ISO-Datum oder ""
          latest_patch: str   — empfohlene Stable-Version oder ""
          cves        : list[str]  — bei is_mega_cve, sonst []
          vuln_name   : str   — bei is_mega_cve, sonst ""
          confidence  : float | None — fuer Admin-Detail
          source      : str   — Detection-Method, fuer Admin-Detail
    """
    if scan_date is None:
        scan_date = date.today()
    if eol_data is None:
        eol_data = {**_load_eol_union(), **EOL_DATA_MANUAL}
    if known_vuln_builds is None:
        known_vuln_builds = KNOWN_VULN_BUILDS

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def _add(name: str, version: str, vendor: str, product: str,
             confidence: float | None, source: str) -> None:
        key = (vendor.lower(), (product or "").lower(), (version or "").lower())
        if key in seen:
            return
        seen.add(key)
        status, is_mega_cve, info = _classify_status(
            vendor, product, version, eol_data, known_vuln_builds, scan_date,
        )
        rows.append({
            "name": name,
            "version": version or "",
            "category": _category_for(vendor, product, name),
            "status": status,
            "is_mega_cve": is_mega_cve,
            "eol_date": info["eol_date"],
            "latest_patch": info["latest_patch"],
            "cves": info["cves"],
            "vuln_name": info["vuln_name"],
            "confidence": confidence,
            "source": source,
        })

    # 1. CMS aus tech_profile
    cms = tech_profile.get("cms")
    if cms:
        cms_version = tech_profile.get("cms_version") or ""
        vendor, product, _ = _normalize_vendor_product(f"{cms}/{cms_version}".rstrip("/"))
        if vendor in ("", cms.lower()):
            # Vendor unklar — nutze cms-Name als vendor
            vendor = cms.lower()
            product = ""
        confidence = tech_profile.get("cms_confidence")
        _add(cms, cms_version, vendor, product, confidence, "cms_fingerprint")

    # 2. Server-Banner (z.B. "Apache/2.4.49")
    server_banner = tech_profile.get("server")
    if server_banner:
        vendor, product, version = _normalize_vendor_product(server_banner)
        if vendor:
            _add(server_banner, version, vendor, product, None, "server_banner")

    # 3. technologies[] (deduplicated nmap+webtech+cms)
    for tech in tech_profile.get("technologies") or []:
        if not isinstance(tech, dict):
            continue
        name = tech.get("name") or ""
        version = tech.get("version") or ""
        if not name:
            continue
        vendor, product, parsed_version = _normalize_vendor_product(f"{name}/{version}".rstrip("/"))
        if vendor in ("", name.lower()):
            vendor = name.lower()
            product = ""
        _add(name, version or parsed_version, vendor, product, None, "tech_detect")

    # 4. WAF (rein informativ — nicht EOL-bewertet, aber wichtige Info)
    waf = tech_profile.get("waf")
    if waf and not any(r["name"].lower() == waf.lower() for r in rows):
        rows.append({
            "name": waf,
            "version": "",
            "category": "WAF/Schutz",
            "status": "current",
            "is_mega_cve": False,
            "eol_date": "",
            "latest_patch": "",
            "cves": [],
            "vuln_name": "",
            "confidence": None,
            "source": "waf_detect",
        })

    # Stable-Sort: Status-Schwere zuerst (eol > outdated > current),
    # mega_cve-Flag erhoeht Prioritaet innerhalb gleichen Status,
    # dann Kategorie, dann Name.
    _STATUS_ORDER = {"eol": 0, "outdated": 1, "current": 2}
    rows.sort(key=lambda r: (
        _STATUS_ORDER.get(r["status"], 99),
        0 if r.get("is_mega_cve") else 1,
        r["category"],
        r["name"].lower(),
    ))
    return rows


__all__ = ["build_tech_table_for_host"]
