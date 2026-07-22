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

Status (vier sich-ausschliessende Zustaende):
- "eol"       -> 🔴 EOL kritisch (eol_data.severity in {CRITICAL, HIGH})
- "minor_eol" -> 🟡 Minor-Version-EOL (severity in {MEDIUM, LOW}) — z.B. WordPress 6.5
                spezifische Minor-Reihe kriegt keine Patches mehr, Major-Familie aktiv.
                Customer sollte upgraden, aber nicht panic.
- "outdated"  -> 🟠 veraltet (version < latest_patch, aber nicht EOL)
- "current"   -> 🟢 aktuell (>= latest_patch oder kein eol_data-Eintrag)

Plus orthogonaler Flag:
- is_mega_cve -> ⚠️ KNOWN_VULN_BUILDS-Match (kann zusaetzlich zu jedem status gelten)

Beispiele:
  WordPress 4.7 (2017 EOL, severity=CRITICAL)  -> "eol"
  WordPress 6.8 (2025-12 EOL, severity=MEDIUM) -> "minor_eol"
  Apache 2.2.34 (2017 EOL, severity=CRITICAL)  -> "eol" + is_mega_cve=True
  Apache 2.4.49                                -> "outdated" + is_mega_cve=True
  Apache 2.4.62                                -> "current"

Mai 2026 — Test-Session-Folge.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any

import logging

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

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────
# M2 Track 2c: Kernel-Blacklist + Min-Public-Version-Whitelist
# ─────────────────────────────────────────────────────────────────────────

# Detection-Strings, die Kernel-Komponenten statt Anwendungssoftware
# identifizieren — Service kommt aus dem Windows-Kernel (http.sys),
# nicht aus einer patchbaren Anwendung. Werden komplett aus der Tech-
# Tabelle entfernt (P2-04 / Doc 01).
KERNEL_DETECTION_BLACKLIST: set[str] = {
    "microsoft httpapi httpd",
    "httpapi",
    "http.sys",
    "microsoft-httpapi",
    "windows kernel",
    # Security-Header werden von webtech/Wappalyzer als "Technology" getaggt
    # — gehoeren aber NICHT in eine patchbare Tech-Liste. Sie werden ueber
    # die Posture-Indikatoren bzw. Befunde getrennt behandelt.
    "hsts",
    "strict-transport-security",
    "csp",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "feature-policy",
}

# Min-Version-Whitelist: erste oeffentliche Version pro Tech.
# Werte unterhalb dieser Schwelle deuten auf Tool-Mislabel
# (z.B. Bootstrap 1 — wurde nie released; P1-05 / Doc 01).
MIN_PUBLIC_VERSIONS: dict[str, int] = {
    "bootstrap": 2,    # Bootstrap 1 nie veroeffentlicht
    "angular": 1,      # Angular 1 = AngularJS legitim
    "angularjs": 1,
    "react": 0,        # React 0.x existiert
    "vue": 1,
    "vue.js": 1,
    "jquery": 1,
    "tailwind": 1,
    "tailwindcss": 1,
    "ember": 1,
    "ember.js": 1,
    "backbone": 0,
    "next.js": 1,
    "nextjs": 1,
    "nuxt": 1,
    "nuxt.js": 1,
}


def _is_kernel_detection(name: str) -> bool:
    """True wenn der Detection-String einen Kernel-Treiber identifiziert."""
    if not name:
        return False
    name_lower = name.lower().strip()
    if name_lower in KERNEL_DETECTION_BLACKLIST:
        return True
    # Substring-Match fuer Banner-Varianten ("Microsoft-HTTPAPI/2.0" etc.)
    for bad in KERNEL_DETECTION_BLACKLIST:
        if bad in name_lower:
            return True
    return False


def _major_int(version: str) -> int | None:
    """Extrahiert die Major-Version als Integer ('1.2.3' → 1, '0.9' → 0)."""
    if not version:
        return None
    m = re.match(r"\s*(\d+)", version)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def _violates_min_version(name: str, version: str) -> bool:
    """True wenn die Version unter der ersten oeffentlichen Version liegt."""
    if not version:
        return False
    name_lower = (name or "").lower().strip()
    lookup_keys = [name_lower] + name_lower.split()
    major = _major_int(version)
    if major is None:
        return False
    for key in lookup_keys:
        if key in MIN_PUBLIC_VERSIONS:
            return major < MIN_PUBLIC_VERSIONS[key]
    return False


_BANNER_SUFFIX_RE = re.compile(
    r"\s+(?:Ubuntu|Debian|RedHat|CentOS|Fedora|FreeBSD|"
    r"\d+\+(?:deb|ubuntu|el)\d+u?\d*|"
    r"\([^)]*\))",
    re.IGNORECASE,
)


def _strip_banner_suffix(version: str) -> str:
    """Schneidet Distro-/Build-Suffixes aus einem Version-String ab + verwirft
    nicht-version-like Strings (z.B. Phase-1-Phantasie-Versionen wie "neos").

    Beispiele:
      "9.6p1 Ubuntu 3ubuntu13.16"      → "9.6p1"
      "9.2p1 Debian 2+deb12u9"         → "9.2p1"
      "2.4.66 (Debian)"                → "2.4.66"
      "8.4p1 Debian 5+deb11u5"         → "8.4p1"
      "neos"                           → ""    (kein digit-Praefix)
      "abc1.0"                         → ""    (kein digit-Praefix)
    """
    if not version:
        return ""
    m = _BANNER_SUFFIX_RE.search(version)
    cleaned = (version[:m.start()] if m else version).strip()
    # Nur akzeptieren wenn die Version mit Ziffer beginnt (Software-Versionen
    # haben praktisch immer einen digit-Praefix).
    if cleaned and not cleaned[0].isdigit():
        return ""
    return cleaned


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


def _confidence_label(confidence: float | None) -> str:
    """Mappt Confidence-Score (0-1) auf User-facing-Label.

    Conventions:
      >= 0.8 → 'hoch'
      >= 0.5 → 'mittel'
      None oder < 0.5 → 'niedrig'
    """
    if confidence is None:
        return "niedrig"
    try:
        c = float(confidence)
    except (TypeError, ValueError):
        return "niedrig"
    if c >= 0.8:
        return "hoch"
    if c >= 0.5:
        return "mittel"
    return "niedrig"


# Source-ID → User-facing Detection-Method-Label
_DETECTION_SOURCE_LABELS: dict[str, str] = {
    "cms_fingerprint":   "CMS-Fingerprint",
    "server_banner":     "HTTP-Server-Banner",
    "tech_detect":       "Tech-Detect",
    "waf_detect":        "WAF-Detect",
    "shodan":            "Shodan",
    "webtech":           "webtech",
    "nmap-banner":       "nmap-Banner",
    "meta-generator":    "Meta-Tag",
}


def _detection_source_label(source: str) -> str:
    """Mappt Source-ID auf User-facing Detection-Method-Label."""
    if not source:
        return ""
    return _DETECTION_SOURCE_LABELS.get(source, source)


# Mapping interner Status-Codes auf User-facing-Label fuer patch_status-Spalte.
_PATCH_STATUS_MAP: dict[str, str] = {
    "eol":         "eol",
    "minor_eol":   "minor_eol",
    "outdated":    "outdated",
    "current":     "aktuell",
}


def _patch_status_from(status: str, version: str) -> str:
    """Leitet patch_status aus internem status + version ab."""
    if not version:
        return "unbekannt"
    return _PATCH_STATUS_MAP.get(status, "unbekannt")


def _select_top_cve(cves: list) -> dict | None:
    """Waehle Top-CVE pro Tech-Row.

    Priorisierung:
      1. KEV-Eintrag (kev=True)
      2. Hoechster epss_score
      3. Hoechster cvss_score

    cves[] kann sowohl list[str] (Backwards-Compat) als auch list[dict] sein.
    list[str] → kein Top-CVE-Auswahl moeglich (keine EPSS/KEV-Daten), nimm
    den ersten als Default fuer die Spalte (M2 2c — sichtbar machen falls
    Daten vorhanden, Anreicherung passiert woanders).
    """
    if not cves:
        return None
    # Liste von strings (Backwards-Compat)
    if all(isinstance(c, str) for c in cves):
        return {"cve_id": cves[0], "epss_score": None, "kev": False}
    # Liste von dicts
    dicts = [c for c in cves if isinstance(c, dict)]
    if not dicts:
        return None
    # 1) KEV
    kev = [c for c in dicts if c.get("kev")]
    if kev:
        c0 = kev[0]
        return {"cve_id": c0.get("cve_id") or c0.get("id"),
                "epss_score": c0.get("epss_score"),
                "kev": True}
    # 2) Highest EPSS
    by_epss = sorted(
        dicts,
        key=lambda c: (c.get("epss_score") or -1),
        reverse=True,
    )
    if by_epss and by_epss[0].get("epss_score") is not None:
        c0 = by_epss[0]
        return {"cve_id": c0.get("cve_id") or c0.get("id"),
                "epss_score": c0.get("epss_score"),
                "kev": bool(c0.get("kev"))}
    # 3) Highest CVSS
    by_cvss = sorted(
        dicts,
        key=lambda c: (c.get("cvss_score") or -1),
        reverse=True,
    )
    c0 = by_cvss[0]
    return {"cve_id": c0.get("cve_id") or c0.get("id"),
            "epss_score": c0.get("epss_score"),
            "kev": bool(c0.get("kev"))}


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
      status:       "eol" | "minor_eol" | "outdated" | "current"  — sich ausschliessend
      is_mega_cve:  bool — orthogonal, kann zusaetzlich zu jedem status gelten
      info: dict mit Feldern eol_date, latest_patch, cves, vuln_name
    """
    info: dict[str, Any] = {"eol_date": "", "latest_patch": "", "cves": [], "vuln_name": ""}
    if not version:
        # Ohne ausgelesene Version ist KEINE Aktualitaets-Aussage moeglich —
        # ehrlich als "unbekannt" (grau) statt falsch-gruen "aktuell" (Juli 2026).
        return ("unbekannt", False, info)

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
                # Severity aus eol_data steuert minor_eol vs eol — endoflife.date
                # liefert MEDIUM/LOW fuer aktuelle Minor-Version-EOLs (z.B. WordPress
                # 6.5 EOL 2024-07 ist nur MEDIUM, weil Major-Familie aktiv).
                eol_sev = (matched_eol.get("severity") or "").upper()
                if eol_sev in ("MEDIUM", "LOW"):
                    return ("minor_eol", is_mega_cve, info)
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
          name             : str   — z.B. "Apache HTTP Server"
          version          : str   — z.B. "2.4.49" oder "(Version unbekannt)"
          category         : str   — z.B. "Web-Server"
          status           : str   — DEPRECATED alias auf patch_status (Backwards-Compat
                                      fuer alten PDF-Renderer; in M4 entfernt)
          patch_status     : str   — "aktuell" | "outdated" | "eol" | "minor_eol" | "unbekannt"
                                     (M2 Track 2c — semantisch klare Spalte)
          is_mega_cve      : bool  — KNOWN_VULN_BUILDS-Match (orthogonal zu status)
          eol_date         : str   — ISO-Datum oder ""
          latest_patch     : str   — empfohlene Stable-Version oder ""
          cves             : list[str]  — bei is_mega_cve, sonst []
          vuln_name        : str   — bei is_mega_cve, sonst ""
          confidence       : float | None — Detection-Confidence (numerisch)
          confidence_label : str   — "hoch" | "mittel" | "niedrig" (M2)
          source           : str   — Detection-Source-ID, fuer Admin-Detail
          detection_source : str   — User-facing Detection-Method-Label (M2)
          top_cve          : dict | None — {cve_id, epss_score, kev} (M2)
    """
    if scan_date is None:
        scan_date = date.today()
    if eol_data is None:
        eol_data = {**_load_eol_union(), **EOL_DATA_MANUAL}
    if known_vuln_builds is None:
        known_vuln_builds = KNOWN_VULN_BUILDS

    rows: list[dict[str, Any]] = []
    # Dedup-Key nutzt nur (vendor, product) — versions-Variant landet beim
    # ersten Vorkommen. Verhindert dass "Apache" v="" + "Apache httpd" v=""
    # als 2 Eintraege landen, oder "Apache 2.4.66" + "Apache" als 2 Eintraege.
    seen: dict[tuple[str, str], int] = {}

    def _add(name: str, version: str, vendor: str, product: str,
             confidence: float | None, source: str) -> None:
        # M2 2c — Kernel-Blacklist: HTTPAPI/http.sys etc. sind Kernel-Treiber,
        # keine patchbare Anwendung. Skip komplett (P2-04 / Doc 01).
        if _is_kernel_detection(name) or _is_kernel_detection(f"{vendor} {product}".strip()):
            log.info(
                "tech_table_kernel_skip",
                extra={"name": name, "vendor": vendor, "product": product},
            )
            return

        version = _strip_banner_suffix(version)

        # M2 2c — Min-Public-Version: Bootstrap 1 nie released etc.
        # Statt zu skippen markieren wir als "unbekannt", weil die Tech
        # selbst real ist, nur die Detection-Version unplausibel.
        version_unknown = False
        if version and _violates_min_version(name, version):
            log.info(
                "tech_table_min_version_violation",
                extra={"name": name, "version": version},
            )
            version_unknown = True

        key = (vendor.lower(), (product or "").lower())
        if key in seen:
            # Bereits vorhanden — wenn neuer Eintrag eine Version hat und der
            # alte keine, upgrade die Version.
            idx = seen[key]
            existing = rows[idx]
            if version and not existing["version"]:
                if version_unknown:
                    existing["version"] = "(Version unbekannt)"
                    existing["patch_status"] = "unbekannt"
                    existing["status"] = "unbekannt"
                    existing["name"] = name
                    existing["confidence"] = confidence
                    existing["confidence_label"] = _confidence_label(confidence)
                    existing["source"] = source
                    existing["detection_source"] = _detection_source_label(source)
                    return
                existing["version"] = version
                existing["name"] = name
                existing["confidence"] = confidence
                existing["confidence_label"] = _confidence_label(confidence)
                existing["source"] = source
                existing["detection_source"] = _detection_source_label(source)
                # Re-classify mit neuer Version
                status, is_mega_cve, info = _classify_status(
                    vendor, product, version, eol_data, known_vuln_builds, scan_date,
                )
                patch_status = _patch_status_from(status, version)
                existing["status"] = status
                existing["patch_status"] = patch_status
                existing["is_mega_cve"] = is_mega_cve
                existing["eol_date"] = info["eol_date"]
                existing["latest_patch"] = info["latest_patch"]
                existing["cves"] = info["cves"]
                existing["vuln_name"] = info["vuln_name"]
                existing["top_cve"] = _select_top_cve(info["cves"])
            return
        seen[key] = len(rows)

        if version_unknown:
            # Tech existiert, aber Detection-Version unplausibel → markieren.
            rows.append({
                "name": name,
                "version": "(Version unbekannt)",
                "category": _category_for(vendor, product, name),
                "status": "unbekannt",
                "patch_status": "unbekannt",
                "is_mega_cve": False,
                "eol_date": "",
                "latest_patch": "",
                "cves": [],
                "vuln_name": "",
                "confidence": confidence,
                "confidence_label": _confidence_label(confidence),
                "source": source,
                "detection_source": _detection_source_label(source),
                "top_cve": None,
            })
            return

        status, is_mega_cve, info = _classify_status(
            vendor, product, version, eol_data, known_vuln_builds, scan_date,
        )
        patch_status = _patch_status_from(status, version)
        rows.append({
            "name": name,
            "version": version or "",
            "category": _category_for(vendor, product, name),
            "status": status,
            "patch_status": patch_status,
            "is_mega_cve": is_mega_cve,
            "eol_date": info["eol_date"],
            "latest_patch": info["latest_patch"],
            "cves": info["cves"],
            "vuln_name": info["vuln_name"],
            "confidence": confidence,
            "confidence_label": _confidence_label(confidence),
            "source": source,
            "detection_source": _detection_source_label(source),
            "top_cve": _select_top_cve(info["cves"]),
        })

    # TODO M2 2c: Multi-VHost-Versions-Range — wenn ein Profil ueber
    # vhost_results mehrere Versionen einer Software liefert (z.B. WordPress
    # 6.9.4 auf www + 6.4.2 auf dev), sollte eine Zeile mit Range gebaut
    # werden ("6.4.2-6.9.4 (verschiedene VHosts)"). Aktuell konsumiert der
    # Builder nur das aggregierte tech_profile (hoechste/letzte Version
    # gewinnt). Audit-Flag wird gesetzt falls Multi-VHost erkannt.
    _multi_vhost_versions = False
    vhost_results = tech_profile.get("vhost_results")
    if isinstance(vhost_results, dict) and len(vhost_results) > 1:
        _multi_vhost_versions = True

    # 1. CMS aus tech_profile
    cms = tech_profile.get("cms")
    if cms:
        cms_version = tech_profile.get("cms_version") or ""
        vendor, product, _ = _normalize_vendor_product(f"{cms}/{cms_version}".rstrip("/"))
        if not vendor:
            vendor = cms.lower()
        confidence = tech_profile.get("cms_confidence")
        _add(cms, cms_version, vendor, product, confidence, "cms_fingerprint")

    # 2. Server-Banner (z.B. "Apache/2.4.49")
    server_banner = tech_profile.get("server")
    if server_banner:
        vendor, product, version = _normalize_vendor_product(server_banner)
        if vendor:
            # Display-Name kompakt: "Apache" statt "Apache/2.4.49 (Debian)"
            display = vendor.title() + ((" " + product.upper()) if product == "iis"
                       else (" " + product.title()) if product else "")
            _add(display.strip(), version, vendor, product, None, "server_banner")

    # 3. technologies[] (deduplicated nmap+webtech+cms)
    for tech in tech_profile.get("technologies") or []:
        if not isinstance(tech, dict):
            continue
        raw_name = tech.get("name") or ""
        version = tech.get("version") or ""
        if not raw_name:
            continue
        # Phase-1-nmap-Banner sind manchmal newline-separated: "PHP/8.3.30\nPleskLin"
        # → erste Zeile als name, Plesk/Distro-Suffixe ignorieren.
        name = raw_name.split("\n")[0].strip()
        # Manche Banner haben Version inline mit name: "PHP/8.3.30" → name="PHP",
        # version="8.3.30" (nur wenn version-Slot bisher leer).
        if not version and "/" in name:
            head, _, tail = name.partition("/")
            tail = tail.strip()
            if tail and tail[0].isdigit():
                name = head.strip()
                version = tail
        if not name:
            continue
        # Vor _normalize_vendor_product bei erstem Whitespace cutten — sonst
        # backtrackt der Regex bei "9.6p1 Ubuntu 3ubuntu13.16" und extrahiert
        # falsche Version "3ubuntu13.16". Banner-Suffix-Stripping in _add greift
        # spaeter eh nochmal.
        version_head = version.split()[0] if version else ""
        vendor, product, parsed_version = _normalize_vendor_product(f"{name}/{version_head}".rstrip("/"))
        if not vendor:
            # Wirklich kein Mapping erkannt — nutze name als vendor (z.B. "Roundcube")
            vendor = name.lower()
        # parsed_version gewinnt wenn _normalize eine Marketing-Korrektur machte
        # (z.B. Exchange "2016" -> "15.1" Build-Mapping). Sonst Original-Version
        # damit Banner-Suffix-Stripping in _add die volle Version sehen kann.
        final_version = parsed_version if (parsed_version and parsed_version != version_head) else version
        _add(name, final_version, vendor, product, None, "tech_detect")

    # 4. WAF (rein informativ — nicht EOL-bewertet, aber wichtige Info)
    waf = tech_profile.get("waf")
    if waf and not any(r["name"].lower() == waf.lower() for r in rows):
        rows.append({
            "name": waf,
            "version": "",
            "category": "WAF/Schutz",
            "status": "unbekannt",  # WAF ohne Version → keine Aktualitaets-Aussage
            "patch_status": "unbekannt",
            "is_mega_cve": False,
            "eol_date": "",
            "latest_patch": "",
            "cves": [],
            "vuln_name": "",
            "confidence": None,
            "confidence_label": _confidence_label(None),
            "source": "waf_detect",
            "detection_source": _detection_source_label("waf_detect"),
            "top_cve": None,
        })

    # 5. Shodan-exponierte Dienste (PR-H, Mai 2026)
    # Aus passive_intel.shodan_services / shodan_ports. Diese Services sind
    # bereits oeffentlich aus Internet sichtbar (Drittseiten-Sicht). Wir
    # zeigen sie als eigene Kategorie "Exponierter Dienst" damit der Customer
    # sie sieht, ohne in Phase 2 jeden Port aktiv geprobt haben zu muessen.
    seen_exposed_ports: set[str] = set()
    for entry in tech_profile.get("exposed_services") or []:
        port = str(entry.get("port") or "").strip()
        if not port or port in seen_exposed_ports:
            continue
        seen_exposed_ports.add(port)
        svc_string = (entry.get("service") or "").strip()
        # Service-Name z.B. "nginx 1.24.0" oder "" → "Port 11434"
        name = svc_string if svc_string else f"Port {port}"
        # Version aus Service-String separieren wenn moeglich
        version = ""
        parts = svc_string.rsplit(" ", 1)
        if len(parts) == 2 and any(c.isdigit() for c in parts[1]):
            name = parts[0]
            version = parts[1]
        rows.append({
            "name": name,
            "version": version,
            "category": f"Exponierter Dienst (Port {port})",
            # Exponierter Dienst wird NICHT EOL-bewertet (Shodan/Port-Sicht) →
            # ehrlich "unbekannt" (grau) statt falsch-gruen "aktuell".
            "status": "unbekannt",
            "patch_status": "unbekannt",
            "is_mega_cve": False,
            "eol_date": "",
            "latest_patch": "",
            "cves": [],
            "vuln_name": "",
            "confidence": None,
            "confidence_label": _confidence_label(None),
            "source": "shodan",
            "detection_source": _detection_source_label("shodan"),
            "top_cve": None,
        })

    # Multi-VHost-Audit-Flag durchsetzen (M2 2c — TODO-Stub bis echte
    # Range-Logik kommt). Sichtbar fuer Downstream-Validator.
    if _multi_vhost_versions:
        for r in rows:
            r["_multi_vhost_versions"] = True

    # Stable-Sort: Status-Schwere zuerst (eol > minor_eol > outdated > current),
    # mega_cve-Flag erhoeht Prioritaet innerhalb gleichen Status,
    # dann Kategorie, dann Name. "unbekannt" sortiert ans Ende.
    _STATUS_ORDER = {"eol": 0, "minor_eol": 1, "outdated": 2,
                     "current": 3, "unbekannt": 4}
    rows.sort(key=lambda r: (
        _STATUS_ORDER.get(r["status"], 99),
        0 if r.get("is_mega_cve") else 1,
        r["category"],
        r["name"].lower(),
    ))
    return rows


__all__ = [
    "build_tech_table_for_host",
    "KERNEL_DETECTION_BLACKLIST",
    "MIN_PUBLIC_VERSIONS",
]
