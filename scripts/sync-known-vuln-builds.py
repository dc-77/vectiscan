#!/usr/bin/env python3
"""Sync KNOWN_VULN_BUILDS gegen OSV-API + CISA-KEV + EPSS.

Aufruf:
    python scripts/sync-known-vuln-builds.py [--dry-run]

Quellen (alle public, kein Auth):
    OSV-API     POST https://api.osv.dev/v1/query  (per package-name + ecosystem)
    CISA-KEV    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    EPSS        https://api.first.org/data/v1/epss?cve=<id>  (optional, slow)

Filter (Severity-Hebel — sonst wird die Liste zu gross fuer Banner-Match):
    1. CVE ist in CISA-KEV-Listing  (HARTER FILTER, ueberschreibt alles)
    2. ODER OSV `severity[].score >= 9.0`           (CVSS 3.1 / 4.0)
    3. ODER EPSS-Score > 0.7                        (nur Stichprobe — slow)

Output: report-worker/reporter/known_vuln_builds_generated.py
    KNOWN_VULN_BUILDS_GENERATED: dict[tuple[str, str, str], dict] = {
        ("apache", "httpd", "<=2.4.55"): {
            "cves": ["CVE-2023-25690"], "severity": "CRITICAL",
            "name": "Apache HTTP Smuggling 2023", "_source": "osv+kev",
        },
        ...
    }

Manuelle Eintraege in `eol_detector.KNOWN_VULN_BUILDS_MANUAL` haben Vorrang
(Loader-Logik in `eol_detector._load_known_vuln_union()`).

Audit-Eintrag: `docs/scan-flow/Scan-Optimierung.md` Sektion 3.11.4 (F-RPT-001).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

# Lokaler Import — `_sync_lib` liegt im selben Ordner.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _sync_lib import (  # noqa: E402
    SyncValidationError,
    atomic_write_python_module,
    fetch_with_retry,
    validate_min_entries,
)


# ────────────────────────────────────────────────────────────────────
# Quellen
# ────────────────────────────────────────────────────────────────────
# OSV /v1/query verlangt `version` ODER `commit` — fuer Server-Software ohne
# Ecosystem (Apache/nginx/Confluence/...) kommt da nur HTTP 400 zurueck.
# Wir nutzen stattdessen CISA-KEV als Vendor-/CVE-Source und fetchen die
# Vuln-Details pro CVE-ID via OSV /v1/vulns/{id} (funktioniert ohne version).
OSV_VULN_BY_ID_URL = "https://api.osv.dev/v1/vulns/{}"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

HTTP_HEADERS = {"User-Agent": "vectiscan-sync-known-vuln-builds/1.0"}

# Vendor-Mapping: (vendor_internal, product_internal, kev_vendor_match,
# kev_product_match). KEV-vendor/product werden case-insensitiv mit
# `vendorProject` / `product` aus CISA-KEV verglichen (substring-Match).
# Leerer kev_product_match = matche alle Produkte des Vendors.
VENDORS: list[tuple[str, str, str, str]] = [
    ("apache",      "httpd",          "apache",      "http server"),
    ("nginx",       "",               "nginx",       ""),
    ("atlassian",   "confluence",     "atlassian",   "confluence"),
    ("atlassian",   "jira",           "atlassian",   "jira"),
    ("atlassian",   "bitbucket",      "atlassian",   "bitbucket"),
    ("gitlab",      "",               "gitlab",      ""),
    ("jetbrains",   "teamcity",       "jetbrains",   "teamcity"),
    ("microsoft",   "exchange",       "microsoft",   "exchange"),
    ("microsoft",   "iis",            "microsoft",   "iis"),
    ("citrix",      "netscaler",      "citrix",      "netscaler"),
    ("citrix",      "adc",            "citrix",      "adc"),
    ("fortinet",    "fortigate",      "fortinet",    "fortios"),
    ("ivanti",      "connect-secure", "ivanti",      "connect secure"),
    ("connectwise", "screenconnect",  "connectwise", "screenconnect"),
    ("progress",    "moveit",         "progress",    "moveit"),
    ("progress",    "ws_ftp",         "progress",    "ws_ftp"),
    ("vmware",      "vcenter",        "vmware",      "vcenter"),
    ("vmware",      "esxi",           "vmware",      "esxi"),
    ("php",         "",               "php",         ""),
    ("openssl",     "",               "openssl",     ""),
]

# CVSS-Schwellwert fuer non-KEV-Eintraege
CVSS_THRESHOLD = 9.0
# EPSS-Schwellwert (optional, sehr restriktiv: nur Aktiv-Exploits)
EPSS_THRESHOLD = 0.7

# Sanity-Min: wenn weniger als 15 Eintraege gefetched, vermutlich Quell-Panne
MIN_TOTAL_ENTRIES = 15

# Cap pro Vendor/Product um Liste handhabbar zu halten
MAX_PER_PRODUCT = 30
# Cap pro CVE — CVE-OSV-Conversions enthalten oft CPE-Eintraege fuer
# Oracle/IBM/Ubuntu-Pakete die Apache/Confluence/etc. einbetten. Wir brauchen
# nur die obersten 3 Upstream-Ranges, sonst polluten Distro-Versionen den
# KNOWN_VULN_BUILDS-Lookup.
MAX_RANGES_PER_VULN = 3


# ────────────────────────────────────────────────────────────────────
# CISA-KEV
# ────────────────────────────────────────────────────────────────────

def fetch_kev_data() -> dict:
    """Returns full CISA-KEV JSON-Document (mit vulnerabilities-Liste).

    Bei Fehlschlag: leeres Dict (kein Hard-Fail).
    """
    try:
        body = fetch_with_retry(KEV_URL, retries=3, timeout=30,
                                 headers=HTTP_HEADERS)
    except Exception as exc:  # noqa: BLE001
        print(f"  [WARN] KEV-Fetch fehlgeschlagen: {exc}", file=sys.stderr)
        return {}
    try:
        return json.loads(body)
    except Exception as exc:  # noqa: BLE001
        print(f"  [WARN] KEV-Parse fehlgeschlagen: {exc}", file=sys.stderr)
        return {}


def kev_cve_set(kev_data: dict) -> set[str]:
    """Set aller CVE-IDs in KEV (fuer schnellen `in_kev`-Check)."""
    return {
        (v.get("cveID") or "").strip().upper()
        for v in kev_data.get("vulnerabilities", [])
        if (v.get("cveID") or "").strip().upper().startswith("CVE-")
    }


# ────────────────────────────────────────────────────────────────────
# OSV (per CVE-ID — /v1/query benoetigt version, was wir fuer Server-
# Software ohne Ecosystem nicht haben. /v1/vulns/{cve} funktioniert ohne.)
# ────────────────────────────────────────────────────────────────────

def fetch_osv_vuln_by_cve(cve_id: str, *, timeout: int = 30) -> dict | None:
    """OSV GET /v1/vulns/{cve_id} → vuln-detail-dict (oder None).

    Schema-Diff zu /v1/query:
      - `affected[].ranges[]` hat oft `type=GIT` mit commit-Hashes in events.
      - Echte Versions-Strings stehen in
        `affected[].ranges[].database_specific.versions[].(introduced|last_affected)`.
      - `severity[].score` ist meist nur ein CVSS-Vector-String, kein Float.
    """
    url = OSV_VULN_BY_ID_URL.format(cve_id)
    req = urllib.request.Request(url, headers=HTTP_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        print(f"  [WARN] OSV {cve_id}: {exc}", file=sys.stderr)
        return None
    except Exception as exc:  # noqa: BLE001
        print(f"  [WARN] OSV {cve_id}: {exc}", file=sys.stderr)
        return None
    try:
        return json.loads(raw)
    except Exception as exc:  # noqa: BLE001
        print(f"  [WARN] OSV-Parse {cve_id}: {exc}", file=sys.stderr)
        return None


def kev_cves_for_vendor(
    kev_data: dict,
    vendor_match: str,
    product_match: str,
) -> list[tuple[str, dict]]:
    """Filtert CISA-KEV-Eintraege per case-insensitivem Substring-Match auf
    vendorProject / product. Returns (cve_id, kev_entry) Liste.
    """
    out: list[tuple[str, dict]] = []
    vm = (vendor_match or "").lower()
    pm = (product_match or "").lower()
    for v in kev_data.get("vulnerabilities", []):
        vendor_proj = (v.get("vendorProject") or "").lower()
        product = (v.get("product") or "").lower()
        if vm and vm not in vendor_proj:
            continue
        if pm and pm not in product:
            continue
        cve = (v.get("cveID") or "").strip().upper()
        if cve.startswith("CVE-"):
            out.append((cve, v))
    return out


_CVSS_SCORE_PAT = re.compile(r"[\d.]+$")


def _parse_cvss_score(severity_entry: dict) -> float:
    """Extrahiert numerischen CVSS-Score aus OSV-severity-Eintrag.

    OSV liefert oft "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" (Vector)
    statt nur Score — Score muss ggf. aus Vector berechnet werden. Hier
    fallen wir bei reinen Vector-Strings auf 0.0 zurueck (Skip) — KEV-Filter
    fuengt das auf.
    Wenn `score` direkt eine Zahl ist (CVSS_V3-Variante), nutzen wir die.
    """
    raw = severity_entry.get("score") or ""
    if not raw:
        return 0.0
    raw = str(raw).strip()
    # Direkter Float
    try:
        return float(raw)
    except ValueError:
        pass
    # Vector-String → Score am Ende? nicht zuverlaessig → 0.0
    return 0.0


def _max_cvss(vuln: dict) -> float:
    """Maximaler CVSS-Score ueber alle severity-Eintraege."""
    sev_list = vuln.get("severity") or []
    return max((_parse_cvss_score(s) for s in sev_list), default=0.0)


def _highest_severity_label(cvss_score: float) -> str:
    if cvss_score >= 9.0:
        return "CRITICAL"
    if cvss_score >= 7.0:
        return "HIGH"
    if cvss_score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _aliases_to_cves(vuln: dict) -> list[str]:
    """Sammelt CVE-IDs aus `id` + `aliases`."""
    out: list[str] = []
    primary = (vuln.get("id") or "").strip().upper()
    if primary.startswith("CVE-"):
        out.append(primary)
    for a in vuln.get("aliases") or []:
        a_up = (a or "").strip().upper()
        if a_up.startswith("CVE-") and a_up not in out:
            out.append(a_up)
    return out


# Git-Commit-SHAs sind 7-40-Zeichen hex; Versions-Strings haben einen Punkt
# ODER sind Sonder-Markers wie "0".
_GIT_SHA = re.compile(r"^[0-9a-f]{7,40}$")


def _is_version_like(val: str) -> bool:
    """True wenn `val` wie eine Software-Version aussieht (nicht Commit-SHA)."""
    if not val:
        return False
    if val == "0":  # OSV-Marker fuer "alle Versionen ab Anfang"
        return True
    if _GIT_SHA.match(val):
        return False
    # Mindestens ein Punkt (z.B. 2.4.55) ODER nicht-rein-hex
    return "." in val


def _pick_version(events: list[dict], key: str) -> str | None:
    """Liefert den ersten version-like-Wert fuer `key` (fixed | last_affected)
    aus events. Git-Commit-SHAs werden uebersprungen.
    """
    for e in events:
        if key in e:
            v = e.get(key)
            if v and _is_version_like(str(v)):
                return str(v)
    return None


def _range_specs_from_vuln(vuln: dict) -> list[str]:
    """Extrahiert range_spec-Strings aus OSV-affected-Daten.

    Quellen (in Reihenfolge, erste die Versionen liefert gewinnt pro Range):
      1. `affected[].ranges[].events[]` wenn versions-like
         (ECOSYSTEM-type, klassischer /v1/query-Pfad).
      2. `affected[].ranges[].database_specific.versions[]` (GIT-type-Fallback;
         events enthalten dann nur Commit-SHAs).
      3. `affected[].database_specific.unresolved_ranges[].events[]`
         (CVE-DB-Source-Pfad fuer Server-Software wie Confluence/Fortinet/IIS
         — OSV hat keine Ecosystem-Mapping aber CPE/version-data).

    Mappings:
      {fixed:2.4.56} → "<2.4.56"
      {last_affected:2.4.55} → "<=2.4.55"
    """
    out: list[str] = []
    for aff in vuln.get("affected") or []:
        # 1./2. ranges + database_specific.versions
        for rng in aff.get("ranges") or []:
            events = rng.get("events") or []
            fixed = _pick_version(events, "fixed")
            last_aff = _pick_version(events, "last_affected") if not fixed else None
            if not fixed and not last_aff:
                ds_versions = (rng.get("database_specific") or {}).get("versions") or []
                fixed = _pick_version(ds_versions, "fixed")
                last_aff = _pick_version(ds_versions, "last_affected") if not fixed else None
            if fixed:
                out.append(f"<{fixed}")
            elif last_aff:
                out.append(f"<={last_aff}")
        # 3. unresolved_ranges (Server-Software via CVE-Source-Conversion)
        unresolved = (aff.get("database_specific") or {}).get("unresolved_ranges") or []
        for rng in unresolved:
            events = rng.get("events") or []
            fixed = _pick_version(events, "fixed")
            last_aff = _pick_version(events, "last_affected") if not fixed else None
            if fixed:
                out.append(f"<{fixed}")
            elif last_aff:
                out.append(f"<={last_aff}")
    # Dedup, stabile Reihenfolge, Cap auf MAX_RANGES_PER_VULN
    seen: set[str] = set()
    uniq: list[str] = []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
            if len(uniq) >= MAX_RANGES_PER_VULN:
                break
    return uniq


# ────────────────────────────────────────────────────────────────────
# Filter + Build
# ────────────────────────────────────────────────────────────────────

def _passes_filter(
    vuln: dict,
    *,
    kev_set: set[str],
) -> tuple[bool, list[str], float]:
    """True wenn vuln den Severity-Filter passiert.

    Returns (passes, cve_list, max_cvss).
    """
    cves = _aliases_to_cves(vuln)
    if not cves:
        return (False, [], 0.0)
    cvss = _max_cvss(vuln)
    in_kev = any(c in kev_set for c in cves)
    passes = in_kev or cvss >= CVSS_THRESHOLD
    return (passes, cves, cvss)


def build_entries(
    *,
    kev_data: dict,
    vendors: list[tuple[str, str, str, str]] | None = None,
) -> dict[tuple[str, str, str], dict]:
    """Iteriert VENDORS, holt KEV-CVEs pro Vendor, fetcht OSV-Details
    pro CVE-ID, baut entries-Dict.

    Filter: alle KEV-Eintraege passen (KEV ist per Definition aktiv exploited
    → CRITICAL). Wir braeuchten OSV nur fuer die range_specs.
    """
    kev_set = kev_cve_set(kev_data)
    out: dict[tuple[str, str, str], dict] = {}
    for vendor, product, kev_vendor, kev_product in (vendors or VENDORS):
        print(f"[INFO] KEV-Filter: vendor={kev_vendor!r} product={kev_product!r}")
        cves = kev_cves_for_vendor(kev_data, kev_vendor, kev_product)
        if not cves:
            print(f"  -> {vendor}/{product or '*'}: 0 KEV matches")
            continue

        kept_for_product = 0
        for cve_id, kev_entry in cves:
            vuln = fetch_osv_vuln_by_cve(cve_id)
            if not vuln:
                # Kein OSV-Eintrag → fallback nutzt KEV-Daten ohne range_spec
                # Wir koennen ohne range_spec keinen sinnvollen Eintrag bauen,
                # also skip.
                continue
            ranges = _range_specs_from_vuln(vuln)
            if not ranges:
                continue
            cve_aliases = _aliases_to_cves(vuln) or [cve_id]
            severity = "CRITICAL"  # KEV = aktiv exploited
            summary = (
                vuln.get("summary")
                or kev_entry.get("vulnerabilityName")
                or cve_id
            ).strip()
            name = summary[:80]

            for rng in ranges:
                key = (vendor, product, rng)
                if key in out:
                    existing = out[key]
                    merged_cves: list[str] = list(existing.get("cves") or [])
                    for c in cve_aliases:
                        if c not in merged_cves:
                            merged_cves.append(c)
                    existing["cves"] = merged_cves
                    continue
                out[key] = {
                    "cves": cve_aliases,
                    "severity": severity,
                    "name": name,
                    "_source": "osv+kev",
                }
                kept_for_product += 1
                if kept_for_product >= MAX_PER_PRODUCT:
                    break
            if kept_for_product >= MAX_PER_PRODUCT:
                print(f"  [INFO] Cap MAX_PER_PRODUCT={MAX_PER_PRODUCT} erreicht "
                      f"fuer {vendor}/{product}.")
                break
        print(f"  -> {vendor}/{product or '*'}: {kept_for_product} kept "
              f"(von {len(cves)} KEV matches)")
    return out


# ────────────────────────────────────────────────────────────────────
# Output
# ────────────────────────────────────────────────────────────────────

def _build_header(timestamp: str) -> str:
    return (
        '"""GENERIERT — NICHT MANUELL EDITIEREN.\n'
        '\n'
        'Quellen:\n'
        '  - OSV (https://osv.dev) — Apache 2.0\n'
        '  - CISA Known Exploited Vulnerabilities (KEV)\n'
        '\n'
        'Generator: scripts/sync-known-vuln-builds.py\n'
        f'Stand:    {timestamp}\n'
        '\n'
        'Filter: KEV-listed CVEs ODER CVSS >= 9.0. Manuelle Eintraege in\n'
        '`reporter/eol_detector.py:KNOWN_VULN_BUILDS_MANUAL` haben Vorrang.\n'
        '\n'
        'Audit-Eintrag: docs/scan-flow/Scan-Optimierung.md Sektion 3.11.4\n'
        '(F-RPT-001).\n'
        '"""\n'
    )


def write_module(entries: dict, dest: Path) -> None:
    header = _build_header(datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
    atomic_write_python_module(
        dest,
        header=header,
        data_name="KNOWN_VULN_BUILDS_GENERATED",
        data_dict=entries,
        dict_type_hint="dict[tuple[str, str, str], dict]",
    )
    print(f"[INFO] wrote {len(entries)} entries -> {dest}")


# ────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="Nur fetchen + zusammenfassen, nicht schreiben")
    ap.add_argument("--out", default=None,
                    help="Override Output-Pfad")
    args = ap.parse_args()

    print("[INFO] fetching CISA-KEV ...")
    kev_data = fetch_kev_data()
    kev_total = len(kev_data.get("vulnerabilities") or [])
    print(f"  -> KEV: {kev_total} CVEs")
    if kev_total == 0:
        print("[ERROR] KEV-Fetch lieferte keine Daten — Abort.", file=sys.stderr)
        return 1

    entries = build_entries(kev_data=kev_data)

    try:
        validate_min_entries(
            entries, min_count=MIN_TOTAL_ENTRIES,
            source_name="known-vuln-builds (OSV+KEV)",
        )
    except SyncValidationError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        print(f"\n[DRY-RUN] {len(entries)} Eintraege gefetched.")
        for k, v in list(sorted(entries.items()))[:8]:
            print(f"  {k} -> cves={v.get('cves')} sev={v.get('severity')}")
        return 0

    repo_root = Path(__file__).resolve().parent.parent
    dest = (Path(args.out) if args.out
            else repo_root / "report-worker" / "reporter"
                            / "known_vuln_builds_generated.py")
    write_module(entries, dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
