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
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

HTTP_HEADERS = {"User-Agent": "vectiscan-sync-known-vuln-builds/1.0"}

# Vendor/Product/OSV-Mapping — nur Server-Software die Banner-matchbar ist.
# (vendor_internal, product_internal, osv_package, ecosystem)
# ecosystem="" → OSV ohne ecosystem-Filter (matched alle Quellen).
VENDORS: list[tuple[str, str, str, str]] = [
    ("apache", "httpd",            "Apache HTTP Server", ""),
    ("nginx", "",                  "nginx", ""),
    ("atlassian", "confluence",    "Atlassian Confluence", ""),
    ("atlassian", "jira",          "Atlassian Jira", ""),
    ("atlassian", "bitbucket",     "Atlassian Bitbucket", ""),
    ("gitlab", "",                 "GitLab", ""),
    ("jetbrains", "teamcity",      "JetBrains TeamCity", ""),
    ("microsoft", "exchange",      "Microsoft Exchange Server", ""),
    ("microsoft", "iis",           "Microsoft IIS", ""),
    ("citrix", "netscaler",        "Citrix NetScaler ADC", ""),
    ("citrix", "adc",              "Citrix ADC", ""),
    ("fortinet", "fortigate",      "Fortinet FortiOS", ""),
    ("ivanti", "connect-secure",   "Ivanti Connect Secure", ""),
    ("connectwise", "screenconnect", "ConnectWise ScreenConnect", ""),
    ("progress", "moveit",         "Progress MOVEit Transfer", ""),
    ("progress", "ws_ftp",         "Progress WS_FTP Server", ""),
    ("vmware", "vcenter",          "VMware vCenter Server", ""),
    ("vmware", "esxi",             "VMware ESXi", ""),
    ("php", "",                    "PHP", ""),
    ("openssl", "",                "OpenSSL", ""),
]

# CVSS-Schwellwert fuer non-KEV-Eintraege
CVSS_THRESHOLD = 9.0
# EPSS-Schwellwert (optional, sehr restriktiv: nur Aktiv-Exploits)
EPSS_THRESHOLD = 0.7

# Sanity-Min: wenn weniger als 15 Eintraege gefetched, vermutlich Quell-Panne
MIN_TOTAL_ENTRIES = 15

# Cap pro Vendor/Product um Liste handhabbar zu halten
MAX_PER_PRODUCT = 30


# ────────────────────────────────────────────────────────────────────
# CISA-KEV
# ────────────────────────────────────────────────────────────────────

def fetch_kev_set() -> set[str]:
    """Returns set of CVE-IDs (uppercase) in CISA-KEV.

    Bei Fehlschlag: leeres Set (kein Hard-Fail — wir koennen ohne KEV
    fallen-back auf reinen CVSS-Filter).
    """
    try:
        body = fetch_with_retry(KEV_URL, retries=3, timeout=30,
                                 headers=HTTP_HEADERS)
    except Exception as exc:  # noqa: BLE001
        print(f"  [WARN] KEV-Fetch fehlgeschlagen: {exc}", file=sys.stderr)
        return set()
    try:
        data = json.loads(body)
    except Exception as exc:  # noqa: BLE001
        print(f"  [WARN] KEV-Parse fehlgeschlagen: {exc}", file=sys.stderr)
        return set()
    out: set[str] = set()
    for v in data.get("vulnerabilities", []):
        cve = (v.get("cveID") or "").strip().upper()
        if cve:
            out.add(cve)
    return out


# ────────────────────────────────────────────────────────────────────
# OSV
# ────────────────────────────────────────────────────────────────────

def fetch_osv_for_vendor(
    osv_package: str,
    *,
    ecosystem: str = "",
    timeout: int = 30,
) -> list[dict]:
    """OSV POST /v1/query mit package-name (+ optional ecosystem).

    OSV-Schema (vereinfacht):
        {"vulns": [{
            "id": "CVE-2023-25690",
            "summary": "...",
            "affected": [{"package": {"name": "..."},
                          "ranges": [{"events": [{"introduced":"0"},
                                                  {"fixed":"2.4.56"}]}]}],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/.../9.8"}],
            ...
        }]}
    """
    payload: dict = {"package": {"name": osv_package}}
    if ecosystem:
        payload["package"]["ecosystem"] = ecosystem
    body_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OSV_QUERY_URL,
        data=body_bytes,
        headers={**HTTP_HEADERS, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        print(f"  [WARN] OSV {osv_package!r}: {exc}", file=sys.stderr)
        return []
    try:
        data = json.loads(raw)
    except Exception as exc:  # noqa: BLE001
        print(f"  [WARN] OSV-Parse {osv_package!r}: {exc}", file=sys.stderr)
        return []
    return data.get("vulns") or []


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


def _range_specs_from_vuln(vuln: dict) -> list[str]:
    """Extrahiert range_spec-Strings aus OSV-`affected[].ranges[].events`.

    Mappt:
      events:[{"introduced":"0"}, {"fixed":"2.4.56"}] → "<2.4.56"
      events:[{"introduced":"2.4.49"}, {"fixed":"2.4.51"}]
        → ">=2.4.49" UND "<2.4.51"  (zwei Events → wir nehmen `<fixed` als Hauptcheck)
      events:[{"introduced":"X"}, {"last_affected":"Y"}] → "<=Y"

    Pro vuln liefern wir nur den ENGSTEN range — typischerweise `<fixed`.
    """
    out: list[str] = []
    for aff in vuln.get("affected") or []:
        for rng in aff.get("ranges") or []:
            events = rng.get("events") or []
            fixed = next((e.get("fixed") for e in events if "fixed" in e), None)
            last_aff = next(
                (e.get("last_affected") for e in events if "last_affected" in e),
                None,
            )
            if fixed:
                out.append(f"<{fixed}")
            elif last_aff:
                out.append(f"<={last_aff}")
    # Dedup, stabile Reihenfolge
    seen: set[str] = set()
    uniq: list[str] = []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
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
    kev_set: set[str],
    vendors: list[tuple[str, str, str, str]] | None = None,
) -> dict[tuple[str, str, str], dict]:
    """Iteriert VENDORS, filtert OSV-Vulns nach KEV/CVSS, baut entries-Dict."""
    out: dict[tuple[str, str, str], dict] = {}
    for vendor, product, osv_pkg, ecosystem in (vendors or VENDORS):
        print(f"[INFO] OSV-Query: {osv_pkg} (ecosystem={ecosystem or '*'})")
        vulns = fetch_osv_for_vendor(osv_pkg, ecosystem=ecosystem)
        kept_for_product = 0
        for v in vulns:
            passes, cves, cvss = _passes_filter(v, kev_set=kev_set)
            if not passes:
                continue
            ranges = _range_specs_from_vuln(v)
            if not ranges:
                continue
            # Severity-Label: wenn KEV-listed → CRITICAL (KEV-Eintraege haben
            # nachweislich aktive Exploits), sonst aus CVSS abgeleitet.
            in_kev = any(c in kev_set for c in cves)
            severity = "CRITICAL" if in_kev else _highest_severity_label(cvss)
            # Name: erste 80 Zeichen der summary
            summary = (v.get("summary") or v.get("id") or "").strip()
            name = summary[:80] if summary else cves[0]

            # Pro range einen Eintrag — typischerweise nur 1
            for rng in ranges:
                key = (vendor, product, rng)
                # Falls dupliziert, vereinige cves
                if key in out:
                    existing = out[key]
                    merged_cves: list[str] = list(existing.get("cves") or [])
                    for c in cves:
                        if c not in merged_cves:
                            merged_cves.append(c)
                    existing["cves"] = merged_cves
                    continue
                out[key] = {
                    "cves": cves,
                    "severity": severity,
                    "name": name,
                    "_source": "osv+kev" if in_kev else "osv",
                }
                kept_for_product += 1
                if kept_for_product >= MAX_PER_PRODUCT:
                    break
            if kept_for_product >= MAX_PER_PRODUCT:
                print(f"  [INFO] Cap MAX_PER_PRODUCT={MAX_PER_PRODUCT} erreicht "
                      f"fuer {vendor}/{product}.")
                break
        print(f"  -> {vendor}/{product or '*'}: {kept_for_product} kept")
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
    kev_set = fetch_kev_set()
    print(f"  -> KEV: {len(kev_set)} CVEs")

    entries = build_entries(kev_set=kev_set)

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
