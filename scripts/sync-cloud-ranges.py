#!/usr/bin/env python3
"""Sync Cloud-Provider-IPv4-Ranges in `scan-worker/data/cloud_ranges_generated.py`.

Aufruf:
    python scripts/sync-cloud-ranges.py [--dry-run]

Quellen (Public-Endpoints, kein Auth noetig):
    AWS              https://ip-ranges.amazonaws.com/ip-ranges.json
    GCP              https://www.gstatic.com/ipranges/cloud.json
    Cloudflare       https://www.cloudflare.com/ips-v4
    Fastly           https://api.fastly.com/public-ip-list
    DigitalOcean     https://digitalocean.com/geo/google.csv
    OVH/IONOS/STRATO/Hetzner-Online via RIPEstat:
        https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS<NR>
        ASNs: AS16276 (OVH), AS8560 (IONOS), AS6724 (STRATO),
              AS24940 (Hetzner-Online)

Azure ist (Stand 2026-05) nicht trivial automatisch fetchbar — der offizielle
Download-Link rotiert wochenweise und braucht eine SAS-getokenete URL aus dem
HTML-Frontend. Wir skippen Azure hier; manuelle Eintraege bleiben in
`saas_heuristic._STATIC_RANGES["azure"]` als Fallback.

Output-Format: Python-Modul mit
    CLOUD_RANGES_GENERATED: dict[str, list[str]] = {
        "aws": ["3.0.0.0/15", ...],
        ...
    }

Manuelle Overrides in `saas_heuristic._STATIC_RANGES` haben Vorrang
(Loader-Logik in `saas_heuristic._build_combined_ranges()`).

Audit-Eintrag: `docs/scan-flow/Scan-Optimierung.md` Sektion 3.1.4 (F-PRE-003).
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import sys
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
# Endpoints + ASN-Mapping
# ────────────────────────────────────────────────────────────────────
AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_URL = "https://www.gstatic.com/ipranges/cloud.json"
CLOUDFLARE_URL = "https://www.cloudflare.com/ips-v4"
FASTLY_URL = "https://api.fastly.com/public-ip-list"
DIGITALOCEAN_URL = "https://digitalocean.com/geo/google.csv"
RIPE_URL_TEMPLATE = (
    "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
)

# (provider-key, ASN-Nummer) — provider-key landet in
# CLOUD_RANGES_GENERATED. Praefixlaengen-Filter siehe MIN_PREFIX_LEN.
RIPE_ASN_PROVIDERS: list[tuple[str, int]] = [
    ("ovh", 16276),
    ("ionos", 8560),
    ("strato", 6724),
    ("hetzner-online", 24940),
]

# ASN-Quelle: nur Prefixes >= /16 (sonst Tabelle wird zu gross,
# /8-/15-Bloecke explodieren bei mehr als 100k IPs den Lookup-Aufwand).
MIN_PREFIX_LEN_ASN = 16

# Sanity-Schwelle: weniger Eintraege = vermutlich Quell-Panne
MIN_TOTAL_ENTRIES = 50


# ────────────────────────────────────────────────────────────────────
# Parser pro Quelle
# ────────────────────────────────────────────────────────────────────

def parse_aws(body: str) -> list[str]:
    """AWS ip-ranges.json — `prefixes[].ip_prefix` (IPv4)."""
    data = json.loads(body)
    out: list[str] = []
    for entry in data.get("prefixes", []):
        prefix = entry.get("ip_prefix")
        if prefix and _is_valid_ipv4_network(prefix):
            out.append(prefix)
    return _dedup_sorted(out)


def parse_gcp(body: str) -> list[str]:
    """GCP cloud.json — `prefixes[].ipv4Prefix`."""
    data = json.loads(body)
    out: list[str] = []
    for entry in data.get("prefixes", []):
        prefix = entry.get("ipv4Prefix")
        if prefix and _is_valid_ipv4_network(prefix):
            out.append(prefix)
    return _dedup_sorted(out)


def parse_cloudflare(body: str) -> list[str]:
    """Cloudflare ips-v4 — Plain-Text, ein Prefix pro Zeile."""
    out: list[str] = []
    for line in body.splitlines():
        prefix = line.strip()
        if prefix and _is_valid_ipv4_network(prefix):
            out.append(prefix)
    return _dedup_sorted(out)


def parse_fastly(body: str) -> list[str]:
    """Fastly public-ip-list — JSON mit `addresses[]` (IPv4)."""
    data = json.loads(body)
    out: list[str] = []
    for prefix in data.get("addresses", []):
        if prefix and _is_valid_ipv4_network(prefix):
            out.append(prefix)
    return _dedup_sorted(out)


def parse_digitalocean(body: str) -> list[str]:
    """DigitalOcean google.csv — CSV: prefix,country,region,city,zip.
    Erste Spalte ist der CIDR-Prefix; nur IPv4 behalten."""
    out: list[str] = []
    reader = csv.reader(io.StringIO(body))
    for row in reader:
        if not row:
            continue
        prefix = row[0].strip()
        if prefix and _is_valid_ipv4_network(prefix):
            out.append(prefix)
    return _dedup_sorted(out)


def parse_ripe_asn(body: str) -> list[str]:
    """RIPEstat announced-prefixes — `data.prefixes[].prefix` (IPv4)."""
    data = json.loads(body)
    prefixes = data.get("data", {}).get("prefixes", [])
    out: list[str] = []
    for entry in prefixes:
        prefix = entry.get("prefix") if isinstance(entry, dict) else None
        if not prefix or not _is_valid_ipv4_network(prefix):
            continue
        # Praefixlaengen-Filter — nur Prefixes >= MIN_PREFIX_LEN_ASN.
        try:
            net = ipaddress.IPv4Network(prefix, strict=False)
        except ValueError:
            continue
        if net.prefixlen < MIN_PREFIX_LEN_ASN:
            continue
        out.append(str(net))
    return _dedup_sorted(out)


# ────────────────────────────────────────────────────────────────────
# Helper
# ────────────────────────────────────────────────────────────────────

def _is_valid_ipv4_network(prefix: str) -> bool:
    """True wenn `prefix` ein gueltiges IPv4-CIDR ist (kein IPv6, kein Host)."""
    try:
        ipaddress.IPv4Network(prefix, strict=False)
        return True
    except (ValueError, ipaddress.AddressValueError):
        return False


def _dedup_sorted(prefixes: list[str]) -> list[str]:
    """Dedupe Prefixe nach Netzwerk-Repraesentation und sortiere stabil."""
    seen: set[str] = set()
    nets: list[ipaddress.IPv4Network] = []
    for p in prefixes:
        try:
            net = ipaddress.IPv4Network(p, strict=False)
        except ValueError:
            continue
        canon = str(net)
        if canon in seen:
            continue
        seen.add(canon)
        nets.append(net)
    nets.sort(key=lambda n: (int(n.network_address), n.prefixlen))
    return [str(n) for n in nets]


# ────────────────────────────────────────────────────────────────────
# Fetch + Build
# ────────────────────────────────────────────────────────────────────

def _safe_fetch(label: str, url: str) -> str | None:
    """Fetch + Retry mit klarer Logmeldung. Gibt None bei Fehlschlag."""
    print(f"[INFO] fetching {label}: {url}")
    try:
        return fetch_with_retry(url, retries=3, timeout=30)
    except Exception as exc:  # noqa: BLE001 — externe Quelle, generisch loggen
        print(f"  [WARN] {label}: {exc}", file=sys.stderr)
        return None


def build_ranges() -> dict[str, list[str]]:
    """Iteriert alle Quellen + RIPEstat-ASNs, baut ranges-Dict."""
    out: dict[str, list[str]] = {}

    # AWS
    body = _safe_fetch("aws", AWS_URL)
    if body:
        prefixes = parse_aws(body)
        if prefixes:
            out["aws"] = prefixes
            print(f"  -> aws: {len(prefixes)} prefixes")

    # GCP
    body = _safe_fetch("gcp", GCP_URL)
    if body:
        prefixes = parse_gcp(body)
        if prefixes:
            out["gcp"] = prefixes
            print(f"  -> gcp: {len(prefixes)} prefixes")

    # Cloudflare
    body = _safe_fetch("cloudflare", CLOUDFLARE_URL)
    if body:
        prefixes = parse_cloudflare(body)
        if prefixes:
            out["cloudflare"] = prefixes
            print(f"  -> cloudflare: {len(prefixes)} prefixes")

    # Fastly
    body = _safe_fetch("fastly", FASTLY_URL)
    if body:
        prefixes = parse_fastly(body)
        if prefixes:
            out["fastly"] = prefixes
            print(f"  -> fastly: {len(prefixes)} prefixes")

    # DigitalOcean
    body = _safe_fetch("digitalocean", DIGITALOCEAN_URL)
    if body:
        prefixes = parse_digitalocean(body)
        if prefixes:
            out["digitalocean"] = prefixes
            print(f"  -> digitalocean: {len(prefixes)} prefixes")

    # RIPEstat-ASN-Sammlung (OVH, IONOS, STRATO, Hetzner-Online)
    for provider, asn in RIPE_ASN_PROVIDERS:
        url = RIPE_URL_TEMPLATE.format(asn=asn)
        body = _safe_fetch(f"ripe-asn-{provider}", url)
        if body:
            prefixes = parse_ripe_asn(body)
            if prefixes:
                out[provider] = prefixes
                print(f"  -> {provider} (AS{asn}): {len(prefixes)} prefixes")

    return out


def _build_header(timestamp: str) -> str:
    """Modul-Docstring — Quelle + Generator + Zeitstempel."""
    return (
        '"""GENERIERT — NICHT MANUELL EDITIEREN.\n'
        '\n'
        'Cloud-Provider-IPv4-Ranges aus offiziellen Public-Endpoints.\n'
        'Generator: scripts/sync-cloud-ranges.py\n'
        f'Stand:    {timestamp}\n'
        '\n'
        'Quellen: AWS ip-ranges.json, GCP cloud.json, Cloudflare ips-v4,\n'
        'Fastly public-ip-list, DigitalOcean google.csv, RIPEstat ASNs\n'
        '(OVH/IONOS/STRATO/Hetzner-Online).\n'
        '\n'
        'Manuelle Overrides + Provider die hier nicht synchronisierbar sind\n'
        '(z.B. Azure ServiceTags) gehoeren in\n'
        '`scan-worker/scanner/precheck/saas_heuristic.py:_STATIC_RANGES`.\n'
        'Diese haben Vorrang vor den Generated-Eintraegen (Loader-Logik in\n'
        '`saas_heuristic._build_combined_ranges()`).\n'
        '"""\n'
    )


def write_module(entries: dict[str, list[str]], dest: Path) -> None:
    header = _build_header(datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
    atomic_write_python_module(
        dest,
        header=header,
        data_name="CLOUD_RANGES_GENERATED",
        data_dict=entries,
        dict_type_hint="dict[str, list[str]]",
    )
    total = sum(len(v) for v in entries.values())
    print(f"[INFO] wrote {len(entries)} providers / {total} prefixes -> {dest}")


# ────────────────────────────────────────────────────────────────────
# CLI-Entry
# ────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="Nur fetchen + zusammenfassen, nicht schreiben")
    ap.add_argument("--out", default=None,
                    help="Override Output-Pfad (default: "
                         "scan-worker/data/cloud_ranges_generated.py)")
    args = ap.parse_args()

    entries = build_ranges()

    # Sanity-Schwelle: total-prefix-count (alle Provider zusammen).
    total = sum(len(v) for v in entries.values())
    flat = {f"{prov}_{i}": p for prov, prefixes in entries.items()
            for i, p in enumerate(prefixes)}
    try:
        validate_min_entries(
            flat, min_count=MIN_TOTAL_ENTRIES,
            source_name="cloud-provider-ranges",
        )
    except SyncValidationError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        print(f"\n[DRY-RUN] {len(entries)} Provider, {total} Prefixes gefetched.")
        for prov in sorted(entries.keys()):
            print(f"  {prov}: {len(entries[prov])} prefixes")
        return 0

    repo_root = Path(__file__).resolve().parent.parent
    dest = (Path(args.out) if args.out
            else repo_root / "scan-worker" / "data"
                            / "cloud_ranges_generated.py")
    write_module(entries, dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
