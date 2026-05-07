"""Cloud-Provider-Erkennung anhand bekannter IPv4-Ranges.

`_STATIC_RANGES` haelt manuelle Haupt-Eintraege (Stable-Defaults, schnelle
Korrekturen ohne Sync-Lauf). Daneben werden Eintraege aus
`data.cloud_ranges_generated.CLOUD_RANGES_GENERATED` (Sync-Skript
`scripts/sync-cloud-ranges.py`, F-PRE-003) geladen — Manual ueberschreibt
Generated bei gleichem Provider-Key.

Quellen Sync: AWS ip-ranges.json, GCP cloud.json, Cloudflare ips-v4,
Fastly public-ip-list, DigitalOcean google.csv, RIPEstat-ASNs fuer
OVH/IONOS/STRATO/Hetzner-Online. Azure bleibt Manual-only (rotierender
SAS-Download, vgl. Sync-Skript-Kommentar).
"""

from __future__ import annotations

import ipaddress
from typing import Optional


_STATIC_RANGES: dict[str, list[str]] = {
    "cloudflare": [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
        "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    ],
    "aws": [
        "3.0.0.0/9", "13.32.0.0/15", "13.224.0.0/14", "15.160.0.0/13",
        "18.32.0.0/11", "34.192.0.0/10", "52.0.0.0/11", "52.84.0.0/15",
        "54.64.0.0/11", "54.144.0.0/12", "54.192.0.0/16", "99.77.128.0/17",
    ],
    "azure": [
        "13.64.0.0/11", "13.104.0.0/14", "20.0.0.0/8",
        "40.64.0.0/10", "51.100.0.0/14", "52.96.0.0/12",
        "104.40.0.0/13", "137.116.0.0/15", "168.61.0.0/16",
    ],
    "gcp": [
        "8.34.208.0/20", "8.35.192.0/20", "34.64.0.0/10",
        "35.184.0.0/13", "35.192.0.0/14", "35.196.0.0/15",
        "35.198.0.0/16", "35.199.0.0/17", "104.154.0.0/15",
        "104.196.0.0/14", "130.211.0.0/16", "146.148.0.0/17",
    ],
    "hetzner_cloud": [
        "5.75.128.0/17", "37.27.0.0/16", "46.4.0.0/16",
        "49.12.0.0/16", "65.21.0.0/16", "88.99.0.0/16",
        "116.202.0.0/16", "135.181.0.0/16", "136.243.0.0/16",
        "144.76.0.0/16", "148.251.0.0/16", "159.69.0.0/16",
        "167.235.0.0/16", "176.9.0.0/16", "188.34.128.0/17",
    ],
}


# Generierte Eintraege aus `scripts/sync-cloud-ranges.py` (F-PRE-003).
# Wird per `data/cloud_ranges_generated.py` ausgeliefert. Bei fehlendem
# Generated-File (z.B. frischer Checkout vor erstem Sync-Lauf) leeres Dict —
# Kombi-Lookup faellt dann auf `_STATIC_RANGES` zurueck.
try:
    from data.cloud_ranges_generated import CLOUD_RANGES_GENERATED as _GENERATED_RANGES
except Exception:  # noqa: BLE001 — generated-File optional zur Build-Zeit
    _GENERATED_RANGES = {}


def _build_combined_ranges() -> dict[str, list[str]]:
    """Generated als Basis, Manual ueberschreibt bei gleichem Provider-Key.

    Reihenfolge wichtig: erst Generated kopieren, dann Manual.update —
    das stellt sicher, dass kuratierte Manual-Listen immer Vorrang haben
    (z.B. wenn ein Sync-Lauf im Output kaputte Eintraege haette).
    """
    combined: dict[str, list[str]] = {k: list(v) for k, v in _GENERATED_RANGES.items()}
    for provider, prefixes in _STATIC_RANGES.items():
        combined[provider] = list(prefixes)
    return combined


def _compiled() -> list[tuple[str, ipaddress.IPv4Network]]:
    out: list[tuple[str, ipaddress.IPv4Network]] = []
    for provider, ranges in _build_combined_ranges().items():
        for r in ranges:
            try:
                out.append((provider, ipaddress.IPv4Network(r)))
            except ValueError:
                continue
    return out


_COMPILED = _compiled()


def detect_cloud_provider(ip: str) -> Optional[str]:
    """Return provider name if ip matches a known cloud range, else None."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except (ValueError, ipaddress.AddressValueError):
        return None
    for provider, net in _COMPILED:
        if addr in net:
            return provider
    return None


# rdns-Suffix-Patterns pro Provider — fuer CDN-Edge-Dedup auch wenn die IP
# (noch) nicht in _STATIC_RANGES bekannt ist (Fastly/Akamai-Edges, rotierende
# CF-Ranges). Suffix-Match (endswith) statt Substring-Match, damit Customer-
# Strings wie `cdn-cloudflare-failover.example.com` nicht falsch klassifiziert
# werden. Quelle: F-P0B-005 (docs/scan-flow/Scan-Optimierung.md §3.3.2).
_RDNS_PROVIDER_PATTERNS: dict[str, list[str]] = {
    "cloudflare": [".cloudflare.com", ".cloudflare.net"],
    "aws": [
        ".amazonaws.com", ".compute.amazonaws.com",
        ".cloudfront.net",
    ],
    "azure": [".azure.com", ".cloudapp.net", ".cloudapp.azure.com"],
    "gcp": [".googleusercontent.com", ".bc.googleusercontent.com",
            ".1e100.net"],
    "fastly": [".fastly.net", ".fastlylb.net"],
    "akamai": [
        ".akamai.net", ".akamaitechnologies.com",
        ".akamaiedge.net", ".akamaihd.net", ".edgekey.net",
        ".edgesuite.net",
    ],
}


def rdns_provider_patterns() -> dict[str, list[str]]:
    """Zentrale Provider-rdns-Suffix-Liste (Kopie). Wird von
    `phase0._collapse_cdn_edge_ips` genutzt um Fastly/Akamai/CF-Edges auch
    dann zu dedupen, wenn ihre IP noch nicht in `_STATIC_RANGES` ist."""
    # Kopie zurueckgeben damit Caller die Liste nicht versehentlich mutieren.
    return {k: list(v) for k, v in _RDNS_PROVIDER_PATTERNS.items()}


def detect_provider_by_rdns(rdns: str) -> Optional[str]:
    """Suffix-Match einer rdns gegen `rdns_provider_patterns()`.

    Beispiel: `104.16.10.6.cdn.cloudflare.net` → `"cloudflare"`.
    Customer-Strings wie `cdn-cloudflare-failover.kunde.de` matchen NICHT
    (kein Suffix-Match auf `.cloudflare.com`/`.cloudflare.net`).
    """
    if not rdns:
        return None
    rdns_lc = rdns.lower().rstrip(".")
    for provider, suffixes in _RDNS_PROVIDER_PATTERNS.items():
        for suf in suffixes:
            if rdns_lc.endswith(suf):
                return provider
    return None
