"""Cloud-Provider-Erkennung anhand bekannter IPv4-Ranges.

Initial-Version mit statischen Haupt-Ranges. Eine wöchentliche
Cron-Aktualisierung aus offiziellen Quellen (Azure ServiceTags,
AWS ip-ranges.json, GCP _cloud-netblocks, Cloudflare ips-v4,
Hetzner ASN) ist in MULTI-TARGET-PLAN §14 als Folge-Iteration vorgesehen.
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


def _compiled() -> list[tuple[str, ipaddress.IPv4Network]]:
    out: list[tuple[str, ipaddress.IPv4Network]] = []
    for provider, ranges in _STATIC_RANGES.items():
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
