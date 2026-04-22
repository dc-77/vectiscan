"""CIDR / Dotted-Mask / IPv4 parsing and expansion helpers."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

MAX_EXPANSION_PREFIX = 24  # /24 = 256 IPs max, serverseitige Grenze


_DOTTED_MASK_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,3}(?:\.\d{1,3}){3})$"
)
_CIDR_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def is_valid_ipv4(raw: str) -> bool:
    try:
        ipaddress.IPv4Address(raw)
        return True
    except ValueError:
        return False


def dotted_mask_to_prefix(mask: str) -> int | None:
    """Convert 255.255.255.224 → 27. None if mask is not contiguous."""
    try:
        n = ipaddress.IPv4Address(mask)
    except ValueError:
        return None
    bits = f"{int(n):032b}"
    if "01" in bits:
        return None
    return bits.count("1")


def parse_cidr(raw: str) -> ipaddress.IPv4Network | None:
    """Parse a CIDR or dotted-mask input into an IPv4Network (network address)."""
    raw = raw.strip()
    m = _CIDR_RE.match(raw)
    if m:
        try:
            return ipaddress.IPv4Network(raw, strict=False)
        except ValueError:
            return None
    m = _DOTTED_MASK_RE.match(raw)
    if m:
        prefix = dotted_mask_to_prefix(m.group(2))
        if prefix is None:
            return None
        try:
            return ipaddress.IPv4Network(f"{m.group(1)}/{prefix}", strict=False)
        except ValueError:
            return None
    return None


def canonical(raw: str) -> str | None:
    """Return canonical form for CIDR/Dotted-Mask/IPv4/FQDN. None if invalid."""
    raw = raw.strip().lower()
    if is_valid_ipv4(raw):
        return raw
    net = parse_cidr(raw)
    if net:
        return str(net)
    # FQDN fallback — caller should validate separately
    return raw if raw else None


def expand(net: ipaddress.IPv4Network, max_hosts: int = 256) -> list[str]:
    """Expand a CIDR to host IPs, capped at max_hosts."""
    if net.prefixlen < MAX_EXPANSION_PREFIX:
        return []
    hosts = list(net.hosts()) if net.prefixlen < 31 else list(net)
    return [str(ip) for ip in hosts[:max_hosts]]


def expand_raw(raw: str, max_hosts: int = 256) -> list[str]:
    net = parse_cidr(raw)
    if net is None:
        return []
    return expand(net, max_hosts)


def is_ipv4_like(raw: str) -> bool:
    """True for plain IPv4, CIDR, or dotted-mask."""
    raw = raw.strip()
    return bool(
        _IPV4_RE.match(raw) or _CIDR_RE.match(raw) or _DOTTED_MASK_RE.match(raw)
    )
