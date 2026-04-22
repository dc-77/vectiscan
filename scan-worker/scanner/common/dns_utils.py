"""DNS resolver helpers.

Dünne Wrapper um dnspython + socket, damit Precheck- und Scan-Worker
dieselbe Auflösungs-Semantik nutzen.
"""

from __future__ import annotations

import socket
from typing import Iterable

try:
    import dns.resolver
    import dns.reversename
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False


DEFAULT_TIMEOUT = 5.0


def _resolver(timeout: float = DEFAULT_TIMEOUT) -> "dns.resolver.Resolver":
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    return r


def resolve_a(fqdn: str, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    """Return A records (IPv4) for fqdn. Empty list if none/timeout."""
    if _HAS_DNSPYTHON:
        try:
            answers = _resolver(timeout).resolve(fqdn, "A")
            return [r.to_text() for r in answers]
        except Exception:
            return []
    try:
        info = socket.getaddrinfo(fqdn, None, socket.AF_INET)
        return sorted({i[4][0] for i in info})
    except Exception:
        return []


def resolve_aaaa(fqdn: str, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    """Return AAAA records (IPv6) for fqdn. Empty list if none/timeout."""
    if not _HAS_DNSPYTHON:
        return []
    try:
        answers = _resolver(timeout).resolve(fqdn, "AAAA")
        return [r.to_text() for r in answers]
    except Exception:
        return []


def resolve_cname(fqdn: str, timeout: float = DEFAULT_TIMEOUT) -> str | None:
    if not _HAS_DNSPYTHON:
        return None
    try:
        answers = _resolver(timeout).resolve(fqdn, "CNAME")
        for r in answers:
            return r.to_text().rstrip(".")
    except Exception:
        return None
    return None


def resolve_mx(fqdn: str, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    if not _HAS_DNSPYTHON:
        return []
    try:
        answers = _resolver(timeout).resolve(fqdn, "MX")
        return [r.exchange.to_text().rstrip(".") for r in answers]
    except Exception:
        return []


def resolve_ns(fqdn: str, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    if not _HAS_DNSPYTHON:
        return []
    try:
        answers = _resolver(timeout).resolve(fqdn, "NS")
        return [r.to_text().rstrip(".") for r in answers]
    except Exception:
        return []


def reverse_dns(ip: str, timeout: float = DEFAULT_TIMEOUT) -> str | None:
    """Return PTR record for IP or None."""
    if _HAS_DNSPYTHON:
        try:
            rev = dns.reversename.from_address(ip)
            answers = _resolver(timeout).resolve(rev, "PTR")
            for r in answers:
                return r.to_text().rstrip(".")
        except Exception:
            return None
        return None
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def resolve_all(fqdn: str, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Resolve A/AAAA/CNAME/MX/NS in one call. Returns dict of lists."""
    return {
        "a": resolve_a(fqdn, timeout),
        "aaaa": resolve_aaaa(fqdn, timeout),
        "cname": resolve_cname(fqdn, timeout),
        "mx": resolve_mx(fqdn, timeout),
        "ns": resolve_ns(fqdn, timeout),
    }
