"""DNS resolver helpers.

Dünne Wrapper um dnspython + socket, damit Precheck- und Scan-Worker
dieselbe Auflösungs-Semantik nutzen.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable

try:
    import dns.resolver
    import dns.reversename
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False


DEFAULT_TIMEOUT = 5.0

# Fixierte DNS-Resolver — siehe scanner/resolvers.txt fuer dnsx.
# Begruendung: System-Default-Resolver wechselt zwischen 8.8.8.8 / 1.1.1.1 /
# Provider-DNS und liefert leicht abweichende Antwort-Sets pro Lauf.
# Mit fixierter Liste (gleiche Reihenfolge wie scanner/resolvers.txt) ist
# der Pre-Check und die Phase-0-DNS-Aufloesung reproduzierbar.
# Ueber ENV `DNS_RESOLVERS` (Komma-Liste) kann man den Default ueberschreiben.
import os as _os
_DEFAULT_NAMESERVERS = [
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
]
FIXED_NAMESERVERS = [
    s.strip() for s in _os.environ.get("DNS_RESOLVERS", ",".join(_DEFAULT_NAMESERVERS)).split(",")
    if s.strip()
]


def _resolver(timeout: float = DEFAULT_TIMEOUT) -> "dns.resolver.Resolver":
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = list(FIXED_NAMESERVERS)
    r.timeout = timeout
    r.lifetime = timeout
    return r


def _filter_public(ips: list[str], public_only: bool) -> list[str]:
    """Optional SSRF-Filter (VEC-196): geblockte/interne IPs entfernen.

    Default ``public_only=False`` haelt das DNS-Reporting unveraendert (interne
    A/AAAA-Records bleiben sichtbar). Egress-Pfade, die anschliessend verbinden,
    setzen ``public_only=True`` -> Defense-in-Depth zusaetzlich zum
    Resolve-and-Pin im :mod:`scanner.common.ssrf_guard`.
    """
    if not public_only:
        return ips
    from scanner.common.ssrf_guard import filter_public

    return filter_public(ips)


def resolve_a(fqdn: str, timeout: float = DEFAULT_TIMEOUT,
              public_only: bool = False) -> list[str]:
    """Return A records (IPv4) for fqdn. Empty list if none/timeout."""
    if _HAS_DNSPYTHON:
        try:
            answers = _resolver(timeout).resolve(fqdn, "A")
            return _filter_public([r.to_text() for r in answers], public_only)
        except Exception:
            return []
    try:
        info = socket.getaddrinfo(fqdn, None, socket.AF_INET)
        return _filter_public(sorted({i[4][0] for i in info}), public_only)
    except Exception:
        return []


def resolve_aaaa(fqdn: str, timeout: float = DEFAULT_TIMEOUT,
                 public_only: bool = False) -> list[str]:
    """Return AAAA records (IPv6) for fqdn. Empty list if none/timeout."""
    if not _HAS_DNSPYTHON:
        return []
    try:
        answers = _resolver(timeout).resolve(fqdn, "AAAA")
        return _filter_public([r.to_text() for r in answers], public_only)
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
    """Resolve A/AAAA/CNAME/MX/NS in one call. Returns dict of lists.

    Parallel via ThreadPoolExecutor(max_workers=5) — Worst-Case bei DNS-Stillstand
    auf einer Record-Sorte: 5×5s sequenziell → 5s parallel. Jeder Sub-Call
    instanziiert einen eigenen `dns.resolver.Resolver` (siehe `_resolver()`),
    daher kein Thread-Safety-Problem. Output-Dict-Schluessel-Reihenfolge bleibt
    deterministisch (a/aaaa/cname/mx/ns).
    """
    tasks = (
        ("a", resolve_a),
        ("aaaa", resolve_aaaa),
        ("cname", resolve_cname),
        ("mx", resolve_mx),
        ("ns", resolve_ns),
    )
    with ThreadPoolExecutor(max_workers=5, thread_name_prefix="dns_resolve_all") as pool:
        futures = {key: pool.submit(fn, fqdn, timeout) for key, fn in tasks}
        return {key: futures[key].result() for key, _ in tasks}
