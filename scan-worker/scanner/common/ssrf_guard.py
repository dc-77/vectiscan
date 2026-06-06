"""SSRF-Guard fuer den Python-Scan-Worker (VEC-196, Follow-up aus VEC-175).

Spiegelt die Semantik von ``api/src/lib/ssrf-guard.ts`` im Python-Worker:

1. Zentraler, **fail-closed** IP-Block-Helfer fuer geblockte/interne Bereiche:
   loopback, RFC1918, link-local (inkl. 169.254.169.254 Cloud-Metadata),
   CGNAT (100.64/10), Benchmark (198.18/15), "this network", reserviert,
   Multicast, Broadcast sowie IPv6 ULA/link-local/site-local/multicast und die
   eingebetteten IPv4-Faelle IPv4-mapped (``::ffff:0:0/96``) und NAT64
   (``64:ff9b::/96``).

2. **Resolve-and-Pin** fuer ``requests``: Der Hostname wird genau einmal
   aufgeloest, geblockte Adressen werden verworfen und die Verbindung gegen die
   gepinnte oeffentliche IP-Literal-URL aufgebaut. Weil der Connect gegen ein
   IP-Literal geht, findet keine erneute DNS-Aufloesung statt -> es gibt kein
   TOCTOU-/DNS-Rebinding-Fenster zwischen Validierung und Verbindung. Die
   Validierung laeuft pro ``send()`` und damit auch pro Redirect-Hop.

Die explizite IPv4-Blockliste ist 1:1 an ``ssrf-guard.ts`` gespiegelt und
verlaesst sich bewusst NICHT allein auf ``ipaddress.is_private`` (dessen
Definition zwischen Python-Versionen variiert), sondern auf
CIDR-Zugehoerigkeit -> deterministisch und version-unabhaengig.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, Optional
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter


DEFAULT_RESOLVE_TIMEOUT = 5.0
DEFAULT_MAX_REDIRECTS = 5


class SsrfBlockedError(Exception):
    """Zieladresse liegt in einem geblockten (internen) Bereich (fail-closed)."""


# Explizite, an ssrf-guard.ts gespiegelte IPv4-Blockliste.
_BLOCKED_V4 = [
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",          # "this network"
        "10.0.0.0/8",         # RFC1918
        "100.64.0.0/10",      # CGNAT
        "127.0.0.0/8",        # loopback
        "169.254.0.0/16",     # link-local (inkl. 169.254.169.254 Metadata)
        "172.16.0.0/12",      # RFC1918
        "192.0.0.0/24",       # IETF protocol assignments
        "192.0.2.0/24",       # TEST-NET-1
        "192.168.0.0/16",     # RFC1918
        "198.18.0.0/15",      # benchmark
        "198.51.100.0/24",    # TEST-NET-2
        "203.0.113.0/24",     # TEST-NET-3
        "224.0.0.0/4",        # multicast
        "240.0.0.0/4",        # reserviert
        "255.255.255.255/32", # broadcast
    )
]

_NAT64_NET = ipaddress.ip_network("64:ff9b::/96")


def _is_blocked_v4(addr: ipaddress.IPv4Address) -> bool:
    return any(addr in net for net in _BLOCKED_V4)


def _is_blocked_v6(addr: ipaddress.IPv6Address) -> bool:
    # IPv4-mapped (::ffff:0:0/96) -> eingebettete IPv4 pruefen.
    mapped = addr.ipv4_mapped
    if mapped is not None:
        return _is_blocked_v4(mapped)
    # NAT64 64:ff9b::/96 -> letzte 32 Bit als IPv4 pruefen.
    if addr in _NAT64_NET:
        return _is_blocked_v4(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF))
    # loopback (::1), link-local (fe80::/10), multicast (ff00::/8),
    # ULA (fc00::/7) zaehlt als is_private, unspecified (::),
    # site-local (fec0::/10, deprecated), reserviert.
    return bool(
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_private
        or addr.is_unspecified
        or addr.is_site_local
        or addr.is_reserved
    )


def is_blocked_address(ip: str) -> bool:
    """True, wenn ``ip`` in einem geblockten Bereich liegt.

    Unparsebare Eingaben gelten als geblockt (fail-closed).
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except (ValueError, AttributeError):
        return True
    if isinstance(addr, ipaddress.IPv4Address):
        return _is_blocked_v4(addr)
    return _is_blocked_v6(addr)


def filter_public(ips: Iterable[str]) -> list[str]:
    """Behaelt nur oeffentliche (nicht geblockte) Adressen, Reihenfolge stabil."""
    return [ip for ip in ips if not is_blocked_address(ip)]


def _resolve_host(host: str, timeout: float) -> list[str]:
    """A + AAAA ueber die fixen Resolver (dns_utils). Lazy-Import gegen Zyklus."""
    from scanner.common import dns_utils

    return list(dns_utils.resolve_a(host, timeout)) + list(
        dns_utils.resolve_aaaa(host, timeout)
    )


def resolve_and_pin(host: str, timeout: float = DEFAULT_RESOLVE_TIMEOUT) -> str:
    """Loese ``host`` auf, verwirf geblockte IPs, pinne erste oeffentliche IP.

    Ist ``host`` bereits ein IP-Literal, wird nur die Blockliste geprueft.
    Raises ``SsrfBlockedError``, wenn ``host`` geblockt ist, nicht aufloesbar
    ist oder nur interne Adressen uebrig bleiben (moegliches DNS-Rebinding).
    """
    try:
        ipaddress.ip_address(host)
        is_literal = True
    except ValueError:
        is_literal = False

    if is_literal:
        if is_blocked_address(host):
            raise SsrfBlockedError(f"Geblockte Ziel-IP: {host}")
        return host

    resolved = _resolve_host(host, timeout)
    if not resolved:
        raise SsrfBlockedError(f"Keine DNS-Aufloesung fuer {host}")
    public = filter_public(resolved)
    if not public:
        raise SsrfBlockedError(
            f"Alle aufgeloesten Adressen fuer {host} sind geblockt "
            f"(moegliches DNS-Rebinding)."
        )
    return public[0]


def _host_for_url(ip: str) -> str:
    return f"[{ip}]" if ":" in ip else ip


class PinnedHTTPAdapter(HTTPAdapter):
    """``requests``-Adapter mit Resolve-and-Pin.

    Bei jedem ``send()`` (auch pro Redirect-Hop) wird der Ziel-Host aufgeloest,
    gegen die Blockliste validiert und die Verbindung auf die gepinnte
    oeffentliche IP umgeschrieben. Der urspruengliche Hostname wandert in den
    ``Host``-Header, damit vhost-basierte Server korrekt antworten.

    Tech-Debt (low, VEC-196): Bei HTTPS geht die SNI gegen das IP-Literal, nicht
    gegen den Hostnamen. Fuer den Probe-Pfad (``verify=False``) unkritisch; eine
    SNI-erhaltende Variante (ForcedIP-Adapter) ist als Folge-Optimierung notiert.
    """

    def __init__(self, *args, resolve_timeout: float = DEFAULT_RESOLVE_TIMEOUT, **kwargs):
        self._resolve_timeout = resolve_timeout
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):  # type: ignore[override]
        parsed = urlparse(request.url)
        host = parsed.hostname
        if not host:
            raise SsrfBlockedError(f"URL ohne Host: {request.url}")

        pinned = resolve_and_pin(host, self._resolve_timeout)
        if pinned != host:
            host_header = host if not parsed.port else f"{host}:{parsed.port}"
            request.headers["Host"] = host_header
            netloc = _host_for_url(pinned)
            if parsed.port:
                netloc = f"{netloc}:{parsed.port}"
            request.url = urlunparse(parsed._replace(netloc=netloc))
        return super().send(request, **kwargs)


def guarded_session(
    verify: bool = False, resolve_timeout: float = DEFAULT_RESOLVE_TIMEOUT
) -> requests.Session:
    """Eine ``requests.Session`` mit gemountetem :class:`PinnedHTTPAdapter`."""
    session = requests.Session()
    adapter = PinnedHTTPAdapter(resolve_timeout=resolve_timeout)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = verify
    return session


def safe_get(
    url: str,
    *,
    timeout: float = DEFAULT_RESOLVE_TIMEOUT,
    allow_redirects: bool = True,
    headers: Optional[dict] = None,
    verify: bool = False,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
) -> requests.Response:
    """SSRF-gepinntes ``GET``. Wirft :class:`SsrfBlockedError` bei internem Ziel."""
    session = guarded_session(verify=verify, resolve_timeout=timeout)
    session.max_redirects = max_redirects
    return session.get(
        url, timeout=timeout, allow_redirects=allow_redirects, headers=headers or {}
    )
