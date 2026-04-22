"""DNS-Resolver fuer Precheck (thin wrapper auf common.dns_utils)."""

from __future__ import annotations

from scanner.common import dns_utils


def resolve(fqdn: str) -> dict:
    """Gib A/AAAA/CNAME/MX/NS zurueck."""
    return dns_utils.resolve_all(fqdn)


def reverse(ip: str) -> str | None:
    return dns_utils.reverse_dns(ip)
