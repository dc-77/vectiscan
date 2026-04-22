"""HTTP-Probe fuer Precheck (thin wrapper auf common.http_utils)."""

from __future__ import annotations

from scanner.common import http_utils


def probe(fqdn_or_ip: str) -> dict:
    return http_utils.probe_both_schemes(fqdn_or_ip)
