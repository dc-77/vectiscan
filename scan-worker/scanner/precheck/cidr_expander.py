"""CIDR-Expansion fuer Precheck (thin wrapper)."""

from __future__ import annotations

from scanner.common import cidr_utils


def expand(raw: str, max_hosts: int = 256) -> list[str]:
    return cidr_utils.expand_raw(raw, max_hosts)
