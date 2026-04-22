"""Top-10-Ports Light-Scan fuer Precheck."""

from __future__ import annotations

from typing import Iterable

from scanner.common import nmap_utils


def scan(ips: Iterable[str], top_ports: int = 10, timeout: int = 180) -> dict[str, list[int]]:
    return nmap_utils.run_top_ports(ips, top_ports=top_ports, timeout=timeout)
