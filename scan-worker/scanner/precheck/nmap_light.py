"""Light Port-Scan fuer Precheck (57 kuratierte Ports, F-PRE-005)."""

from __future__ import annotations

from typing import Iterable

from scanner.common import nmap_utils


def scan(
    ips: Iterable[str],
    top_ports: int | None = None,
    timeout: int = 180,
) -> dict[str, list[int]]:
    """Pre-Check Port-Scan via nmap_utils.run_top_ports.

    Default: 57-Port-Liste (siehe `nmap_utils.PRECHECK_PORTS`). Wenn
    `top_ports` gesetzt ist, faellt der Aufrufer auf `--top-ports N` zurueck
    (Backwards-Compat).
    """
    return nmap_utils.run_top_ports(ips, top_ports=top_ports, timeout=timeout)
