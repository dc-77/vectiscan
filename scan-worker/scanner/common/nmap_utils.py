"""nmap XML parsing + Top-Ports helpers."""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from typing import Iterable


def run_top_ports(
    ips: Iterable[str],
    top_ports: int = 10,
    min_rate: int = 200,
    timeout: int = 180,
) -> dict[str, list[int]]:
    """Run nmap -Pn --top-ports N over a list of IPs. Return {ip: [open ports]}."""
    ip_list = [ip for ip in ips if ip]
    if not ip_list:
        return {}
    cmd = [
        "nmap", "-T4", "-Pn", "--top-ports", str(top_ports),
        "--min-rate", str(min_rate), "-oX", "-", *ip_list,
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return {ip: [] for ip in ip_list}
    return parse_open_ports(result.stdout)


def parse_open_ports(nmap_xml: str) -> dict[str, list[int]]:
    """Parse nmap XML output. Returns {ip: [open ports sorted]}."""
    out: dict[str, list[int]] = {}
    if not nmap_xml:
        return out
    try:
        root = ET.fromstring(nmap_xml)
    except ET.ParseError:
        return out

    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")
        if not ip:
            continue
        ports: list[int] = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid")
            if portid and portid.isdigit():
                ports.append(int(portid))
        out[ip] = sorted(ports)
    return out
