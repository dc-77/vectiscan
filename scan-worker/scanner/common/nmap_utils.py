"""nmap XML parsing + Top-Ports helpers."""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from typing import Iterable


# Pre-Check Port-Liste (F-PRE-005, Option B++):
# 57 kuratierte Ports — Standard + S1 RCE/Pre-Auth + S2 KMU-Mgmt + S3 Industrial.
# Ersetzt `--top-ports 10` (deckte nur 80/23/443/21/22/25/3389/110/445/139).
# Quelle: docs/scan-flow/Scan-Optimierung.md Sektion 3.1.4.
PRECHECK_PORTS: str = (
    "21,22,23,25,53,80,88,102,110,111,143,389,443,445,465,"
    "500,502,587,636,873,993,995,1099,1433,1521,1883,2049,"
    "2375,2525,3000,3306,3389,5432,5601,5900,5984,5985,5986,"
    "6379,6443,7547,8000,8080,8086,8200,8443,8500,8883,8888,"
    "9090,9200,9300,9443,10000,11211,27017,28017"
)


def run_top_ports(
    ips: Iterable[str],
    top_ports: int | None = None,
    min_rate: int = 200,
    timeout: int = 180,
    ports: str | None = None,
) -> dict[str, list[int]]:
    """Run nmap -Pn over a list of IPs. Return {ip: [open ports]}.

    Default: kuratierte 57-Port-Liste via `-p` (PRECHECK_PORTS).
    Wenn `top_ports` gesetzt ist, wird stattdessen `--top-ports N` verwendet
    (Backwards-Compat fuer Aufrufer, die das explizit verlangen).
    `ports` ueberschreibt beide (custom Port-Liste).

    Performance-Flags (F-PRE-004):
    - `--max-retries 2`  — kappt nmap-Default 10 fuer Internet-Targets mit -T4
    - `--host-timeout 30s` — kappt einzeln haengende IPs
    - `-n`               — Pre-Check macht reverse-DNS separat via dnspython
    - `--open`           — XML-Reduktion (nur offene Ports im Output)
    """
    ip_list = [ip for ip in ips if ip]
    if not ip_list:
        return {}

    cmd: list[str] = [
        "nmap", "-T4", "-Pn",
        "--max-retries", "2",
        "--host-timeout", "30s",
        "-n",
        "--open",
    ]
    if ports:
        cmd += ["-p", ports]
    elif top_ports is not None:
        cmd += ["--top-ports", str(top_ports)]
    else:
        cmd += ["-p", PRECHECK_PORTS]

    cmd += ["--min-rate", str(min_rate), "-oX", "-", *ip_list]

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
