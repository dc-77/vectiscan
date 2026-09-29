"""Drosselung und Sperrerkennung fuer Netze, die nach dem Portscan sperren.

S6c/Q17 (spec/09): Hetzner-Server (``your-server.de``) sperren die Pruefadresse
nach dem vollen Portscan; die Phase-2-Werkzeuge liefen dann ins Leere (LW, JW, HL).
DC-Entscheidung: niedrigere nmap-Rate je Host (nicht ``-T2``), danach eine
Sperrerkennung als eigener Schritt; bleibt der Host gesperrt, ist jedes
Phase-2-Werkzeug failed statt leerem ok.

Die Netzliste ist konfigurierbar (Umgebungsvariable ``VECTISCAN_THROTTLE_NETS``,
komma-getrennte CIDRs), damit weitere Anbieter ohne Codeaenderung nachgetragen
werden koennen. Rate und Wiederholungen ebenso (``VECTISCAN_THROTTLE_MAX_RATE``,
``VECTISCAN_THROTTLE_MAX_RETRIES``), seit S6d auch Pause und Reihung der
Per-Port-Sonden (``VECTISCAN_THROTTLE_PROBE_PAUSE_S``,
``VECTISCAN_THROTTLE_PROBE_ORDER``).
"""

from __future__ import annotations

import ipaddress
import os
import socket
import time
from typing import Any, Optional

import structlog

log = structlog.get_logger()

# rDNS-Suffixe und ISP-Namen, die einen drosselnden Anbieter kennzeichnen.
_THROTTLE_RDNS_SUFFIXES = (".your-server.de",)
_THROTTLE_ISP_MARKERS = ("hetzner",)


def _configured_nets() -> list[Any]:
    raw = os.environ.get("VECTISCAN_THROTTLE_NETS", "")
    nets: list[Any] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            log.warning("throttle_net_invalid", value=part)
    return nets


def throttle_max_rate() -> int:
    try:
        return int(os.environ.get("VECTISCAN_THROTTLE_MAX_RATE", "120"))
    except ValueError:
        return 120


def throttle_max_retries() -> int:
    try:
        return int(os.environ.get("VECTISCAN_THROTTLE_MAX_RETRIES", "1"))
    except ValueError:
        return 1


# S6d (C3): Messbefund aus JW f9a2a2f6: auf dem gedrosselten Hetzner-Host brachen die
# gleichzeitigen Per-Port-Sonden (testssl je Port, smtp_ehlo) ab, obwohl die
# Einzel-Sperrprobe den Host erreichte. Auf gedrosselten Hosts laufen die Sonden
# deshalb nacheinander mit Pause; Pause und Reihung sind konfigurierbar.
DEFAULT_PROBE_PAUSE_S = 5.0


def throttle_probe_pause_s() -> float:
    """Pause zwischen zwei Per-Port-Sonden auf einem gedrosselten Host (Sekunden).

    ``VECTISCAN_THROTTLE_PROBE_PAUSE_S``; ungueltig oder negativ: Vorgabe 5.
    """
    raw = os.environ.get("VECTISCAN_THROTTLE_PROBE_PAUSE_S", "")
    if not raw.strip():
        return DEFAULT_PROBE_PAUSE_S
    try:
        value = float(raw)
    except ValueError:
        log.warning("throttle_probe_pause_invalid", value=raw)
        return DEFAULT_PROBE_PAUSE_S
    return value if value >= 0 else DEFAULT_PROBE_PAUSE_S


def throttle_probe_order(ports: list[int]) -> list[int]:
    """Reihung der Per-Port-Sonden auf einem gedrosselten Host.

    ``VECTISCAN_THROTTLE_PROBE_ORDER``: ``asc`` (Vorgabe), ``desc`` oder eine
    komma-getrennte Portliste; die genannten Ports laufen zuerst in dieser
    Reihenfolge, die uebrigen danach aufsteigend. Ein ungueltiger Wert faellt auf
    ``asc`` zurueck.
    """
    uniq = sorted({int(p) for p in ports})
    raw = os.environ.get("VECTISCAN_THROTTLE_PROBE_ORDER", "").strip().lower()
    if raw in ("", "asc"):
        return uniq
    if raw == "desc":
        return list(reversed(uniq))
    wanted: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            log.warning("throttle_probe_order_invalid", value=raw)
            return uniq
        port = int(part)
        if port in uniq and port not in wanted:
            wanted.append(port)
    return wanted + [p for p in uniq if p not in wanted]


def pause_between_probes(throttled: bool) -> None:
    """Pause vor der naechsten Per-Port-Sonde, nur auf gedrosselten Hosts."""
    if not throttled:
        return
    pause = throttle_probe_pause_s()
    if pause > 0:
        time.sleep(pause)


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def is_throttled_host(ip: str, rdns: str = "", isp: str = "") -> bool:
    """Gehoert die Adresse zu einem drosselnden Anbieter?

    Regel (DC): rDNS endet auf ``your-server.de`` ODER der AbuseIPDB-``isp`` nennt
    Hetzner ODER die Adresse liegt in der konfigurierbaren Netzliste. rDNS wird bei
    Bedarf aufgeloest.
    """
    if not ip or ":" in ip:
        # IPv6 wird ueber das eigene Gate behandelt.
        return False
    rd = (rdns or _reverse_dns(ip)).lower()
    if any(rd.endswith(sfx) for sfx in _THROTTLE_RDNS_SUFFIXES):
        return True
    if isp and any(m in isp.lower() for m in _THROTTLE_ISP_MARKERS):
        return True
    try:
        addr = ipaddress.ip_address(ip)
        for net in _configured_nets():
            if addr in net:
                return True
    except ValueError:
        return False
    return False


def probe_reachable_after_portscan(ip: str, known_ports: Optional[list[int]] = None,
                                   attempts: int = 3, max_seconds: float = 300.0) -> dict[str, Any]:
    """Sperrerkennung nach dem vollen Portscan (S6c/Q17, DC (c)).

    TCP-Connect auf einen bereits als offen bekannten Port (sonst 443, dann 80),
    mehrere Versuche mit wachsendem Abstand bis ``max_seconds``. Ergebnis als
    Rohdatum: gesperrt ja/nein, Zeit bis zur Erreichbarkeit, Zeitstempel.
    """
    ports = [p for p in (known_ports or []) if p] or [443, 80]
    start = time.monotonic()
    delay = 5.0
    reachable = False
    time_to_reachable: Optional[float] = None
    for i in range(max(1, attempts)):
        for port in ports:
            try:
                with socket.create_connection((ip, port), timeout=8):
                    reachable = True
                    time_to_reachable = round(time.monotonic() - start, 1)
                    break
            except OSError:
                continue
        if reachable:
            break
        if time.monotonic() - start + delay > max_seconds:
            break
        time.sleep(delay)
        delay *= 2
    result = {
        "ip": ip,
        "blocked": not reachable,
        "reachable": reachable,
        "time_to_reachable_s": time_to_reachable,
        # S6d (A8): Dauer der Messung, auch im gesperrten Fall (dort ist
        # time_to_reachable_s None); der Bericht nennt sie in der Einschraenkung.
        "waited_s": round(time.monotonic() - start, 1),
        "checked_ports": ports,
        "attempts": attempts,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    log.info("provider_block_probe", ip=ip, blocked=result["blocked"],
             time_to_reachable_s=time_to_reachable)
    return result
