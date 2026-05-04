"""Helper for iterating primary VHosts of a host with consistent caps.

Multi-VHost-Probe (Mai 2026): host['vhosts'] enthaelt 0..N primary
VHosts mit eigenen Web-Anwendungen. Tools die VHost-abhaengig sind
(httpx, nikto, header_check, ZAP, wpscan, ...) sollen ueber alle
primaries iterieren — aber gecappt um Performance zu kontrollieren.

Backwards-Compat: Wenn host['vhosts'] fehlt (Legacy), liefere die
ersten N FQDNs aus host['fqdns'] zurueck (alte Logik).
"""

from __future__ import annotations

import os
from typing import Any

MAX_VHOSTS_PER_HOST = int(os.environ.get("MAX_VHOSTS_PER_HOST", "5"))


def iter_primary_vhosts(host: dict[str, Any], cap: int | None = None) -> list[str]:
    """Liefert Liste primary-VHost-FQDNs des Hosts (gecappt).

    Args:
        host: Host-Dict aus host_inventory mit 'vhosts' (oder 'fqdns' Legacy)
        cap: Override fuer MAX_VHOSTS_PER_HOST

    Returns:
        Liste FQDN-Strings, sortiert wie host['vhosts'] (200er zuerst).
        Bei fehlendem vhosts-Feld: fqdns[:cap] (Legacy-Path).
        Garantiert mindestens 1 Element wenn fqdns nicht leer.
    """
    n = cap if cap is not None else MAX_VHOSTS_PER_HOST
    vhosts = host.get("vhosts") or []
    if vhosts:
        return [v["fqdn"] for v in vhosts[:n] if v.get("fqdn")]
    # Legacy-Pfad: kein Multi-VHost-Probe gelaufen
    fqdns = host.get("fqdns") or []
    return list(fqdns[:n])


def primary_vhost(host: dict[str, Any]) -> str | None:
    """Liefert die "wichtigste" FQDN (vhosts[0] oder fqdns[0]).

    Wird von Tools genutzt die nur 1 VHost brauchen (z.B. testssl,
    Logging, Context-Names).
    """
    vh = iter_primary_vhosts(host, cap=1)
    return vh[0] if vh else None
