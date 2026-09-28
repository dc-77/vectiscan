"""RDAP-Client — Netzbetreiber je IP aus der autoritativen RIR-Registry.

S6c/T2, E17 (spec/11): die Netzbetreiber-Spalte im Bericht soll eine echte
Registry-Quelle (RIR) bekommen, nicht nur AbuseIPDB `isp`. RDAP ist das
Nachfolgeprotokoll von WHOIS und liefert je IP den Netzblock und den Betreiber
strukturiert als JSON. rdap.org leitet auf den zustaendigen RIR (RIPE, ARIN,
APNIC, LACNIC, AfriNIC) weiter. Kein API-Schluessel, kein neues Binary — reiner
HTTP-Abruf ueber urllib.

Der Fakt heisst ``netblock_owner`` mit Quelle RIR; der report-worker liest ihn
erst in der Berichtsseiten-Session (S6c ist nur Export).
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Optional

import structlog

log = structlog.get_logger()

_RIR_BY_PORT43 = {
    "whois.ripe.net": "RIPE",
    "whois.arin.net": "ARIN",
    "whois.apnic.net": "APNIC",
    "whois.lacnic.net": "LACNIC",
    "whois.afrinic.net": "AfriNIC",
}


def _vcard_field(vcard: Any, field: str) -> Optional[str]:
    """Liest ein Feld (fn, org) aus einem jCard (vcardArray) einer RDAP-Entity."""
    try:
        entries = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []
        for e in entries:
            if isinstance(e, list) and e and e[0] == field:
                val = e[3] if len(e) > 3 else None
                if isinstance(val, list):
                    val = " ".join(str(v) for v in val)
                return str(val) if val else None
    except Exception:
        return None
    return None


def _owner_from_entities(entities: Any) -> Optional[str]:
    """Betreibername aus den RDAP-Entities (Registrant bevorzugt)."""
    if not isinstance(entities, list):
        return None
    ranked: list[tuple[int, str]] = []
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        roles = ent.get("roles") or []
        name = _vcard_field(ent.get("vcardArray"), "org") or _vcard_field(ent.get("vcardArray"), "fn")
        if not name:
            continue
        rank = 0
        if "registrant" in roles:
            rank = 3
        elif "administrative" in roles:
            rank = 2
        elif "technical" in roles:
            rank = 1
        ranked.append((rank, name))
    if not ranked:
        return None
    ranked.sort(key=lambda t: t[0], reverse=True)
    return ranked[0][1]


class RDAPClient:
    """Fragt rdap.org (mit RIR-Weiterleitung) nach dem Netzbetreiber je IP."""

    name = "rdap"
    BASE_URL = "https://rdap.org/ip/"

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def lookup_ip(self, ip: str) -> Optional[dict[str, Any]]:
        url = f"{self.BASE_URL}{ip}"
        try:
            req = urllib.request.Request(
                url, headers={"Accept": "application/rdap+json",
                              "User-Agent": "vectiscan-rdap"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                final_url = resp.geturl()
            data = json.loads(raw)
        except Exception as e:
            log.warning("rdap_lookup_failed", ip=ip, error=str(e))
            return None
        if not isinstance(data, dict):
            return None

        port43 = str(data.get("port43") or "").lower()
        rir = _RIR_BY_PORT43.get(port43)
        if not rir:
            for host, name in _RIR_BY_PORT43.items():
                if host.split(".")[1] in final_url:
                    rir = name
                    break
        owner = _owner_from_entities(data.get("entities")) or data.get("name")
        result = {
            "ip": ip,
            "netblock_owner": owner,
            "netname": data.get("name"),
            "handle": data.get("handle"),
            "country": data.get("country"),
            "start_address": data.get("startAddress"),
            "end_address": data.get("endAddress"),
            "cidr": data.get("cidr0_cidrs"),
            "rir": rir,
            "source": "RIR" if rir else "RDAP",
            "source_url": final_url,
        }
        log.info("rdap_lookup", ip=ip, owner=owner, rir=rir)
        return result
