"""S6c/T2, E17 (spec/11): RDAP liefert den Netzbetreiber je IP als Registry-Fakt."""

import json
from io import BytesIO
from unittest.mock import patch

from scanner.passive.rdap_client import (RDAPClient, _owner_from_entities,
                                         _vcard_field)

# Gekuerzte RIPE-RDAP-Antwort fuer eine Hetzner-Adresse (Struktur real).
_RIPE_HETZNER = {
    "handle": "HETZNER-nl",
    "name": "HETZNER-nl",
    "country": "DE",
    "startAddress": "116.202.0.0",
    "endAddress": "116.203.255.255",
    "cidr0_cidrs": [{"v4prefix": "116.202.0.0", "length": 15}],
    "port43": "whois.ripe.net",
    "entities": [
        {
            "handle": "HOAC1-RIPE",
            "roles": ["registrant"],
            "vcardArray": ["vcard", [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "Hetzner Online GmbH"],
                ["org", {}, "text", "Hetzner Online GmbH"],
            ]],
        },
    ],
}


def test_vcard_field_liest_org() -> None:
    ent = _RIPE_HETZNER["entities"][0]
    assert _vcard_field(ent["vcardArray"], "org") == "Hetzner Online GmbH"


def test_owner_from_entities_bevorzugt_registrant() -> None:
    assert _owner_from_entities(_RIPE_HETZNER["entities"]) == "Hetzner Online GmbH"


def test_lookup_ip_liefert_netblock_owner_mit_rir() -> None:
    payload = json.dumps(_RIPE_HETZNER).encode()

    class _Resp(BytesIO):
        def geturl(self):
            return "https://rdap.db.ripe.net/ip/116.202.77.64"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("urllib.request.urlopen", return_value=_Resp(payload)):
        r = RDAPClient().lookup_ip("116.202.77.64")
    assert r is not None
    assert r["netblock_owner"] == "Hetzner Online GmbH"
    assert r["rir"] == "RIPE"
    assert r["source"] == "RIR"


def test_lookup_ip_none_bei_fehler() -> None:
    with patch("urllib.request.urlopen", side_effect=OSError("timeout")):
        assert RDAPClient().lookup_ip("1.2.3.4") is None
