"""S6d (C2, Issue #19): synthetische NAT64-Adressen sind kein IPv6-Ziel.

Handgebautes Fixture nach dem S2b-Beleg (spec/07, dortmund-beach.com): der lokale
Resolver des Pruefstands synthetisierte fuer die Namen AAAA-Adressen aus
64:ff9b::/96, autoritativ hat keine der Domains einen AAAA-Eintrag. Rohdaten des
S2b-Auftrags liegen nicht im Repo; die Adressen hier sind aus der IPv4 des
Webservers 88.99.35.112 gebildet (64:ff9b::5863:2370), so wie DNS64 sie bildet.

Vorher kam eine solche Adresse als IPv6-Host ins Inventar (bei eigenem FQDN-Satz)
oder zaehlte als aufgeloester Name. Jetzt steht sie mit Grund in
``synthetic_ipv6`` und nicht in der Hostliste.
"""

import json
import socket
from unittest.mock import patch

from scanner.common.cidr_utils import nat64_embedded_ipv4
from scanner.phase0 import _found_not_in_inventory, merge_and_group

DB_V4 = "88.99.35.112"
DB_NAT64 = "64:ff9b::5863:2370"


def test_eingebettete_ipv4():
    assert nat64_embedded_ipv4(DB_NAT64) == DB_V4
    assert nat64_embedded_ipv4("64:ff9b::1.2.3.4") == "1.2.3.4"
    # Echte IPv6 und IPv4 sind keine NAT64-Adressen.
    assert nat64_embedded_ipv4("2a01:4f8:d0a:668b::2") is None
    assert nat64_embedded_ipv4(DB_V4) is None
    assert nat64_embedded_ipv4("kein-ip") is None
    # 64:ff9b:1::/48 (lokales NAT64 nach RFC 8215) ist nicht das Wohlbekannte Praefix.
    assert nat64_embedded_ipv4("64:ff9b:1::5863:2370") is None


def _merge(tmp_path, dnsx_results, getaddrinfo=None):
    (tmp_path / "phase0").mkdir(parents=True, exist_ok=True)

    def _gai(host, *a, **k):
        if getaddrinfo and host in getaddrinfo:
            return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, 1, 6, "", (ip, 0))
                    for ip in getaddrinfo[host]]
        raise socket.gaierror("nx")

    with patch("scanner.phase0.socket.getaddrinfo", side_effect=_gai), \
            patch("scanner.phase0.socket.gethostbyaddr", side_effect=socket.herror("x")):
        inv = merge_and_group("dortmund-beach.com", ["www.dortmund-beach.com"],
                              dnsx_results, {}, {}, str(tmp_path))
    return inv


def test_nat64_adresse_kommt_nicht_ins_inventar(tmp_path):
    dnsx = [
        {"host": "dortmund-beach.com", "a": [DB_V4], "aaaa": [DB_NAT64]},
        {"host": "www.dortmund-beach.com", "a": [DB_V4], "aaaa": [DB_NAT64]},
        # Eigener FQDN-Satz nur mit synthetischer Adresse: vorher ein IPv6-Host.
        {"host": "mail.dortmund-beach.com", "a": [], "aaaa": ["64:ff9b::5863:2371"]},
    ]
    inv = _merge(tmp_path, dnsx)

    ips = [h["ip"] for h in inv["hosts"]]
    assert ips == [DB_V4]
    assert not any(":" in ip for ip in ips)
    synth = inv["synthetic_ipv6"]
    assert synth == [
        {"ip": DB_NAT64, "embedded_ipv4": DB_V4,
         "fqdns": ["dortmund-beach.com", "www.dortmund-beach.com"],
         "reason": "nat64_synthesized"},
        {"ip": "64:ff9b::5863:2371", "embedded_ipv4": "88.99.35.113",
         "fqdns": ["mail.dortmund-beach.com"], "reason": "nat64_synthesized"},
    ]
    # Auch in der Datei.
    saved = json.loads((tmp_path / "phase0" / "host_inventory.json").read_text())
    assert saved["synthetic_ipv6"][0]["reason"] == "nat64_synthesized"


def test_socket_rueckfall_filtert_ebenfalls(tmp_path):
    """Der Systemresolver (getaddrinfo) ist die eigentliche DNS64-Quelle."""
    inv = _merge(tmp_path, [], getaddrinfo={
        "dortmund-beach.com": [DB_V4, DB_NAT64],
        "www.dortmund-beach.com": [DB_V4, DB_NAT64],
    })
    assert [h["ip"] for h in inv["hosts"]] == [DB_V4]
    assert [e["ip"] for e in inv["synthetic_ipv6"]] == [DB_NAT64]


def test_ohne_nat64_bleibt_das_inventar_unveraendert(tmp_path):
    inv = _merge(tmp_path, [
        {"host": "dortmund-beach.com", "a": [DB_V4], "aaaa": []},
        {"host": "www.dortmund-beach.com", "a": [DB_V4]},
    ])
    assert "synthetic_ipv6" not in inv
    assert [h["ip"] for h in inv["hosts"]] == [DB_V4]


def test_echtes_ipv6_bleibt_ein_host(tmp_path):
    """Gegenprobe: ein echter AAAA-Host mit eigenem FQDN-Satz bleibt im Inventar."""
    inv = _merge(tmp_path, [
        {"host": "dortmund-beach.com", "a": [DB_V4]},
        {"host": "v6.dortmund-beach.com", "aaaa": ["2a01:4f8:d0a:668b::2"]},
    ])
    assert "2a01:4f8:d0a:668b::2" in [h["ip"] for h in inv["hosts"]]
    assert "synthetic_ipv6" not in inv


def test_name_nur_mit_nat64_zaehlt_nicht_als_gefunden():
    dnsx = [
        {"host": "mail.dortmund-beach.com", "a": [], "aaaa": ["64:ff9b::5863:2371"]},
        {"host": "ftp.dortmund-beach.com", "a": ["88.99.35.114"], "aaaa": [DB_NAT64]},
    ]
    found = _found_not_in_inventory(
        dnsx, {"mail.dortmund-beach.com", "ftp.dortmund-beach.com"}, {"hosts": []})
    assert found == ["ftp.dortmund-beach.com"]
