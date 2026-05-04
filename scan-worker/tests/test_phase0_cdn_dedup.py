"""Tests fuer phase0._collapse_cdn_edge_ips (B2 — CF/CDN-IP-Dedup)."""

from scanner.phase0 import _collapse_cdn_edge_ips


def test_cf_round_robin_collapsed():
    """Heuel-Bug: 104.16.10.6 + 104.16.11.6 mit selber FQDN → 1 Host."""
    hosts = [
        {"ip": "104.16.10.6", "fqdns": ["online.heuel.com"], "rdns": ""},
        {"ip": "104.16.11.6", "fqdns": ["online.heuel.com"], "rdns": ""},
        {"ip": "217.72.203.132", "fqdns": ["heuel.com"], "rdns": ""},
    ]
    out = _collapse_cdn_edge_ips(hosts)
    # 2 Hosts: 1 CF-collapsed + 1 standalone
    assert len(out) == 2
    cf_host = next(h for h in out if h["fqdns"] == ["online.heuel.com"])
    assert "edge_ips" in cf_host
    assert sorted(cf_host["edge_ips"]) == ["104.16.10.6", "104.16.11.6"]
    assert cf_host["cdn_provider"] == "cloudflare"


def test_different_fqdns_not_merged():
    """2 CF-IPs mit verschiedenen FQDNs → bleiben getrennt."""
    hosts = [
        {"ip": "104.16.10.6", "fqdns": ["a.x.com"], "rdns": ""},
        {"ip": "104.16.11.6", "fqdns": ["b.x.com"], "rdns": ""},
    ]
    out = _collapse_cdn_edge_ips(hosts)
    assert len(out) == 2


def test_non_cf_ips_untouched():
    """Hetzner / private IPs → kein Merge."""
    hosts = [
        {"ip": "1.2.3.4", "fqdns": ["a.com"], "rdns": ""},
        {"ip": "5.6.7.8", "fqdns": ["b.com"], "rdns": ""},
    ]
    out = _collapse_cdn_edge_ips(hosts)
    assert len(out) == 2
    assert all("edge_ips" not in h for h in out)


def test_rdns_with_machine_identity_not_merged():
    """rdns z.B. 'webserver01.kunde.de' → eigene Maschine, nicht mergen."""
    hosts = [
        {"ip": "104.16.10.6", "fqdns": ["a.com"],
         "rdns": "webserver01.kunde.de"},
        {"ip": "104.16.11.6", "fqdns": ["a.com"],
         "rdns": "webserver02.kunde.de"},
    ]
    out = _collapse_cdn_edge_ips(hosts)
    # 2 Hosts (verschiedene Maschinen-rdns)
    assert len(out) == 2


def test_empty_hosts():
    assert _collapse_cdn_edge_ips([]) == []
