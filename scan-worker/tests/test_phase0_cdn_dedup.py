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


def test_fastly_rdns_collapsed_even_without_static_range():
    """F-P0B-005: Fastly-Edges deren IP nicht in `_STATIC_RANGES` ist
    werden ueber rdns-Suffix-Match dedupliziert."""
    hosts = [
        {"ip": "151.101.1.10", "fqdns": ["x.com"],
         "rdns": "151.101.1.10.fastly.net"},
        {"ip": "151.101.65.10", "fqdns": ["x.com"],
         "rdns": "151.101.65.10.fastly.net"},
    ]
    out = _collapse_cdn_edge_ips(hosts)
    assert len(out) == 1
    assert out[0]["cdn_provider"] == "fastly"
    assert sorted(out[0]["edge_ips"]) == ["151.101.1.10", "151.101.65.10"]


def test_akamai_rdns_collapsed():
    """F-P0B-005: Akamai-Edges (deedge.akamaiedge.net) ueber rdns-Suffix
    erkannt und dedupliziert."""
    hosts = [
        {"ip": "23.40.5.6", "fqdns": ["y.com"],
         "rdns": "a23-40-5-6.deploy.static.akamaitechnologies.com"},
        {"ip": "23.40.5.7", "fqdns": ["y.com"],
         "rdns": "a23-40-5-7.deploy.static.akamaitechnologies.com"},
    ]
    out = _collapse_cdn_edge_ips(hosts)
    assert len(out) == 1
    assert out[0]["cdn_provider"] == "akamai"


def test_customer_rdns_with_provider_substring_not_merged():
    """F-P0B-005: Customer-rdns wie `cdn-cloudflare-failover.kunde.de`
    enthaelt zwar 'cloudflare' als Substring, ist aber kein Suffix-Match
    auf `.cloudflare.com`/`.cloudflare.net` → kein False-Positive-Merge."""
    hosts = [
        {"ip": "1.2.3.4", "fqdns": ["a.com"],
         "rdns": "cdn-cloudflare-failover.kunde.de"},
        {"ip": "5.6.7.8", "fqdns": ["a.com"],
         "rdns": "cdn-cloudflare-backup.kunde.de"},
    ]
    out = _collapse_cdn_edge_ips(hosts)
    # rdns matched kein Provider-Suffix → standalone, nicht zusammengelegt.
    assert len(out) == 2
