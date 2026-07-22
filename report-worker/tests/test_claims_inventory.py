"""Tests fuer reporter/claims_inventory.py — deterministisches Evidenz-Inventar (C1)."""

from __future__ import annotations

from reporter.claims_inventory import (
    EvidenceInventory,
    build_evidence_inventory,
)


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------

def test_hosts_from_inventory_and_profiles():
    """ip, fqdns, rdns, primary_vhost, vhost_results-Keys, web_fqdn, domain."""
    sc = {
        "host_inventory": {
            "domain": "example.com",
            "hosts": [
                {"ip": "88.99.35.112", "fqdns": ["example.com", "www.example.com"],
                 "rdns": "static.hetzner.de"},
            ],
        },
        "tech_profiles": [
            {
                "ip": "88.99.35.112",
                "fqdns": ["example.com"],
                "primary_vhost": "shop.example.com",
                "web_fqdn": "app.example.com",
                "vhost_results": {"blog.example.com": {}},
            },
        ],
    }
    inv = build_evidence_inventory(sc)
    for host in (
        "example.com", "www.example.com", "88.99.35.112", "static.hetzner.de",
        "shop.example.com", "app.example.com", "blog.example.com",
    ):
        assert host in inv.hosts, f"{host} fehlt im Host-Inventar"


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

def test_ports_from_open_ports_and_exposed_services():
    """tech_profiles[].open_ports + exposed_services[{port,service}]."""
    sc = {
        "host_inventory": {"domain": "x.de", "hosts": []},
        "tech_profiles": [
            {
                "ip": "1.2.3.4",
                "open_ports": [80, 443, 22],
                "exposed_services": [{"port": "3306", "service": "mysql"}],
            },
        ],
    }
    inv = build_evidence_inventory(sc)
    assert {80, 443, 22, 3306} <= inv.all_ports
    assert inv.ports_by_host["1.2.3.4"] == {80, 443, 22, 3306}


def test_ports_from_host_tool_data_nmap():
    """host_tool_data nmap open_ports (Port->Produkt->Version) fliesst ein."""
    sc = {"host_inventory": {"hosts": []}, "tech_profiles": []}
    htd = {
        "1.2.3.4": {"nmap": {"open_ports": [
            {"port": 8443, "protocol": "tcp", "service": "https",
             "product": "nginx", "version": "1.24.0"},
        ]}},
    }
    inv = build_evidence_inventory(sc, host_tool_data=htd)
    assert 8443 in inv.all_ports


# ---------------------------------------------------------------------------
# Versionen + Status
# ---------------------------------------------------------------------------

def test_versions_from_technologies_and_tech_rows():
    """technologies[{name,version}] + build_tech_table_for_host-Status-Mapping."""
    sc = {
        "host_inventory": {"domain": "x.de", "hosts": []},
        "tech_profiles": [
            {
                "ip": "1.2.3.4",
                "fqdns": ["x.de"],
                "server": "Apache/2.4.49",
                "cms": None, "cms_version": None,
                "technologies": [{"name": "jQuery", "version": "3.6.0"}],
            },
        ],
    }
    inv = build_evidence_inventory(sc)
    # Roh-Version aus technologies
    assert "3.6.0" in inv.versions.get("jquery", set())
    # Server-Produkt gesplittet
    assert "apache" in inv.versions
    # Apache 2.4.49 ist laut Tech-Tabelle NICHT aktuell (mega-cve/outdated/eol)
    apache_statuses = [v for k, v in inv.version_status.items() if "apache" in k]
    assert apache_statuses, "kein Apache-Status klassifiziert"
    assert all(s not in ("aktuell", "current", "latest") for s in apache_statuses)


def test_wpscan_latest_status_marks_wordpress_current():
    """wp_version_status='latest' -> WordPress gilt als aktuell (Defekt 2)."""
    sc = {"host_inventory": {"hosts": []}, "tech_profiles": []}
    htd = {"1.2.3.4": {"wpscan": {"wp_version": "6.7.1", "wp_version_status": "latest"}}}
    inv = build_evidence_inventory(sc, host_tool_data=htd)
    assert inv.is_current("wordpress")
    assert "6.7.1" in inv.versions.get("wordpress", set())


def test_conservative_status_worst_wins():
    """Meldet ein Host outdated, gilt das Produkt NICHT als aktuell."""
    inv = EvidenceInventory()
    inv._record_status("WordPress", "aktuell")
    inv._record_status("WordPress", "outdated")
    assert not inv.is_current("wordpress")
    assert inv.version_status["wordpress"] == "outdated"


# ---------------------------------------------------------------------------
# Robustheit / Fail-open
# ---------------------------------------------------------------------------

def test_defensive_against_garbage():
    """None/[]/str/fehlende Keys -> leeres Inventar, keine Exception."""
    for bad in (None, [], "nonsense", 42, {"tech_profiles": "not-a-list"}):
        inv = build_evidence_inventory(bad)
        assert isinstance(inv, EvidenceInventory)
    # Kaputte Teilstrukturen kippen das Inventar nicht.
    sc = {
        "host_inventory": {"hosts": [None, {"ip": 123}, "x"]},
        "tech_profiles": [None, "x", {"open_ports": ["nope", 80]}],
    }
    inv = build_evidence_inventory(sc)
    assert 80 in inv.all_ports


def test_empty_inventory_is_empty():
    inv = build_evidence_inventory({"host_inventory": {"hosts": []},
                                    "tech_profiles": []})
    assert inv.is_empty()
