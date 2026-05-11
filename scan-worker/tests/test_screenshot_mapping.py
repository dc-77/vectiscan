"""Tests fuer map_screenshots_to_hosts (Bug-Fix Mai 2026 / PR-D).

Vorher: 1 Screenshot pro IP (break im fqdns-Loop, falsche Sanitisierung mit
``replace(".", "_")``). Bei Multi-VHost-IPs gingen alle weiteren Screenshots
verloren. Jetzt: Per-VHost-Mapping + Top-Level-Backwards-Compat-Key auf
primary_vhost.
"""

from __future__ import annotations


def test_multi_vhost_each_gets_own_key() -> None:
    """3 VHosts auf einer IP -> 3 separate screenshot_minio_key Eintraege."""
    from scanner.upload import map_screenshots_to_hosts

    hosts = [{
        "ip": "18.65.0.55",
        "vhosts": [
            {"fqdn": "heuel.com", "is_primary": True},
            {"fqdn": "mail.heuel.com", "is_primary": False},
            {"fqdn": "panel.heuel.com", "is_primary": False},
        ],
    }]
    screenshot_keys = {
        "heuel.com":       "order-abc/18.65.0.55__heuel.com.png",
        "mail.heuel.com":  "order-abc/18.65.0.55__mail.heuel.com.png",
        "panel.heuel.com": "order-abc/18.65.0.55__panel.heuel.com.png",
    }

    map_screenshots_to_hosts(hosts, screenshot_keys, "order-abc")

    vhosts = hosts[0]["vhosts"]
    assert vhosts[0]["screenshot_minio_key"] == "order-abc/18.65.0.55__heuel.com.png"
    assert vhosts[1]["screenshot_minio_key"] == "order-abc/18.65.0.55__mail.heuel.com.png"
    assert vhosts[2]["screenshot_minio_key"] == "order-abc/18.65.0.55__panel.heuel.com.png"


def test_primary_vhost_mirrored_to_top_level() -> None:
    """Primary-VHost-Screenshot wird zusaetzlich auf host.screenshot_minio_key gespiegelt."""
    from scanner.upload import map_screenshots_to_hosts

    hosts = [{
        "ip": "1.2.3.4",
        "vhosts": [
            {"fqdn": "alt.example.com", "is_primary": False},
            {"fqdn": "www.example.com", "is_primary": True},
        ],
    }]
    screenshot_keys = {
        "alt.example.com": "ord/1.2.3.4__alt.example.com.png",
        "www.example.com": "ord/1.2.3.4__www.example.com.png",
    }

    map_screenshots_to_hosts(hosts, screenshot_keys, "ord")

    # Primary -> Top-Level
    assert hosts[0]["screenshot_minio_key"] == "ord/1.2.3.4__www.example.com.png"
    # Beide VHosts haben ihren eigenen Key
    keys = [v["screenshot_minio_key"] for v in hosts[0]["vhosts"]]
    assert "ord/1.2.3.4__alt.example.com.png" in keys
    assert "ord/1.2.3.4__www.example.com.png" in keys


def test_missing_screenshots_no_crash() -> None:
    """Wenn keine Screenshots fuer einen Host vorhanden sind, kein Crash + kein Key."""
    from scanner.upload import map_screenshots_to_hosts

    hosts = [{
        "ip": "9.9.9.9",
        "vhosts": [
            {"fqdn": "noimg.example.com", "is_primary": True},
        ],
    }]
    screenshot_keys = {
        "other.example.com": "ord/8.8.8.8__other.example.com.png",
    }

    map_screenshots_to_hosts(hosts, screenshot_keys, "ord")

    assert "screenshot_minio_key" not in hosts[0]
    assert "screenshot_minio_key" not in hosts[0]["vhosts"][0]


def test_no_primary_fallback_to_first_vhost() -> None:
    """Wenn kein VHost is_primary=True, faellt host.screenshot_minio_key auf ersten vorhandenen."""
    from scanner.upload import map_screenshots_to_hosts

    hosts = [{
        "ip": "5.5.5.5",
        "vhosts": [
            {"fqdn": "first.example.com", "is_primary": False},
            {"fqdn": "second.example.com", "is_primary": False},
        ],
    }]
    screenshot_keys = {
        "first.example.com":  "ord/5.5.5.5__first.example.com.png",
        "second.example.com": "ord/5.5.5.5__second.example.com.png",
    }

    map_screenshots_to_hosts(hosts, screenshot_keys, "ord")

    # Fallback auf ersten vorhandenen.
    assert hosts[0]["screenshot_minio_key"] == "ord/5.5.5.5__first.example.com.png"


def test_dots_in_fqdn_preserved() -> None:
    """Sanitisierung behaelt Punkte (kein replace('.', '_'))."""
    from scanner.upload import map_screenshots_to_hosts

    hosts = [{
        "ip": "10.0.0.1",
        "vhosts": [{"fqdn": "sub.domain.example.co.uk", "is_primary": True}],
    }]
    screenshot_keys = {
        "sub.domain.example.co.uk": "o/10.0.0.1__sub.domain.example.co.uk.png",
    }

    map_screenshots_to_hosts(hosts, screenshot_keys, "o")

    assert hosts[0]["vhosts"][0]["screenshot_minio_key"] \
        == "o/10.0.0.1__sub.domain.example.co.uk.png"


def test_ip_fallback_when_direct_key_missing() -> None:
    """Wenn screenshot_keys-Dict den FQDN-Key nicht hat (Edge-Case),
    aber der Wert per IP+Suffix matched, wird er trotzdem gefunden."""
    from scanner.upload import map_screenshots_to_hosts

    hosts = [{
        "ip": "8.8.8.8",
        "vhosts": [{"fqdn": "dns.google", "is_primary": True}],
    }]
    # Simuliere kaputten Key-Index, aber korrekten Pfad in den Values.
    screenshot_keys = {
        "wrong-key": "ord/8.8.8.8__dns.google.png",
    }

    map_screenshots_to_hosts(hosts, screenshot_keys, "ord")

    assert hosts[0]["vhosts"][0]["screenshot_minio_key"] == "ord/8.8.8.8__dns.google.png"


def test_empty_inputs_safe() -> None:
    """Leere Inputs crashen nicht."""
    from scanner.upload import map_screenshots_to_hosts

    map_screenshots_to_hosts([], {}, "ord")
    map_screenshots_to_hosts([{"ip": "1.1.1.1", "vhosts": []}], {}, "ord")
    map_screenshots_to_hosts([{"ip": "1.1.1.1"}], {"x.example.com": "ord/1.1.1.1__x.example.com.png"}, "ord")
