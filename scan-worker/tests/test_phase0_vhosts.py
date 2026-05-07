"""Tests fuer Multi-VHost-Probe + _canonicalize_vhosts (Phase 0b).

Hintergrund: bis Mai 2026 wurde nur die ERSTE FQDN pro IP geprobt
(`for fqdn in fqdns[:3]: ... break`). Fix: alle FQDNs probed, in
host['vhosts'] kanonisiert (primary + Aliase). Backwards-Compat:
host['web_probe'] wird aus vhosts[0] befuellt.
"""

from scanner.phase0 import _canonicalize_vhosts


def _probe(fqdn, status, *, title="", final_url="", body_hash="", parking=False):
    return {
        "fqdn": fqdn, "status": status, "title": title,
        "final_url": final_url or f"https://{fqdn}/", "body_hash": body_hash,
        "parking": parking,
    }


def test_two_primaries_both_kept():
    """heuel.com-Szenario: edi.heuel.com (403) + ose.heuel.com (200) — beide primary."""
    host = {
        "ip": "20.79.218.75",
        "fqdns": ["edi.heuel.com", "ose.heuel.com"],
        "_raw_probes": [
            _probe("edi.heuel.com", 403, title="403 Forbidden", body_hash="h_edi"),
            _probe("ose.heuel.com", 200, title="Login", body_hash="h_ose"),
        ],
    }
    _canonicalize_vhosts(host, "heuel.com")
    fqdns = [v["fqdn"] for v in host["vhosts"]]
    assert "ose.heuel.com" in fqdns
    assert "edi.heuel.com" in fqdns
    # 200 schlaegt 403 in der Sortierung
    assert host["vhosts"][0]["fqdn"] == "ose.heuel.com"
    # web_probe (Compat) zeigt den primary
    assert host["web_probe"]["web_fqdn"] == "ose.heuel.com"
    assert host["web_probe"]["status"] == 200


def test_internal_redirect_becomes_alias():
    """edi → ose (gleiche eigene FQDN-Liste): edi wird Alias von ose."""
    host = {
        "ip": "1.2.3.4",
        "fqdns": ["edi.x.com", "ose.x.com"],
        "_raw_probes": [
            _probe("edi.x.com", 301, final_url="https://ose.x.com/", body_hash="h1"),
            _probe("ose.x.com", 200, body_hash="h2"),
        ],
    }
    _canonicalize_vhosts(host, "x.com")
    assert len(host["vhosts"]) == 1
    assert host["vhosts"][0]["fqdn"] == "ose.x.com"
    assert any(a["fqdn"] == "edi.x.com" and a["reason"] == "redirect"
               for a in host["vhosts"][0]["aliases"])


def test_body_hash_dedup_keeps_one_primary():
    """Default-VHost-Catch-All: 2 FQDNs gleicher body_hash → 1 primary + 1 alias."""
    host = {
        "ip": "1.1.1.1",
        "fqdns": ["a.x.com", "b.x.com"],
        "_raw_probes": [
            _probe("a.x.com", 200, body_hash="same"),
            _probe("b.x.com", 200, body_hash="same"),
        ],
    }
    _canonicalize_vhosts(host, "x.com")
    assert len(host["vhosts"]) == 1
    aliases = host["vhosts"][0]["aliases"]
    assert any(a["reason"] == "body-hash-dup" for a in aliases)


def test_external_redirect_skipped():
    """FQDN redirected zu anderer Root-Domain → skip-extern."""
    host = {
        "ip": "1.2.3.4",
        "fqdns": ["a.x.com"],
        "_raw_probes": [
            _probe("a.x.com", 200, final_url="https://otherco.de/", body_hash="h"),
        ],
    }
    _canonicalize_vhosts(host, "x.com")
    assert host["vhosts"] == []
    assert any(s["reason"].startswith("redirect-extern")
               for s in host["vhost_skipped"])


def test_no_probes_means_empty_vhosts():
    """Host ohne erfolgreiche Probes → vhosts leer, web_probe.has_web=False."""
    host = {"ip": "9.9.9.9", "fqdns": ["x.com"], "_raw_probes": []}
    _canonicalize_vhosts(host, "x.com")
    assert host["vhosts"] == []
    assert host["web_probe"]["has_web"] is False


def test_parking_only_no_primary():
    """Nur Parking-Page → kein primary, aber web_probe gibt das Parking wieder."""
    host = {
        "ip": "1.2.3.4",
        "fqdns": ["a.x.com"],
        "_raw_probes": [
            _probe("a.x.com", 200, title="Welcome to nginx",
                   parking=True, body_hash="h"),
        ],
    }
    _canonicalize_vhosts(host, "x.com")
    assert host["vhosts"] == []
    assert host["web_probe"]["has_web"] is False
    assert host["web_probe"].get("parking") is True


def test_web_probe_compat_fields_present():
    """Backwards-Compat: web_probe enthaelt alle alten Felder."""
    host = {
        "ip": "1.2.3.4",
        "fqdns": ["a.x.com"],
        "_raw_probes": [_probe("a.x.com", 200, title="T", body_hash="h")],
    }
    _canonicalize_vhosts(host, "x.com")
    wp = host["web_probe"]
    for k in ("has_web", "status", "final_url", "title", "web_fqdn"):
        assert k in wp, f"web_probe fehlt Feld {k}"


# ---------------------------------------------------------------------------
# F-P0B-007: batch-httpx NDJSON-Parser
# ---------------------------------------------------------------------------
from scanner.phase0 import _parse_httpx_probe_line


def test_parse_httpx_probe_line_basic():
    """Parsed eine httpx-Zeile mit Status/Title/URL korrekt."""
    line = {
        "input": "https://www.example.com",
        "url": "https://www.example.com",
        "status_code": 200,
        "title": "Example",
        "final_url": "https://www.example.com/",
        "hash": {"body_sha256": "abc123"},
    }
    probe = _parse_httpx_probe_line(line)
    assert probe is not None
    assert probe["fqdn"] == "www.example.com"
    assert probe["status"] == 200
    assert probe["title"] == "Example"
    assert probe["body_hash"] == "abc123"
    assert probe["parking"] is False


def test_parse_httpx_probe_line_5xx_dropped():
    """Status >=500 wird verworfen (analog _probe_single_fqdn)."""
    assert _parse_httpx_probe_line({
        "input": "https://x.com", "status_code": 503,
    }) is None


def test_parse_httpx_probe_line_parking_detected():
    """Title-Pattern → parking=True."""
    probe = _parse_httpx_probe_line({
        "input": "https://x.com", "status_code": 200,
        "title": "Welcome to nginx!", "hash": "h",
    })
    assert probe is not None
    assert probe["parking"] is True


def test_parse_httpx_probe_line_no_status_dropped():
    assert _parse_httpx_probe_line({"input": "https://x.com"}) is None
