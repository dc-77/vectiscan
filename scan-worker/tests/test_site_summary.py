"""Tests fuer site_summary.classify + build_summaries_for_host (PR-E, Mai 2026)."""

from __future__ import annotations

from scanner.site_summary import (
    SiteSummary,
    build_summaries_for_host,
    classify,
)


# ---------------------------------------------------------------------------
# Klassifikation
# ---------------------------------------------------------------------------

def test_classify_web_content_with_cms_and_server() -> None:
    """WordPress + Apache + Title → web_content, is_real=true."""
    v = {"fqdn": "heuel.com", "status": 200, "title": "Heuel - Home"}
    tp = {"cms": "WordPress", "cms_version": "6.4", "server": "Apache/2.4.62", "open_ports": [80, 443]}
    s = classify(v, tp)
    assert s.classification == "web_content"
    assert s.is_real_content is True
    assert "WordPress 6.4" in s.description
    assert "Heuel - Home" in s.description


def test_classify_control_panel_plesk() -> None:
    """Title enthaelt 'Plesk' → control_panel, is_real=true."""
    v = {"fqdn": "panel.heuel.com", "status": 200, "title": "Plesk Onyx 18.0 Login"}
    s = classify(v, {"server": "nginx", "open_ports": [443]})
    assert s.classification == "control_panel"
    assert s.is_real_content is True
    assert "Plesk" in s.description


def test_classify_generic_apache_default_page() -> None:
    """Apache2 Default Page → error, is_real=false."""
    v = {"fqdn": "default.example.com", "status": 200,
         "title": "Apache2 Ubuntu Default Page: It works"}
    s = classify(v, {"server": "Apache/2.4.41", "open_ports": [80]})
    assert s.classification == "error"
    assert s.is_real_content is False
    assert "Default-Page" in s.description


def test_classify_error_404() -> None:
    """HTTP 404 → error, is_real=false."""
    v = {"fqdn": "missing.example.com", "status": 404, "title": ""}
    s = classify(v, {})
    assert s.classification == "error"
    assert s.is_real_content is False
    assert "404" in s.description


def test_classify_parking_via_skipped_entry() -> None:
    """vhost_skipped reason=parking → parking, is_real=false."""
    v = {"fqdn": "parked.example.com", "status": 200, "title": "Sponsored Listings"}
    sk = {"fqdn": "parked.example.com", "status": 200, "reason": "parking",
          "title": "Sponsored Listings"}
    s = classify(v, {}, skipped_entry=sk)
    assert s.classification == "parking"
    assert s.is_real_content is False


def test_classify_external_redirect() -> None:
    """vhost_skipped reason=redirect-extern → error, is_real=false."""
    v = {"fqdn": "redir.example.com", "status": 301}
    sk = {"fqdn": "redir.example.com", "status": 301,
          "reason": "redirect-extern → external.com",
          "final_url": "https://external.com/"}
    s = classify(v, {}, skipped_entry=sk)
    assert s.classification == "error"
    assert s.is_real_content is False


def test_classify_non_web_mail_only() -> None:
    """Open Ports nur Mail (25,587) ohne 80/443/Status → non_web."""
    v = {"fqdn": "mail.heuel.com"}
    tp = {"open_ports": [25, 587, 993]}
    s = classify(v, tp)
    assert s.classification == "non_web"
    assert s.is_real_content is False
    assert "Mail-Server" in s.description


def test_classify_non_web_ssh_only() -> None:
    """Nur SSH-Port (22) → non_web mit SSH-Label."""
    v = {"fqdn": "ssh.example.com"}
    tp = {"open_ports": [22]}
    s = classify(v, tp)
    assert s.classification == "non_web"
    assert "SSH" in s.description


def test_classify_login_only() -> None:
    """Title enthaelt 'Login' + Status 200 → login_only."""
    v = {"fqdn": "shop.example.com", "status": 200, "title": "Kundenlogin"}
    tp = {"cms": "Shopware", "cms_version": "6", "server": "nginx", "open_ports": [443]}
    s = classify(v, tp)
    assert s.classification == "login_only"
    assert s.is_real_content is True


def test_classify_minimal_no_tech_falls_back_to_web_content() -> None:
    """Kein cms/server/title → generischer web_content-Fallback."""
    v = {"fqdn": "bare.example.com", "status": 200}
    s = classify(v, {})
    assert s.classification == "web_content"
    assert s.description == "Webseite"  # exakter Fallback


def test_classify_403_cloudflare_not_error() -> None:
    """Cloudflare-403 ist ein Error (>=400). Kein silent-skip."""
    v = {"fqdn": "cf.example.com", "status": 403, "title": "Just a moment..."}
    s = classify(v, {"server": "cloudflare", "open_ports": [443]})
    assert s.classification == "error"
    assert s.is_real_content is False


def test_classify_truncates_long_description() -> None:
    """description ist auf 120 Zeichen begrenzt + Ellipsis."""
    very_long_title = "A" * 200
    v = {"fqdn": "long.example.com", "status": 200, "title": very_long_title}
    s = classify(v, {"cms": "WordPress", "cms_version": "6.4"})
    assert len(s.description) <= 120
    assert s.description.endswith("…")


# ---------------------------------------------------------------------------
# build_summaries_for_host
# ---------------------------------------------------------------------------

def test_build_summaries_for_host_multi_vhost() -> None:
    """Host mit 2 primary VHosts + 1 skipped → 3 Summaries."""
    host = {
        "ip": "1.2.3.4",
        "vhosts": [
            {"fqdn": "heuel.com",     "status": 200, "title": "Heuel - Home", "is_primary": True},
            {"fqdn": "shop.heuel.com", "status": 200, "title": "Kundenlogin", "is_primary": True},
        ],
        "vhost_skipped": [
            {"fqdn": "old.heuel.com", "status": 200, "reason": "parking"},
        ],
    }
    tp = {"cms": "WordPress", "cms_version": "6.4", "server": "Apache", "open_ports": [80, 443]}
    out = build_summaries_for_host(host, tp)
    assert set(out.keys()) == {"heuel.com", "shop.heuel.com", "old.heuel.com"}
    assert out["heuel.com"].classification == "web_content"
    assert out["shop.heuel.com"].classification == "login_only"
    assert out["old.heuel.com"].classification == "parking"


def test_build_summaries_empty_host() -> None:
    """Host ohne vhosts/skipped → leeres Dict, kein Crash."""
    assert build_summaries_for_host({"ip": "1.2.3.4"}, None) == {}


def test_summary_to_dict_round_trips() -> None:
    """SiteSummary.to_dict liefert JSON-kompatible Form mit gerundeter confidence."""
    s = SiteSummary("Heuel - Home", "web_content", True, 0.7)
    d = s.to_dict()
    assert d["description"] == "Heuel - Home"
    assert d["classification"] == "web_content"
    assert d["is_real_content"] is True
    assert d["confidence"] == 0.7
