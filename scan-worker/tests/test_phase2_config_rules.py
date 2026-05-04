"""Tests fuer phase2_config_rules.try_rule_based_config (C1 — Rule-Engine)."""

from scanner.phase2_config_rules import try_rule_based_config


def test_wordpress_no_waf_standard():
    tp = {"cms": "WordPress", "waf": None, "has_ssl": True,
          "fqdns": ["shop.heuel.com"], "open_ports": [80, 443]}
    r = try_rule_based_config(tp, "perimeter")
    assert r is not None
    assert r["zap_scan_policy"] == "standard"
    assert r["_rule_based"] is True
    assert "wordpress" in r["reasoning"].lower()


def test_cloudflare_waf_safe():
    tp = {"cms": None, "waf": "Cloudflare", "has_ssl": True,
          "fqdns": ["x.com"], "open_ports": [443]}
    r = try_rule_based_config(tp, "perimeter")
    assert r is not None
    assert r["zap_scan_policy"] == "waf-safe"
    assert r["zap_threads"] <= 5


def test_mail_only_skips_web_tools():
    tp = {"cms": None, "waf": None, "has_ssl": False,
          "fqdns": ["mx.x.com"], "open_ports": [25, 587, 993]}
    r = try_rule_based_config(tp, "perimeter")
    assert r is not None
    assert "zap_active" in r["skip_tools"]
    assert "zap_spider" in r["skip_tools"]


def test_spa_enables_ajax_spider():
    tp = {"cms": None, "waf": None, "has_ssl": True, "is_spa": True,
          "server": "Next.js", "fqdns": ["spa.x.com"], "open_ports": [443]}
    r = try_rule_based_config(tp, "perimeter")
    assert r is not None
    assert r["zap_ajax_spider_enabled"] is True


def test_edge_case_returns_none():
    """Komplexer Tech-Profile ohne klare Regel → None → KI-Fallback."""
    tp = {"cms": None, "waf": None, "has_ssl": True, "is_spa": False,
          "server": "weird-server", "fqdns": ["weird.com"],
          "open_ports": [80, 443, 8080, 9999]}
    r = try_rule_based_config(tp, "perimeter")
    assert r is None


def test_drupal_standard():
    tp = {"cms": "drupal", "waf": None, "has_ssl": True,
          "fqdns": ["d.com"], "open_ports": [443]}
    r = try_rule_based_config(tp, "perimeter")
    assert r is not None
    assert "wpscan" in r["skip_tools"]


def test_webcheck_quick_path():
    tp = {"cms": None, "waf": None, "has_ssl": True,
          "fqdns": ["x.com"], "open_ports": [443]}
    r = try_rule_based_config(tp, "webcheck")
    assert r is not None
    assert "wpscan" in r["skip_tools"]
    assert "feroxbuster" in r["skip_tools"]
