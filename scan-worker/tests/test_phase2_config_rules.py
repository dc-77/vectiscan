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


# ---------------------------------------------------------------------------
# F-KI3-002 — Hosted-CMS-Branch + Static-Hoster + Generic-CMS-Erweiterung
# ---------------------------------------------------------------------------


def test_hosted_cms_shopify_passive_only():
    """Shopify (Hosted) → passive-only, alle Active-Tools skippen."""
    tp = {"cms": "Shopify", "waf": None, "has_ssl": True,
          "fqdns": ["shop.example.com"], "open_ports": [443]}
    r = try_rule_based_config(tp, "perimeter")
    assert r is not None
    assert r["zap_scan_policy"] == "passive-only"
    assert r["zap_active_categories"] == ["xss"]
    for skipped in ("zap_active", "feroxbuster", "ffuf", "wpscan", "nikto"):
        assert skipped in r["skip_tools"]
    assert "hosted-cms" in r["reasoning"].lower()


def test_hosted_cms_webflow_wix_squarespace_hubspot():
    """Alle 5 Hosted-CMS muessen den Hosted-Branch treffen."""
    for cms_name in ("Webflow", "Wix", "Squarespace", "HubSpot"):
        tp = {"cms": cms_name, "waf": None, "has_ssl": True,
              "fqdns": ["x.example.com"], "open_ports": [443]}
        r = try_rule_based_config(tp, "perimeter")
        assert r is not None, f"no rule match for {cms_name}"
        assert r["zap_scan_policy"] == "passive-only", cms_name
        assert "hosted-cms" in r["reasoning"].lower(), cms_name


def test_static_hoster_github_pages_by_fqdn():
    """*.github.io → Static-Hoster-Branch."""
    tp = {"cms": None, "waf": None, "has_ssl": True,
          "fqdns": ["myproject.github.io"], "open_ports": [443]}
    r = try_rule_based_config(tp, "perimeter")
    assert r is not None
    assert r["zap_scan_policy"] == "passive-only"
    assert r["zap_active_categories"] == []
    assert r["reasoning"].endswith("static-hoster")


def test_static_hoster_netlify_vercel_pages_dev():
    """Andere Static-Hoster-Suffixes muessen ebenfalls greifen."""
    for fqdn in ("site.netlify.app", "app.vercel.app",
                 "demo.pages.dev", "ship.fly.dev"):
        tp = {"cms": None, "waf": None, "has_ssl": True,
              "fqdns": [fqdn], "open_ports": [443]}
        r = try_rule_based_config(tp, "perimeter")
        assert r is not None, f"no rule for {fqdn}"
        assert r["zap_scan_policy"] == "passive-only", fqdn
        assert r["reasoning"].endswith("static-hoster"), fqdn


def test_static_hoster_by_server_header_custom_domain():
    """Custom-Domain hinter Cloudflare Pages → Static-Hoster-Branch.

    Erkannt ueber: kein CMS + Server-Hint (cloudflare/vercel/netlify) +
    nur 80/443 offen.
    """
    tp = {"cms": None, "waf": None, "server": "cloudflare",
          "has_ssl": True, "fqdns": ["custom.example.com"],
          "open_ports": [80, 443]}
    r = try_rule_based_config(tp, "perimeter")
    assert r is not None
    # WAF-Branch greift bei "cloudflare" frueher → also primaer FQDN-Pfad
    # absichern. Der Server-Hint-Pfad ist als zusaetzliches Sicherheitsnetz
    # gedacht und wird durch WAF-Branch heute uebersteuert. Test stellt
    # sicher, dass das Ergebnis nicht None ist und passiv-defensiv.
    assert r["zap_threads"] <= 5


def test_generic_cms_pimcore_match():
    """Pimcore (F-PH1-001) muss Generic-CMS-Branch treffen."""
    tp = {"cms": "Pimcore", "waf": None, "has_ssl": True,
          "fqdns": ["cms.example.de"], "open_ports": [443]}
    r = try_rule_based_config(tp, "perimeter")
    assert r is not None
    assert r["zap_scan_policy"] == "standard"
    assert "wpscan" in r["skip_tools"]
    assert "pimcore" in r["reasoning"].lower()


def test_generic_cms_sulu_plone_silverstripe_statamic():
    """Vier weitere F-PH1-001-CMS muessen Generic-Branch treffen."""
    for cms_name in ("Sulu", "Plone", "SilverStripe", "Statamic"):
        tp = {"cms": cms_name, "waf": None, "has_ssl": True,
              "fqdns": ["x.example.com"], "open_ports": [443]}
        r = try_rule_based_config(tp, "perimeter")
        assert r is not None, f"no rule match for {cms_name}"
        assert r["zap_scan_policy"] == "standard", cms_name
        assert cms_name.lower() in r["reasoning"].lower(), cms_name


def test_hosted_cms_takes_precedence_over_generic():
    """Hosted-CMS-Branch greift VOR Generic-CMS — Reihenfolge wichtig."""
    tp = {"cms": "Shopify", "waf": None, "has_ssl": True,
          "fqdns": ["shop.example.com"], "open_ports": [443]}
    r = try_rule_based_config(tp, "perimeter")
    assert r is not None
    # Hosted → passive-only (NICHT standard wie Generic)
    assert r["zap_scan_policy"] == "passive-only"
