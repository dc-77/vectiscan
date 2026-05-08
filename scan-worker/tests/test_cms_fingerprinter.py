"""Tests fuer scanner.cms_fingerprinter — F-PH1-001 (+10 CMS) Coverage.

Validiert:
- Detection der 10 neuen CMS (Pimcore/Sulu/Plone/SilverStripe/Statamic/
  Webflow/Shopify/HubSpot/Wix/Squarespace) ueber Meta-Generator,
  Body-References (Static-CDN-URLs/JS-Globals), Cookies und Header.
- Probe-Cap-Erweiterung 20→25.
- Bestehende CMS (WordPress) bleiben erkannt (Regressionsschutz).

Tests laufen offline — kein HTTP. Verwendet `detect_cms()`-Helper, der
dieselben Matcher wie die CMSFingerprinter-HTTP-Pipeline anwendet.
"""
from __future__ import annotations

from scanner.cms_fingerprinter import CMSFingerprinter, detect_cms


# ---------------------------------------------------------------------------
# F-PH1-001: 10 neue CMS — je ein Test pro CMS
# ---------------------------------------------------------------------------

def test_pimcore_detected_via_meta():
    html = (
        '<html><head>'
        '<meta name="generator" content="Pimcore 11.2">'
        '</head><body></body></html>'
    )
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "Pimcore"
    assert result["confidence"] >= 0.85


def test_pimcore_detected_via_header():
    result = detect_cms(
        html="",
        headers={"X-Pimcore-Version": "11.2.3"},
        cookies={},
    )
    assert result["cms"] == "Pimcore"
    assert result["confidence"] >= 0.70


def test_pimcore_detected_via_cookie():
    result = detect_cms(
        html="",
        headers={},
        cookies={"pimcore_config_perspective": "default"},
    )
    assert result["cms"] == "Pimcore"
    assert result["confidence"] >= 0.70


def test_sulu_detected_via_cookie():
    result = detect_cms(
        html="",
        headers={"X-Powered-By": "Sulu"},
        cookies={"_sulu_token": "abc123"},
    )
    assert result["cms"] == "Sulu"
    assert result["confidence"] >= 0.70


def test_sulu_detected_via_meta():
    html = '<meta name="generator" content="Sulu 2.5.0">'
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "Sulu"
    assert result["confidence"] >= 0.85


def test_plone_detected_via_meta():
    html = '<meta name="generator" content="Plone 6.0 - https://plone.org">'
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "Plone"
    assert result["confidence"] >= 0.85


def test_plone_detected_via_body_toolbar():
    html = '<html><body><div class="cmsui-toolbar"></div></body></html>'
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "Plone"
    assert result["confidence"] >= 0.70


def test_silverstripe_detected_via_meta():
    html = '<meta name="generator" content="SilverStripe 4.13">'
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "SilverStripe"
    assert result["confidence"] >= 0.85


def test_silverstripe_detected_via_resources_path():
    html = (
        '<link rel="stylesheet" '
        'href="/_resources/themes/default/css/main.css">'
    )
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "SilverStripe"
    assert result["confidence"] >= 0.70


def test_statamic_detected_via_meta():
    html = '<meta name="generator" content="Statamic 4.0">'
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "Statamic"
    assert result["confidence"] >= 0.85


def test_statamic_detected_via_cookie():
    result = detect_cms(
        html="",
        headers={},
        cookies={"statamic_session": "xyz"},
    )
    assert result["cms"] == "Statamic"
    assert result["confidence"] >= 0.70


def test_webflow_detected_via_data_attribute():
    html = '<html data-wf-page="abc123" data-wf-site="def456"><body></body></html>'
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "Webflow"
    assert result["confidence"] >= 0.85


def test_webflow_detected_via_meta():
    html = '<meta name="generator" content="Webflow">'
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "Webflow"
    assert result["confidence"] >= 0.85


def test_shopify_detected_via_cdn():
    html = '<script src="https://cdn.shopify.com/s/files/1/0/assets/theme.js"></script>'
    result = detect_cms(
        html=html,
        headers={"X-Shopify-Stage": "production"},
        cookies={},
    )
    assert result["cms"] == "Shopify"
    assert result["confidence"] >= 0.85


def test_shopify_detected_via_js_global():
    html = '<script>var Shopify = Shopify || {}; Shopify.shop = "demo.myshopify.com";</script>'
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "Shopify"
    assert result["confidence"] >= 0.85


def test_shopify_detected_via_cookie():
    result = detect_cms(
        html="",
        headers={},
        cookies={"_shopify_y": "xyz"},
    )
    assert result["cms"] == "Shopify"
    assert result["confidence"] >= 0.70


def test_hubspot_detected_via_meta():
    html = '<meta name="generator" content="HubSpot CMS">'
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "HubSpot"
    assert result["confidence"] >= 0.85


def test_hubspot_detected_via_cdn():
    html = '<script src="//js.hs-scripts.com/12345.js"></script>'
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "HubSpot"
    assert result["confidence"] >= 0.85


def test_hubspot_detected_via_cookie():
    result = detect_cms(
        html="",
        headers={},
        cookies={"__hssc": "abc.1.123", "__hstc": "def"},
    )
    assert result["cms"] == "HubSpot"
    assert result["confidence"] >= 0.70


def test_wix_detected_via_meta():
    html = '<meta name="generator" content="Wix.com Website Builder">'
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "Wix"
    assert result["confidence"] >= 0.85


def test_wix_detected_via_static_cdn():
    html = '<img src="https://static.wixstatic.com/media/abc.jpg">'
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "Wix"
    assert result["confidence"] >= 0.85


def test_wix_detected_via_cookie():
    result = detect_cms(
        html="",
        headers={"X-Wix-Request-Id": "req-abc"},
        cookies={"_wixCIDX": "xyz"},
    )
    assert result["cms"] == "Wix"
    assert result["confidence"] >= 0.70


def test_squarespace_detected_via_meta():
    html = '<meta name="generator" content="Squarespace">'
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "Squarespace"
    assert result["confidence"] >= 0.85


def test_squarespace_detected_via_cdn():
    html = '<link href="https://static.squarespace.com/static/abc.css" rel="stylesheet">'
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "Squarespace"
    assert result["confidence"] >= 0.85


def test_squarespace_detected_via_cookie():
    result = detect_cms(
        html="",
        headers={},
        cookies={"crumb": "xyz123"},
    )
    assert result["cms"] == "Squarespace"
    assert result["confidence"] >= 0.70


# ---------------------------------------------------------------------------
# Regressionsschutz: bestehende CMS (WordPress)
# ---------------------------------------------------------------------------

def test_wordpress_still_detected_via_meta():
    html = '<meta name="generator" content="WordPress 6.4">'
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "WordPress"
    assert result["confidence"] >= 0.85


# ---------------------------------------------------------------------------
# F-PH1-001: Probe-Cap-Erweiterung 20→25
# ---------------------------------------------------------------------------

def test_default_max_requests_is_25():
    fp = CMSFingerprinter()
    assert fp.max_requests == 25


def test_max_requests_explicit_override():
    fp = CMSFingerprinter(max_requests=10)
    assert fp.max_requests == 10


# ---------------------------------------------------------------------------
# Negative-Tests: leerer Input → kein CMS
# ---------------------------------------------------------------------------

def test_empty_input_returns_no_cms():
    result = detect_cms(html="", headers={}, cookies={})
    assert result["cms"] is None
    assert result["confidence"] == 0.0


def test_unrelated_html_returns_no_cms():
    html = '<html><head><title>Plain</title></head><body><h1>Hi</h1></body></html>'
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] is None


# ---------------------------------------------------------------------------
# Bug #9 (Test-Session Mai 2026, heuel.com): Neos CMS via X-Flow-Powered
# Header und Flow-Resource-Pfade.
# ---------------------------------------------------------------------------

def test_neos_detected_via_x_flow_powered_header():
    """heuel.com hat X-Flow-Powered: 'Flow Neos' — vor dem Fix nicht erkannt."""
    result = detect_cms(
        html="",
        headers={"X-Flow-Powered": "Flow Neos"},
        cookies={},
    )
    assert result["cms"] == "NEOS"
    assert result["confidence"] >= 0.70


def test_neos_detected_via_flow_resource_path():
    """Flow-Framework-Resource-Pfade im rendered HTML → Neos-Detection."""
    html = (
        '<html><body>'
        '<link rel="stylesheet" href="/_Resources/Static/Packages/Neos.Neos/Styles/main.css">'
        '</body></html>'
    )
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "NEOS"


def test_neos_detected_via_meta_generator():
    """Bestehende meta_generator-Regel bleibt erhalten."""
    html = '<html><head><meta name="generator" content="NEOS 8.3"></head></html>'
    result = detect_cms(html=html, headers={}, cookies={})
    assert result["cms"] == "NEOS"
