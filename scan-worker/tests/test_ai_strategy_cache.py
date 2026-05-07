"""Tests fuer F-XS-002: Cache-Architektur-Symmetrie KI #2 + KI #3.

KI #1 (plan_host_strategy) nutzt schon `content_hash` fuer Order-uebergreifende
Cache-Hits. KI #2 (plan_tech_analysis) und KI #3 (plan_phase2_config) muessen
das gleiche Verhalten zeigen — sonst sind Re-Scans bei identischen Inputs
nur Order-scoped reproduzierbar.

Verifiziert:
- content_hash-Argument an _call_haiku ist gesetzt (nicht None) und 32-char hex.
- Identische Inputs ueber verschiedene order_ids liefern den gleichen Hash.
"""

from __future__ import annotations

from unittest.mock import patch

import scanner.ai_strategy as ai_s


# ---------------------------------------------------------------------------
# Fixtures: stabiler Mock-Return fuer _call_haiku
# ---------------------------------------------------------------------------

_KI2_RETURN = {
    "hosts": {
        "1.2.3.4": {
            "cms": None,
            "cms_version": None,
            "cms_confidence": 0.0,
            "technology_stack": ["nginx"],
            "is_spa": False,
            "reasoning": "mock",
        }
    },
    "_raw": "{}",
    "_cost": {"total_cost_usd": 0.0},
}

_KI3_RETURN = {
    "zap_scan_policy": "standard",
    "zap_spider_max_depth": 5,
    "zap_ajax_spider_enabled": False,
    "zap_active_categories": ["sqli", "xss"],
    "zap_rate_req_per_sec": 80,
    "zap_threads": 5,
    "zap_spider_delay_ms": 0,
    "zap_extra_urls": [],
    "skip_tools": [],
    "reasoning": "mock",
    "_raw": "{}",
    "_cost": {"total_cost_usd": 0.0},
}


# Tech-Profile, das KEINEN Rule-Engine-Match ausloest
# (siehe scanner/phase2_config_rules.py:try_rule_based_config):
# - cms: kein "wordpress"/"drupal"/"typo3"/"joomla"/"shopware"/"magento"
# - waf: leer
# - is_spa: False, server enthaelt keine SPA-Marker
# - primary_fqdn startet nicht mit "api." und enthaelt kein "graphql"
# - package "perimeter" (nicht webcheck/basic)
# - open_ports: nur 443 (kein reines Mail-Set)
_TECH_PROFILE_NO_RULE = {
    "ip": "1.2.3.4",
    "fqdns": ["example.com"],
    "cms": "Unknown",
    "cms_confidence": 0.0,
    "server": "nginx/1.25",
    "waf": None,
    "has_ssl": True,
    "is_spa": False,
    "open_ports": [443],
    "cms_details": {},
}


# ---------------------------------------------------------------------------
# KI #2 — plan_tech_analysis
# ---------------------------------------------------------------------------


@patch("scanner.ai_strategy._call_haiku")
def test_ki2_tech_analysis_uses_content_hash(mock_haiku):
    """KI #2 muss `content_hash` an _call_haiku uebergeben (nicht None, 32 hex)."""
    mock_haiku.return_value = dict(_KI2_RETURN)

    tech_profiles = [{
        "ip": "1.2.3.4",
        "fqdns": ["example.com"],
        "cms": "WordPress",
        "cms_confidence": 0.6,
        "server": "nginx",
        "open_ports": [443],
    }]
    redirect_data = {"example.com": {"final_url": "https://example.com/"}}

    ai_s.plan_tech_analysis(tech_profiles, redirect_data, order_id="ord-A")

    assert mock_haiku.called
    _, kwargs = mock_haiku.call_args
    ch = kwargs.get("content_hash")
    assert ch is not None, "KI #2 muss content_hash setzen"
    assert isinstance(ch, str)
    assert len(ch) == 32, f"content_hash muss 32 hex chars sein, ist {len(ch)}"
    int(ch, 16)  # raises wenn nicht hex


@patch("scanner.ai_strategy._call_haiku")
def test_ki2_tech_analysis_same_input_same_hash(mock_haiku):
    """Identische tech_profiles+redirect_data → identischer content_hash,
    auch ueber verschiedene order_ids hinweg. Das ist die Kern-Eigenschaft
    fuer Order-uebergreifende Cache-Hits.
    """
    mock_haiku.return_value = dict(_KI2_RETURN)

    tech_profiles = [{
        "ip": "1.2.3.4",
        "fqdns": ["example.com"],
        "cms": "WordPress",
        "cms_confidence": 0.6,
        "server": "nginx",
        "open_ports": [443],
    }]
    redirect_data = {"example.com": {"final_url": "https://example.com/"}}

    ai_s.plan_tech_analysis(tech_profiles, redirect_data, order_id="ord-A")
    ai_s.plan_tech_analysis(tech_profiles, redirect_data, order_id="ord-B")

    assert mock_haiku.call_count == 2
    ch_a = mock_haiku.call_args_list[0].kwargs.get("content_hash")
    ch_b = mock_haiku.call_args_list[1].kwargs.get("content_hash")
    assert ch_a is not None and ch_b is not None
    assert ch_a == ch_b, (
        "Gleiche Inputs muessen gleichen content_hash erzeugen — sonst "
        "ist Order-uebergreifender Cache-Hit unmoeglich."
    )


# ---------------------------------------------------------------------------
# KI #3 — plan_phase2_config
# ---------------------------------------------------------------------------


@patch("scanner.ai_strategy._call_haiku")
def test_ki3_phase2_config_uses_content_hash(mock_haiku):
    """KI #3 muss `content_hash` an _call_haiku uebergeben (nicht None, 32 hex)."""
    mock_haiku.return_value = dict(_KI3_RETURN)

    host_inventory = {"hosts": [], "domain": "example.com"}

    ai_s.plan_phase2_config(
        tech_profile=_TECH_PROFILE_NO_RULE,
        host_inventory=host_inventory,
        package="perimeter",
        order_id="ord-A",
    )

    assert mock_haiku.called, (
        "KI #3 sollte _call_haiku rufen — wenn die Rule-Engine matcht, "
        "ist der Test-Tech-Profile zu spezifisch (siehe phase2_config_rules.py)."
    )
    _, kwargs = mock_haiku.call_args
    ch = kwargs.get("content_hash")
    assert ch is not None, "KI #3 muss content_hash setzen"
    assert isinstance(ch, str)
    assert len(ch) == 32, f"content_hash muss 32 hex chars sein, ist {len(ch)}"
    int(ch, 16)


@patch("scanner.ai_strategy._call_haiku")
def test_ki3_phase2_config_same_input_same_hash(mock_haiku):
    """Identisches enriched_profile + package → identischer content_hash,
    auch ueber verschiedene order_ids hinweg.
    """
    mock_haiku.return_value = dict(_KI3_RETURN)

    host_inventory = {"hosts": [], "domain": "example.com"}

    ai_s.plan_phase2_config(
        tech_profile=_TECH_PROFILE_NO_RULE,
        host_inventory=host_inventory,
        package="perimeter",
        order_id="ord-A",
    )
    ai_s.plan_phase2_config(
        tech_profile=_TECH_PROFILE_NO_RULE,
        host_inventory=host_inventory,
        package="perimeter",
        order_id="ord-B",
    )

    assert mock_haiku.call_count == 2
    ch_a = mock_haiku.call_args_list[0].kwargs.get("content_hash")
    ch_b = mock_haiku.call_args_list[1].kwargs.get("content_hash")
    assert ch_a is not None and ch_b is not None
    assert ch_a == ch_b, (
        "Gleiche Inputs muessen gleichen content_hash erzeugen — sonst "
        "ist Order-uebergreifender Cache-Hit unmoeglich."
    )
