"""Tests fuer KI #4 Optionalitaetsgate (C3) und KI #3 Rule-Engine-Integration."""

from unittest.mock import patch

import scanner.ai_strategy as ai_s


def _no_call(*a, **kw):
    raise AssertionError("KI-Call sollte nicht stattfinden (skip-gate aktiv)")


def test_phase3_skip_when_too_few_findings():
    with patch.object(ai_s, "_call_sonnet", side_effect=_no_call):
        r = ai_s.plan_phase3_prioritization(
            [{"tool": "a", "cve": "CVE-1"}, {"tool": "b", "cve": "CVE-2"}],
            tech_profiles=[], has_waf=False,
        )
    assert r.get("_skipped_by_gate") is True
    assert r["confidence_scores"] == []


def test_phase3_skip_when_single_tool():
    with patch.object(ai_s, "_call_sonnet", side_effect=_no_call):
        fs = [{"tool": "zap", "cve": f"CVE-{i}"} for i in range(10)]
        r = ai_s.plan_phase3_prioritization(fs, [], False)
    assert r.get("_skipped_by_gate") is True


def test_phase3_skip_when_no_cve():
    with patch.object(ai_s, "_call_sonnet", side_effect=_no_call):
        fs = [{"tool": "zap"}, {"tool": "nikto"}, {"tool": "testssl"}] * 4
        r = ai_s.plan_phase3_prioritization(fs, [], False)
    assert r.get("_skipped_by_gate") is True


def test_phase3_does_call_when_qualified():
    """5+ Findings, 2+ Tools, mindestens 1 CVE → KI #4 wird gerufen."""
    fake_response = {"confidence_scores": [], "strategy_notes": "ok",
                     "_raw": "{}", "_cost": {"total_cost_usd": 0.01}}
    with patch.object(ai_s, "_call_sonnet", return_value=fake_response) as mock_call:
        fs = [{"tool": "zap", "cve": "CVE-1"},
              {"tool": "nikto"}, {"tool": "testssl"},
              {"tool": "nuclei", "cve": "CVE-2"},
              {"tool": "wpscan", "cve": "CVE-3"}, {"tool": "headers"}]
        r = ai_s.plan_phase3_prioritization(fs, [], False)
    assert mock_call.called
    assert "_skipped_by_gate" not in r


def test_phase2_config_rule_based_avoids_haiku():
    """C1: Rule-Engine matcht WordPress → kein Haiku-Call."""
    with patch.object(ai_s, "_call_haiku", side_effect=_no_call):
        r = ai_s.plan_phase2_config(
            tech_profile={"ip": "1.1.1.1", "cms": "WordPress",
                          "waf": None, "has_ssl": True,
                          "fqdns": ["x.com"], "open_ports": [443]},
            host_inventory={"hosts": [], "domain": "x.com"},
            package="perimeter",
        )
    assert r.get("_rule_based") is True
