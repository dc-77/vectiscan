"""Tests fuer should_parallelize_stage2 (WAF-Safe-Fallback in Stage 2)."""

import pytest

from scanner.phase2 import should_parallelize_stage2


class TestShouldParallelizeStage2:
    def test_parallel_by_default(self, monkeypatch):
        monkeypatch.delenv("PHASE2_STAGE2_WAF_SAFE", raising=False)
        assert should_parallelize_stage2({}, {"has_web": True}) is True

    def test_sequential_when_waf_detected_via_waf_field(self, monkeypatch):
        monkeypatch.setenv("PHASE2_STAGE2_WAF_SAFE", "true")
        assert should_parallelize_stage2({}, {"waf": "Cloudflare"}) is False

    def test_sequential_when_waf_list_non_empty(self, monkeypatch):
        monkeypatch.setenv("PHASE2_STAGE2_WAF_SAFE", "true")
        assert should_parallelize_stage2({}, {"waf": ["AWS WAF"]}) is False

    def test_sequential_when_explicit_waf_detected(self, monkeypatch):
        monkeypatch.setenv("PHASE2_STAGE2_WAF_SAFE", "true")
        assert should_parallelize_stage2({}, {"waf_detected": True}) is False

    def test_sequential_when_ai_policy_waf_safe(self, monkeypatch):
        monkeypatch.setenv("PHASE2_STAGE2_WAF_SAFE", "true")
        ac = {"zap_scan_policy": "waf-safe"}
        assert should_parallelize_stage2(ac, {}) is False

    def test_flag_disabled_forces_parallel_even_with_waf(self, monkeypatch):
        monkeypatch.setenv("PHASE2_STAGE2_WAF_SAFE", "false")
        assert should_parallelize_stage2({"zap_scan_policy": "waf-safe"},
                                         {"waf": "Cloudflare"}) is True

    def test_empty_waf_string_is_not_a_waf(self, monkeypatch):
        monkeypatch.setenv("PHASE2_STAGE2_WAF_SAFE", "true")
        assert should_parallelize_stage2({}, {"waf": ""}) is True

    def test_none_profile_is_safe(self, monkeypatch):
        monkeypatch.setenv("PHASE2_STAGE2_WAF_SAFE", "true")
        assert should_parallelize_stage2(None, None) is True
