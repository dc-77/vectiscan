"""Tests fuer _build_performance_metrics (orders.performance_metrics)."""

from unittest.mock import patch

import pytest

from scanner.worker import _build_performance_metrics


class TestBuildPerformanceMetrics:
    def test_minimal_metrics_without_pool(self, monkeypatch):
        monkeypatch.setenv("ZAP_POOL_ENABLED", "false")
        monkeypatch.setenv("PHASE1_MAX_WORKERS", "3")
        monkeypatch.setenv("PHASE2_STAGE2_WAF_SAFE", "true")
        phases = {"phase0a": 1200, "phase0b": 18000, "phase1": 720000,
                  "phase2": 1440000, "phase3": 300000}

        m = _build_performance_metrics(phase_durations_ms=phases)

        assert m["phase_durations_ms"] == phases
        assert m["zap_pool_enabled"] is False
        assert m["zap_pool_size"] == 0
        assert m["parallelism_effective"]["phase1_max_workers"] == 3
        assert m["parallelism_effective"]["phase2_stage2_waf_safe_enabled"] is True
        # No pool-stats when pool disabled
        assert "zap_leases_total" not in m

    def test_metrics_with_pool_enabled(self, monkeypatch):
        monkeypatch.setenv("ZAP_POOL_ENABLED", "true")
        monkeypatch.setenv("ZAP_POOL", "zap-1,zap-2,zap-3,zap-4")
        monkeypatch.setenv("ZAP_MAX_PARALLEL_PER_ORDER", "3")
        monkeypatch.setenv("PHASE1_MAX_WORKERS", "6")

        class _FakeRedis:
            def get(self, key):
                if key == "zap:stats:leases_total":
                    return "18"
                return None

            def lrange(self, key, start, stop):
                if key == "zap:stats:lease_wait_ms":
                    return ["100", "250", "4200"]
                return []

        with patch("scanner.worker.redis.from_url", return_value=_FakeRedis()):
            m = _build_performance_metrics(phase_durations_ms={"phase1": 100})

        assert m["zap_pool_enabled"] is True
        assert m["zap_pool_size"] == 4
        assert m["zap_max_parallel_per_order"] == 3
        assert m["zap_leases_total"] == 18
        assert m["zap_avg_lease_wait_ms"] == int((100 + 250 + 4200) / 3)
        assert m["zap_max_lease_wait_ms"] == 4200
        assert m["parallelism_effective"]["phase1_max_workers"] == 6
        assert m["parallelism_effective"]["zap_pool_enabled"] is True

    def test_pool_enabled_but_redis_unreachable(self, monkeypatch):
        monkeypatch.setenv("ZAP_POOL_ENABLED", "true")
        with patch("scanner.worker.redis.from_url", side_effect=Exception("conn refused")):
            m = _build_performance_metrics(phase_durations_ms={})
        # Pool-Flags bleiben gesetzt, Stats-Felder fehlen ohne zu werfen
        assert m["zap_pool_enabled"] is True
        assert "zap_leases_total" not in m

    def test_invalid_phase1_env_defaults_to_3(self, monkeypatch):
        monkeypatch.setenv("ZAP_POOL_ENABLED", "false")
        monkeypatch.setenv("PHASE1_MAX_WORKERS", "")
        m = _build_performance_metrics(phase_durations_ms={})
        assert m["parallelism_effective"]["phase1_max_workers"] == 3
