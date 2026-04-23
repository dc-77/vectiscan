"""Tests for scanner.tools.zap_client — ZAP REST API client."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from scanner.tools.zap_client import ZapClient, ZapError


@pytest.fixture
def zap():
    return ZapClient(base_url="http://localhost:8090")


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

class TestHealthCheck:
    def test_success(self, zap):
        with patch.object(zap.session, "get") as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: {"version": "2.15.0"},
            )
            mock_get.return_value.raise_for_status = lambda: None
            assert zap.health_check() is True

    def test_connection_error(self, zap):
        with patch.object(zap.session, "get", side_effect=requests.ConnectionError("refused")):
            assert zap.health_check() is False

    def test_timeout(self, zap):
        with patch.object(zap.session, "get", side_effect=requests.Timeout("timed out")):
            assert zap.health_check() is False


# ---------------------------------------------------------------------------
# Context management
# ---------------------------------------------------------------------------

class TestContext:
    def test_create_context_returns_id(self, zap):
        with patch.object(zap, "_get", return_value={"contextId": "42"}):
            ctx_id = zap.create_context("test-ctx")
            assert ctx_id == 42

    def test_include_in_context(self, zap):
        with patch.object(zap, "_get") as mock_get:
            zap.include_in_context("test-ctx", ".*example\\.com.*")
            mock_get.assert_called_once_with(
                "/JSON/context/action/includeInContext/",
                {"contextName": "test-ctx", "regex": ".*example\\.com.*"},
            )

    def test_remove_context(self, zap):
        with patch.object(zap, "_get") as mock_get:
            zap.remove_context("test-ctx")
            mock_get.assert_called_once()

    def test_remove_context_error_swallowed(self, zap):
        """remove_context should not raise even if ZAP returns an error."""
        with patch.object(zap, "_get", side_effect=ZapError("not found")):
            zap.remove_context("nonexistent")  # Should not raise


# ---------------------------------------------------------------------------
# Spider
# ---------------------------------------------------------------------------

class TestSpider:
    def test_start_spider_returns_scan_id(self, zap):
        with patch.object(zap, "_get") as mock_get:
            mock_get.return_value = {"scan": "7"}
            scan_id = zap.start_spider("https://example.com", context_name="ctx-1")
            assert scan_id == 7

    def test_spider_status(self, zap):
        with patch.object(zap, "_get", return_value={"status": "75"}):
            assert zap.spider_status(7) == 75

    def test_spider_results(self, zap):
        urls = ["https://example.com/", "https://example.com/about"]
        with patch.object(zap, "_get", return_value={"results": urls}):
            assert zap.spider_results(7) == urls


# ---------------------------------------------------------------------------
# AJAX Spider
# ---------------------------------------------------------------------------

class TestAjaxSpider:
    def test_start(self, zap):
        with patch.object(zap, "_get") as mock_get:
            zap.start_ajax_spider("https://example.com", context_name="ctx-1")
            mock_get.assert_called_once()

    def test_status_running(self, zap):
        with patch.object(zap, "_get", return_value={"status": "running"}):
            assert zap.ajax_spider_status() == "running"

    def test_status_stopped(self, zap):
        with patch.object(zap, "_get", return_value={"status": "stopped"}):
            assert zap.ajax_spider_status() == "stopped"

    def test_stop(self, zap):
        with patch.object(zap, "_get") as mock_get:
            zap.stop_ajax_spider()
            mock_get.assert_called_once()


# ---------------------------------------------------------------------------
# Active Scan
# ---------------------------------------------------------------------------

class TestActiveScan:
    def test_start_returns_scan_id(self, zap):
        with patch.object(zap, "_get", return_value={"scan": "12"}):
            scan_id = zap.start_active_scan("https://example.com", context_id=42)
            assert scan_id == 12

    def test_status(self, zap):
        with patch.object(zap, "_get", return_value={"status": "50"}):
            assert zap.active_scan_status(12) == 50

    def test_stop(self, zap):
        with patch.object(zap, "_get") as mock_get:
            zap.stop_active_scan(12)
            mock_get.assert_called_once()


# ---------------------------------------------------------------------------
# Scan Policy
# ---------------------------------------------------------------------------

class TestScanPolicy:
    def test_create_scan_policy(self, zap):
        calls = []
        def mock_get(path, params=None):
            calls.append((path, params))
            return {}

        with patch.object(zap, "_get", side_effect=mock_get):
            zap.create_scan_policy("test-policy", ["xss", "sqli"], "standard")

        # Should have: addScanPolicy, disableAllScanners, enableScanners,
        # + strength/threshold per scanner
        paths = [c[0] for c in calls]
        assert "/JSON/ascan/action/addScanPolicy/" in paths
        assert "/JSON/ascan/action/disableAllScanners/" in paths
        assert "/JSON/ascan/action/enableScanners/" in paths

    def test_remove_scan_policy_error_swallowed(self, zap):
        with patch.object(zap, "_get", side_effect=ZapError("not found")):
            zap.remove_scan_policy("nonexistent")  # Should not raise


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimit:
    def test_configure_rate_limit(self, zap):
        calls = []
        def mock_get(path, params=None):
            calls.append(path)
            return {}

        with patch.object(zap, "_get", side_effect=mock_get):
            zap.configure_rate_limit(req_per_sec=15, threads=2, delay_ms=800)

        assert "/JSON/spider/action/setOptionThreadCount/" in calls
        assert "/JSON/ascan/action/setOptionThreadPerHost/" in calls
        assert "/JSON/ascan/action/setOptionDelayInMs/" in calls


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

class TestAlerts:
    def test_get_alerts(self, zap):
        mock_alerts = [{"alert": "XSS", "risk": "High"}]
        with patch.object(zap, "_get", return_value={"alerts": mock_alerts}):
            result = zap.get_alerts(base_url="https://example.com")
            assert len(result) == 1
            assert result[0]["alert"] == "XSS"

    def test_get_alerts_empty(self, zap):
        with patch.object(zap, "_get", return_value={"alerts": []}):
            result = zap.get_alerts()
            assert result == []


# ---------------------------------------------------------------------------
# Polling
# ---------------------------------------------------------------------------

class TestPolling:
    def test_poll_success(self, zap):
        """Status goes 0 → 50 → 100 (complete)."""
        statuses = iter([0, 50, 100])

        with patch("scanner.tools.zap_client.time.sleep"):
            result = zap.poll_until_complete(
                status_fn=lambda: next(statuses),
                timeout=300,
                interval=1,
                stop_value=100,
                tool_name="test",
            )
        assert result is True

    def test_poll_timeout(self, zap):
        """Status stuck at 50 → timeout."""
        import scanner.tools.zap_client as zap_mod

        # Make time.monotonic advance by 100s each call to trigger timeout quickly
        times = iter([0, 50, 150, 250, 350])
        with patch.object(zap_mod.time, "monotonic", side_effect=times):
            with patch.object(zap_mod.time, "sleep"):
                result = zap.poll_until_complete(
                    status_fn=lambda: 50,
                    timeout=300,
                    interval=1,
                    stop_value=100,
                    tool_name="test",
                )
        assert result is False

    def test_poll_zap_error(self, zap):
        """Status function raises ZapError → returns False."""
        with patch("scanner.tools.zap_client.time.sleep"):
            result = zap.poll_until_complete(
                status_fn=MagicMock(side_effect=ZapError("connection lost")),
                timeout=300,
                interval=1,
                stop_value=100,
                tool_name="test",
            )
        assert result is False


# ---------------------------------------------------------------------------
# Concurrent contexts
# ---------------------------------------------------------------------------

class TestConcurrentContexts:
    def test_two_contexts_independent(self, zap):
        """Creating two contexts should work independently."""
        context_counter = iter([1, 2])

        def mock_get(path, params=None):
            if "newContext" in path:
                return {"contextId": str(next(context_counter))}
            return {}

        with patch.object(zap, "_get", side_effect=mock_get):
            ctx1 = zap.create_context("ctx-order1-192_168_1_1")
            ctx2 = zap.create_context("ctx-order2-10_0_0_1")
            assert ctx1 == 1
            assert ctx2 == 2


# ---------------------------------------------------------------------------
# Pool-mode constructor (zap_id resolves base URL)
# ---------------------------------------------------------------------------

class TestPoolConstructor:
    def test_zap_id_builds_internal_url(self):
        client = ZapClient(zap_id="zap-3")
        assert client.base_url == "http://zap-3:8090"
        assert client.zap_id == "zap-3"

    def test_explicit_base_url_wins_over_zap_id(self):
        client = ZapClient(base_url="http://custom:9090", zap_id="zap-3")
        assert client.base_url == "http://custom:9090"


# ---------------------------------------------------------------------------
# cleanup_stale_contexts
# ---------------------------------------------------------------------------

class TestCleanupStaleContexts:
    def test_removes_stale_ctx_contexts_only(self, zap):
        listed = ["Default Context", "ctx-abcd1234-10_0_0_1", "ctx-ffeedd11-10_0_0_2"]
        deleted: list[str] = []

        def mock_get(path, params=None):
            if "contextList" in path:
                return {"contextList": listed}
            if "removeContext" in path:
                deleted.append(params["contextName"])
                return {}
            return {}

        with patch.object(zap, "_get", side_effect=mock_get):
            count = zap.cleanup_stale_contexts(active_context_names=set())
        assert count == 2
        assert "Default Context" not in deleted
        assert set(deleted) == {"ctx-abcd1234-10_0_0_1", "ctx-ffeedd11-10_0_0_2"}

    def test_keeps_active_contexts(self, zap):
        listed = ["ctx-abcd1234-10_0_0_1", "ctx-ffeedd11-10_0_0_2"]
        deleted: list[str] = []

        def mock_get(path, params=None):
            if "contextList" in path:
                return {"contextList": listed}
            if "removeContext" in path:
                deleted.append(params["contextName"])
                return {}
            return {}

        with patch.object(zap, "_get", side_effect=mock_get):
            count = zap.cleanup_stale_contexts(
                active_context_names={"ctx-abcd1234-10_0_0_1"}
            )
        assert count == 1
        assert deleted == ["ctx-ffeedd11-10_0_0_2"]

    def test_returns_zero_on_list_error(self, zap):
        with patch.object(zap, "_get", side_effect=ZapError("unreachable")):
            assert zap.cleanup_stale_contexts(active_context_names=set()) == 0

    def test_parses_string_contextlist_shape(self, zap):
        """Some ZAP builds return contextList as a JSON-encoded string."""
        deleted: list[str] = []

        def mock_get(path, params=None):
            if "contextList" in path:
                return {"contextList": '["ctx-aaaa-1_1_1_1", "Default Context"]'}
            if "removeContext" in path:
                deleted.append(params["contextName"])
                return {}
            return {}

        with patch.object(zap, "_get", side_effect=mock_get):
            count = zap.cleanup_stale_contexts(active_context_names=set())
        assert count == 1
        assert deleted == ["ctx-aaaa-1_1_1_1"]
