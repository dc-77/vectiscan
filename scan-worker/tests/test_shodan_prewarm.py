"""Tests for F-P0A-006: Shodan on-demand Pre-Warm."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest


class TestShodanRequestScan:
    @patch.dict("os.environ", {"SHODAN_API_KEY": ""})
    def test_no_api_key_returns_none(self):
        from scanner.passive.shodan_client import ShodanClient
        client = ShodanClient()
        assert client.request_scan(["1.2.3.4"]) is None

    @patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"})
    def test_empty_ips_returns_none(self):
        from scanner.passive.shodan_client import ShodanClient
        client = ShodanClient()
        assert client.request_scan([]) is None

    @patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"})
    def test_post_returns_scan_id_on_success(self):
        from scanner.passive.shodan_client import ShodanClient
        client = ShodanClient()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"id": "shodan-abc-123", "credits_left": 4998}
        with patch.object(client.session, "post", return_value=mock_resp) as mock_post:
            scan_id = client.request_scan(["1.2.3.4", "5.6.7.8"])
            assert scan_id == "shodan-abc-123"
            # Verify POST-Body
            call_kwargs = mock_post.call_args.kwargs
            assert call_kwargs["data"]["ips"] == "1.2.3.4,5.6.7.8"
            assert call_kwargs["params"]["key"] == "test-key"

    @patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"})
    def test_post_caps_at_50_ips(self):
        from scanner.passive.shodan_client import ShodanClient
        client = ShodanClient()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"id": "shodan-x"}
        with patch.object(client.session, "post", return_value=mock_resp) as mock_post:
            ips = [f"10.0.{i // 256}.{i % 256}" for i in range(75)]
            client.request_scan(ips)
            posted = mock_post.call_args.kwargs["data"]["ips"]
            assert posted.count(",") == 49  # 50 IPs => 49 commas

    @patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"})
    def test_http_error_returns_none(self):
        from scanner.passive.shodan_client import ShodanClient
        client = ShodanClient()

        mock_resp = MagicMock()
        mock_resp.status_code = 401
        with patch.object(client.session, "post", return_value=mock_resp):
            assert client.request_scan(["1.2.3.4"]) is None

    @patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"})
    def test_response_without_id_returns_none(self):
        from scanner.passive.shodan_client import ShodanClient
        client = ShodanClient()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"error": "no scans available"}
        with patch.object(client.session, "post", return_value=mock_resp):
            assert client.request_scan(["1.2.3.4"]) is None


class TestPreWarmTriggerLogic:
    def test_one_off_without_optin_skips(self):
        from scanner import shodan_prewarm

        with patch.object(shodan_prewarm, "_load_order_context",
                          return_value={"subscription_id": None,
                                        "pre_warm_requested": False}):
            assert shodan_prewarm.maybe_trigger_prewarm("order-id") is None

    def test_subscription_path_triggers(self):
        from scanner import shodan_prewarm

        ctx = {"subscription_id": "sub-uuid", "pre_warm_requested": False}
        with patch.object(shodan_prewarm, "_load_order_context", return_value=ctx), \
             patch.object(shodan_prewarm, "_load_approved_ips",
                          return_value=["1.2.3.4", "5.6.7.8"]), \
             patch.object(shodan_prewarm, "_persist_subscription_request") as mock_persist, \
             patch("scanner.shodan_prewarm.ShodanClient") as mock_cls:
            mock_client = MagicMock()
            mock_client.available = True
            mock_client.request_scan.return_value = "scan-xyz"
            mock_cls.return_value = mock_client

            scan_id = shodan_prewarm.maybe_trigger_prewarm("order-id")
            assert scan_id == "scan-xyz"
            mock_client.request_scan.assert_called_once_with(["1.2.3.4", "5.6.7.8"])
            mock_persist.assert_called_once()

    def test_one_off_with_optin_triggers_no_persist(self):
        """One-Off-Pfad: kein Persistenz-Schreib (nicht subscription)."""
        from scanner import shodan_prewarm

        ctx = {"subscription_id": None, "pre_warm_requested": True}
        with patch.object(shodan_prewarm, "_load_order_context", return_value=ctx), \
             patch.object(shodan_prewarm, "_load_approved_ips",
                          return_value=["9.9.9.9"]), \
             patch.object(shodan_prewarm, "_persist_subscription_request") as mock_persist, \
             patch("scanner.shodan_prewarm.ShodanClient") as mock_cls:
            mock_client = MagicMock()
            mock_client.available = True
            mock_client.request_scan.return_value = "scan-abc"
            mock_cls.return_value = mock_client

            scan_id = shodan_prewarm.maybe_trigger_prewarm("order-id")
            assert scan_id == "scan-abc"
            mock_persist.assert_not_called()  # One-Off => kein DB-Write

    def test_no_ips_skips(self):
        from scanner import shodan_prewarm

        ctx = {"subscription_id": "sub-uuid", "pre_warm_requested": False}
        with patch.object(shodan_prewarm, "_load_order_context", return_value=ctx), \
             patch.object(shodan_prewarm, "_load_approved_ips", return_value=[]):
            assert shodan_prewarm.maybe_trigger_prewarm("order-id") is None

    def test_no_api_key_skips(self):
        from scanner import shodan_prewarm

        ctx = {"subscription_id": "sub-uuid", "pre_warm_requested": False}
        with patch.object(shodan_prewarm, "_load_order_context", return_value=ctx), \
             patch.object(shodan_prewarm, "_load_approved_ips",
                          return_value=["1.2.3.4"]), \
             patch("scanner.shodan_prewarm.ShodanClient") as mock_cls:
            mock_client = MagicMock()
            mock_client.available = False
            mock_cls.return_value = mock_client

            assert shodan_prewarm.maybe_trigger_prewarm("order-id") is None
