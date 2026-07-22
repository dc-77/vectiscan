"""Tests for Phase 2 package-aware tool selection (3-stage pipeline)."""

from unittest.mock import patch, MagicMock
import os

import pytest
from scanner.packages import get_config


class TestPhase2Packages:
    """Test that phase2 runs the correct tools per package."""

    def _make_tech_profile(self, has_ssl=True):
        return {
            "ip": "1.2.3.4",
            "fqdns": ["example.com"],
            "has_ssl": has_ssl,
            "has_web": True,
            "open_ports": [80, 443],
        }

    def _make_mock_zap_client(self):
        """Create a mock ZapClient that simulates spider + passive + active scan."""
        mock_zap = MagicMock()
        mock_zap.health_check.return_value = True
        mock_zap.get_version.return_value = "2.15.0"
        mock_zap.create_context.return_value = 1
        mock_zap.start_spider.return_value = 1
        mock_zap.spider_status.return_value = 100
        mock_zap.spider_results.return_value = ["https://example.com/", "https://example.com/about"]
        mock_zap.ajax_spider_status.return_value = "stopped"
        mock_zap.start_active_scan.return_value = 1
        mock_zap.active_scan_status.return_value = 100
        mock_zap.wait_for_passive_scan.return_value = True
        mock_zap.get_alerts.return_value = []
        return mock_zap

    @patch("scanner.phase2.publish_tool_output")
    @patch("scanner.phase2.publish_event")
    @patch("scanner.phase2._save_result")
    @patch("scanner.phase2.record_tool_run")
    @patch("scanner.phase2.run_testssl", return_value=[{"id": "TLS1", "severity": "OK"}])
    @patch("scanner.phase2.run_header_check", return_value={"score": "3/7"})
    @patch("scanner.phase2.run_httpx", return_value={"status_code": 200})
    def test_webcheck_runs_zap_spider_not_active(
        self, mock_httpx,
        mock_headers, mock_testssl, mock_record, mock_save, mock_event, mock_publish,
        tmp_path
    ):
        from scanner.phase2 import run_phase2

        mock_zap = self._make_mock_zap_client()
        with patch("scanner.tools.zap_client.ZapClient", return_value=mock_zap):
            # dict()-Copy: get_config liefert das geteilte Modul-Dict; package
            # setzt worker.py vor Phase 2 (VEC-308), hier nachgestellt.
            config = dict(get_config("basic"))
            config["package"] = "webcheck"
            scan_dir = str(tmp_path / "scan")
            callback = MagicMock()

            result = run_phase2(
                "1.2.3.4", ["example.com"], self._make_tech_profile(),
                scan_dir, "test-id", callback, config
            )

        mock_headers.assert_called_once()
        assert "zap_spider" in result["tools_run"]
        # VEC-308: testssl ist Teil des WebCheck-Vertrags (report verspricht
        # SSL-Analyse) → Runner muss laufen. fast_mode bei webcheck.
        assert "testssl" in result["tools_run"]
        mock_testssl.assert_called_once()
        assert mock_testssl.call_args.kwargs.get("fast_mode") is True
        # WebCheck: no active scan
        assert "zap_active" not in result["tools_run"]
        # gowitness removed — screenshots now via Playwright in Phase 1
        assert "gowitness" not in result["tools_run"]
        for legacy in ("nikto", "gobuster_dir", "katana"):
            assert legacy not in result["tools_run"]

    @patch("scanner.phase2.publish_tool_output")
    @patch("scanner.phase2.publish_event")
    @patch("scanner.phase2._save_result")
    @patch("scanner.phase2.record_tool_run")
    @patch("scanner.phase2.run_testssl", return_value=[{"id": "TLS1", "severity": "OK"}])
    @patch("scanner.phase2.run_header_check", return_value={"score": "3/7"})
    @patch("scanner.phase2.run_httpx", return_value={"status_code": 200})
    def test_perimeter_runs_zap_and_deep_scan(
        self, mock_httpx,
        mock_headers, mock_testssl, mock_record, mock_save, mock_event, mock_publish,
        tmp_path
    ):
        from scanner.phase2 import run_phase2

        mock_zap = self._make_mock_zap_client()
        with patch("scanner.tools.zap_client.ZapClient", return_value=mock_zap):
            config = dict(get_config("professional"))
            config["package"] = "perimeter"
            scan_dir = str(tmp_path / "scan")
            callback = MagicMock()

            result = run_phase2(
                "1.2.3.4", ["example.com"], self._make_tech_profile(),
                scan_dir, "test-id", callback, config
            )

        mock_headers.assert_called_once()
        assert "zap_spider" in result["tools_run"]
        # VEC-308: testssl ist Teil des perimeter-Vertrags → Runner laeuft.
        # perimeter nutzt vollen Cipher-Walk (kein fast_mode).
        assert "testssl" in result["tools_run"]
        mock_testssl.assert_called_once()
        assert mock_testssl.call_args.kwargs.get("fast_mode") is False

    @patch("scanner.phase2.publish_tool_output")
    @patch("scanner.phase2.publish_event")
    @patch("scanner.phase2._save_result")
    @patch("scanner.phase2.record_tool_run")
    @patch("scanner.phase2.run_testssl", return_value=[{"id": "TLS1", "severity": "OK"}])
    @patch("scanner.phase2.run_header_check", return_value={"score": "3/7"})
    @patch("scanner.phase2.run_httpx", return_value={"status_code": 200})
    def test_webcheck_tools_run_excludes_legacy(
        self, mock_httpx,
        mock_headers, mock_testssl, mock_record, mock_save, mock_event, mock_publish,
        tmp_path
    ):
        """Verify tools_run list does not contain removed legacy tools."""
        from scanner.phase2 import run_phase2

        mock_zap = self._make_mock_zap_client()
        with patch("scanner.tools.zap_client.ZapClient", return_value=mock_zap):
            config = get_config("basic")
            scan_dir = str(tmp_path / "scan")
            callback = MagicMock()

            result = run_phase2(
                "1.2.3.4", ["example.com"], self._make_tech_profile(),
                scan_dir, "test-id", callback, config
            )

        for legacy in ("nikto", "gobuster_dir", "katana", "gowitness"):
            assert legacy not in result["tools_run"]


class TestPhase2CircuitBreaker:
    """Strang-A Befund 2: Pre-Execution-Gate gegen erkannte WAF.

    Ist der Host durch ein ECHTES WAF-Signal bereits als geblockt bekannt,
    duerfen die teuren Phase-2-Tools (ffuf/feroxbuster/wpscan/zap_active) NICHT
    mehr voll bis zum Timeout laufen — sie werden als status='blocked'
    protokolliert und uebersprungen.
    """

    def _make_tech_profile(self):
        return {
            "ip": "1.2.3.4",
            "fqdns": ["example.com"],
            "has_ssl": True,
            "has_web": True,
            "open_ports": [80, 443],
            "cms": "wordpress",  # wpscan waere sonst eh geskippt
        }

    def _make_mock_zap_client(self):
        mock_zap = MagicMock()
        mock_zap.health_check.return_value = True
        mock_zap.get_version.return_value = "2.15.0"
        mock_zap.create_context.return_value = 1
        mock_zap.start_spider.return_value = 1
        mock_zap.spider_status.return_value = 100
        mock_zap.spider_results.return_value = ["https://example.com/"]
        mock_zap.ajax_spider_status.return_value = "stopped"
        mock_zap.start_active_scan.return_value = 1
        mock_zap.active_scan_status.return_value = 100
        mock_zap.wait_for_passive_scan.return_value = True
        mock_zap.get_alerts.return_value = []
        return mock_zap

    @patch("scanner.phase2.run_wpscan")
    @patch("scanner.phase2.run_feroxbuster")
    @patch("scanner.phase2.run_ffuf")
    @patch("scanner.phase2.publish_tool_output")
    @patch("scanner.phase2.publish_event")
    @patch("scanner.phase2._save_result")
    @patch("scanner.phase2.record_tool_run")
    @patch("scanner.phase2.run_testssl", return_value=[{"id": "TLS1", "severity": "OK"}])
    @patch("scanner.phase2.run_header_check", return_value={"score": "3/7"})
    @patch("scanner.phase2.run_httpx", return_value={"status_code": 200})
    def test_blocked_host_skips_expensive_tools(
        self, mock_httpx, mock_headers, mock_testssl, mock_record, mock_save,
        mock_event, mock_publish, mock_ffuf, mock_ferox, mock_wpscan, tmp_path
    ):
        from scanner.phase2 import run_phase2
        from scanner import tools

        order_id = "cb-order"
        ip = "1.2.3.4"
        tools._detectors.clear()
        try:
            # Host durch echtes WAF-Signal (429-burst) in den Block-Zustand
            det = tools._get_or_create_detector(order_id)
            for _ in range(3):
                det.report_response(ip, 429, 100)
            det.is_blocked(ip)  # Sticky-Verdikt materialisieren

            mock_zap = self._make_mock_zap_client()
            with patch("scanner.tools.zap_client.ZapClient", return_value=mock_zap):
                config = dict(get_config("professional"))
                config["package"] = "perimeter"
                result = run_phase2(
                    ip, ["example.com"], self._make_tech_profile(),
                    str(tmp_path / "scan"), order_id, MagicMock(), config
                )

            # Teure Tools duerfen NICHT gelaufen sein.
            mock_ferox.assert_not_called()
            mock_wpscan.assert_not_called()
            mock_ffuf.assert_not_called()

            # ... sondern als 'blocked' protokolliert worden sein.
            blocked_tools = {
                c.args[3] for c in mock_record.call_args_list
                if len(c.args) >= 5 and c.args[4] == "blocked"
            }
            for t in ("feroxbuster", "wpscan", "zap_active"):
                assert t in blocked_tools, f"{t} nicht als 'blocked' protokolliert"
        finally:
            tools._detectors.clear()

    @patch("scanner.phase2.run_wpscan", return_value=None)
    @patch("scanner.phase2.run_feroxbuster", return_value=[])
    @patch("scanner.phase2.run_ffuf", return_value=[])
    @patch("scanner.phase2.publish_tool_output")
    @patch("scanner.phase2.publish_event")
    @patch("scanner.phase2._save_result")
    @patch("scanner.phase2.record_tool_run")
    @patch("scanner.phase2.run_testssl", return_value=[{"id": "TLS1", "severity": "OK"}])
    @patch("scanner.phase2.run_header_check", return_value={"score": "3/7"})
    @patch("scanner.phase2.run_httpx", return_value={"status_code": 200})
    def test_unblocked_host_runs_tools_normally(
        self, mock_httpx, mock_headers, mock_testssl, mock_record, mock_save,
        mock_event, mock_publish, mock_ffuf, mock_ferox, mock_wpscan, tmp_path
    ):
        """Ohne Block-Verdikt (fail-open) laufen die Tools regulaer."""
        from scanner.phase2 import run_phase2
        from scanner import tools

        tools._detectors.clear()
        try:
            mock_zap = self._make_mock_zap_client()
            with patch("scanner.tools.zap_client.ZapClient", return_value=mock_zap):
                config = dict(get_config("professional"))
                config["package"] = "perimeter"
                run_phase2(
                    "1.2.3.4", ["example.com"], self._make_tech_profile(),
                    str(tmp_path / "scan"), "no-block-order", MagicMock(), config
                )
            # feroxbuster laeuft (has_web=True, im Paket, kein Block).
            mock_ferox.assert_called()
        finally:
            tools._detectors.clear()


class TestTestsslWiring:
    """VEC-308: Claims↔Engine-Gap — report_mapper verspricht testssl.sh fuer
    webcheck (_build_basic_scope) und perimeter-class (_build_scope +
    SCAN_TOOLS-Appendix). Die phase2_tools-Liste muss testssl enthalten,
    sonst laeuft der gated Runner (_run_testssl_group) nie."""

    @pytest.mark.parametrize("package", [
        "webcheck", "basic",            # WebCheck + Legacy-Alias
        "perimeter", "professional",    # Perimeter + Legacy-Alias
        "compliance", "nis2",           # Compliance + Legacy-Alias
        "supplychain",
        "insurance",
    ])
    def test_phase2_tools_contains_testssl(self, package):
        assert "testssl" in get_config(package)["phase2_tools"], (
            f"{package}: report verspricht testssl.sh, aber phase2_tools "
            f"enthaelt es nicht (VEC-308 Claims↔Engine-Gap)"
        )
