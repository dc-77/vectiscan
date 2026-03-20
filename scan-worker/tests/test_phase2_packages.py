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
    @patch("scanner.phase2.run_header_check", return_value={"score": "3/7"})
    @patch("scanner.phase2.run_httpx", return_value={"status_code": 200})
    @patch("scanner.phase2.run_gowitness", return_value="/tmp/screenshots")
    @patch("scanner.phase2.run_testssl", return_value={})
    def test_webcheck_runs_zap_spider_not_active(
        self, mock_testssl, mock_gowitness, mock_httpx,
        mock_headers, mock_save, mock_event, mock_publish, tmp_path
    ):
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

        mock_testssl.assert_called_once()
        mock_gowitness.assert_called_once()
        mock_headers.assert_called_once()
        assert "zap_spider" in result["tools_run"]
        assert "testssl" in result["tools_run"]
        # WebCheck: no active scan, no nuclei
        assert "zap_active" not in result["tools_run"]
        for legacy in ("nikto", "gobuster_dir", "katana"):
            assert legacy not in result["tools_run"]

    @patch("scanner.phase2.publish_tool_output")
    @patch("scanner.phase2.publish_event")
    @patch("scanner.phase2._save_result")
    @patch("scanner.phase2.run_header_check", return_value={"score": "3/7"})
    @patch("scanner.phase2.run_httpx", return_value={"status_code": 200})
    @patch("scanner.phase2.run_gowitness", return_value="/tmp/screenshots")
    @patch("scanner.phase2.run_nuclei", return_value=[])
    @patch("scanner.phase2.run_testssl", return_value={})
    def test_perimeter_runs_zap_and_nuclei(
        self, mock_testssl, mock_nuclei, mock_gowitness, mock_httpx,
        mock_headers, mock_save, mock_event, mock_publish, tmp_path
    ):
        from scanner.phase2 import run_phase2

        mock_zap = self._make_mock_zap_client()
        with patch("scanner.tools.zap_client.ZapClient", return_value=mock_zap):
            config = get_config("professional")
            scan_dir = str(tmp_path / "scan")
            callback = MagicMock()

            result = run_phase2(
                "1.2.3.4", ["example.com"], self._make_tech_profile(),
                scan_dir, "test-id", callback, config
            )

        mock_testssl.assert_called_once()
        mock_gowitness.assert_called_once()
        mock_headers.assert_called_once()
        assert "zap_spider" in result["tools_run"]
        assert "nuclei" in result["tools_run"]

    @patch("scanner.phase2.publish_tool_output")
    @patch("scanner.phase2.publish_event")
    @patch("scanner.phase2._save_result")
    @patch("scanner.phase2.run_header_check", return_value={"score": "3/7"})
    @patch("scanner.phase2.run_httpx", return_value={"status_code": 200})
    @patch("scanner.phase2.run_gowitness", return_value="/tmp/screenshots")
    @patch("scanner.phase2.run_testssl", return_value={})
    def test_webcheck_tools_run_excludes_legacy(
        self, mock_testssl, mock_gowitness, mock_httpx,
        mock_headers, mock_save, mock_event, mock_publish, tmp_path
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

        for legacy in ("nikto", "gobuster_dir", "katana"):
            assert legacy not in result["tools_run"]
