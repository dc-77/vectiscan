"""Tests for Phase 2 package-aware tool selection (ZAP integration)."""

from unittest.mock import patch, MagicMock
import os

import pytest
from scanner.packages import get_config


class TestPhase2Packages:
    """Test that phase2 only runs tools specified in config."""

    def _make_tech_profile(self, has_ssl=True):
        return {
            "ip": "1.2.3.4",
            "fqdns": ["example.com"],
            "has_ssl": has_ssl,
            "has_web": True,
            "open_ports": [80, 443],
        }

    @patch("scanner.phase2.publish_tool_output")
    @patch("scanner.phase2.run_header_check", return_value={"score": "3/7"})
    @patch("scanner.phase2.run_httpx", return_value={"status_code": 200})
    @patch("scanner.phase2.run_gowitness", return_value="/tmp/screenshots")
    @patch("scanner.phase2.run_zap_scan", return_value={
        "alerts": [], "findings": [], "spider_urls": [],
        "tools_run": ["zap_spider"], "duration_ms": 1000,
    })
    @patch("scanner.phase2.run_testssl", return_value={})
    def test_webcheck_runs_zap_spider_not_active(
        self, mock_testssl, mock_zap, mock_gowitness, mock_httpx,
        mock_headers, mock_publish, tmp_path
    ):
        from scanner.phase2 import run_phase2
        config = get_config("basic")
        scan_dir = str(tmp_path / "scan")
        callback = MagicMock()

        result = run_phase2(
            "1.2.3.4", ["example.com"], self._make_tech_profile(),
            scan_dir, "test-id", callback, config
        )

        mock_testssl.assert_called_once()
        mock_zap.assert_called_once()
        mock_gowitness.assert_called_once()
        mock_headers.assert_called_once()
        # ZAP spider should be in tools_run
        assert "zap_spider" in result["tools_run"]
        # nikto, gobuster, katana should NOT be in tools_run
        for legacy in ("nikto", "gobuster_dir", "katana", "nuclei"):
            assert legacy not in result["tools_run"]

    @patch("scanner.phase2.publish_tool_output")
    @patch("scanner.phase2.run_header_check", return_value={"score": "3/7"})
    @patch("scanner.phase2.run_httpx", return_value={"status_code": 200})
    @patch("scanner.phase2.run_gowitness", return_value="/tmp/screenshots")
    @patch("scanner.phase2.run_nuclei", return_value=[])
    @patch("scanner.phase2.run_zap_scan", return_value={
        "alerts": [{"alert": "XSS", "risk": "High"}],
        "findings": [{"tool": "zap_active", "title": "XSS"}],
        "spider_urls": ["https://example.com/"],
        "tools_run": ["zap_spider", "zap_active"],
        "duration_ms": 5000,
    })
    @patch("scanner.phase2.run_testssl", return_value={})
    def test_perimeter_runs_zap_and_nuclei(
        self, mock_testssl, mock_zap, mock_nuclei,
        mock_gowitness, mock_httpx, mock_headers, mock_publish, tmp_path
    ):
        from scanner.phase2 import run_phase2
        config = get_config("professional")
        scan_dir = str(tmp_path / "scan")
        callback = MagicMock()

        result = run_phase2(
            "1.2.3.4", ["example.com"], self._make_tech_profile(),
            scan_dir, "test-id", callback, config
        )

        mock_testssl.assert_called_once()
        mock_zap.assert_called_once()
        mock_nuclei.assert_called_once()
        mock_gowitness.assert_called_once()
        mock_headers.assert_called_once()
        # ZAP tools in tools_run
        assert "zap_spider" in result["tools_run"]
        assert "zap_active" in result["tools_run"]
        assert "nuclei" in result["tools_run"]
        # ZAP findings stored
        assert len(result["zap_findings"]) == 1

    @patch("scanner.phase2.publish_tool_output")
    @patch("scanner.phase2.run_header_check", return_value={"score": "3/7"})
    @patch("scanner.phase2.run_httpx", return_value={"status_code": 200})
    @patch("scanner.phase2.run_gowitness", return_value="/tmp/screenshots")
    @patch("scanner.phase2.run_zap_scan", return_value={
        "alerts": [], "findings": [], "spider_urls": [],
        "tools_run": ["zap_spider"], "duration_ms": 1000,
    })
    @patch("scanner.phase2.run_testssl", return_value={})
    def test_webcheck_tools_run_excludes_legacy(
        self, mock_testssl, mock_zap, mock_gowitness, mock_httpx,
        mock_headers, mock_publish, tmp_path
    ):
        """Verify tools_run list does not contain legacy tools."""
        from scanner.phase2 import run_phase2
        config = get_config("basic")
        scan_dir = str(tmp_path / "scan")
        callback = MagicMock()

        result = run_phase2(
            "1.2.3.4", ["example.com"], self._make_tech_profile(),
            scan_dir, "test-id", callback, config
        )

        # Legacy tools should not appear
        for legacy in ("nikto", "gobuster_dir", "katana", "feroxbuster", "ffuf", "dalfox"):
            assert legacy not in result["tools_run"]
