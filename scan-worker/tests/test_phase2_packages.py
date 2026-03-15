"""Tests for Phase 2 package-aware tool selection."""

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
            "open_ports": [80, 443],
        }

    @patch("scanner.phase2.publish_tool_output")
    @patch("scanner.phase2.run_header_check", return_value={"score": "3/7"})
    @patch("scanner.phase2.run_gowitness", return_value="/tmp/screenshots")
    @patch("scanner.phase2.run_gobuster_dir", return_value="/tmp/gobuster.txt")
    @patch("scanner.phase2.run_nuclei", return_value=[])
    @patch("scanner.phase2.run_nikto", return_value={})
    @patch("scanner.phase2.run_testssl", return_value={})
    def test_basic_only_runs_testssl_headers_gowitness(
        self, mock_testssl, mock_nikto, mock_nuclei,
        mock_gobuster, mock_gowitness, mock_headers, mock_publish, tmp_path
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
        mock_nikto.assert_not_called()
        mock_nuclei.assert_not_called()
        mock_gobuster.assert_not_called()
        mock_gowitness.assert_called_once()
        mock_headers.assert_called_once()

    @patch("scanner.phase2.publish_tool_output")
    @patch("scanner.phase2.run_header_check", return_value={"score": "3/7"})
    @patch("scanner.phase2.run_gowitness", return_value="/tmp/screenshots")
    @patch("scanner.phase2.run_gobuster_dir", return_value="/tmp/gobuster.txt")
    @patch("scanner.phase2.run_nuclei", return_value=[])
    @patch("scanner.phase2.run_nikto", return_value={})
    @patch("scanner.phase2.run_testssl", return_value={})
    def test_professional_runs_all_tools(
        self, mock_testssl, mock_nikto, mock_nuclei,
        mock_gobuster, mock_gowitness, mock_headers, mock_publish, tmp_path
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
        mock_nikto.assert_called_once()
        mock_nuclei.assert_called_once()
        mock_gobuster.assert_called_once()
        mock_gowitness.assert_called_once()
        mock_headers.assert_called_once()

    @patch("scanner.phase2.publish_tool_output")
    @patch("scanner.phase2.run_header_check", return_value={"score": "3/7"})
    @patch("scanner.phase2.run_gowitness", return_value="/tmp/screenshots")
    @patch("scanner.phase2.run_gobuster_dir", return_value="/tmp/gobuster.txt")
    @patch("scanner.phase2.run_nuclei", return_value=[])
    @patch("scanner.phase2.run_nikto", return_value={})
    @patch("scanner.phase2.run_testssl", return_value={})
    def test_basic_tools_run_list(
        self, mock_testssl, mock_nikto, mock_nuclei,
        mock_gobuster, mock_gowitness, mock_headers, mock_publish, tmp_path
    ):
        """Verify tools_run list only contains actually executed tools."""
        from scanner.phase2 import run_phase2
        config = get_config("basic")
        scan_dir = str(tmp_path / "scan")
        callback = MagicMock()

        result = run_phase2(
            "1.2.3.4", ["example.com"], self._make_tech_profile(),
            scan_dir, "test-id", callback, config
        )

        # Basic should only have testssl, gowitness, header_check in tools_run
        assert "nikto" not in result["tools_run"]
        assert "nuclei" not in result["tools_run"]
        assert "gobuster_dir" not in result["tools_run"]
