"""Tests for Phase 0 package-aware tool selection."""

import json
import os
from unittest.mock import patch, MagicMock

import pytest
from scanner.packages import get_config


class TestPhase0Packages:
    """Test that phase0 only runs tools specified in config."""

    @patch("scanner.phase0.run_dnsx", return_value=[])
    @patch("scanner.phase0.collect_dns_records", return_value={"spf": None, "dmarc": None, "dkim": False, "mx": [], "ns": []})
    @patch("scanner.phase0.run_zone_transfer", return_value={"success": False, "data": {}})
    @patch("scanner.phase0.run_gobuster_dns", return_value=["sub3.example.com"])
    @patch("scanner.phase0.run_amass", return_value=["sub2.example.com"])
    @patch("scanner.phase0.run_subfinder", return_value=["sub1.example.com"])
    @patch("scanner.phase0.run_crtsh", return_value=["www.example.com"])
    def test_webcheck_only_runs_crtsh_and_subfinder(
        self, mock_crtsh, mock_subfinder, mock_amass, mock_gobuster,
        mock_zone, mock_dns, mock_dnsx, tmp_path
    ):
        from scanner.phase0 import run_phase0
        config = get_config("webcheck")
        scan_dir = str(tmp_path / "scan")
        os.makedirs(scan_dir, exist_ok=True)

        run_phase0("example.com", scan_dir, "test-id", config)

        mock_crtsh.assert_called_once()
        mock_subfinder.assert_called_once()
        mock_amass.assert_not_called()
        mock_gobuster.assert_not_called()
        mock_zone.assert_not_called()
        # dnsx is in webcheck phase0b_tools
        mock_dnsx.assert_called_once()
        # DNS records should always be collected
        mock_dns.assert_called_once()

    @patch("scanner.phase0.run_dnsx", return_value=[])
    @patch("scanner.phase0.collect_dns_records", return_value={"spf": None, "dmarc": None, "dkim": False, "mx": [], "ns": []})
    @patch("scanner.phase0.run_zone_transfer", return_value={"success": False, "data": {}})
    @patch("scanner.phase0.run_gobuster_dns", return_value=["sub3.example.com"])
    @patch("scanner.phase0.run_amass", return_value=["sub2.example.com"])
    @patch("scanner.phase0.run_subfinder", return_value=["sub1.example.com"])
    @patch("scanner.phase0.run_crtsh", return_value=["www.example.com"])
    def test_perimeter_runs_all_tools(
        self, mock_crtsh, mock_subfinder, mock_amass, mock_gobuster,
        mock_zone, mock_dns, mock_dnsx, tmp_path
    ):
        from scanner.phase0 import run_phase0
        config = get_config("perimeter")
        scan_dir = str(tmp_path / "scan")
        os.makedirs(scan_dir, exist_ok=True)

        run_phase0("example.com", scan_dir, "test-id", config)

        mock_crtsh.assert_called_once()
        mock_subfinder.assert_called_once()
        # amass v5 ist seit 2026-05-03 aus phase0_tools entfernt
        # (siehe packages.py: subfinder -all + certspotter decken die
        # Sources besser ab als amass v5).
        mock_amass.assert_not_called()
        mock_gobuster.assert_called_once()
        mock_zone.assert_called_once()
        mock_dnsx.assert_called_once()
        mock_dns.assert_called_once()

    @patch("scanner.phase0.run_dnsx")
    @patch("scanner.phase0.collect_dns_records", return_value={"spf": None, "dmarc": None, "dkim": False, "mx": [], "ns": []})
    @patch("scanner.phase0.run_zone_transfer", return_value={"success": False, "data": {}})
    @patch("scanner.phase0.run_gobuster_dns", return_value=[])
    @patch("scanner.phase0.run_amass", return_value=[])
    @patch("scanner.phase0.run_subfinder", return_value=[])
    @patch("scanner.phase0.run_crtsh", return_value=[])
    def test_webcheck_max_hosts_limits_to_3(
        self, mock_crtsh, mock_subfinder, mock_amass, mock_gobuster,
        mock_zone, mock_dns, mock_dnsx, tmp_path
    ):
        """When 8 hosts are discovered, webcheck config should limit to 3."""
        # Make dnsx return 8 validated hosts with different IPs
        mock_dnsx.return_value = [
            {"host": f"h{i}.example.com", "a": [f"1.2.3.{i}"]}
            for i in range(8)
        ]
        from scanner.phase0 import run_phase0
        config = get_config("webcheck")
        scan_dir = str(tmp_path / "scan")
        os.makedirs(scan_dir, exist_ok=True)

        inventory = run_phase0("example.com", scan_dir, "test-id", config)

        assert len(inventory["hosts"]) <= 3
