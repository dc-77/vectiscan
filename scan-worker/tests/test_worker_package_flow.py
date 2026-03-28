"""Tests for worker package flow — reading package from payload and forwarding it."""

import json
from unittest.mock import patch, MagicMock, call

import pytest


class TestWorkerPackageFlow:
    """Test that worker reads package from queue payload and forwards it."""

    @patch("scanner.worker.set_scan_complete")
    @patch("scanner.worker.upload_to_minio", return_value="test.tar.gz")
    @patch("scanner.worker.pack_results", return_value="/tmp/test.tar.gz")
    @patch("scanner.worker.enqueue_report_job")
    @patch("scanner.worker.update_progress")
    @patch("scanner.worker.set_discovered_hosts")
    @patch("scanner.worker.set_scan_started")
    @patch("scanner.worker.run_phase2")
    @patch("scanner.worker.run_phase1", return_value={"ip": "1.2.3.4", "has_ssl": True})
    @patch("scanner.worker.run_phase0")
    @patch("scanner.worker.get_config")
    def test_package_read_from_payload(
        self, mock_get_config, mock_phase0, mock_phase1, mock_phase2,
        mock_started, mock_hosts, mock_progress, mock_enqueue,
        mock_pack, mock_upload, mock_complete, tmp_path
    ):
        """Verify that _process_job reads and uses the package from payload."""
        mock_get_config.return_value = {
            "phase0_tools": ["crtsh", "subfinder"],
            "phase0_timeout": 300,
            "max_hosts": 5,
            "nmap_ports": "--top-ports 100",
            "phase1_tools": ["nmap", "webtech", "wafw00f"],
            "phase2_tools": ["headers"],
            "total_timeout": 600,
        }
        mock_phase0.return_value = {"hosts": [], "domain": "example.com"}

        from scanner.worker import _process_job
        _process_job("scan-123", "example.com", "basic")

        mock_get_config.assert_called_once_with("basic")

    @patch("scanner.worker.set_scan_complete")
    @patch("scanner.worker.upload_to_minio", return_value="test.tar.gz")
    @patch("scanner.worker.pack_results", return_value="/tmp/test.tar.gz")
    @patch("scanner.worker.enqueue_report_job")
    @patch("scanner.worker.update_progress")
    @patch("scanner.worker.set_discovered_hosts")
    @patch("scanner.worker.set_scan_started")
    @patch("scanner.worker.run_phase2")
    @patch("scanner.worker.run_phase1", return_value={"ip": "1.2.3.4", "has_ssl": True})
    @patch("scanner.worker.run_phase0")
    @patch("scanner.worker.get_config")
    def test_package_forwarded_to_report_queue(
        self, mock_get_config, mock_phase0, mock_phase1, mock_phase2,
        mock_started, mock_hosts, mock_progress, mock_enqueue,
        mock_pack, mock_upload, mock_complete, tmp_path
    ):
        """Verify that package is included in the report queue payload."""
        mock_get_config.return_value = {
            "phase0_tools": ["crtsh"],
            "phase0_timeout": 300,
            "max_hosts": 5,
            "nmap_ports": "--top-ports 100",
            "phase1_tools": ["nmap"],
            "phase2_tools": ["headers"],
            "total_timeout": 600,
        }
        mock_phase0.return_value = {"hosts": [], "domain": "example.com"}

        from scanner.worker import _process_job
        _process_job("scan-456", "example.com", "nis2")

        # Check enqueue_report_job was called with package="nis2"
        mock_enqueue.assert_called_once()
        args = mock_enqueue.call_args
        # package should be the last positional arg or a kwarg
        # The call should be: enqueue_report_job(scan_id, minio_path, host_inventory, tech_profiles, package)
        assert args[0][-1] == "nis2" or args[1].get("package") == "nis2"

    @patch("scanner.worker.set_scan_complete")
    @patch("scanner.worker.upload_to_minio", return_value="test.tar.gz")
    @patch("scanner.worker.pack_results", return_value="/tmp/test.tar.gz")
    @patch("scanner.worker.enqueue_report_job")
    @patch("scanner.worker.update_progress")
    @patch("scanner.worker.set_discovered_hosts")
    @patch("scanner.worker.set_scan_started")
    @patch("scanner.worker.run_phase2")
    @patch("scanner.worker.run_phase1", return_value={"ip": "1.2.3.4", "has_ssl": True})
    @patch("scanner.worker.run_phase0")
    @patch("scanner.worker.get_config")
    def test_default_package_is_perimeter(
        self, mock_get_config, mock_phase0, mock_phase1, mock_phase2,
        mock_started, mock_hosts, mock_progress, mock_enqueue,
        mock_pack, mock_upload, mock_complete, tmp_path
    ):
        """Verify that when no package is specified, perimeter is used."""
        mock_get_config.return_value = {
            "phase0b_tools": ["crtsh", "subfinder", "amass", "gobuster_dns", "axfr", "dnsx"],
            "phase0b_timeout": 900,
            "phase0a_tools": ["shodan", "abuseipdb", "securitytrails", "whois"],
            "phase0a_timeout": 120,
            "max_hosts": 15,
            "nmap_ports": "--top-ports 1000",
            "phase1_tools": ["nmap", "webtech", "wafw00f", "cms_fingerprint"],
            "phase2_tools": ["zap_spider", "zap_active", "ffuf", "feroxbuster", "headers", "httpx", "wpscan"],
            "phase3_tools": ["nvd", "epss", "cisa_kev", "exploitdb", "correlator", "fp_filter", "business_impact"],
            "phase3_timeout": 300,
            "total_timeout": 7200,
        }
        mock_phase0.return_value = {"hosts": [], "domain": "example.com"}

        from scanner.worker import _process_job
        # Call without explicit package — should default to "perimeter"
        _process_job("scan-789", "example.com")

        mock_get_config.assert_called_once_with("perimeter")
