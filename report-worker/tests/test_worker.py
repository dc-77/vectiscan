"""Unit tests for reporter.worker module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def test_reporter_package_imports() -> None:
    """Verify the reporter package can be imported."""
    import reporter
    assert reporter.__doc__ is not None


def test_worker_module_imports() -> None:
    """Verify reporter.worker module imports without errors."""
    from reporter import worker
    assert worker.__doc__ is not None


class TestProcessJob:
    """Tests for the process_job function."""

    @patch("reporter.worker._get_db_connection")
    @patch("reporter.worker._get_minio_client")
    @patch("reporter.worker._download_rawdata")
    @patch("reporter.worker.tarfile")
    @patch("reporter.worker.parse_scan_data")
    @patch("reporter.worker.call_claude")
    @patch("reporter.worker.map_to_report_data")
    @patch("reporter.worker.generate_report")
    @patch("reporter.worker._upload_report")
    @patch("reporter.worker._create_report_record")
    @patch("reporter.worker._update_order_status")
    @patch("reporter.worker.shutil")
    def test_process_job_success(
        self,
        mock_shutil,
        mock_update_status,
        mock_create_record,
        mock_upload,
        mock_gen_report,
        mock_map,
        mock_claude,
        mock_parse,
        mock_tarfile,
        mock_download,
        mock_minio,
        mock_db,
        tmp_path,
    ) -> None:
        from reporter.worker import process_job

        # Setup mocks
        mock_conn = MagicMock()
        mock_db.return_value = mock_conn

        mock_download.return_value = tmp_path / "rawdata.tar.gz"

        mock_parse.return_value = {
            "host_inventory": {"domain": "beispiel.de", "hosts": [{"ip": "1.2.3.4"}]},
            "tech_profiles": [{"ip": "1.2.3.4"}],
            "consolidated_findings": "test findings",
        }
        mock_claude.return_value = {"overall_risk": "HIGH", "findings": []}
        mock_map.return_value = {"meta": {}, "findings": []}
        mock_upload.return_value = 12345
        mock_create_record.return_value = ("report-id-123", "token-456")

        # generate_report is mocked — create a fake PDF so pdf_path.stat() works
        def fake_generate(data, path):
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_bytes(b"fake-pdf")
        mock_gen_report.side_effect = fake_generate

        job_data = {
            "scanId": "scan-123",
            "rawDataPath": "scan-123.tar.gz",
            "hostInventory": {"domain": "beispiel.de", "hosts": []},
            "techProfiles": [],
        }

        process_job(job_data)

        # Verify key steps were called
        mock_parse.assert_called_once()
        mock_claude.assert_called_once()
        mock_map.assert_called_once()
        mock_gen_report.assert_called_once()
        mock_upload.assert_called_once()
        mock_create_record.assert_called_once()
        # First run (no excluded findings) → pending_review for admin approval
        mock_update_status.assert_called_with(mock_conn, "scan-123", "pending_review"
        )

    @patch("reporter.worker._get_db_connection")
    @patch("reporter.worker._get_minio_client")
    @patch("reporter.worker._download_rawdata")
    @patch("reporter.worker._update_order_status")
    @patch("reporter.worker.shutil")
    def test_process_job_failure_updates_status(
        self,
        mock_shutil,
        mock_update_status,
        mock_download,
        mock_minio,
        mock_db,
    ) -> None:
        from reporter.worker import process_job

        mock_conn = MagicMock()
        mock_db.return_value = mock_conn
        mock_download.side_effect = Exception("Download failed")

        job_data = {
            "scanId": "scan-fail",
            "rawDataPath": "scan-fail.tar.gz",
            "hostInventory": {},
            "techProfiles": [],
        }

        process_job(job_data)

        # Should have tried to set status to failed
        mock_update_status.assert_called_once()
        args = mock_update_status.call_args
        assert args[0][2] == "failed"  # status arg
