"""Tests for worker.py package integration."""
from pathlib import Path
from unittest.mock import patch, MagicMock
import json
import pytest
from reporter.worker import process_job

@pytest.fixture
def base_job_data():
    return {
        "scanId": "test-scan-123",
        "rawDataPath": "test-scan-123.tar.gz",
        "hostInventory": {"domain": "example.com", "hosts": []},
        "techProfiles": [],
    }

@patch("reporter.worker._get_minio_client")
@patch("reporter.worker._get_db_connection")
@patch("reporter.worker._download_rawdata")
@patch("reporter.worker.parse_scan_data")
@patch("reporter.worker.call_claude")
@patch("reporter.worker.map_to_report_data")
@patch("reporter.worker.generate_report")
@patch("reporter.worker._upload_report")
@patch("reporter.worker._create_report_record")
@patch("reporter.worker._update_order_status")
def test_package_passed_to_claude(
    mock_status, mock_create, mock_upload, mock_gen,
    mock_map, mock_claude, mock_parse, mock_download,
    mock_db, mock_minio, base_job_data, tmp_path
):
    """Package should be passed to call_claude()."""
    base_job_data["package"] = "basic"
    mock_download.return_value = tmp_path / "raw.tar.gz"
    (tmp_path / "raw.tar.gz").write_bytes(b"")  # dummy
    mock_parse.return_value = {"host_inventory": {"hosts": [], "domain": "example.com"}, "tech_profiles": [], "consolidated_findings": {}}
    mock_claude.return_value = {"overall_risk": "LOW", "findings": []}
    mock_map.return_value = {}
    mock_upload.return_value = 1000
    mock_create.return_value = ("report-id", "token-123")

    # Mock tarfile
    with patch("tarfile.open"):
        with patch("tempfile.mkdtemp", return_value=str(tmp_path)):
            with patch("shutil.rmtree"):
                process_job(base_job_data)

    mock_claude.assert_called_once()
    call_kwargs = mock_claude.call_args
    assert call_kwargs.kwargs.get("package") == "basic" or (len(call_kwargs.args) > 4 and call_kwargs.args[4] == "basic")

@patch("reporter.worker._get_minio_client")
@patch("reporter.worker._get_db_connection")
@patch("reporter.worker._download_rawdata")
@patch("reporter.worker.parse_scan_data")
@patch("reporter.worker.call_claude")
@patch("reporter.worker.map_to_report_data")
@patch("reporter.worker.generate_report")
@patch("reporter.worker._upload_report")
@patch("reporter.worker._create_report_record")
@patch("reporter.worker._update_order_status")
def test_package_passed_to_mapper(
    mock_status, mock_create, mock_upload, mock_gen,
    mock_map, mock_claude, mock_parse, mock_download,
    mock_db, mock_minio, base_job_data, tmp_path
):
    """Package should be passed to map_to_report_data()."""
    base_job_data["package"] = "nis2"
    mock_download.return_value = tmp_path / "raw.tar.gz"
    (tmp_path / "raw.tar.gz").write_bytes(b"")
    mock_parse.return_value = {"host_inventory": {"hosts": [], "domain": "example.com"}, "tech_profiles": [], "consolidated_findings": {}}
    mock_claude.return_value = {"overall_risk": "LOW", "findings": []}
    mock_map.return_value = {}
    mock_upload.return_value = 1000
    mock_create.return_value = ("report-id", "token-123")

    with patch("tarfile.open"):
        with patch("tempfile.mkdtemp", return_value=str(tmp_path)):
            with patch("shutil.rmtree"):
                process_job(base_job_data)

    mock_map.assert_called_once()
    call_kwargs = mock_map.call_args
    assert call_kwargs.kwargs.get("package") == "nis2"

@patch("reporter.worker._get_minio_client")
@patch("reporter.worker._get_db_connection")
@patch("reporter.worker._download_rawdata")
@patch("reporter.worker.parse_scan_data")
@patch("reporter.worker.call_claude")
@patch("reporter.worker.map_to_report_data")
@patch("reporter.worker.generate_report")
@patch("reporter.worker._upload_report")
@patch("reporter.worker._create_report_record")
@patch("reporter.worker._update_order_status")
def test_default_package_professional(
    mock_status, mock_create, mock_upload, mock_gen,
    mock_map, mock_claude, mock_parse, mock_download,
    mock_db, mock_minio, base_job_data, tmp_path
):
    """Missing package should default to professional."""
    # No "package" key in job_data
    mock_download.return_value = tmp_path / "raw.tar.gz"
    (tmp_path / "raw.tar.gz").write_bytes(b"")
    mock_parse.return_value = {"host_inventory": {"hosts": [], "domain": "example.com"}, "tech_profiles": [], "consolidated_findings": {}}
    mock_claude.return_value = {"overall_risk": "LOW", "findings": []}
    mock_map.return_value = {}
    mock_upload.return_value = 1000
    mock_create.return_value = ("report-id", "token-123")

    with patch("tarfile.open"):
        with patch("tempfile.mkdtemp", return_value=str(tmp_path)):
            with patch("shutil.rmtree"):
                process_job(base_job_data)

    call_kwargs = mock_claude.call_args
    assert call_kwargs.kwargs.get("package") == "professional" or (len(call_kwargs.args) > 4 and call_kwargs.args[4] == "professional")

def test_package_in_scan_meta(base_job_data, tmp_path):
    """Package should appear in scan_meta passed to mapper."""
    base_job_data["package"] = "nis2"

    captured_meta = {}

    def capture_mapper(claude_output, scan_meta, host_inventory, package="professional"):
        captured_meta.update(scan_meta)
        return {}

    with patch("reporter.worker._get_minio_client"), \
         patch("reporter.worker._get_db_connection"), \
         patch("reporter.worker._download_rawdata") as mock_dl, \
         patch("reporter.worker.parse_scan_data") as mock_parse, \
         patch("reporter.worker.call_claude") as mock_claude, \
         patch("reporter.worker.map_to_report_data", side_effect=capture_mapper), \
         patch("reporter.worker.generate_report"), \
         patch("reporter.worker._upload_report", return_value=1000), \
         patch("reporter.worker._create_report_record", return_value=("rid", "tok")), \
         patch("reporter.worker._update_order_status"), \
         patch("tarfile.open"), \
         patch("tempfile.mkdtemp", return_value=str(tmp_path)), \
         patch("shutil.rmtree"):

        mock_dl.return_value = tmp_path / "raw.tar.gz"
        mock_parse.return_value = {"host_inventory": {"hosts": [], "domain": "example.com"}, "tech_profiles": [], "consolidated_findings": {}}
        mock_claude.return_value = {"overall_risk": "LOW", "findings": []}

        process_job(base_job_data)

    assert captured_meta.get("package") == "nis2"
