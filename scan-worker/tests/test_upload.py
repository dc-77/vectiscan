"""Tests for upload — MinIO upload and report job enqueue."""

import json
import os
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _reset_bucket_cache():
    """Modul-Cache fuer Bucket-Existence-Check pro Test zuruecksetzen.

    F-PH9-001: ensure_bucket() cached verifizierte Buckets im Modul-State.
    Ohne Reset wuerde der naechste Test je nach Test-Reihenfolge
    `bucket_exists`/`make_bucket`-Calls verlieren.
    """
    from scanner import upload as _upload_mod
    _upload_mod._VERIFIED_BUCKETS.clear()
    yield
    _upload_mod._VERIFIED_BUCKETS.clear()


def test_pack_results_creates_valid_tar_gz(tmp_path: Path) -> None:
    """pack_results creates a valid tar.gz archive from the scan directory."""
    from scanner.upload import pack_results

    # Create a fake scan directory with files
    scan_dir = tmp_path / "scan-data"
    scan_dir.mkdir()
    (scan_dir / "meta.json").write_text('{"scanId": "test-123"}')
    phase0_dir = scan_dir / "phase0"
    phase0_dir.mkdir()
    (phase0_dir / "crtsh.json").write_text("[]")

    archive_path = pack_results(str(scan_dir), "test-123")

    assert os.path.exists(archive_path)
    assert archive_path.endswith(".tar.gz")

    # Verify the archive is valid and contains expected files
    with tarfile.open(archive_path, "r:gz") as tar:
        names = tar.getnames()
        assert any("meta.json" in n for n in names)
        assert any("crtsh.json" in n for n in names)

    # Cleanup
    os.remove(archive_path)


def test_pack_results_uses_scan_id_as_arcname(tmp_path: Path) -> None:
    """pack_results uses scan_id as the archive root directory name."""
    from scanner.upload import pack_results

    scan_dir = tmp_path / "scan-data"
    scan_dir.mkdir()
    (scan_dir / "meta.json").write_text("{}")

    archive_path = pack_results(str(scan_dir), "my-scan-id")

    with tarfile.open(archive_path, "r:gz") as tar:
        # Root entry should be the scan_id
        root_dirs = {n.split("/")[0] for n in tar.getnames()}
        assert "my-scan-id" in root_dirs

    os.remove(archive_path)


@patch("scanner.upload.get_minio_client")
def test_upload_to_minio_calls_fput_object(mock_get_client: MagicMock, tmp_path: Path) -> None:
    """upload_to_minio calls fput_object with correct bucket and object name."""
    from scanner.upload import upload_to_minio

    mock_client = MagicMock()
    mock_client.bucket_exists.return_value = True
    mock_get_client.return_value = mock_client

    # Create a fake archive file
    archive_path = str(tmp_path / "test-scan.tar.gz")
    with open(archive_path, "w") as f:
        f.write("fake archive data")

    result = upload_to_minio(archive_path, "scan-456")

    assert result == "scan-456.tar.gz"
    mock_client.fput_object.assert_called_once_with(
        "scan-rawdata", "scan-456.tar.gz", archive_path,
    )
    # Archive should be cleaned up
    assert not os.path.exists(archive_path)


@patch("scanner.upload.get_minio_client")
def test_upload_to_minio_creates_bucket_if_missing(mock_get_client: MagicMock, tmp_path: Path) -> None:
    """upload_to_minio creates the bucket if it doesn't exist."""
    from scanner.upload import upload_to_minio

    mock_client = MagicMock()
    mock_client.bucket_exists.return_value = False
    mock_get_client.return_value = mock_client

    archive_path = str(tmp_path / "test.tar.gz")
    with open(archive_path, "w") as f:
        f.write("data")

    upload_to_minio(archive_path, "scan-789")

    mock_client.make_bucket.assert_called_once_with("scan-rawdata")


@patch("scanner.upload.redis")
def test_enqueue_report_job_pushes_correct_payload(mock_redis_module: MagicMock) -> None:
    """enqueue_report_job pushes correct JSON to report-pending queue."""
    from scanner.upload import enqueue_report_job

    mock_redis_client = MagicMock()
    mock_redis_module.from_url.return_value = mock_redis_client

    host_inventory = {"domain": "example.com", "hosts": [{"ip": "1.1.1.1"}]}
    tech_profiles = [{"ip": "1.1.1.1", "has_ssl": True}]

    enqueue_report_job(
        order_id="scan-abc",
        minio_path="scan-rawdata/scan-abc.tar.gz",
        host_inventory=host_inventory,
        tech_profiles=tech_profiles,
    )

    mock_redis_client.rpush.assert_called_once()
    queue_name = mock_redis_client.rpush.call_args[0][0]
    payload_json = mock_redis_client.rpush.call_args[0][1]

    assert queue_name == "report-pending"

    payload = json.loads(payload_json)
    assert payload["orderId"] == "scan-abc"
    assert payload["rawDataPath"] == "scan-rawdata/scan-abc.tar.gz"
    assert payload["hostInventory"] == host_inventory
    assert payload["techProfiles"] == tech_profiles


# ---------------------------------------------------------------------------
# F-PH9-001: Parallel-Screenshot-Upload + Modul-Bucket-Cache
# ---------------------------------------------------------------------------


@patch("scanner.upload.get_minio_client")
def test_ensure_bucket_caches_after_first_call(mock_get_client: MagicMock) -> None:
    """ensure_bucket ruft bucket_exists nur beim ersten Aufruf auf."""
    from scanner.upload import ensure_bucket

    mock_client = MagicMock()
    mock_client.bucket_exists.return_value = True

    ensure_bucket(mock_client, "scan-rawdata")
    ensure_bucket(mock_client, "scan-rawdata")
    ensure_bucket(mock_client, "scan-rawdata")

    # Nur ein Roundtrip — danach Cache-Hit
    assert mock_client.bucket_exists.call_count == 1
    mock_client.make_bucket.assert_not_called()


@patch("scanner.upload.get_minio_client")
def test_ensure_bucket_creates_when_missing_then_caches(mock_get_client: MagicMock) -> None:
    """ensure_bucket erstellt Bucket bei Fehl-Status, dann cache-Hit."""
    from scanner.upload import ensure_bucket

    mock_client = MagicMock()
    mock_client.bucket_exists.return_value = False

    ensure_bucket(mock_client, "scan-screenshots")
    ensure_bucket(mock_client, "scan-screenshots")

    # bucket_exists genau einmal, make_bucket genau einmal
    assert mock_client.bucket_exists.call_count == 1
    mock_client.make_bucket.assert_called_once_with("scan-screenshots")


@patch("scanner.upload.get_minio_client")
def test_prewarm_buckets_verifies_default_set(mock_get_client: MagicMock) -> None:
    """prewarm_buckets verifiziert beide Standard-Buckets beim Worker-Start."""
    from scanner import upload as _upload_mod
    from scanner.upload import prewarm_buckets

    mock_client = MagicMock()
    mock_client.bucket_exists.return_value = True
    mock_get_client.return_value = mock_client

    prewarm_buckets()

    # Beide Standard-Buckets im Cache
    assert "scan-rawdata" in _upload_mod._VERIFIED_BUCKETS
    assert "scan-screenshots" in _upload_mod._VERIFIED_BUCKETS
    assert mock_client.bucket_exists.call_count == 2


@patch("scanner.upload.get_minio_client")
def test_upload_screenshots_uploads_all_pngs_in_parallel(
    mock_get_client: MagicMock, tmp_path: Path,
) -> None:
    """upload_screenshots laedt alle gefundenen PNGs parallel hoch."""
    from scanner.upload import upload_screenshots

    mock_client = MagicMock()
    mock_client.bucket_exists.return_value = True
    mock_get_client.return_value = mock_client

    # Erstelle Screenshots-Layout: scan_dir/hosts/<ip>/phase1/screenshot_*.png
    scan_dir = tmp_path / "scan-data"
    host_dir = scan_dir / "hosts" / "1.2.3.4" / "phase1"
    host_dir.mkdir(parents=True)
    fqdns = ["a_example_com", "b_example_com", "c_example_com"]
    for safe in fqdns:
        (host_dir / f"screenshot_{safe}.png").write_bytes(b"fake-png")

    result = upload_screenshots(str(scan_dir), "order-xyz")

    # Alle drei Screenshots im Mapping
    assert len(result) == 3
    assert "a.example.com" in result
    assert "b.example.com" in result
    assert "c.example.com" in result
    # fput_object wurde fuer jeden Screenshot mindestens einmal aufgerufen
    assert mock_client.fput_object.call_count == 3


@patch("scanner.upload.get_minio_client")
def test_upload_screenshots_empty_dir_returns_empty_dict(
    mock_get_client: MagicMock, tmp_path: Path,
) -> None:
    """Ohne Screenshots liefert upload_screenshots leeres Dict (kein Crash)."""
    from scanner.upload import upload_screenshots

    mock_client = MagicMock()
    mock_client.bucket_exists.return_value = True
    mock_get_client.return_value = mock_client

    scan_dir = tmp_path / "empty-scan"
    scan_dir.mkdir()

    result = upload_screenshots(str(scan_dir), "order-empty")

    assert result == {}
    mock_client.fput_object.assert_not_called()
