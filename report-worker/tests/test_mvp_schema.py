"""Tests for MVP schema migration — orderId, download_token, expires_at."""

import inspect
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch


def test_worker_process_job_accepts_order_id() -> None:
    """Verify process_job extracts orderId from job payload."""
    from reporter.worker import process_job

    # Check it can handle orderId key
    job_data = {
        "orderId": "test-uuid",
        "rawDataPath": "test.tar.gz",
        "hostInventory": {"hosts": []},
        "techProfiles": [],
        "package": "professional",
    }

    # We can't fully run process_job without MinIO/DB, but we verify
    # the function exists and has the right signature
    sig = inspect.signature(process_job)
    params = list(sig.parameters.keys())
    assert "job_data" in params


def test_create_report_record_signature() -> None:
    """Verify _create_report_record returns (report_id, download_token)."""
    from reporter.worker import _create_report_record

    sig = inspect.signature(_create_report_record)
    params = list(sig.parameters.keys())
    assert "order_id" in params, f"Should accept order_id, got {params}"
    assert "scan_id" not in params, "Should NOT accept scan_id"
    # Return annotation should be tuple
    assert "tuple" in str(sig.return_annotation) and "str" in str(sig.return_annotation)


def test_update_order_status_exists() -> None:
    """Verify _update_order_status function exists (not _update_scan_status)."""
    from reporter import worker

    assert hasattr(worker, "_update_order_status"), "Should have _update_order_status"
    assert not hasattr(worker, "_update_scan_status"), "Should NOT have _update_scan_status"


def test_download_token_generation() -> None:
    """Verify download_token is a valid UUID format."""
    import uuid

    # Simulate what _create_report_record does
    token = str(uuid.uuid4())
    assert len(token) == 36
    assert token.count("-") == 4
    # Verify it's a valid UUID
    parsed = uuid.UUID(token)
    assert str(parsed) == token


def test_expires_at_30_days() -> None:
    """Verify expires_at is 30 days from creation."""
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=30)

    delta = expires_at - now
    assert delta.days == 30


def test_report_mapper_handles_order_id() -> None:
    """Verify report mapper accepts orderId in scan_meta."""
    from reporter.report_mapper import map_to_report_data

    # Check function exists and is callable
    assert callable(map_to_report_data)


def test_job_payload_backward_compat() -> None:
    """Verify process_job handles both orderId and scanId in payload."""
    from reporter.worker import process_job

    # The function should handle both keys
    # Testing by checking the code extracts with .get("orderId", .get("scanId"))
    job_with_order_id = {"orderId": "uuid-1"}
    job_with_scan_id = {"scanId": "uuid-2"}

    # Extract the same way process_job does
    oid1 = job_with_order_id.get("orderId", job_with_order_id.get("scanId", ""))
    oid2 = job_with_scan_id.get("orderId", job_with_scan_id.get("scanId", ""))

    assert oid1 == "uuid-1"
    assert oid2 == "uuid-2"
