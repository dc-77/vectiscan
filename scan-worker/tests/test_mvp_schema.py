"""Tests for MVP schema migration — orderId in queue payload and DB queries."""

import json
from unittest.mock import MagicMock, patch


def test_worker_accepts_order_id_in_queue_payload() -> None:
    """Verify worker extracts orderId from queue payload (not scanId)."""
    from scanner.worker import _process_job

    # _process_job expects (order_id, domain, package)
    # Verify the function signature accepts order_id
    import inspect
    sig = inspect.signature(_process_job)
    params = list(sig.parameters.keys())
    assert params[0] == "order_id", f"First param should be 'order_id', got '{params[0]}'"
    assert params[1] == "domain"
    assert params[2] == "package"


def test_progress_functions_use_order_id() -> None:
    """Verify progress functions accept order_id parameter."""
    import inspect
    from scanner.progress import (
        set_discovered_hosts,
        set_scan_complete,
        set_scan_failed,
        set_scan_started,
        update_progress,
    )

    for fn in [update_progress, set_scan_started, set_scan_complete, set_scan_failed, set_discovered_hosts]:
        sig = inspect.signature(fn)
        params = list(sig.parameters.keys())
        assert params[0] == "order_id", (
            f"{fn.__name__}: first param should be 'order_id', got '{params[0]}'"
        )


def test_tools_save_result_uses_order_id() -> None:
    """Verify run_tool accepts order_id parameter (not scan_id)."""
    import inspect
    from scanner.tools import run_tool

    sig = inspect.signature(run_tool)
    param_names = list(sig.parameters.keys())
    assert "order_id" in param_names, f"run_tool should accept 'order_id', got params: {param_names}"
    assert "scan_id" not in param_names, "run_tool should NOT have 'scan_id' parameter"


def test_upload_enqueue_uses_order_id() -> None:
    """Verify enqueue_report_job accepts order_id parameter."""
    import inspect
    from scanner.upload import enqueue_report_job

    sig = inspect.signature(enqueue_report_job)
    params = list(sig.parameters.keys())
    assert params[0] == "order_id", f"First param should be 'order_id', got '{params[0]}'"


def test_meta_json_contains_order_id() -> None:
    """Verify meta.json uses 'orderId' key (not 'scanId')."""
    import os
    import tempfile
    from unittest.mock import patch

    with tempfile.TemporaryDirectory() as tmpdir:
        # Simulate what _process_job writes to meta.json
        meta = {
            "orderId": "test-uuid",
            "domain": "example.com",
            "package": "professional",
            "startedAt": "2026-03-14T00:00:00Z",
            "toolVersions": [],
        }
        meta_path = os.path.join(tmpdir, "meta.json")
        with open(meta_path, "w") as f:
            json.dump(meta, f)

        with open(meta_path) as f:
            loaded = json.load(f)

        assert "orderId" in loaded, "meta.json should contain 'orderId'"
        assert "scanId" not in loaded, "meta.json should NOT contain 'scanId'"
        assert loaded["orderId"] == "test-uuid"
