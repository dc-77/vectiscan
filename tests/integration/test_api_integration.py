"""API integration tests for VectiScan.

Tests error handling, validation, and edge cases against a running API.

Usage:
    pytest tests/integration/test_api_integration.py -v --timeout=30

Environment:
    API_BASE_URL: Base URL of the API (default: http://localhost:4000)
"""

import os
import uuid

import pytest
import requests

API_BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:4000")


class TestHealthEndpoint:
    """GET /health"""

    def test_health_returns_200(self):
        resp = requests.get(f"{API_BASE_URL}/health", timeout=5)
        assert resp.status_code == 200

    def test_health_returns_ok_status(self):
        resp = requests.get(f"{API_BASE_URL}/health", timeout=5)
        body = resp.json()
        assert body["status"] == "ok"

    def test_health_has_timestamp(self):
        resp = requests.get(f"{API_BASE_URL}/health", timeout=5)
        body = resp.json()
        assert "timestamp" in body


class TestPostScansValidation:
    """POST /api/scans — error cases"""

    def test_missing_domain_returns_400(self):
        resp = requests.post(
            f"{API_BASE_URL}/api/scans",
            json={},
            timeout=10,
        )
        assert resp.status_code == 400
        body = resp.json()
        assert body["success"] is False

    def test_empty_domain_returns_400(self):
        resp = requests.post(
            f"{API_BASE_URL}/api/scans",
            json={"domain": ""},
            timeout=10,
        )
        assert resp.status_code == 400

    def test_domain_with_protocol_returns_400(self):
        resp = requests.post(
            f"{API_BASE_URL}/api/scans",
            json={"domain": "https://example.com"},
            timeout=10,
        )
        assert resp.status_code == 400

    def test_domain_with_path_returns_400(self):
        resp = requests.post(
            f"{API_BASE_URL}/api/scans",
            json={"domain": "example.com/path"},
            timeout=10,
        )
        assert resp.status_code == 400

    def test_domain_with_port_returns_400(self):
        resp = requests.post(
            f"{API_BASE_URL}/api/scans",
            json={"domain": "example.com:8080"},
            timeout=10,
        )
        assert resp.status_code == 400

    def test_invalid_tld_returns_400(self):
        resp = requests.post(
            f"{API_BASE_URL}/api/scans",
            json={"domain": "not-a-domain"},
            timeout=10,
        )
        assert resp.status_code == 400

    def test_error_response_format(self):
        resp = requests.post(
            f"{API_BASE_URL}/api/scans",
            json={"domain": "invalid"},
            timeout=10,
        )
        body = resp.json()
        assert body["success"] is False
        assert "error" in body


class TestGetScanNotFound:
    """GET /api/scans/:id — not found cases"""

    def test_nonexistent_uuid_returns_404(self):
        fake_id = str(uuid.uuid4())
        resp = requests.get(
            f"{API_BASE_URL}/api/scans/{fake_id}", timeout=10
        )
        assert resp.status_code == 404
        body = resp.json()
        assert body["success"] is False

    def test_invalid_id_format_returns_400_or_404(self):
        resp = requests.get(
            f"{API_BASE_URL}/api/scans/not-a-uuid", timeout=10
        )
        assert resp.status_code in (400, 404)


class TestGetReportNotReady:
    """GET /api/scans/:id/report — before report is ready"""

    def test_nonexistent_scan_returns_404(self):
        fake_id = str(uuid.uuid4())
        resp = requests.get(
            f"{API_BASE_URL}/api/scans/{fake_id}/report", timeout=10
        )
        assert resp.status_code == 404

    def test_new_scan_has_no_report(self):
        """Create a scan and immediately request report — should be 404."""
        create_resp = requests.post(
            f"{API_BASE_URL}/api/scans",
            json={"domain": "scanme.nmap.org"},
            timeout=10,
        )
        if create_resp.status_code != 201:
            pytest.skip("Could not create scan")

        scan_id = create_resp.json()["data"]["id"]
        report_resp = requests.get(
            f"{API_BASE_URL}/api/scans/{scan_id}/report", timeout=10
        )
        assert report_resp.status_code == 404
        body = report_resp.json()
        assert body["success"] is False


class TestResponseFormat:
    """Verify consistent JSON response format across endpoints."""

    def test_success_response_has_data_key(self):
        resp = requests.post(
            f"{API_BASE_URL}/api/scans",
            json={"domain": "scanme.nmap.org"},
            timeout=10,
        )
        if resp.status_code == 201:
            body = resp.json()
            assert "success" in body
            assert "data" in body

    def test_error_response_has_error_key(self):
        resp = requests.post(
            f"{API_BASE_URL}/api/scans",
            json={"domain": "invalid"},
            timeout=10,
        )
        body = resp.json()
        assert "success" in body
        assert "error" in body

    def test_content_type_is_json(self):
        resp = requests.get(f"{API_BASE_URL}/health", timeout=5)
        assert "application/json" in resp.headers.get("content-type", "")
