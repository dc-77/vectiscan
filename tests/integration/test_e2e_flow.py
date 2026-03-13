"""End-to-end integration test for the VectiScan scan pipeline.

Requires a running VectiScan stack (docker compose up).
Uses scanme.nmap.org as the test target (explicitly allows scanning).

Usage:
    pytest tests/integration/test_e2e_flow.py -v -s --timeout=900

Environment:
    API_BASE_URL: Base URL of the API (default: http://localhost:4000)
"""

import os
import time

import pytest
import requests

API_BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:4000")
TEST_DOMAIN = "scanme.nmap.org"

# Maximum time to wait for the entire scan+report pipeline (15 minutes)
E2E_TIMEOUT_SECONDS = 900
POLL_INTERVAL_SECONDS = 10

# Expected status transitions in order
VALID_STATUSES = [
    "created",
    "dns_recon",
    "scan_phase1",
    "scan_phase2",
    "scan_complete",
    "report_generating",
    "report_complete",
]


@pytest.fixture(scope="module")
def scan_id():
    """Create a scan and return its ID."""
    resp = requests.post(
        f"{API_BASE_URL}/api/scans",
        json={"domain": TEST_DOMAIN},
        timeout=10,
    )
    assert resp.status_code == 201, f"Failed to create scan: {resp.text}"
    body = resp.json()
    assert body["success"] is True
    assert "id" in body["data"]
    assert body["data"]["domain"] == TEST_DOMAIN
    assert body["data"]["status"] == "created"
    return body["data"]["id"]


def _poll_scan(scan_id: str) -> list[dict]:
    """Poll scan status until completion or timeout. Returns list of observed states."""
    observed_states = []
    start = time.time()

    while time.time() - start < E2E_TIMEOUT_SECONDS:
        resp = requests.get(f"{API_BASE_URL}/api/scans/{scan_id}", timeout=10)
        assert resp.status_code == 200
        data = resp.json()["data"]
        status = data["status"]

        if not observed_states or observed_states[-1]["status"] != status:
            observed_states.append(
                {
                    "status": status,
                    "timestamp": time.time() - start,
                    "data": data,
                }
            )

        if status == "report_complete":
            return observed_states

        if status == "failed":
            pytest.fail(
                f"Scan failed after {time.time() - start:.0f}s: "
                f"{data.get('error', 'unknown error')}"
            )

        time.sleep(POLL_INTERVAL_SECONDS)

    pytest.fail(
        f"Scan did not complete within {E2E_TIMEOUT_SECONDS}s. "
        f"Last status: {observed_states[-1]['status'] if observed_states else 'unknown'}"
    )


@pytest.fixture(scope="module")
def scan_result(scan_id):
    """Poll until scan completes and return all observed state transitions."""
    return _poll_scan(scan_id)


class TestStatusTransitions:
    """Verify that status transitions follow the expected order."""

    def test_statuses_in_correct_order(self, scan_result):
        statuses = [s["status"] for s in scan_result]
        # Each observed status must appear in VALID_STATUSES and be in order
        for i, status in enumerate(statuses):
            assert status in VALID_STATUSES, f"Unexpected status: {status}"
            if i > 0:
                prev_idx = VALID_STATUSES.index(statuses[i - 1])
                curr_idx = VALID_STATUSES.index(status)
                assert curr_idx > prev_idx, (
                    f"Status went backwards: {statuses[i-1]} → {status}"
                )

    def test_starts_with_created(self, scan_result):
        assert scan_result[0]["status"] == "created"

    def test_ends_with_report_complete(self, scan_result):
        assert scan_result[-1]["status"] == "report_complete"

    def test_dns_recon_phase_observed(self, scan_result):
        statuses = [s["status"] for s in scan_result]
        assert "dns_recon" in statuses, "dns_recon phase was never observed"


class TestDiscoveredHosts:
    """Verify host discovery after Phase 0."""

    def test_hosts_populated_after_dns_recon(self, scan_result):
        """After dns_recon, discovered_hosts should be populated."""
        # Find first state after dns_recon
        for state in scan_result:
            if state["status"] in ("scan_phase1", "scan_phase2", "scan_complete",
                                    "report_generating", "report_complete"):
                progress = state["data"].get("progress", {})
                hosts = progress.get("discoveredHosts", [])
                assert len(hosts) > 0, "No hosts discovered after dns_recon"
                return
        pytest.skip("No post-dns_recon state captured in polling")

    def test_hosts_total_matches_discovered(self, scan_result):
        final = scan_result[-1]["data"]
        progress = final.get("progress", {})
        hosts = progress.get("discoveredHosts", [])
        hosts_total = progress.get("hostsTotal", 0)
        assert hosts_total == len(hosts)

    def test_hosts_total_within_limit(self, scan_result):
        """Max 10 hosts as per CLAUDE.md spec."""
        final = scan_result[-1]["data"]
        progress = final.get("progress", {})
        assert progress.get("hostsTotal", 0) <= 10


class TestHostsCompleted:
    """Verify hosts_completed counter increments."""

    def test_all_hosts_completed_at_end(self, scan_result):
        final = scan_result[-1]["data"]
        progress = final.get("progress", {})
        assert progress.get("hostsCompleted", 0) == progress.get("hostsTotal", 0)

    def test_hosts_completed_monotonically_increasing(self, scan_result):
        prev = 0
        for state in scan_result:
            progress = state["data"].get("progress", {})
            completed = progress.get("hostsCompleted", 0)
            assert completed >= prev, (
                f"hostsCompleted decreased: {prev} → {completed}"
            )
            prev = completed


class TestReportDownload:
    """Verify the report is available and is a valid PDF."""

    def test_report_endpoint_returns_download_url(self, scan_id, scan_result):
        resp = requests.get(
            f"{API_BASE_URL}/api/scans/{scan_id}/report", timeout=10
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is True
        assert "downloadUrl" in body["data"]
        assert "fileName" in body["data"]
        assert body["data"]["fileName"].endswith(".pdf")

    def test_pdf_exists_in_minio(self, scan_id, scan_result):
        resp = requests.get(
            f"{API_BASE_URL}/api/scans/{scan_id}/report", timeout=10
        )
        download_url = resp.json()["data"]["downloadUrl"]

        pdf_resp = requests.get(download_url, timeout=30)
        assert pdf_resp.status_code == 200, (
            f"Failed to download PDF: {pdf_resp.status_code}"
        )
        assert len(pdf_resp.content) > 0, "PDF is empty"

    def test_pdf_has_valid_magic_bytes(self, scan_id, scan_result):
        resp = requests.get(
            f"{API_BASE_URL}/api/scans/{scan_id}/report", timeout=10
        )
        download_url = resp.json()["data"]["downloadUrl"]

        pdf_resp = requests.get(download_url, timeout=30)
        # PDF magic bytes: %PDF
        assert pdf_resp.content[:4] == b"%PDF", (
            f"Invalid PDF magic bytes: {pdf_resp.content[:4]!r}"
        )

    def test_pdf_file_size_reasonable(self, scan_id, scan_result):
        resp = requests.get(
            f"{API_BASE_URL}/api/scans/{scan_id}/report", timeout=10
        )
        body = resp.json()["data"]
        # PDF should be at least 10KB and less than 50MB
        file_size = body.get("fileSize", 0)
        assert file_size > 10_000, f"PDF too small: {file_size} bytes"
        assert file_size < 50_000_000, f"PDF too large: {file_size} bytes"
