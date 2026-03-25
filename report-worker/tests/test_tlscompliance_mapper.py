"""Tests for TLS Compliance package mapper and integration."""

import pytest

from reporter.report_mapper import (
    map_tlscompliance_report,
    map_to_report_data,
    TR_MANUAL_CHECKLIST,
)


@pytest.fixture
def scan_meta():
    return {
        "domain": "example.com",
        "orderId": "test-123",
        "startedAt": "2026-03-25T10:00:00Z",
        "completedAt": "2026-03-25T10:05:00Z",
        "package": "tlscompliance",
        "toolVersions": ["testssl.sh 3.2"],
    }


@pytest.fixture
def host_inventory():
    return {
        "domain": "example.com",
        "hosts": [
            {"ip": "1.2.3.4", "fqdns": ["example.com"]},
        ],
    }


@pytest.fixture
def claude_output():
    return {
        "overall_risk": "LOW",
        "executive_summary": "Die TLS-Konfiguration von example.com ist weitgehend konform.",
        "recommendations": [],
    }


class TestMapTlscomplianceReport:
    """Tests for the tlscompliance mapper function."""

    def test_produces_valid_report_data(self, claude_output, scan_meta, host_inventory):
        result = map_tlscompliance_report(claude_output, scan_meta, host_inventory)
        assert "meta" in result
        assert "cover" in result
        assert "toc" in result
        assert "executive_summary" in result
        assert result["cover"]["package"] == "tlscompliance"

    def test_cover_title_contains_domain(self, claude_output, scan_meta, host_inventory):
        result = map_tlscompliance_report(claude_output, scan_meta, host_inventory)
        assert "example.com" in result["cover"]["cover_title"]

    def test_manual_checklist_present(self, claude_output, scan_meta, host_inventory):
        result = map_tlscompliance_report(claude_output, scan_meta, host_inventory)
        assert "manual_checklist" in result
        checklist = result["manual_checklist"]
        assert len(checklist) >= 5
        # Verify structure
        for item in checklist:
            assert "check_id" in item
            assert "title" in item
            assert "instruction" in item
            assert "expected" in item

    def test_no_pentest_findings(self, claude_output, scan_meta, host_inventory):
        result = map_tlscompliance_report(claude_output, scan_meta, host_inventory)
        assert result["findings"] == []

    def test_toc_has_checklist_and_attestation(self, claude_output, scan_meta, host_inventory):
        result = map_tlscompliance_report(claude_output, scan_meta, host_inventory)
        toc_titles = [t for _, t, _ in result["toc"]]
        assert "Manuelle Checkliste" in toc_titles
        assert "Compliance-Bescheinigung" in toc_titles

    def test_executive_summary_from_haiku(self, claude_output, scan_meta, host_inventory):
        result = map_tlscompliance_report(claude_output, scan_meta, host_inventory)
        paragraphs = result["executive_summary"]["subsections"][0]["paragraphs"]
        assert "weitgehend konform" in paragraphs[0]


class TestDispatcherTlscompliance:
    """Tests for the dispatcher routing to tlscompliance mapper."""

    def test_dispatcher_routes_to_tlscompliance(self, claude_output, scan_meta, host_inventory):
        result = map_to_report_data(
            claude_output, scan_meta, host_inventory,
            package="tlscompliance",
        )
        assert result["cover"]["package"] == "tlscompliance"
        assert "manual_checklist" in result


class TestManualChecklist:
    """Tests for the manual checklist content."""

    def test_checklist_has_smime(self):
        ids = [c["check_id"] for c in TR_MANUAL_CHECKLIST]
        assert "3.1" in ids

    def test_checklist_has_saml(self):
        ids = [c["check_id"] for c in TR_MANUAL_CHECKLIST]
        assert "4.1" in ids

    def test_checklist_has_openpgp(self):
        ids = [c["check_id"] for c in TR_MANUAL_CHECKLIST]
        assert "5.1" in ids

    def test_checklist_has_truncated_hmac(self):
        ids = [c["check_id"] for c in TR_MANUAL_CHECKLIST]
        assert "2.5.3" in ids
