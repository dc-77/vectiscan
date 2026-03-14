"""Unit tests for reporter.report_mapper module."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from reporter.report_mapper import (
    map_to_report_data,
    _count_by_severity,
    _map_finding,
    _map_positive_finding,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def claude_output() -> dict[str, Any]:
    return json.loads((FIXTURES / "claude_response.json").read_text())


@pytest.fixture()
def host_inventory() -> dict[str, Any]:
    return {
        "domain": "beispiel.de",
        "hosts": [
            {"ip": "88.99.35.112", "fqdns": ["beispiel.de", "www.beispiel.de"]},
        ],
    }


@pytest.fixture()
def scan_meta() -> dict[str, Any]:
    return {
        "domain": "beispiel.de",
        "scanId": "test-scan-123",
        "startedAt": "2026-03-12T10:00:00",
    }


# ---------------------------------------------------------------------------
# _count_by_severity
# ---------------------------------------------------------------------------


class TestCountBySeverity:
    def test_counts_correctly(self, claude_output: dict) -> None:
        counts = _count_by_severity(claude_output["findings"])
        assert counts.get("HIGH", 0) == 1
        assert counts.get("LOW", 0) == 1
        assert counts.get("CRITICAL", 0) == 0

    def test_empty_findings(self) -> None:
        counts = _count_by_severity([])
        assert all(v == 0 for v in counts.values()) if counts else True


# ---------------------------------------------------------------------------
# _map_finding
# ---------------------------------------------------------------------------


class TestMapFinding:
    def test_maps_all_fields(self, claude_output: dict) -> None:
        f = claude_output["findings"][0]
        mapped = _map_finding(f)
        assert mapped["id"] == "VS-2026-001"
        assert mapped["severity"] == "HIGH"
        assert mapped["label_description"] == "Beschreibung"
        assert mapped["label_evidence"] == "Nachweis"
        assert mapped["label_impact"] == "Geschäftsauswirkung"
        assert mapped["label_recommendation"] == "Empfehlung"


# ---------------------------------------------------------------------------
# _map_positive_finding
# ---------------------------------------------------------------------------


class TestMapPositiveFinding:
    def test_maps_positive(self, claude_output: dict) -> None:
        f = claude_output["positive_findings"][0]
        mapped = _map_positive_finding(f)
        assert mapped["severity"] == "INFO"
        assert mapped["cvss_score"] == "\u2014"
        assert mapped["label_impact"] == "Bewertung"
        assert mapped["title"] == "Korrekte TLS-Konfiguration"


# ---------------------------------------------------------------------------
# map_to_report_data (integration)
# ---------------------------------------------------------------------------


class TestMapToReportData:
    def test_returns_all_required_keys(
        self, claude_output: dict, scan_meta: dict, host_inventory: dict
    ) -> None:
        result = map_to_report_data(claude_output, scan_meta, host_inventory)
        required_keys = [
            "meta", "cover", "toc", "executive_summary", "scope",
            "findings_section_label", "findings", "recommendations",
            "appendices", "disclaimer",
        ]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"

    def test_meta_contains_vectiscan_branding(
        self, claude_output: dict, scan_meta: dict, host_inventory: dict
    ) -> None:
        result = map_to_report_data(claude_output, scan_meta, host_inventory)
        assert "VECTISCAN" in result["meta"]["header_left"]
        assert "beispiel.de" in result["meta"]["header_right"]
        assert "VERTRAULICH" in result["meta"]["classification_label"]

    def test_cover_has_domain(
        self, claude_output: dict, scan_meta: dict, host_inventory: dict
    ) -> None:
        result = map_to_report_data(claude_output, scan_meta, host_inventory)
        assert "beispiel.de" in result["cover"]["cover_title"]

    def test_findings_count(
        self, claude_output: dict, scan_meta: dict, host_inventory: dict
    ) -> None:
        result = map_to_report_data(claude_output, scan_meta, host_inventory)
        # 2 regular findings + 1 positive = 3
        assert len(result["findings"]) == 3

    def test_toc_has_finding_entries(
        self, claude_output: dict, scan_meta: dict, host_inventory: dict
    ) -> None:
        result = map_to_report_data(claude_output, scan_meta, host_inventory)
        toc = result["toc"]
        # Should contain entries for each finding
        sub_entries = [e for e in toc if e[2] is True]
        assert len(sub_entries) >= 3  # 2 findings + 1 positive

    def test_disclaimer_in_german(
        self, claude_output: dict, scan_meta: dict, host_inventory: dict
    ) -> None:
        result = map_to_report_data(claude_output, scan_meta, host_inventory)
        assert "Haftungsausschluss" in result["disclaimer"]

    def test_findings_section_label_german(
        self, claude_output: dict, scan_meta: dict, host_inventory: dict
    ) -> None:
        result = map_to_report_data(claude_output, scan_meta, host_inventory)
        assert "Befunde" in result["findings_section_label"]

    def test_appendices_contain_cvss_and_tools(
        self, claude_output: dict, scan_meta: dict, host_inventory: dict
    ) -> None:
        result = map_to_report_data(claude_output, scan_meta, host_inventory)
        appendices = result["appendices"]
        assert len(appendices) >= 2
        titles = [a["title"] for a in appendices]
        # Check we have CVSS and tools appendices
        assert any("CVSS" in t for t in titles)
        assert any("Tool" in t for t in titles)
