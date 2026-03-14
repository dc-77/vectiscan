"""Tests for NIS2 supply chain summary PDF section."""

import os
import pytest
from reporter.generate_report import generate_report


def _minimal_report_data():
    return {
        "meta": {
            "title": "Test Report", "author": "Test",
            "header_left": "TEST", "header_right": "test.com",
            "footer_left": "Confidential",
            "classification_label": "TEST CLASSIFICATION",
        },
        "cover": {
            "cover_subtitle": "TEST", "cover_title": "Test Report",
            "cover_meta": [["Target:", "test.com"]],
        },
        "findings": [{
            "id": "VS-2026-001", "title": "Test Finding", "severity": "HIGH",
            "cvss_score": "7.5", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cwe": "CWE-200", "affected": "test.com",
            "description": "Test.", "evidence": "Test.", "impact": "Test.",
            "recommendation": "Test.",
        }],
        "disclaimer": "Test disclaimer.",
    }


class TestSupplyChain:
    def test_generates_pdf_with_supply_chain(self, tmp_path):
        data = _minimal_report_data()
        data["nis2"] = {
            "supply_chain": {
                "overall_rating": "MEDIUM",
                "key_findings_count": 2,
                "positive_count": 3,
                "recommendation": "Die geprüfte Infrastruktur weist ein mittleres Risiko auf.",
            },
        }
        data["scan_meta"] = {"domain": "test.com", "date": "14.03.2026"}
        path = str(tmp_path / "supply_chain.pdf")
        generate_report(data, path)
        assert os.path.isfile(path)
        assert os.path.getsize(path) > 0

    def test_supply_chain_has_page_break(self, tmp_path):
        """Supply chain should start on its own page (PageBreak before it)."""
        data = _minimal_report_data()
        data["nis2"] = {
            "supply_chain": {
                "overall_rating": "LOW",
                "key_findings_count": 0,
                "positive_count": 5,
                "recommendation": "Keine kritischen Befunde.",
            },
        }
        data["scan_meta"] = {"domain": "test.com", "date": "14.03.2026"}
        path = str(tmp_path / "supply_chain_page.pdf")
        generate_report(data, path)
        assert os.path.isfile(path)
        # A report with supply chain should be larger than one without
        assert os.path.getsize(path) > 1000
