"""Tests for NIS2 compliance summary PDF section."""

import os
import pytest
from reporter.generate_report import generate_report


def _minimal_report_data():
    """Minimal report_data for PDF generation."""
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


class TestComplianceSummary:
    def test_generates_pdf_all_covered(self, tmp_path):
        data = _minimal_report_data()
        data["nis2"] = {
            "compliance_summary": {
                "nr1_risikoanalyse": "COVERED",
                "nr2_vorfallbewaeltigung": "COVERED",
                "nr4_lieferkette": "COVERED",
                "nr5_schwachstellenmanagement": "COVERED",
                "nr6_wirksamkeitsbewertung": "COVERED",
                "nr8_kryptografie": "COVERED",
                "scope_note": "Dieser Scan deckt die externe Angriffsoberfläche ab.",
            },
        }
        path = str(tmp_path / "compliance_all_covered.pdf")
        generate_report(data, path)
        assert os.path.isfile(path)
        assert os.path.getsize(path) > 0

    def test_generates_pdf_mixed_status(self, tmp_path):
        data = _minimal_report_data()
        data["nis2"] = {
            "compliance_summary": {
                "nr1_risikoanalyse": "PARTIAL",
                "nr2_vorfallbewaeltigung": "NOT_IN_SCOPE",
                "nr4_lieferkette": "COVERED",
                "nr5_schwachstellenmanagement": "COVERED",
                "nr6_wirksamkeitsbewertung": "PARTIAL",
                "nr8_kryptografie": "COVERED",
                "scope_note": "Teilweise Abdeckung.",
            },
        }
        path = str(tmp_path / "compliance_mixed.pdf")
        generate_report(data, path)
        assert os.path.isfile(path)
        assert os.path.getsize(path) > 0

    def test_handles_missing_fields(self, tmp_path):
        """Missing fields should not crash."""
        data = _minimal_report_data()
        data["nis2"] = {
            "compliance_summary": {
                "nr5_schwachstellenmanagement": "COVERED",
                # Other fields missing — should default gracefully
            },
        }
        path = str(tmp_path / "compliance_partial_fields.pdf")
        generate_report(data, path)
        assert os.path.isfile(path)
        assert os.path.getsize(path) > 0
