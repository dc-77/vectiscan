"""Tests for NIS2 reference badge in findings."""

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
        "findings": [],
        "disclaimer": "Test disclaimer.",
    }


class TestNIS2RefBadge:
    def test_finding_with_nis2_ref(self, tmp_path):
        data = _minimal_report_data()
        data["findings"] = [{
            "id": "VS-2026-001", "title": "TLS-Schwäche", "severity": "MEDIUM",
            "cvss_score": "5.4", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            "cwe": "CWE-326", "affected": "test.com:443",
            "description": "TLS 1.0 aktiv.", "evidence": "testssl output",
            "impact": "Schwache Verschlüsselung.", "recommendation": "TLS 1.2+ erzwingen.",
            "nis2_ref": "§30 Abs. 2 Nr. 8 BSIG",
        }]
        path = str(tmp_path / "finding_with_nis2.pdf")
        generate_report(data, path)
        assert os.path.isfile(path)
        assert os.path.getsize(path) > 0

    def test_finding_without_nis2_ref(self, tmp_path):
        data = _minimal_report_data()
        data["findings"] = [{
            "id": "VS-2026-001", "title": "Test Finding", "severity": "HIGH",
            "cvss_score": "7.5", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cwe": "CWE-200", "affected": "test.com",
            "description": "Test.", "evidence": "Test.", "impact": "Test.",
            "recommendation": "Test.",
            # No nis2_ref field
        }]
        path = str(tmp_path / "finding_without_nis2.pdf")
        generate_report(data, path)
        assert os.path.isfile(path)
        assert os.path.getsize(path) > 0
