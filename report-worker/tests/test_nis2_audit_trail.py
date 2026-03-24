"""Tests for NIS2 audit trail PDF section."""

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


class TestAuditTrail:
    def test_generates_pdf_with_audit_trail(self, tmp_path):
        data = _minimal_report_data()
        data["nis2"] = {
            "audit_trail": {
                "scan_start": "2026-03-14T10:00:00Z",
                "scan_end": "2026-03-14T10:45:00Z",
                "duration": "45 Minuten",
                "hosts_scanned": 3,
                "tools": [
                    "nmap 7.94", "testssl.sh 3.2", "gobuster 3.8.2",
                    "ffuf 2.1.0", "feroxbuster 2.11.0",
                ],
            },
        }
        path = str(tmp_path / "audit_trail.pdf")
        generate_report(data, path)
        assert os.path.isfile(path)
        assert os.path.getsize(path) > 0

    def test_handles_empty_tools_list(self, tmp_path):
        data = _minimal_report_data()
        data["nis2"] = {
            "audit_trail": {
                "scan_start": "2026-03-14T10:00:00Z",
                "scan_end": "2026-03-14T10:45:00Z",
                "duration": "45 Minuten",
                "hosts_scanned": 1,
                "tools": [],
            },
        }
        path = str(tmp_path / "audit_empty_tools.pdf")
        generate_report(data, path)
        assert os.path.isfile(path)
        assert os.path.getsize(path) > 0
