"""Tests for a complete NIS2 report with all sections."""

import os
import pytest
from reporter.generate_report import generate_report


def _full_nis2_report_data():
    """Complete report_data for NIS2 report with all sections."""
    return {
        "meta": {
            "title": "NIS2 Security Assessment — test.com",
            "author": "VectiScan Automated Security Assessment",
            "header_left": "VECTISCAN — SECURITY ASSESSMENT",
            "header_right": "test.com",
            "footer_left": "Vertraulich | 14.03.2026",
            "classification_label": "KLASSIFIZIERUNG: VERTRAULICH — NUR FÜR AUTORISIERTE EMPFÄNGER",
        },
        "cover": {
            "cover_subtitle": "AUTOMATED SECURITY ASSESSMENT",
            "cover_title": "Sicherheitsbewertung<br/>test.com",
            "package": "nis2",
            "cover_meta": [
                ["Ziel:", "test.com (3 Hosts)"],
                ["Datum:", "14.03.2026"],
                ["Methodik:", "PTES (automatisiert)"],
                ["Scoring:", "CVSS v3.1"],
                ["Klassifizierung:", "Vertraulich"],
                ["Befunde:", "1 HIGH, 1 INFO"],
            ],
        },
        "toc": [
            ("1", "Executive Summary", False),
            ("2", "NIS2-Compliance-Übersicht", False),
            ("3", "Befunde", False),
            ("3.1", "VS-2026-001 — TLS-Schwäche", True),
            ("3.2", "VS-2026-002 — Korrekte HSTS-Konfiguration", True),
            ("4", "Empfehlungen", False),
            ("5", "Audit-Trail", False),
            ("6", "Lieferketten-Zusammenfassung", False),
        ],
        "executive_summary": {
            "section_label": "1&nbsp;&nbsp;&nbsp;Executive Summary",
            "subsections": [{
                "title": "1.1&nbsp;&nbsp;&nbsp;Gesamtbewertung",
                "paragraphs": ["Die Infrastruktur weist ein mittleres Risiko auf."],
                "risk_box": {
                    "label": "Gesamtrisiko",
                    "level": "MEDIUM",
                    "description": "Mittlere Schwachstellen identifiziert.",
                },
            }],
        },
        "findings_section_label": "3&nbsp;&nbsp;&nbsp;Befunde",
        "findings": [
            {
                "id": "VS-2026-001", "title": "Veraltete TLS-Version",
                "severity": "HIGH", "cvss_score": "7.5",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cwe": "CWE-326", "affected": "test.com:443",
                "description": "TLS 1.0 und 1.1 sind noch aktiv.",
                "evidence": "testssl.sh: TLS 1.0 supported",
                "impact": "Schwache Verschlüsselung ermöglicht Abhören.",
                "recommendation": "<b>Sofort:</b> TLS 1.0/1.1 deaktivieren.",
                "nis2_ref": "§30 Abs. 2 Nr. 8 BSIG",
            },
            {
                "id": "VS-2026-002", "title": "Korrekte HSTS-Konfiguration",
                "severity": "INFO", "cvss_score": "N/A",
                "cvss_vector": "N/A", "cwe": "N/A",
                "affected": "test.com",
                "description": "HSTS ist korrekt konfiguriert.",
                "evidence": "strict-transport-security: max-age=31536000",
                "impact": "Positiver Befund.", "recommendation": "Beibehalten.",
            },
        ],
        "recommendations": {
            "section_label": "4&nbsp;&nbsp;&nbsp;Empfehlungen",
            "paragraphs": ["Die folgenden Maßnahmen werden empfohlen."],
        },
        "nis2": {
            "compliance_summary": {
                "nr1_risikoanalyse": "COVERED",
                "nr2_vorfallbewaeltigung": "PARTIAL",
                "nr4_lieferkette": "COVERED",
                "nr5_schwachstellenmanagement": "COVERED",
                "nr6_wirksamkeitsbewertung": "COVERED",
                "nr8_kryptografie": "COVERED",
                "scope_note": "Dieser Scan deckt die externe Angriffsoberfläche ab. "
                              "Interne Prozesse und organisatorische Maßnahmen können "
                              "durch einen externen Scan nicht bewertet werden.",
            },
            "audit_trail": {
                "scan_start": "2026-03-14T10:00:00Z",
                "scan_end": "2026-03-14T10:45:00Z",
                "duration": "45 Minuten",
                "hosts_scanned": 3,
                "tools": [
                    "nmap 7.94", "testssl.sh 3.2", "nikto 2.5.0",
                    "nuclei 3.7.1", "gobuster 3.8.2", "gowitness 3.1.1",
                ],
            },
            "supply_chain": {
                "overall_rating": "MEDIUM",
                "key_findings_count": 1,
                "positive_count": 1,
                "recommendation": "Die geprüfte Infrastruktur weist ein mittleres Risiko auf. "
                                  "Eine Behebung der TLS-Schwäche wird empfohlen.",
            },
        },
        "scan_meta": {"domain": "test.com", "date": "14.03.2026"},
        "appendices": [],
        "disclaimer": "<b>Haftungsausschluss:</b> Dieser Bericht gibt den Sicherheitsstatus "
                       "zum Zeitpunkt der Prüfung wieder.",
    }


class TestFullNIS2Report:
    def test_generates_complete_nis2_report(self, tmp_path):
        data = _full_nis2_report_data()
        path = str(tmp_path / "full_nis2_report.pdf")
        generate_report(data, path)
        assert os.path.isfile(path)
        size = os.path.getsize(path)
        assert size > 5000  # NIS2 report should be substantial

    def test_nis2_report_larger_than_professional(self, tmp_path):
        # Professional report (no nis2 key)
        pro_data = _full_nis2_report_data()
        del pro_data["nis2"]
        del pro_data["scan_meta"]
        # Remove nis2_ref from findings
        for f in pro_data["findings"]:
            f.pop("nis2_ref", None)
        pro_path = str(tmp_path / "professional_report.pdf")
        generate_report(pro_data, pro_path)
        pro_size = os.path.getsize(pro_path)

        # NIS2 report (with all sections)
        nis2_data = _full_nis2_report_data()
        nis2_path = str(tmp_path / "nis2_report.pdf")
        generate_report(nis2_data, nis2_path)
        nis2_size = os.path.getsize(nis2_path)

        # NIS2 should be significantly larger
        assert nis2_size > pro_size

    def test_generates_example_pdf(self, tmp_path):
        """Generate a viewable NIS2 example PDF."""
        data = _full_nis2_report_data()
        path = str(tmp_path / "vectiscan-nis2-test.pdf")
        generate_report(data, path)
        assert os.path.isfile(path)
        assert os.path.getsize(path) > 5000
