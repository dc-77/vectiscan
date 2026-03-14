#!/usr/bin/env python3
"""Tests for VectiScan branding integration in PDF reports."""

import os
import sys
import tempfile
import pytest

# Ensure report-worker root is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from reporter.pdf.branding import (
    COLORS, SEVERITY_COLORS, PACKAGE_BADGES,
    COMPANY_NAME, CLASSIFICATION_LABEL_DE, LOGO_PATH,
    FONT_BODY, FONT_HEADING, FONT_MONO,
    FONT_SIZE_BODY, FONT_SIZE_HEADING1, FONT_SIZE_HEADING2,
    FONT_SIZE_EVIDENCE, FONT_SIZE_TABLE_HEADER, FONT_SIZE_TABLE_CELL,
    FONT_SIZE_FOOTER, FONT_SIZE_COVER_TITLE, FONT_SIZE_COVER_SUBTITLE,
)
from reporter.generate_report import generate_report, create_styles, PackageBadge, build_package_badge


# ============================================================================
# Branding module tests
# ============================================================================

class TestBrandingModule:
    """Test that branding.py is importable and has all required fields."""

    def test_colors_has_minimum_entries(self):
        """COLORS must have at least 15 entries."""
        assert len(COLORS) >= 15, f"COLORS has only {len(COLORS)} entries, expected >= 15"

    def test_colors_required_keys(self):
        """COLORS must contain essential keys."""
        required = [
            "primary", "secondary", "accent", "text", "muted", "white",
            "critical", "high", "medium", "low", "info",
            "bg_light", "bg_evidence", "light_accent",
            "cover_bg", "cover_accent_bar", "cover_overlay",
            "cover_meta_label", "cover_meta_value", "cover_rule",
        ]
        for key in required:
            assert key in COLORS, f"COLORS missing key: {key}"

    def test_severity_colors_german_labels(self):
        """SEVERITY_COLORS must include German labels."""
        german = ["KRITISCH", "HOCH", "MITTEL", "NIEDRIG", "INFORMATIV"]
        for label in german:
            assert label in SEVERITY_COLORS, f"SEVERITY_COLORS missing German label: {label}"

    def test_severity_colors_english_labels(self):
        """SEVERITY_COLORS must include English labels."""
        english = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL"]
        for label in english:
            assert label in SEVERITY_COLORS, f"SEVERITY_COLORS missing English label: {label}"

    def test_package_badges_all_packages(self):
        """PACKAGE_BADGES must define basic, professional, nis2."""
        for pkg in ("basic", "professional", "nis2"):
            assert pkg in PACKAGE_BADGES, f"PACKAGE_BADGES missing package: {pkg}"
            badge = PACKAGE_BADGES[pkg]
            assert "label" in badge
            assert "color" in badge
            assert "text_color" in badge

    def test_company_name_set(self):
        assert COMPANY_NAME and len(COMPANY_NAME) > 0

    def test_classification_label_de(self):
        assert "VERTRAULICH" in CLASSIFICATION_LABEL_DE

    def test_font_constants(self):
        assert FONT_BODY == "Helvetica"
        assert FONT_HEADING == "Helvetica-Bold"
        assert FONT_MONO == "Courier"

    def test_font_sizes_positive(self):
        sizes = [
            FONT_SIZE_BODY, FONT_SIZE_HEADING1, FONT_SIZE_HEADING2,
            FONT_SIZE_EVIDENCE, FONT_SIZE_TABLE_HEADER, FONT_SIZE_TABLE_CELL,
            FONT_SIZE_FOOTER, FONT_SIZE_COVER_TITLE, FONT_SIZE_COVER_SUBTITLE,
        ]
        for s in sizes:
            assert s > 0, f"Font size must be positive, got {s}"


# ============================================================================
# Style integration tests
# ============================================================================

class TestStyleIntegration:
    """Test that create_styles() uses branding values."""

    def test_create_styles_returns_stylesheet(self):
        styles = create_styles()
        assert styles is not None

    def test_section_title_uses_primary_color(self):
        styles = create_styles()
        assert styles["SectionTitle"].textColor == COLORS["primary"]

    def test_subsection_title_uses_accent_color(self):
        styles = create_styles()
        assert styles["SubsectionTitle"].textColor == COLORS["accent"]

    def test_evidence_uses_bg_evidence(self):
        styles = create_styles()
        assert styles["Evidence"].backColor == COLORS["bg_evidence"]


# ============================================================================
# Package badge tests
# ============================================================================

class TestPackageBadge:
    """Test the PackageBadge flowable."""

    def test_badge_dimensions(self):
        from reportlab.lib.units import mm
        badge = PackageBadge("professional")
        assert badge.width == 50 * mm
        assert badge.height == 8 * mm

    def test_badge_uses_correct_colors(self):
        badge = PackageBadge("nis2")
        assert badge.bg_color == PACKAGE_BADGES["nis2"]["color"]
        assert badge.label == "NIS2 COMPLIANCE"

    def test_badge_fallback_for_unknown_package(self):
        badge = PackageBadge("unknown_package")
        # Should fall back to professional
        assert badge.label == PACKAGE_BADGES["professional"]["label"]


# ============================================================================
# PDF generation tests
# ============================================================================

def _make_test_report_data(package=None):
    """Create minimal report_data for testing."""
    cover = {
        "cover_subtitle": "AUTOMATED SECURITY ASSESSMENT",
        "cover_title": "Sicherheitsbewertung<br/>test.example.com",
        "cover_meta": [
            ["Ziel:", "test.example.com (1 Host)"],
            ["Datum:", "14. März 2026"],
            ["Methodik:", "PTES (automatisiert)"],
            ["Scoring:", "CVSS v3.1"],
            ["Klassifizierung:", "Vertraulich"],
            ["Befunde:", "1 High, 1 Info"],
        ],
    }
    if package:
        cover["package"] = package

    return {
        "meta": {
            "title": "Security Assessment — test.example.com",
            "author": "VectiScan Automated Security Assessment",
            "header_left": "VECTISCAN — SECURITY ASSESSMENT",
            "header_right": "test.example.com",
            "footer_left": "Vertraulich  |  14. März 2026",
            "classification_label": CLASSIFICATION_LABEL_DE,
        },
        "cover": cover,
        "toc": [
            ("1", "Managementzusammenfassung", False),
            ("2", "Umfang und Methodik", False),
            ("3", "Befunde", False),
            ("3.1", "VS-2026-001 — Exponierter Datenbankport", True),
            ("3.2", "VS-2026-002 — Korrekte TLS-Konfiguration", True),
            ("4", "Empfehlungen", False),
        ],
        "executive_summary": {
            "section_label": "1&nbsp;&nbsp;&nbsp;Managementzusammenfassung",
            "subsections": [
                {
                    "title": "1.1&nbsp;&nbsp;&nbsp;Gesamtbewertung",
                    "paragraphs": [
                        "Die automatisierte Sicherheitsbewertung von test.example.com "
                        "ergab insgesamt zwei Befunde: eine Schwachstelle mit hohem "
                        "Schweregrad und einen positiven Befund."
                    ],
                    "risk_box": {
                        "label": "Gesamtrisikobewertung",
                        "level": "HIGH",
                        "description": "Aufgrund des exponierten Datenbankports besteht ein hohes Risiko.",
                    },
                },
            ],
        },
        "scope": {
            "section_label": "2&nbsp;&nbsp;&nbsp;Umfang und Methodik",
            "subsections": [
                {
                    "title": "2.1&nbsp;&nbsp;&nbsp;Umfang",
                    "paragraphs": ["Externer Scan der Domain test.example.com."],
                },
            ],
        },
        "findings_section_label": "3&nbsp;&nbsp;&nbsp;Befunde",
        "findings": [
            {
                "id": "VS-2026-001",
                "title": "Exponierter MySQL-Datenbankport",
                "severity": "HIGH",
                "cvss_score": "7.5",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cwe": "CWE-284",
                "affected": "192.168.1.100:3306 (test.example.com)",
                "description": "Der MySQL-Port 3306 ist öffentlich erreichbar.",
                "evidence": "$ nmap -sV 192.168.1.100<br/>3306/tcp open mysql MySQL 8.0.35",
                "impact": "Angreifer könnten Brute-Force-Angriffe gegen die Datenbank durchführen.",
                "recommendation": "<b>Kurzfristig (Tage):</b> Port per Firewall schließen.<br/><b>Mittelfristig:</b> VPN-Zugang einrichten.",
                "label_description": "Beschreibung",
                "label_evidence": "Nachweis",
                "label_impact": "Geschäftsauswirkung",
                "label_recommendation": "Empfehlung",
            },
            {
                "id": "VS-2026-002",
                "title": "Korrekte TLS-Konfiguration",
                "severity": "INFO",
                "cvss_score": "N/A",
                "cvss_vector": "N/A",
                "cwe": "N/A",
                "affected": "https://test.example.com/",
                "description": "Alle Hosts nutzen TLS 1.2+, keine veralteten Cipher-Suites.",
                "evidence": "TLS 1.3 aktiv, HSTS mit max-age=31536000",
                "impact": "Positiver Befund — korrekte Konfiguration.",
                "recommendation": "Aktuelle Konfiguration beibehalten.",
                "label_description": "Beschreibung",
                "label_evidence": "Nachweis",
                "label_impact": "Bewertung",
                "label_recommendation": "Empfehlung",
            },
        ],
        "recommendations": {
            "section_label": "4&nbsp;&nbsp;&nbsp;Empfehlungen",
            "paragraphs": ["Konsolidierte Empfehlungen nach Priorität."],
        },
        "appendices": [],
        "disclaimer": (
            "<b>Haftungsausschluss:</b> Dieser Bericht gibt den Sicherheitsstatus "
            "zum Zeitpunkt der Prüfung wieder. Regelmäßige Wiederholungsprüfungen "
            "werden empfohlen."
        ),
    }


class TestPDFGeneration:
    """Test actual PDF generation."""

    def test_generate_basic_pdf(self, tmp_path):
        """Generate a test PDF and check file size > 10KB."""
        output = str(tmp_path / "test_report.pdf")
        data = _make_test_report_data()
        result = generate_report(data, output)
        assert os.path.isfile(result)
        size = os.path.getsize(result)
        assert size > 10 * 1024, f"PDF too small: {size} bytes, expected > 10KB"

    @pytest.mark.parametrize("package", ["basic", "professional", "nis2"])
    def test_generate_pdf_with_package_badge(self, tmp_path, package):
        """Generate PDFs for all 3 packages, check file size."""
        output = str(tmp_path / f"test_{package}.pdf")
        data = _make_test_report_data(package=package)
        result = generate_report(data, output)
        assert os.path.isfile(result)
        size = os.path.getsize(result)
        assert size > 10 * 1024, f"{package} PDF too small: {size} bytes"

    def test_pdf_without_package_field(self, tmp_path):
        """PDF should generate fine without package field."""
        output = str(tmp_path / "no_package.pdf")
        data = _make_test_report_data()
        # Ensure no package key
        data["cover"].pop("package", None)
        result = generate_report(data, output)
        assert os.path.isfile(result)
