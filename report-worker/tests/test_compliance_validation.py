"""Tests for _validate_compliance_summary() and NIS2 compliance plausibility."""
import json
from pathlib import Path
from typing import Any
import pytest
from reporter.report_mapper import _validate_compliance_summary, map_nis2_report

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def scan_meta():
    return json.loads((FIXTURES / "scan_meta.json").read_text())


@pytest.fixture
def host_inventory():
    return json.loads((FIXTURES / "host_inventory.json").read_text())


@pytest.fixture
def nis2_output():
    return json.loads((FIXTURES / "claude_output_nis2.json").read_text())


class TestValidateComplianceSummary:
    """Tests for _validate_compliance_summary()."""

    def test_nr1_always_partial(self):
        """Nr. 1 (Risikoanalyse) should always be PARTIAL."""
        summary = {"nr1_risikoanalyse": "COVERED"}
        result = _validate_compliance_summary(summary)
        assert result["nr1_risikoanalyse"] == "PARTIAL"

    def test_nr2_always_partial(self):
        """Nr. 2 (Vorfallbewältigung) should always be PARTIAL."""
        summary = {"nr2_vorfallbewaeltigung": "NOT_IN_SCOPE"}
        result = _validate_compliance_summary(summary)
        assert result["nr2_vorfallbewaeltigung"] == "PARTIAL"

    def test_nr4_always_covered(self):
        """Nr. 4 (Lieferkette) should always be COVERED."""
        summary = {"nr4_lieferkette": "PARTIAL"}
        result = _validate_compliance_summary(summary)
        assert result["nr4_lieferkette"] == "COVERED"

    def test_nr5_always_covered(self):
        """Nr. 5 (Schwachstellenmanagement) should always be COVERED."""
        summary = {"nr5_schwachstellenmanagement": "PARTIAL"}
        result = _validate_compliance_summary(summary)
        assert result["nr5_schwachstellenmanagement"] == "COVERED"

    def test_nr6_always_covered(self):
        """Nr. 6 (Wirksamkeitsbewertung) should always be COVERED."""
        summary = {"nr6_wirksamkeitsbewertung": "PARTIAL"}
        result = _validate_compliance_summary(summary)
        assert result["nr6_wirksamkeitsbewertung"] == "COVERED"

    def test_nr8_not_overridden(self):
        """Nr. 8 (Kryptografie) should NOT be overridden."""
        summary = {"nr8_kryptografie": "PARTIAL"}
        result = _validate_compliance_summary(summary)
        assert result["nr8_kryptografie"] == "PARTIAL"

    def test_nr8_covered_preserved(self):
        """Nr. 8 COVERED should be preserved."""
        summary = {"nr8_kryptografie": "COVERED"}
        result = _validate_compliance_summary(summary)
        assert result["nr8_kryptografie"] == "COVERED"

    def test_invalid_value_corrected_to_partial(self):
        """Invalid compliance values should be corrected to PARTIAL."""
        summary = {"nr5_schwachstellenmanagement": "UNKNOWN"}
        result = _validate_compliance_summary(summary)
        # Override takes precedence
        assert result["nr5_schwachstellenmanagement"] == "COVERED"

    def test_invalid_non_overridden_value_corrected(self):
        """Invalid value on non-overridden field should become PARTIAL."""
        summary = {"nr8_kryptografie": "INVALID"}
        result = _validate_compliance_summary(summary)
        assert result["nr8_kryptografie"] == "PARTIAL"

    def test_scope_note_preserved(self):
        """Existing scope_note should be preserved."""
        summary = {"scope_note": "Custom scope note"}
        result = _validate_compliance_summary(summary)
        assert result["scope_note"] == "Custom scope note"

    def test_scope_note_added_if_missing(self):
        """scope_note should be added if not present."""
        summary = {}
        result = _validate_compliance_summary(summary)
        assert "scope_note" in result
        assert "externe Angriffsoberfläche" in result["scope_note"]

    def test_empty_summary_gets_all_overrides(self):
        """Empty summary should get all override values + scope_note."""
        result = _validate_compliance_summary({})
        assert result["nr1_risikoanalyse"] == "PARTIAL"
        assert result["nr2_vorfallbewaeltigung"] == "PARTIAL"
        assert result["nr4_lieferkette"] == "COVERED"
        assert result["nr5_schwachstellenmanagement"] == "COVERED"
        assert result["nr6_wirksamkeitsbewertung"] == "COVERED"
        assert "scope_note" in result

    def test_correct_summary_passes_through(self):
        """Already correct summary should pass through unchanged."""
        summary = {
            "nr1_risikoanalyse": "PARTIAL",
            "nr2_vorfallbewaeltigung": "PARTIAL",
            "nr4_lieferkette": "COVERED",
            "nr5_schwachstellenmanagement": "COVERED",
            "nr6_wirksamkeitsbewertung": "COVERED",
            "nr8_kryptografie": "COVERED",
            "scope_note": "Test note",
        }
        result = _validate_compliance_summary(summary)
        assert result == summary


class TestNIS2MapperValidation:
    """Tests that map_nis2_report() applies compliance validation."""

    def test_nis2_report_validates_compliance(self, nis2_output, scan_meta, host_inventory):
        """map_nis2_report should apply compliance validation."""
        # Tamper with the output to have wrong values
        nis2_output["nis2_compliance_summary"]["nr2_vorfallbewaeltigung"] = "NOT_IN_SCOPE"
        nis2_output["nis2_compliance_summary"]["nr4_lieferkette"] = "PARTIAL"

        result = map_nis2_report(nis2_output, scan_meta, host_inventory)
        summary = result["nis2"]["compliance_summary"]

        # Should be corrected
        assert summary["nr2_vorfallbewaeltigung"] == "PARTIAL"
        assert summary["nr4_lieferkette"] == "COVERED"

    def test_nis2_report_preserves_nr8(self, nis2_output, scan_meta, host_inventory):
        """map_nis2_report should preserve nr8 value from Claude."""
        nis2_output["nis2_compliance_summary"]["nr8_kryptografie"] = "PARTIAL"
        result = map_nis2_report(nis2_output, scan_meta, host_inventory)
        assert result["nis2"]["compliance_summary"]["nr8_kryptografie"] == "PARTIAL"
