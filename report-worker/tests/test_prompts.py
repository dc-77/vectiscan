"""Tests for reporter.prompts — system prompt variants per package."""

import pytest
from reporter.prompts import (
    SYSTEM_PROMPT_BASIC,
    SYSTEM_PROMPT_PROFESSIONAL,
    SYSTEM_PROMPT_NIS2,
    get_system_prompt,
)


class TestSystemPromptBasic:
    def test_has_cvss(self):
        assert "cvss_score" in SYSTEM_PROMPT_BASIC
        assert "cvss_vector" in SYSTEM_PROMPT_BASIC

    def test_no_bsig(self):
        assert "§30 BSIG" not in SYSTEM_PROMPT_BASIC

    def test_has_cwe(self):
        assert '"cwe"' in SYSTEM_PROMPT_BASIC

    def test_max_findings_instruction(self):
        assert "5-8 Findings" in SYSTEM_PROMPT_BASIC

    def test_management_language(self):
        assert "Management-tauglich" in SYSTEM_PROMPT_BASIC

    def test_severity_labels(self):
        assert "CRITICAL" in SYSTEM_PROMPT_BASIC
        assert "HIGH" in SYSTEM_PROMPT_BASIC
        assert "MEDIUM" in SYSTEM_PROMPT_BASIC
        assert "LOW" in SYSTEM_PROMPT_BASIC

    def test_top_recommendations_schema(self):
        assert "top_recommendations" in SYSTEM_PROMPT_BASIC

    def test_tonality_rules(self):
        assert "Professionell" in SYSTEM_PROMPT_BASIC
        assert "sachlich" in SYSTEM_PROMPT_BASIC


class TestSystemPromptProfessional:
    def test_contains_cvss_vector(self):
        assert "CVSS-Vektorstring" in SYSTEM_PROMPT_PROFESSIONAL

    def test_contains_cwe(self):
        assert "CWE" in SYSTEM_PROMPT_PROFESSIONAL

    def test_no_bsig(self):
        assert "§30 BSIG" not in SYSTEM_PROMPT_PROFESSIONAL

    def test_no_nis2_compliance(self):
        assert "nis2_compliance_summary" not in SYSTEM_PROMPT_PROFESSIONAL

    def test_contains_cvss_reference_values(self):
        assert "CVSS-REFERENZWERTE" in SYSTEM_PROMPT_PROFESSIONAL

    def test_contains_output_format(self):
        assert "OUTPUT-FORMAT" in SYSTEM_PROMPT_PROFESSIONAL

    def test_contains_ptes(self):
        assert "PTES" in SYSTEM_PROMPT_PROFESSIONAL


class TestSystemPromptNis2:
    def test_contains_bsig(self):
        assert "§30 BSIG" in SYSTEM_PROMPT_NIS2

    def test_contains_lieferkette(self):
        assert "Lieferkette" in SYSTEM_PROMPT_NIS2
        assert "supply_chain_summary" in SYSTEM_PROMPT_NIS2

    def test_contains_cvss_vector(self):
        assert "CVSS-Vektorstring" in SYSTEM_PROMPT_NIS2

    def test_contains_compliance_summary(self):
        assert "nis2_compliance_summary" in SYSTEM_PROMPT_NIS2

    def test_contains_all_bsig_paragraphs(self):
        assert "Nr. 1" in SYSTEM_PROMPT_NIS2
        assert "Nr. 2" in SYSTEM_PROMPT_NIS2
        assert "Nr. 4" in SYSTEM_PROMPT_NIS2
        assert "Nr. 5" in SYSTEM_PROMPT_NIS2
        assert "Nr. 6" in SYSTEM_PROMPT_NIS2
        assert "Nr. 8" in SYSTEM_PROMPT_NIS2

    def test_contains_compliance_statuses(self):
        assert "COVERED" in SYSTEM_PROMPT_NIS2
        assert "PARTIAL" in SYSTEM_PROMPT_NIS2
        assert "NOT_IN_SCOPE" in SYSTEM_PROMPT_NIS2

    def test_contains_nis2_ref_field(self):
        assert "nis2_ref" in SYSTEM_PROMPT_NIS2

    def test_includes_professional_content(self):
        """NIS2 prompt should include all professional prompt content."""
        assert "CVSS-SCORING" in SYSTEM_PROMPT_NIS2
        assert "PTES" in SYSTEM_PROMPT_NIS2


class TestGetSystemPrompt:
    def test_webcheck(self):
        assert get_system_prompt("webcheck") is SYSTEM_PROMPT_BASIC

    def test_perimeter(self):
        assert get_system_prompt("perimeter") is SYSTEM_PROMPT_PROFESSIONAL

    def test_compliance(self):
        assert get_system_prompt("compliance") is SYSTEM_PROMPT_NIS2

    def test_supplychain(self):
        prompt = get_system_prompt("supplychain")
        assert "ISO 27001" in prompt
        assert "supply_chain_attestation" in prompt

    def test_insurance(self):
        prompt = get_system_prompt("insurance")
        assert "insurance_questionnaire" in prompt
        assert "risk_score" in prompt

    # Legacy aliases still work
    def test_legacy_basic(self):
        assert get_system_prompt("basic") is SYSTEM_PROMPT_BASIC

    def test_legacy_professional(self):
        assert get_system_prompt("professional") is SYSTEM_PROMPT_PROFESSIONAL

    def test_legacy_nis2(self):
        assert get_system_prompt("nis2") is SYSTEM_PROMPT_NIS2

    def test_invalid_raises(self):
        with pytest.raises(ValueError, match="Unknown package"):
            get_system_prompt("invalid")

    def test_invalid_error_message(self):
        with pytest.raises(ValueError, match="webcheck"):
            get_system_prompt("enterprise")
