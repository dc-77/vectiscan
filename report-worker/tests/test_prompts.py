"""Tests for reporter.prompts — system prompt variants per package."""

import pytest
from reporter.prompts import (
    ATOMICITY_PROMPT_BLOCK,
    SYSTEM_PROMPT_BASIC,
    SYSTEM_PROMPT_PROFESSIONAL,
    SYSTEM_PROMPT_NIS2,
    SYSTEM_PROMPT_TLSCOMPLIANCE,
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
        # C2 (21.07.2026): von "5-8 Findings" angehoben — Atomarisierung
        # erhoeht die Anzahl zwangslaeufig, die Kappung macht selection.py.
        assert "10-14 atomare Befunde" in SYSTEM_PROMPT_BASIC

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


class TestAtomicityBlock:
    """C2 (21.07.2026) — ein Befund = eine Schwachstellenklasse."""

    NEGATIVE_EXAMPLE = "Veraltetes WordPress und fehlende Security-Header"

    def test_block_is_shared_constant(self):
        """Geteilte Konstante statt Duplikat — sonst driftet der Text auseinander."""
        assert "ATOMARITAET" in ATOMICITY_PROMPT_BLOCK
        assert self.NEGATIVE_EXAMPLE in ATOMICITY_PROMPT_BLOCK
        assert ATOMICITY_PROMPT_BLOCK in SYSTEM_PROMPT_BASIC
        assert ATOMICITY_PROMPT_BLOCK in SYSTEM_PROMPT_PROFESSIONAL

    def test_basic_and_professional_contain_rule(self):
        for prompt in (SYSTEM_PROMPT_BASIC, SYSTEM_PROMPT_PROFESSIONAL):
            assert "EIN BEFUND = EINE SCHWACHSTELLENKLASSE" in prompt
            assert self.NEGATIVE_EXAMPLE in prompt

    @pytest.mark.parametrize(
        "package",
        ["webcheck", "perimeter", "compliance", "supplychain", "insurance"],
    )
    def test_all_customer_packages_inherit_block(self, package):
        assert ATOMICITY_PROMPT_BLOCK in get_system_prompt(package)

    def test_tlscompliance_untouched(self):
        """Nicht im Kunden-Katalog (VEC-284), hat eigene Finding-pro-Check-Regel."""
        assert ATOMICITY_PROMPT_BLOCK not in SYSTEM_PROMPT_TLSCOMPLIANCE
        assert "Erstelle ein Finding pro FAIL- oder WARN-Check" in SYSTEM_PROMPT_TLSCOMPLIANCE

    def test_block_sits_above_cvss_rules(self):
        """Der Block gehoert oben zu den Finding-Regeln, nicht unten bei CVSS."""
        for prompt in (SYSTEM_PROMPT_BASIC, SYSTEM_PROMPT_PROFESSIONAL):
            assert prompt.index("ATOMARITAET") < prompt.index("OUTPUT-FORMAT")

    def test_shodan_collective_finding_preserved(self):
        """Regel 1: nichts gestrichen — der gewollte Sammelbefund bleibt Pflicht
        und ist ausdruecklich als Ausnahme markiert."""
        for prompt in (SYSTEM_PROMPT_BASIC, SYSTEM_PROMPT_PROFESSIONAL):
            assert "SHODAN/PASSIVE-INTEL-PFLICHT" in prompt
            assert "Ausnahme von der Atomaritaets-Regel" in prompt
        assert "EINZIGE AUSNAHME" in ATOMICITY_PROMPT_BLOCK

    def test_eol_obligation_preserved(self):
        """EOL-PFLICHT bleibt unveraendert bestehen (additive Aenderung)."""
        for prompt in (SYSTEM_PROMPT_BASIC, SYSTEM_PROMPT_PROFESSIONAL):
            assert "EOL-PFLICHT" in prompt
