"""Tests for NIS2 prompt §30 mapping consistency."""
import pytest
from reporter.prompts import SYSTEM_PROMPT_NIS2, get_system_prompt


class TestNIS2PromptMappingRules:
    """Tests that the NIS2 prompt contains correct §30 mapping guidance."""

    def test_exposed_ports_map_to_nr5(self):
        """Exposed ports should map to Nr. 5 (Schwachstellenmanagement)."""
        assert "Exponierte Ports" in SYSTEM_PROMPT_NIS2
        # Find the line with "Exponierte Ports" and verify it mentions Nr. 5
        lines = SYSTEM_PROMPT_NIS2.split("\n")
        port_lines = [l for l in lines if "Exponierte Ports" in l]
        assert len(port_lines) >= 1
        # At least one line with "Exponierte Ports" must reference Nr. 5
        assert any("Nr. 5" in l for l in port_lines)

    def test_tls_problems_map_to_nr8(self):
        """TLS problems should map to Nr. 8 (Kryptografie)."""
        lines = SYSTEM_PROMPT_NIS2.split("\n")
        tls_lines = [l for l in lines if "TLS-Probleme" in l]
        assert len(tls_lines) >= 1
        assert "Nr. 8" in tls_lines[0]

    def test_missing_headers_map_to_nr5(self):
        """Missing headers should map to Nr. 5."""
        lines = SYSTEM_PROMPT_NIS2.split("\n")
        header_lines = [l for l in lines if "Security-Header" in l and "Fehlende" in l]
        assert len(header_lines) >= 1
        assert "Nr. 5" in header_lines[0]

    def test_positive_tls_maps_to_nr8(self):
        """Positive TLS config should map to Nr. 8."""
        lines = SYSTEM_PROMPT_NIS2.split("\n")
        pos_tls = [l for l in lines if "Positive TLS" in l]
        assert len(pos_tls) >= 1
        assert "Nr. 8" in pos_tls[0]

    def test_http_no_redirect_maps_to_nr8(self):
        """HTTP without HTTPS redirect should map to Nr. 8."""
        lines = SYSTEM_PROMPT_NIS2.split("\n")
        http_lines = [l for l in lines if "HTTPS-Redirect" in l and "Nr." in l]
        assert len(http_lines) >= 1
        assert "Nr. 8" in http_lines[0]

    def test_info_disclosure_maps_to_nr5(self):
        """Information disclosure should map to Nr. 5."""
        lines = SYSTEM_PROMPT_NIS2.split("\n")
        info_lines = [l for l in lines if "Information Disclosure" in l and "Nr." in l]
        assert len(info_lines) >= 1
        assert "Nr. 5" in info_lines[0]

    def test_compliance_rules_nr1_partial(self):
        """Prompt should state Nr. 1 is always PARTIAL."""
        assert "Nr. 1" in SYSTEM_PROMPT_NIS2
        lines = SYSTEM_PROMPT_NIS2.split("\n")
        nr1_rule_lines = [l for l in lines if "Nr. 1" in l and "PARTIAL" in l]
        assert len(nr1_rule_lines) >= 1

    def test_compliance_rules_nr2_partial(self):
        """Prompt should state Nr. 2 is always PARTIAL."""
        lines = SYSTEM_PROMPT_NIS2.split("\n")
        nr2_rule_lines = [l for l in lines if "Nr. 2" in l and "PARTIAL" in l]
        assert len(nr2_rule_lines) >= 1

    def test_compliance_rules_nr4_covered(self):
        """Prompt should state Nr. 4 is always COVERED."""
        lines = SYSTEM_PROMPT_NIS2.split("\n")
        nr4_rule_lines = [l for l in lines if "Nr. 4" in l and "COVERED" in l]
        assert len(nr4_rule_lines) >= 1

    def test_compliance_rules_nr5_covered(self):
        """Prompt should state Nr. 5 is always COVERED."""
        lines = SYSTEM_PROMPT_NIS2.split("\n")
        nr5_rule_lines = [l for l in lines if "Nr. 5" in l and "COVERED" in l]
        assert len(nr5_rule_lines) >= 1

    def test_prompt_has_zuordnungsregeln_section(self):
        """Prompt should have ZUORDNUNGSREGELN section."""
        assert "ZUORDNUNGSREGELN" in SYSTEM_PROMPT_NIS2

    def test_prompt_has_compliance_rules_section(self):
        """Prompt should have REGELN FÜR COMPLIANCE-SUMMARY section."""
        assert "REGELN FÜR COMPLIANCE-SUMMARY" in SYSTEM_PROMPT_NIS2
