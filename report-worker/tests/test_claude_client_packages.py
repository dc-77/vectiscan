"""Tests for claude_client package-aware behavior (max_tokens, prompt selection)."""

import json
from unittest.mock import MagicMock, patch

import pytest

from reporter.claude_client import call_claude, MAX_TOKENS_BY_PACKAGE


def _make_mock_anthropic(response_data: dict):
    """Create a mock anthropic module with a pre-configured response."""
    mock_mod = MagicMock()
    mock_client = MagicMock()
    mock_mod.Anthropic.return_value = mock_client

    mock_response = MagicMock()
    mock_content = MagicMock()
    mock_content.text = json.dumps(response_data)
    mock_response.content = [mock_content]
    mock_client.messages.create.return_value = mock_response

    mock_mod.RateLimitError = type("RateLimitError", (Exception,), {})
    mock_mod.APITimeoutError = type("APITimeoutError", (Exception,), {})

    return mock_mod, mock_client


class TestMaxTokensByPackage:
    def test_all_packages_use_correct_max_tokens(self):
        """Opus packages get 32000, Sonnet packages get 16384."""
        for pkg, tokens in MAX_TOKENS_BY_PACKAGE.items():
            if pkg in ("webcheck", "basic"):
                assert tokens == 16384, f"{pkg} (Sonnet) should be 16384, got {tokens}"
            else:
                assert tokens == 32000, f"{pkg} (Opus) should be 32000, got {tokens}"


class TestCallClaudePackages:
    """Test that call_claude uses package-specific max_tokens and system prompt."""

    @pytest.fixture()
    def basic_response(self):
        return {
            "overall_risk": "LOW",
            "overall_description": "Geringe Risiken.",
            "findings": [
                {
                    "id": "VS-2026-001",
                    "title": "Test Finding",
                    "severity": "LOW",
                    "affected": "example.com",
                    "description": "Test.",
                    "recommendation": "Fix it.",
                }
            ],
            "positive_findings": [
                {"title": "Good TLS", "description": "TLS 1.3 aktiv."}
            ],
            "top_recommendations": [
                {"action": "Update", "timeframe": "Monat 1"}
            ],
        }

    @pytest.fixture()
    def professional_response(self):
        return {
            "overall_risk": "HIGH",
            "overall_description": "Mehrere Schwachstellen.",
            "findings": [
                {
                    "id": "VS-2026-001",
                    "title": "DB exponiert",
                    "severity": "HIGH",
                    "cvss_score": "8.6",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                    "cwe": "CWE-284",
                    "affected": "1.2.3.4:3306",
                    "description": "MySQL offen.",
                    "evidence": "nmap output",
                    "impact": "Datenbank-Zugriff.",
                    "recommendation": "Firewall.",
                }
            ],
            "positive_findings": [],
            "recommendations": [],
        }

    @pytest.fixture()
    def nis2_response(self):
        return {
            "overall_risk": "MEDIUM",
            "overall_description": "Mittleres Risiko.",
            "findings": [
                {
                    "id": "VS-2026-001",
                    "title": "TLS-Schwäche",
                    "severity": "MEDIUM",
                    "cvss_score": "5.4",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                    "cwe": "CWE-326",
                    "affected": "example.com:443",
                    "description": "TLS 1.0 aktiv.",
                    "evidence": "testssl output",
                    "impact": "Verschlüsselung schwach.",
                    "recommendation": "TLS 1.2+ erzwingen.",
                    "nis2_ref": "§30 Abs. 2 Nr. 8 BSIG",
                }
            ],
            "positive_findings": [],
            "recommendations": [],
            "nis2_compliance_summary": {
                "nr1_risikoanalyse": "PARTIAL",
                "nr2_vorfallbewaeltigung": "NOT_IN_SCOPE",
                "nr4_lieferkette": "COVERED",
                "nr5_schwachstellenmanagement": "COVERED",
                "nr6_wirksamkeitsbewertung": "COVERED",
                "nr8_kryptografie": "COVERED",
                "scope_note": "Externer Scan.",
            },
            "supply_chain_summary": {
                "overall_rating": "MEDIUM",
                "key_findings_count": 1,
                "positive_count": 0,
                "recommendation": "Mittleres Risiko.",
            },
        }

    def test_basic_uses_sonnet_tokens(self, basic_response):
        """basic/webcheck uses Sonnet → 16384 tokens."""
        mock_mod, mock_client = _make_mock_anthropic(basic_response)
        with patch("reporter.claude_client.anthropic", mock_mod), \
             patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            call_claude("example.com", {}, [], "", package="basic")

        call_args = mock_client.messages.create.call_args
        assert call_args.kwargs["max_tokens"] == 16384
        assert call_args.kwargs["model"] == "claude-sonnet-4-6"

    def test_professional_uses_4096_tokens(self, professional_response):
        mock_mod, mock_client = _make_mock_anthropic(professional_response)
        with patch("reporter.claude_client.anthropic", mock_mod), \
             patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            call_claude("example.com", {}, [], "", package="professional")

        call_args = mock_client.messages.create.call_args
        assert call_args.kwargs["max_tokens"] == 32000

    def test_nis2_uses_6144_tokens(self, nis2_response):
        mock_mod, mock_client = _make_mock_anthropic(nis2_response)
        with patch("reporter.claude_client.anthropic", mock_mod), \
             patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            call_claude("example.com", {}, [], "", package="nis2")

        call_args = mock_client.messages.create.call_args
        assert call_args.kwargs["max_tokens"] == 32000

    def test_nis2_response_has_compliance_summary(self, nis2_response):
        mock_mod, _ = _make_mock_anthropic(nis2_response)
        with patch("reporter.claude_client.anthropic", mock_mod), \
             patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            result = call_claude("example.com", {}, [], "", package="nis2")

        assert "nis2_compliance_summary" in result
        assert result["nis2_compliance_summary"]["nr5_schwachstellenmanagement"] == "COVERED"

    def test_basic_response_findings_without_cvss_vector(self, basic_response):
        mock_mod, _ = _make_mock_anthropic(basic_response)
        with patch("reporter.claude_client.anthropic", mock_mod), \
             patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            result = call_claude("example.com", {}, [], "", package="basic")

        for finding in result["findings"]:
            assert "cvss_vector" not in finding

    def test_default_package_is_professional(self, professional_response):
        """When no package is specified, professional max_tokens should be used."""
        mock_mod, mock_client = _make_mock_anthropic(professional_response)
        with patch("reporter.claude_client.anthropic", mock_mod), \
             patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            call_claude("example.com", {}, [], "")

        call_args = mock_client.messages.create.call_args
        assert call_args.kwargs["max_tokens"] == 32000

    def test_basic_uses_basic_prompt(self, basic_response):
        """Verify that basic package uses the basic system prompt (no CVSS vectors)."""
        mock_mod, mock_client = _make_mock_anthropic(basic_response)
        with patch("reporter.claude_client.anthropic", mock_mod), \
             patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            call_claude("example.com", {}, [], "", package="basic")

        call_args = mock_client.messages.create.call_args
        system_prompt = _extract_system_text(call_args.kwargs["system"])
        assert "CVSS-Vektorstring" not in system_prompt
        assert "Management-tauglich" in system_prompt

    def test_nis2_uses_nis2_prompt(self, nis2_response):
        """Verify that NIS2 package uses the NIS2 system prompt (with §30 BSIG)."""
        mock_mod, mock_client = _make_mock_anthropic(nis2_response)
        with patch("reporter.claude_client.anthropic", mock_mod), \
             patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            call_claude("example.com", {}, [], "", package="nis2")

        call_args = mock_client.messages.create.call_args
        system_prompt = _extract_system_text(call_args.kwargs["system"])
        assert "§30 BSIG" in system_prompt
        assert "Lieferkette" in system_prompt


def _extract_system_text(system_param):
    """M1 Prompt Caching (PR-KI-Optim, 2026-05-03): system kann jetzt
    entweder str (kleine Prompts) oder list[{type:'text', text:..., cache_control:...}]
    (cached Prompts) sein. Helper extrahiert den Text-Inhalt fuer Assertions."""
    if isinstance(system_param, str):
        return system_param
    if isinstance(system_param, list):
        parts = []
        for block in system_param:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
        return "\n".join(parts)
    return str(system_param)
