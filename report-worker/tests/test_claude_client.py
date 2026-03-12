"""Unit tests for reporter.claude_client module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from reporter.claude_client import call_claude, SYSTEM_PROMPT

FIXTURES = Path(__file__).parent / "fixtures"


class TestSystemPrompt:
    def test_contains_cvss_rules(self) -> None:
        assert "CVSS-SCORING" in SYSTEM_PROMPT

    def test_contains_output_format(self) -> None:
        assert "OUTPUT-FORMAT" in SYSTEM_PROMPT

    def test_contains_severity_levels(self) -> None:
        assert "CRITICAL" in SYSTEM_PROMPT
        assert "HIGH" in SYSTEM_PROMPT
        assert "MEDIUM" in SYSTEM_PROMPT
        assert "LOW" in SYSTEM_PROMPT

    def test_german_tonality_rules(self) -> None:
        assert "TONALITÄT" in SYSTEM_PROMPT
        assert "Professionell" in SYSTEM_PROMPT


class TestCallClaude:
    @pytest.fixture()
    def claude_response_data(self) -> dict:
        return json.loads((FIXTURES / "claude_response.json").read_text())

    @pytest.fixture()
    def mock_anthropic(self, claude_response_data: dict):
        """Mock the anthropic client."""
        with patch("reporter.claude_client.anthropic") as mock_mod:
            mock_client = MagicMock()
            mock_mod.Anthropic.return_value = mock_client

            mock_response = MagicMock()
            mock_content = MagicMock()
            mock_content.text = json.dumps(claude_response_data)
            mock_response.content = [mock_content]
            mock_client.messages.create.return_value = mock_response

            # Also set up the exception classes
            mock_mod.RateLimitError = type("RateLimitError", (Exception,), {})
            mock_mod.APITimeoutError = type("APITimeoutError", (Exception,), {})

            yield mock_client

    def test_successful_call(self, mock_anthropic, claude_response_data) -> None:
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            result = call_claude(
                domain="beispiel.de",
                host_inventory={"domain": "beispiel.de", "hosts": []},
                tech_profiles=[],
                consolidated_findings="test findings",
            )
        assert result["overall_risk"] == "HIGH"
        assert len(result["findings"]) == 2
        assert len(result["positive_findings"]) == 1

    def test_model_and_params(self, mock_anthropic) -> None:
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            call_claude(
                domain="beispiel.de",
                host_inventory={},
                tech_profiles=[],
                consolidated_findings="",
            )
        call_args = mock_anthropic.messages.create.call_args
        assert call_args.kwargs["model"] == "claude-sonnet-4-20250514"
        assert call_args.kwargs["max_tokens"] == 4096

    def test_missing_api_key_raises(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            # Remove ANTHROPIC_API_KEY if present
            import os
            os.environ.pop("ANTHROPIC_API_KEY", None)
            with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
                call_claude(
                    domain="beispiel.de",
                    host_inventory={},
                    tech_profiles=[],
                    consolidated_findings="",
                )

    def test_handles_markdown_wrapped_json(self, mock_anthropic, claude_response_data) -> None:
        """Claude sometimes wraps JSON in ```json ... ```."""
        wrapped = "```json\n" + json.dumps(claude_response_data) + "\n```"
        mock_anthropic.messages.create.return_value.content[0].text = wrapped

        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            result = call_claude(
                domain="beispiel.de",
                host_inventory={},
                tech_profiles=[],
                consolidated_findings="",
            )
        assert result["overall_risk"] == "HIGH"

    def test_json_parse_error_raises(self, mock_anthropic) -> None:
        mock_anthropic.messages.create.return_value.content[0].text = "not json"

        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            with pytest.raises(RuntimeError, match="parse Claude response"):
                call_claude(
                    domain="beispiel.de",
                    host_inventory={},
                    tech_profiles=[],
                    consolidated_findings="",
                )
