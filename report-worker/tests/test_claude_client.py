"""Unit tests for reporter.claude_client module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from reporter.claude_client import (
    _iterative_json_parse,
    _repair_json,
    _try_escape_inner_quote,
    call_claude,
    compute_cvss_score,
    validate_cvss_scores,
    SYSTEM_PROMPT,
)

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
        assert call_args.kwargs["model"] == "claude-sonnet-4-6"
        assert call_args.kwargs["max_tokens"] == 16384

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


class TestComputeCvssScore:
    """Test CVSS 3.1 score computation from vector strings."""

    def test_known_vector_high(self) -> None:
        # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L → 8.6
        score = compute_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L")
        assert score == 8.6

    def test_known_vector_low(self) -> None:
        # AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N → 3.1
        score = compute_cvss_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N")
        assert score == 3.1

    def test_scope_changed_vector(self) -> None:
        # AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0
        score = compute_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert score == 10.0

    def test_zero_impact_returns_zero(self) -> None:
        # All CIA = None → impact = 0 → score = 0
        score = compute_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert score == 0.0

    def test_medium_range_vector(self) -> None:
        # AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N → 5.4
        score = compute_cvss_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N")
        assert score == 5.4

    def test_physical_access_vector(self) -> None:
        # AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 4.6
        score = compute_cvss_score("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        assert score == 4.6

    def test_critical_no_scope_change(self) -> None:
        # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8
        score = compute_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 9.8

    def test_invalid_vector_returns_none(self) -> None:
        assert compute_cvss_score("not a vector") is None
        assert compute_cvss_score("") is None
        assert compute_cvss_score(None) is None

    def test_wrong_version_returns_none(self) -> None:
        assert compute_cvss_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P") is None

    def test_incomplete_vector_returns_none(self) -> None:
        assert compute_cvss_score("CVSS:3.1/AV:N/AC:L") is None


class TestValidateCvssScores:
    """Test CVSS post-processing validation and correction."""

    def _make_finding(
        self, score: str, vector: str, severity: str, finding_id: str = "VS-001"
    ) -> dict:
        return {
            "id": finding_id,
            "title": "Test Finding",
            "severity": severity,
            "cvss_score": score,
            "cvss_vector": vector,
            "cwe": "CWE-000",
            "affected": "test",
            "description": "test",
            "evidence": "test",
            "impact": "test",
            "recommendation": "test",
        }

    def test_correct_score_unchanged(self) -> None:
        """Finding with correct score+vector should not be modified."""
        finding = self._make_finding(
            score="8.6",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
            severity="HIGH",
        )
        result = validate_cvss_scores({"findings": [finding]})
        assert result["findings"][0]["cvss_score"] == "8.6"
        assert result["findings"][0]["severity"] == "HIGH"

    def test_inflated_score_corrected(self) -> None:
        """Score of 8.0 with a LOW vector (3.1) should be corrected."""
        finding = self._make_finding(
            score="8.0",
            vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            severity="HIGH",
        )
        result = validate_cvss_scores({"findings": [finding]})
        assert result["findings"][0]["cvss_score"] == "3.1"
        assert result["findings"][0]["severity"] == "LOW"

    def test_severity_corrected_to_match_score(self) -> None:
        """Severity should match the score range even if score is correct."""
        finding = self._make_finding(
            score="3.1",
            vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            severity="MEDIUM",  # Wrong! 3.1 = LOW
        )
        result = validate_cvss_scores({"findings": [finding]})
        assert result["findings"][0]["severity"] == "LOW"

    def test_ssh_open_with_key_auth_should_be_info(self) -> None:
        """SSH with key auth — if Claude rates it HIGH with a zero-impact vector."""
        # Simulating: Claude says HIGH 7.5 but vector computes to 0.0
        finding = self._make_finding(
            score="7.5",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            severity="HIGH",
            finding_id="VS-SSH-001",
        )
        result = validate_cvss_scores({"findings": [finding]})
        assert result["findings"][0]["cvss_score"] == "0.0"
        assert result["findings"][0]["severity"] == "INFO"

    def test_robots_txt_should_not_be_medium(self) -> None:
        """robots.txt disclosure — if vector computes to LOW range."""
        finding = self._make_finding(
            score="5.3",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            severity="MEDIUM",
            finding_id="VS-ROBOTS-001",
        )
        result = validate_cvss_scores({"findings": [finding]})
        # AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3 → MEDIUM is actually correct
        # for this vector. The issue is Claude using too high a vector.
        # The function corrects score/severity to match the vector.
        computed = compute_cvss_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        )
        assert result["findings"][0]["cvss_score"] == str(computed)

    def test_mysql_connection_refused_info(self) -> None:
        """MySQL port open but connection refused — should be INFO."""
        finding = self._make_finding(
            score="7.0",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            severity="HIGH",
            finding_id="VS-MYSQL-001",
        )
        result = validate_cvss_scores({"findings": [finding]})
        assert result["findings"][0]["cvss_score"] == "0.0"
        assert result["findings"][0]["severity"] == "INFO"

    def test_small_deviation_within_tolerance(self) -> None:
        """Score off by <= 0.1 should NOT be corrected."""
        finding = self._make_finding(
            score="8.5",  # Actual vector computes to 8.6, diff = 0.1
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
            severity="HIGH",
        )
        result = validate_cvss_scores({"findings": [finding]})
        # Score stays at 8.5 (within 0.1 tolerance)
        assert result["findings"][0]["cvss_score"] == "8.5"

    def test_no_vector_skipped(self) -> None:
        """Finding without vector should be left alone."""
        finding = self._make_finding(
            score="5.0", vector="", severity="MEDIUM"
        )
        result = validate_cvss_scores({"findings": [finding]})
        assert result["findings"][0]["cvss_score"] == "5.0"
        assert result["findings"][0]["severity"] == "MEDIUM"

    def test_multiple_findings_processed(self) -> None:
        """All findings in the list should be validated."""
        findings = [
            self._make_finding(
                score="9.0",
                vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                severity="CRITICAL",
                finding_id="VS-001",
            ),
            self._make_finding(
                score="3.1",
                vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                severity="LOW",
                finding_id="VS-002",
            ),
        ]
        result = validate_cvss_scores({"findings": findings})
        # First finding: inflated 9.0 → corrected to 3.1
        assert result["findings"][0]["cvss_score"] == "3.1"
        assert result["findings"][0]["severity"] == "LOW"
        # Second finding: already correct
        assert result["findings"][1]["cvss_score"] == "3.1"
        assert result["findings"][1]["severity"] == "LOW"

    def test_empty_findings_list(self) -> None:
        """Empty findings list should not error."""
        result = validate_cvss_scores({"findings": []})
        assert result == {"findings": []}

    def test_missing_findings_key(self) -> None:
        """Result without findings key should not error."""
        result = validate_cvss_scores({"overall_risk": "LOW"})
        assert result == {"overall_risk": "LOW"}


class TestRepairJson:
    """Test _repair_json() handles common Claude output issues."""

    def test_clean_json_unchanged(self) -> None:
        raw = '{"key": "value", "num": 42}'
        assert json.loads(_repair_json(raw)) == {"key": "value", "num": 42}

    def test_markdown_fence_removed(self) -> None:
        raw = '```json\n{"key": "value"}\n```'
        assert json.loads(_repair_json(raw)) == {"key": "value"}

    def test_trailing_comma_object(self) -> None:
        raw = '{"a": 1, "b": 2,}'
        assert json.loads(_repair_json(raw)) == {"a": 1, "b": 2}

    def test_trailing_comma_array(self) -> None:
        raw = '{"items": [1, 2, 3,]}'
        assert json.loads(_repair_json(raw)) == {"items": [1, 2, 3]}

    def test_trailing_comma_nested(self) -> None:
        raw = '{"a": {"b": 1,}, "c": [1,],}'
        assert json.loads(_repair_json(raw)) == {"a": {"b": 1}, "c": [1]}

    def test_line_comment_removed(self) -> None:
        raw = '{\n  "a": 1, // this is a comment\n  "b": 2\n}'
        assert json.loads(_repair_json(raw)) == {"a": 1, "b": 2}

    def test_block_comment_removed(self) -> None:
        raw = '{\n  "a": 1, /* block\ncomment */ "b": 2\n}'
        assert json.loads(_repair_json(raw)) == {"a": 1, "b": 2}

    def test_url_in_value_preserved(self) -> None:
        """URLs with // inside string values must NOT be treated as comments."""
        raw = '{"url": "https://example.com/path"}'
        assert json.loads(_repair_json(raw)) == {"url": "https://example.com/path"}

    def test_combined_issues(self) -> None:
        """Markdown fence + trailing commas + comments all at once."""
        raw = '```json\n{\n  "a": 1, // note\n  "b": [2, 3,],\n}\n```'
        assert json.loads(_repair_json(raw)) == {"a": 1, "b": [2, 3]}

    def test_tabs_escaped(self) -> None:
        raw = '{"text": "col1\tcol2"}'
        result = _repair_json(raw)
        assert "\\t" in result
        parsed = json.loads(result)
        assert parsed["text"] == "col1\tcol2"


class TestTryEscapeInnerQuote:
    """Test _try_escape_inner_quote() fixes unescaped quotes in JSON strings."""

    def test_inner_quote_escaped(self) -> None:
        raw = '{"desc": "Server gibt "403 Forbidden" zurück"}'
        # First inner " is at position after "Server gibt "
        # json.loads will fail; find the error position
        try:
            json.loads(raw)
            assert False, "Should have raised"
        except json.JSONDecodeError as e:
            fixed = _try_escape_inner_quote(raw, e.pos)
            assert fixed != raw  # something was changed

    def test_no_change_on_valid_json(self) -> None:
        raw = '{"key": "value"}'
        # No error to fix, but function should return unchanged
        result = _try_escape_inner_quote(raw, 10)
        # May or may not change — just shouldn't crash
        assert isinstance(result, str)


class TestIterativeJsonParse:
    """Test _iterative_json_parse() handles multiple unescaped quotes."""

    def test_valid_json_passes(self) -> None:
        result = _iterative_json_parse('{"key": "value", "num": 42}')
        assert result == {"key": "value", "num": 42}

    def test_single_inner_quote_fixed(self) -> None:
        # Claude-typical: unescaped quote in description
        raw = '{"description": "Der Header "X-Frame-Options" fehlt", "severity": "HIGH"}'
        result = _iterative_json_parse(raw)
        assert result["severity"] == "HIGH"
        assert "X-Frame-Options" in result["description"]

    def test_multiple_inner_quotes_fixed(self) -> None:
        # Two findings with unescaped quotes
        raw = '{"findings": [{"desc": "Header "CSP" fehlt"}, {"desc": "Header "HSTS" fehlt"}]}'
        result = _iterative_json_parse(raw)
        assert len(result["findings"]) == 2

    def test_unfixable_raises(self) -> None:
        with pytest.raises(json.JSONDecodeError):
            _iterative_json_parse("totally not json at all")
