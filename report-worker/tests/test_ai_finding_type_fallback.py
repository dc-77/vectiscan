"""Tests fuer B2 — KI-Fallback-Mapper."""

import json
from unittest.mock import patch, MagicMock

import os
from reporter.ai_finding_type_fallback import (
    map_finding_type_via_ai, _normalize_for_cache, FINDING_TYPE_CATALOG,
)
from reporter.finding_type_mapper import annotate_finding_types


def test_normalize_for_cache_deterministic():
    a = _normalize_for_cache("  Title TEST  ", "Description with  spaces", "CWE-79")
    b = _normalize_for_cache("title test", "description with spaces", "cwe-79")
    assert a == b


def test_no_api_key_returns_none(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out = map_finding_type_via_ai({"title": "OWA exposed without WAF"})
    assert out is None


def test_haiku_returns_valid_type(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")

    fake_response = MagicMock()
    fake_response.content = [MagicMock(text=json.dumps({
        "finding_type": "csrf_token_missing",
        "confidence": 0.85,
        "reason": "Form ohne CSRF-Token",
    }))]
    fake_response.usage = MagicMock(input_tokens=120, output_tokens=30)

    with patch("anthropic.Anthropic") as MockClient:
        MockClient.return_value.messages.create.return_value = fake_response
        with patch("reporter.ai_finding_type_fallback.get_cached_response", return_value=None):
            with patch("reporter.ai_finding_type_fallback.set_cached_response"):
                out = map_finding_type_via_ai({
                    "title": "Login-Formular ohne CSRF-Schutz",
                    "description": "POST ohne anti-csrf token",
                    "cwe": "CWE-352",
                })
    assert out == "csrf_token_missing"


def test_haiku_unknown_returns_none(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    fake_response = MagicMock()
    fake_response.content = [MagicMock(text=json.dumps({
        "finding_type": "unknown",
        "confidence": 0.3,
        "reason": "kein klares Pattern",
    }))]
    fake_response.usage = MagicMock(input_tokens=100, output_tokens=20)
    with patch("anthropic.Anthropic") as MockClient:
        MockClient.return_value.messages.create.return_value = fake_response
        with patch("reporter.ai_finding_type_fallback.get_cached_response", return_value=None):
            with patch("reporter.ai_finding_type_fallback.set_cached_response"):
                out = map_finding_type_via_ai({"title": "Unklarer Befund"})
    assert out is None


def test_haiku_invalid_type_returns_none(monkeypatch):
    """KI gibt einen finding_type zurueck der nicht in CATALOG ist."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    fake_response = MagicMock()
    fake_response.content = [MagicMock(text=json.dumps({
        "finding_type": "made_up_type",
        "confidence": 0.9,
    }))]
    fake_response.usage = MagicMock(input_tokens=50, output_tokens=10)
    with patch("anthropic.Anthropic") as MockClient:
        MockClient.return_value.messages.create.return_value = fake_response
        with patch("reporter.ai_finding_type_fallback.get_cached_response", return_value=None):
            with patch("reporter.ai_finding_type_fallback.set_cached_response"):
                out = map_finding_type_via_ai({"title": "X"})
    assert out is None


def test_annotate_with_ai_fallback_disabled():
    """use_ai_fallback=False → kein Haiku-Aufruf."""
    fs = [{"title": "Outlook Web App oeffentlich"}]
    annotate_finding_types(fs, use_ai_fallback=False)
    assert fs[0].get("finding_type") is None


def test_annotate_marks_source_field():
    fs = [{"title": "SPF-Record fehlt"}]
    annotate_finding_types(fs, use_ai_fallback=False)
    assert fs[0]["finding_type"] == "spf_missing"
    assert fs[0]["_finding_type_source"] == "regex"


def test_catalog_has_minimum_types():
    assert len(FINDING_TYPE_CATALOG) >= 40
    # Wichtige finding_types muessen drin sein
    for name in ("software_eol", "cookie_no_secure", "spf_missing",
                  "csrf_token_missing", "csp_missing"):
        assert name in FINDING_TYPE_CATALOG
