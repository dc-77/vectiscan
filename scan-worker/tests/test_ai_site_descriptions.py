"""Tests fuer ai_site_descriptions.refine_with_ai (Mai 2026, PR-E)."""

from __future__ import annotations

from unittest.mock import patch

from scanner.ai_cache import CacheStats


def _fake_cached_call_factory(json_text: str, hit: bool = False):
    """Mock-Helfer: liefert (response_dict, CacheStats)-Tupel mit dem gegebenen Text."""
    def _fake(**kwargs):
        return (
            {
                "content": [{"type": "text", "text": json_text}],
                "usage": {"input_tokens": 200, "output_tokens": 80},
            },
            CacheStats(hit=hit, input_tokens=200, output_tokens=80,
                       cost_estimated_usd=0.001, cache_key_short="abc123"),
        )
    return _fake


def test_refine_returns_mapping_from_haiku() -> None:
    """Haiku-Response liefert ``{"summaries": {...}}`` → das wird sauber geparst."""
    response = '{"summaries": {"heuel.com": "Unternehmens-Webseite eines Stahlherstellers auf WordPress.", "shop.heuel.com": "Online-Shop fuer Stahlteile mit Login."}}'
    candidates = [
        {"fqdn": "heuel.com", "title": "Heuel - Home", "status": 200},
        {"fqdn": "shop.heuel.com", "title": "Heuel Shop", "status": 200},
    ]
    with patch("scanner.ai_cache.cached_call", _fake_cached_call_factory(response)):
        from scanner.ai_site_descriptions import refine_with_ai
        out = refine_with_ai(candidates, order_id="ord-1")
    assert out == {
        "heuel.com": "Unternehmens-Webseite eines Stahlherstellers auf WordPress.",
        "shop.heuel.com": "Online-Shop fuer Stahlteile mit Login.",
    }


def test_refine_handles_markdown_fenced_response() -> None:
    """KI antwortet mit ```json\\n{...}\\n``` Wrapper → wird abgestrippt."""
    response = '```json\n{"summaries": {"a.example.com": "Marketing-Webseite."}}\n```'
    with patch("scanner.ai_cache.cached_call", _fake_cached_call_factory(response)):
        from scanner.ai_site_descriptions import refine_with_ai
        out = refine_with_ai([{"fqdn": "a.example.com", "title": "X"}])
    assert out == {"a.example.com": "Marketing-Webseite."}


def test_refine_empty_candidates_returns_empty_dict() -> None:
    """Leere Kandidaten-Liste → kein Haiku-Call, leeres Resultat."""
    from scanner.ai_site_descriptions import refine_with_ai
    assert refine_with_ai([]) == {}


def test_refine_api_error_returns_empty_dict() -> None:
    """Anthropic-Error (``_error``-Feld) → silent fallback (leeres Dict)."""
    def _err(**kw):
        return {"_error": "rate limit"}, CacheStats(hit=False, cache_key_short="x")
    with patch("scanner.ai_cache.cached_call", _err):
        from scanner.ai_site_descriptions import refine_with_ai
        assert refine_with_ai([{"fqdn": "a", "title": "T"}], order_id="o") == {}


def test_refine_parse_error_returns_empty_dict() -> None:
    """KI antwortet kein JSON → silent fallback."""
    with patch("scanner.ai_cache.cached_call",
               _fake_cached_call_factory("not really json")):
        from scanner.ai_site_descriptions import refine_with_ai
        out = refine_with_ai([{"fqdn": "a", "title": "T"}])
    assert out == {}


def test_refine_sanitizes_quotes_and_truncates() -> None:
    """Lange + gequotete Beschreibungen werden saniert."""
    long = '"' + ("A" * 400) + '"'
    response = '{"summaries": {"x.example.com": ' + long + '}}'
    with patch("scanner.ai_cache.cached_call", _fake_cached_call_factory(response)):
        from scanner.ai_site_descriptions import refine_with_ai
        out = refine_with_ai([{"fqdn": "x.example.com", "title": "Y"}])
    assert "x.example.com" in out
    val = out["x.example.com"]
    assert len(val) <= 200
    assert not val.startswith('"')


def test_refine_drops_non_string_values() -> None:
    """KI liefert versehentlich Number statt String → wird ignoriert."""
    response = '{"summaries": {"valid.example.com": "OK", "bad.example.com": 123}}'
    with patch("scanner.ai_cache.cached_call", _fake_cached_call_factory(response)):
        from scanner.ai_site_descriptions import refine_with_ai
        out = refine_with_ai([
            {"fqdn": "valid.example.com", "title": "v"},
            {"fqdn": "bad.example.com", "title": "b"},
        ])
    assert out == {"valid.example.com": "OK"}


def test_tech_hint_passed_to_prompt() -> None:
    """``tech_hint_by_fqdn`` wird in ``_tech_hint`` des Kandidaten gesetzt."""
    response = '{"summaries": {}}'
    captured: dict = {}

    def _capture(**kw):
        captured["messages"] = kw.get("messages")
        return _fake_cached_call_factory(response)(**kw)

    with patch("scanner.ai_cache.cached_call", _capture):
        from scanner.ai_site_descriptions import refine_with_ai
        refine_with_ai(
            [{"fqdn": "a.example.com", "title": "T"}],
            order_id="ord",
            tech_hint_by_fqdn={"a.example.com": "WordPress 6.4 auf Apache"},
        )
    content = captured["messages"][0]["content"]
    assert "WordPress 6.4 auf Apache" in content
