"""Tests fuer scanner/ai_cache.py — Hash-Stability, Cache-Hit/Miss, TTL, Telemetrie."""

from __future__ import annotations

import json
import time
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_redis_client(monkeypatch):
    """Patcht ai_cache._get_redis() so dass eine fakeredis-Instanz zurueckkommt.

    Ein einziger fakeredis-Server, sodass Test-Setup (set) und Test-Code (get)
    auf demselben Datenstand arbeiten.
    """
    import fakeredis
    server = fakeredis.FakeServer()
    client = fakeredis.FakeRedis(server=server)
    from scanner import ai_cache
    monkeypatch.setattr(ai_cache, "_get_redis", lambda: client)
    return client


@pytest.fixture
def stub_anthropic(monkeypatch):
    """Erzeugt einen Stub-Anthropic-Client mit zaehlenden messages.create-Aufrufen.

    Nutzung:
        client, calls = stub_anthropic
        # `calls` ist eine Liste; jeder Aufruf von messages.create haengt ein Dict an.
    """
    calls: list[dict] = []

    class _Usage:
        def __init__(self):
            self.input_tokens = 100
            self.output_tokens = 50

    class _Block:
        def __init__(self, text: str):
            self.text = text

    class _Response:
        def __init__(self, text: str):
            self.content = [_Block(text)]
            self.usage = _Usage()
            self.stop_reason = "end_turn"

        def model_dump(self, mode="json"):
            return {
                "content": [{"type": "text", "text": self.content[0].text}],
                "usage": {
                    "input_tokens": self.usage.input_tokens,
                    "output_tokens": self.usage.output_tokens,
                },
                "stop_reason": self.stop_reason,
            }

    class _Messages:
        def create(self, **kwargs):
            calls.append(kwargs)
            payload = {"answer": "hello", "n": len(calls)}
            return _Response(json.dumps(payload))

    class _Client:
        def __init__(self):
            self.messages = _Messages()

    return _Client(), calls


# ---------------------------------------------------------------------------
# Hash-Stability
# ---------------------------------------------------------------------------

class TestCacheKey:
    def test_identical_inputs_yield_identical_hash(self):
        from scanner.ai_cache import cache_key
        a = cache_key(
            model="claude-haiku-4-5-20251001",
            system="sys",
            messages=[{"role": "user", "content": "hello"}],
            temperature=0.0,
            max_tokens=8192,
            namespace="ns",
        )
        b = cache_key(
            model="claude-haiku-4-5-20251001",
            system="sys",
            messages=[{"role": "user", "content": "hello"}],
            temperature=0.0,
            max_tokens=8192,
            namespace="ns",
        )
        assert a == b
        assert a.startswith("ai_cache:ns:")

    def test_whitespace_change_in_message_yields_different_hash(self):
        from scanner.ai_cache import cache_key
        a = cache_key(model="m", system="s", messages=[{"role": "user", "content": "hi"}])
        b = cache_key(model="m", system="s", messages=[{"role": "user", "content": "hi "}])
        assert a != b

    def test_namespace_isolates_keys(self):
        from scanner.ai_cache import cache_key
        a = cache_key(model="m", system="s", messages=[{"role": "user", "content": "x"}],
                      namespace="ns_a")
        b = cache_key(model="m", system="s", messages=[{"role": "user", "content": "x"}],
                      namespace="ns_b")
        assert a != b
        assert a.startswith("ai_cache:ns_a:")
        assert b.startswith("ai_cache:ns_b:")

    def test_temperature_affects_hash(self):
        from scanner.ai_cache import cache_key
        a = cache_key(model="m", system="s", messages=[{"role": "user", "content": "x"}],
                      temperature=0.0)
        b = cache_key(model="m", system="s", messages=[{"role": "user", "content": "x"}],
                      temperature=1.0)
        assert a != b


# ---------------------------------------------------------------------------
# Cache-Hit / Cache-Miss
# ---------------------------------------------------------------------------

class TestCachedCall:
    def test_first_call_misses_then_writes(self, fake_redis_client, stub_anthropic):
        from scanner.ai_cache import cached_call
        client, calls = stub_anthropic

        response, stats = cached_call(
            model="claude-haiku-4-5-20251001",
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            temperature=0.0,
            cache_namespace="test_ns",
            anthropic_client=client,
        )

        assert stats.hit is False
        assert len(calls) == 1
        # Cache wurde geschrieben → Redis enthaelt einen Key im Namespace
        keys = list(fake_redis_client.scan_iter(match="ai_cache:test_ns:*"))
        assert len(keys) == 1

    def test_second_call_hits_cache_no_anthropic(self, fake_redis_client, stub_anthropic):
        from scanner.ai_cache import cached_call
        client, calls = stub_anthropic

        kwargs = dict(
            model="claude-haiku-4-5-20251001",
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            temperature=0.0,
            cache_namespace="test_ns",
            anthropic_client=client,
        )
        # 1. Aufruf: Miss
        cached_call(**kwargs)
        assert len(calls) == 1
        # 2. Aufruf identischer Inputs: Hit
        response, stats = cached_call(**kwargs)
        assert stats.hit is True
        assert len(calls) == 1  # Anthropic NICHT erneut aufgerufen
        # Response-Inhalt entspricht dem urspruenglichen
        assert response["content"][0]["text"] == json.dumps({"answer": "hello", "n": 1})

    def test_temperature_forced_to_zero_in_api_call(self, fake_redis_client, stub_anthropic):
        from scanner.ai_cache import cached_call
        client, calls = stub_anthropic
        cached_call(
            model="claude-haiku-4-5-20251001",
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            temperature=0.0,
            anthropic_client=client,
        )
        assert calls[0]["temperature"] == 0.0

    def test_cache_stats_age_increases_over_time(self, fake_redis_client, stub_anthropic):
        from scanner.ai_cache import cached_call
        client, _ = stub_anthropic

        kwargs = dict(
            model="claude-haiku-4-5-20251001",
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            anthropic_client=client,
            cache_namespace="age_ns",
        )
        cached_call(**kwargs)
        time.sleep(0.05)  # 50 ms
        _, stats = cached_call(**kwargs)
        assert stats.hit is True
        assert stats.age_seconds is not None
        assert stats.age_seconds >= 0.04


# ---------------------------------------------------------------------------
# Cache-Verhalten bei Redis-Ausfall
# ---------------------------------------------------------------------------

class TestRedisDegradation:
    def test_no_redis_falls_through_to_anthropic(self, monkeypatch, stub_anthropic):
        """Bei fehlender Redis-Verbindung wird Cache uebersprungen."""
        from scanner import ai_cache
        from scanner.ai_cache import cached_call
        monkeypatch.setattr(ai_cache, "_get_redis", lambda: None)
        client, calls = stub_anthropic

        # Zwei aufeinanderfolgende Calls → beide treffen Anthropic, kein Hit
        kwargs = dict(
            model="claude-haiku-4-5-20251001",
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            anthropic_client=client,
        )
        _, s1 = cached_call(**kwargs)
        _, s2 = cached_call(**kwargs)
        assert s1.hit is False
        assert s2.hit is False
        assert len(calls) == 2


# ---------------------------------------------------------------------------
# Invalidation
# ---------------------------------------------------------------------------

class TestInvalidation:
    def test_invalidate_namespace_deletes_only_that_namespace(self, fake_redis_client,
                                                              stub_anthropic):
        from scanner.ai_cache import cached_call, invalidate_namespace
        client, _ = stub_anthropic
        cached_call(model="m", system="s", messages=[{"role": "user", "content": "a"}],
                    cache_namespace="ns_a", anthropic_client=client)
        cached_call(model="m", system="s", messages=[{"role": "user", "content": "b"}],
                    cache_namespace="ns_b", anthropic_client=client)

        deleted = invalidate_namespace("ns_a")
        assert deleted == 1
        assert list(fake_redis_client.scan_iter(match="ai_cache:ns_a:*")) == []
        assert len(list(fake_redis_client.scan_iter(match="ai_cache:ns_b:*"))) == 1


# ---------------------------------------------------------------------------
# Telemetrie
# ---------------------------------------------------------------------------

class TestOrderAIStats:
    def test_aggregates_hits_and_misses(self):
        from scanner.ai_cache import CacheStats, OrderAIStats
        stats = OrderAIStats()
        stats.add("ki1", CacheStats(hit=False, cost_estimated_usd=0.5,
                                    input_tokens=100, output_tokens=50))
        stats.add("ki1", CacheStats(hit=True, cost_estimated_usd=0.5,
                                    input_tokens=100, output_tokens=50,
                                    age_seconds=10))
        stats.add("ki2", CacheStats(hit=False, cost_estimated_usd=0.3,
                                    input_tokens=80, output_tokens=20))

        d = stats.to_dict()
        assert d["total_calls"] == 3
        assert d["cache_hits"] == 1
        assert d["cache_misses"] == 2
        assert abs(d["cache_hit_rate"] - 1 / 3) < 1e-9
        assert abs(d["total_cost_usd"] - 0.8) < 1e-9
        assert abs(d["cost_saved_usd"] - 0.5) < 1e-9
        assert d["per_namespace"]["ki1"]["hits"] == 1
        assert d["per_namespace"]["ki2"]["hits"] == 0


# ---------------------------------------------------------------------------
# Extract-text helper
# ---------------------------------------------------------------------------

class TestExtractText:
    def test_extracts_first_text_block(self):
        from scanner.ai_cache import extract_text
        response = {"content": [{"type": "text", "text": "hello"}]}
        assert extract_text(response) == "hello"

    def test_returns_empty_on_missing_content(self):
        from scanner.ai_cache import extract_text
        assert extract_text({}) == ""
        assert extract_text({"content": []}) == ""
