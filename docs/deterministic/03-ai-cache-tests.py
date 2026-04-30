"""
scan-worker/tests/test_ai_cache.py

Tests für ai_cache.py.
Spec: docs/specs/2026-Q2-determinism/03-ai-determinism.md

Strategie:
1. Hash-Tests laufen ohne Anthropic-Mock (rein Funktion)
2. Cache-Hit/Miss-Tests mit fakeredis + Anthropic-Mock
3. Telemetrie-Tests (OrderAIStats)
4. Determinismus-Tests (zwei Instanzen → identischer Hash)

REQUIREMENTS:
    pip install fakeredis pytest pytest-mock

TODO(claude-code): Falls ihr fakeredis nicht nutzen wollt, alternative
ist ein Test-Redis im docker-compose.test.yml aufzuziehen.
"""

import json
import time
from unittest.mock import MagicMock, patch

import pytest

# TODO(claude-code): Import-Pfade anpassen
from scanner.ai_cache import (
    POLICY_VERSION,
    CACHE_VERSION,
    CacheStats,
    OrderAIStats,
    cache_key,
    cached_call,
    invalidate_namespace,
    invalidate_all,
)


# ====================================================================
# FIXTURES
# ====================================================================
@pytest.fixture
def fake_redis(mocker):
    """Patcht _get_redis() mit fakeredis."""
    import fakeredis
    fr = fakeredis.FakeRedis(decode_responses=True)
    mocker.patch("scanner.ai_cache._get_redis", return_value=fr)
    yield fr
    fr.flushall()


@pytest.fixture
def mock_anthropic():
    """Mock für Anthropic SDK Client."""
    client = MagicMock()
    response = MagicMock()
    response.model_dump = MagicMock(return_value={
        "id": "msg_abc123",
        "content": [{"type": "text", "text": "Hello world"}],
        "model": "claude-haiku-4-5-20251001",
        "usage": {"input_tokens": 100, "output_tokens": 50},
    })
    client.messages.create.return_value = response
    return client


# ====================================================================
# 1. HASH-TESTS
# ====================================================================
class TestCacheKey:
    def test_same_input_same_hash(self):
        k1 = cache_key(
            model="claude-haiku-4-5-20251001",
            system="You are a helpful assistant.",
            messages=[{"role": "user", "content": "Hi"}],
            temperature=0.0,
            max_tokens=1000,
            namespace="test",
        )
        k2 = cache_key(
            model="claude-haiku-4-5-20251001",
            system="You are a helpful assistant.",
            messages=[{"role": "user", "content": "Hi"}],
            temperature=0.0,
            max_tokens=1000,
            namespace="test",
        )
        assert k1 == k2

    def test_different_messages_different_hash(self):
        k1 = cache_key(
            model="claude-haiku-4-5-20251001",
            system="X",
            messages=[{"role": "user", "content": "Hi"}],
            namespace="test",
        )
        k2 = cache_key(
            model="claude-haiku-4-5-20251001",
            system="X",
            messages=[{"role": "user", "content": "Hello"}],
            namespace="test",
        )
        assert k1 != k2

    def test_different_temperature_different_hash(self):
        k1 = cache_key(
            model="claude-haiku-4-5-20251001",
            system="X",
            messages=[],
            temperature=0.0,
        )
        k2 = cache_key(
            model="claude-haiku-4-5-20251001",
            system="X",
            messages=[],
            temperature=0.5,
        )
        assert k1 != k2

    def test_different_namespace_different_hash(self):
        k1 = cache_key(model="m", system="X", messages=[], namespace="ns1")
        k2 = cache_key(model="m", system="X", messages=[], namespace="ns2")
        assert k1 != k2

    def test_namespace_in_key(self):
        k = cache_key(model="m", system="X", messages=[], namespace="ki1_host_strategy")
        assert "ki1_host_strategy" in k

    def test_dict_key_order_invariant(self):
        """messages mit unterschiedlicher Key-Reihenfolge → gleicher Hash."""
        k1 = cache_key(
            model="m", system="X",
            messages=[{"role": "user", "content": "Hi"}],
        )
        k2 = cache_key(
            model="m", system="X",
            messages=[{"content": "Hi", "role": "user"}],
        )
        assert k1 == k2

    def test_whitespace_in_content_matters(self):
        """Unterschiedliche Whitespace im content → unterschiedliche Hashes."""
        k1 = cache_key(
            model="m", system="X",
            messages=[{"role": "user", "content": "Hello world"}],
        )
        k2 = cache_key(
            model="m", system="X",
            messages=[{"role": "user", "content": "Hello  world"}],  # 2 spaces
        )
        assert k1 != k2

    def test_policy_version_change_invalidates(self, monkeypatch):
        """POLICY_VERSION-Änderung muss Hash ändern."""
        k1 = cache_key(model="m", system="X", messages=[])
        monkeypatch.setattr("scanner.ai_cache.POLICY_VERSION", "9999-99-99.9")
        k2 = cache_key(model="m", system="X", messages=[])
        assert k1 != k2


# ====================================================================
# 2. CACHED-CALL: HIT vs MISS
# ====================================================================
class TestCachedCall:
    def test_cache_miss_calls_anthropic(self, fake_redis, mock_anthropic):
        response, stats = cached_call(
            model="claude-haiku-4-5-20251001",
            system="X",
            messages=[{"role": "user", "content": "Hi"}],
            anthropic_client=mock_anthropic,
        )
        assert stats.hit is False
        assert mock_anthropic.messages.create.call_count == 1
        assert "content" in response

    def test_second_call_hits_cache(self, fake_redis, mock_anthropic):
        # 1. Call → Miss → API + Cache
        cached_call(
            model="claude-haiku-4-5-20251001",
            system="X",
            messages=[{"role": "user", "content": "Hi"}],
            anthropic_client=mock_anthropic,
        )
        # 2. Call → Hit
        response, stats = cached_call(
            model="claude-haiku-4-5-20251001",
            system="X",
            messages=[{"role": "user", "content": "Hi"}],
            anthropic_client=mock_anthropic,
        )
        assert stats.hit is True
        assert mock_anthropic.messages.create.call_count == 1  # Nur 1× aufgerufen
        assert "content" in response

    def test_temperature_zero_default(self, fake_redis, mock_anthropic):
        """temperature=0.0 als Default eingebaut."""
        cached_call(
            model="claude-haiku-4-5-20251001",
            system="X",
            messages=[{"role": "user", "content": "Hi"}],
            anthropic_client=mock_anthropic,
        )
        call_kwargs = mock_anthropic.messages.create.call_args.kwargs
        assert call_kwargs["temperature"] == 0.0

    def test_namespace_isolation(self, fake_redis, mock_anthropic):
        """Gleiche Inputs in verschiedenen Namespaces = separater Cache."""
        cached_call(
            model="m", system="X", messages=[{"role": "user", "content": "Hi"}],
            cache_namespace="ns1",
            anthropic_client=mock_anthropic,
        )
        cached_call(
            model="m", system="X", messages=[{"role": "user", "content": "Hi"}],
            cache_namespace="ns2",
            anthropic_client=mock_anthropic,
        )
        # Beide sind Miss
        assert mock_anthropic.messages.create.call_count == 2

    def test_ttl_expiry(self, fake_redis, mock_anthropic):
        """Nach TTL-Ablauf wird neu gefetcht."""
        cached_call(
            model="m", system="X", messages=[{"role": "user", "content": "Hi"}],
            cache_ttl_seconds=1,
            anthropic_client=mock_anthropic,
        )
        time.sleep(1.5)
        # 2. Call sollte Miss sein
        _, stats = cached_call(
            model="m", system="X", messages=[{"role": "user", "content": "Hi"}],
            anthropic_client=mock_anthropic,
        )
        assert stats.hit is False
        assert mock_anthropic.messages.create.call_count == 2

    def test_corrupt_cache_entry_falls_through(self, fake_redis, mock_anthropic):
        """Cache-Eintrag mit kaputtem JSON → fall-through zu API."""
        # Manuell kaputten Eintrag setzen
        key = cache_key(model="m", system="X", messages=[])
        fake_redis.set(key, "{not json")

        _, stats = cached_call(
            model="m", system="X", messages=[],
            anthropic_client=mock_anthropic,
        )
        assert stats.hit is False
        assert mock_anthropic.messages.create.call_count == 1


# ====================================================================
# 3. TELEMETRY
# ====================================================================
class TestStats:
    def test_cost_estimation_haiku(self, fake_redis, mock_anthropic):
        _, stats = cached_call(
            model="claude-haiku-4-5-20251001",
            system="X", messages=[{"role": "user", "content": "Hi"}],
            anthropic_client=mock_anthropic,
        )
        # 100 input + 50 output Tokens, Haiku-Pricing
        # input: 100 × 1.00/M = 0.0001
        # output: 50 × 5.00/M = 0.00025
        # total: 0.00035
        assert stats.cost_estimated_usd is not None
        assert 0.0001 < stats.cost_estimated_usd < 0.001

    def test_order_stats_aggregation(self):
        order_stats = OrderAIStats()
        order_stats.add(CacheStats(hit=False, cost_estimated_usd=0.001,
                                    input_tokens=100, output_tokens=50))
        order_stats.add(CacheStats(hit=True, cost_estimated_usd=0.001,
                                    input_tokens=100, output_tokens=50))
        order_stats.add(CacheStats(hit=False, cost_estimated_usd=0.002,
                                    input_tokens=200, output_tokens=100))

        assert order_stats.total_calls == 3
        assert order_stats.cache_hits == 1
        assert order_stats.cache_misses == 2
        assert abs(order_stats.total_cost_usd - 0.003) < 1e-6
        assert abs(order_stats.cost_saved_usd - 0.001) < 1e-6

        d = order_stats.to_dict()
        assert d["cache_hit_rate"] == pytest.approx(1/3)


# ====================================================================
# 4. INVALIDATION
# ====================================================================
class TestInvalidation:
    def test_invalidate_namespace(self, fake_redis, mock_anthropic):
        # Zwei Einträge in unterschiedlichen Namespaces
        cached_call(model="m", system="X", messages=[],
                    cache_namespace="ns1", anthropic_client=mock_anthropic)
        cached_call(model="m", system="Y", messages=[],
                    cache_namespace="ns2", anthropic_client=mock_anthropic)

        # ns1 löschen
        deleted = invalidate_namespace("ns1")
        assert deleted == 1

        # ns2 sollte noch da sein
        keys = list(fake_redis.scan_iter(match="ai_cache:*"))
        assert len(keys) == 1
        assert "ns2" in keys[0]

    def test_invalidate_all(self, fake_redis, mock_anthropic):
        cached_call(model="m", system="X", messages=[],
                    cache_namespace="a", anthropic_client=mock_anthropic)
        cached_call(model="m", system="Y", messages=[],
                    cache_namespace="b", anthropic_client=mock_anthropic)

        deleted = invalidate_all()
        assert deleted == 2
        keys = list(fake_redis.scan_iter(match="ai_cache:*"))
        assert keys == []


# ====================================================================
# 5. DETERMINISMUS (End-to-End)
# ====================================================================
class TestDeterminism:
    def test_same_call_same_response_via_cache(self, fake_redis, mock_anthropic):
        """Zwei Calls mit identischem Input → identische Response (durch Cache)."""
        r1, _ = cached_call(
            model="m", system="X", messages=[{"role": "user", "content": "Hi"}],
            anthropic_client=mock_anthropic,
        )
        r2, _ = cached_call(
            model="m", system="X", messages=[{"role": "user", "content": "Hi"}],
            anthropic_client=mock_anthropic,
        )
        assert r1 == r2

    def test_redis_unavailable_falls_through_to_api(self, mocker, mock_anthropic):
        """Wenn Redis-GET fehlschlägt: API-Call läuft trotzdem."""
        broken_redis = MagicMock()
        broken_redis.get.side_effect = Exception("Connection refused")
        mocker.patch("scanner.ai_cache._get_redis", return_value=broken_redis)

        response, stats = cached_call(
            model="m", system="X", messages=[],
            anthropic_client=mock_anthropic,
        )
        assert mock_anthropic.messages.create.call_count == 1
        assert stats.hit is False
