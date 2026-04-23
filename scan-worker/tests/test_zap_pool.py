"""Tests fuer scanner.zap_pool.

Nutzt einen minimalen In-Memory-Fake statt fakeredis, weil die
Scan-Worker-Test-Umgebung keine zusaetzlichen Abhaengigkeiten erwuenscht.
Der Fake implementiert genau die Redis-Methoden, die zap_pool aufruft,
und interpretiert die beiden konkret genutzten Lua-Scripts.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from scanner import zap_pool
from scanner.zap_pool import _HEARTBEAT_LUA, _RELEASE_LUA


class FakeRedis:
    """Sehr schlanker Redis-Ersatz fuer Pool-Tests."""

    def __init__(self) -> None:
        self._strings: dict[str, tuple[str, float | None]] = {}  # key -> (value, expiry_monotonic)
        self._sets: dict[str, set[str]] = {}
        self._lists: dict[str, list[str]] = {}

    # ---- expiry helpers -------------------------------------------------
    def _now(self) -> float:
        return time.monotonic()

    def _expired(self, key: str) -> bool:
        entry = self._strings.get(key)
        if entry is None:
            return True
        _, expiry = entry
        if expiry is not None and self._now() >= expiry:
            del self._strings[key]
            return True
        return False

    # ---- SET / GET ------------------------------------------------------
    def set(self, key: str, value: str, nx: bool = False, ex: int | None = None) -> bool | None:
        if self._expired(key):
            pass  # already cleaned
        if nx and key in self._strings:
            return None
        expiry = self._now() + ex if ex is not None else None
        self._strings[key] = (str(value), expiry)
        return True

    def get(self, key: str) -> str | None:
        if self._expired(key):
            return None
        entry = self._strings.get(key)
        return entry[0] if entry else None

    def incr(self, key: str) -> int:
        current = int(self.get(key) or 0) + 1
        # INCR preserves existing TTL in real Redis; for our usage expiry is never set on counters.
        self._strings[key] = (str(current), None)
        return current

    def expire(self, key: str, seconds: int) -> int:
        entry = self._strings.get(key)
        if entry is None:
            return 0
        value, _ = entry
        self._strings[key] = (value, self._now() + seconds)
        return 1

    def delete(self, *keys: str) -> int:
        removed = 0
        for k in keys:
            if k in self._strings:
                del self._strings[k]
                removed += 1
        return removed

    # ---- SET type -------------------------------------------------------
    def sadd(self, key: str, *members: str) -> int:
        s = self._sets.setdefault(key, set())
        before = len(s)
        s.update(members)
        return len(s) - before

    def smembers(self, key: str) -> set[str]:
        return set(self._sets.get(key, set()))

    def scard(self, key: str) -> int:
        return len(self._sets.get(key, set()))

    # ---- LIST type ------------------------------------------------------
    def lpush(self, key: str, *values: Any) -> int:
        lst = self._lists.setdefault(key, [])
        for v in values:
            lst.insert(0, str(v))
        return len(lst)

    def ltrim(self, key: str, start: int, stop: int) -> bool:
        lst = self._lists.get(key, [])
        # Redis-Semantik: stop ist inklusiv
        self._lists[key] = lst[start : stop + 1]
        return True

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        lst = self._lists.get(key, [])
        if stop == -1:
            return list(lst[start:])
        return list(lst[start : stop + 1])

    # ---- SCAN -----------------------------------------------------------
    def scan_iter(self, match: str):
        # Simples fnmatch-Globbing nur fuer den match-Pattern, den wir nutzen.
        import fnmatch
        for key in list(self._strings.keys()):
            if self._expired(key):
                continue
            if fnmatch.fnmatchcase(key, match):
                yield key

    # ---- EVAL (nur die bekannten Scripts) --------------------------------
    def eval(self, script: str, numkeys: int, *args: Any) -> int:
        keys = list(args[:numkeys])
        argv = list(args[numkeys:])

        if script == _RELEASE_LUA:
            lease_key, hb_key = keys[0], keys[1]
            expected = argv[0]
            if self.get(lease_key) == expected:
                self.delete(hb_key)
                return self.delete(lease_key)
            return 0

        if script == _HEARTBEAT_LUA:
            lease_key, hb_key = keys[0], keys[1]
            expected = argv[0]
            lease_ttl = int(argv[1])
            hb_ttl = int(argv[2])
            if self.get(lease_key) == expected:
                self.expire(lease_key, lease_ttl)
                self.set(hb_key, "1", ex=hb_ttl)
                return 1
            return 0

        raise AssertionError(f"Unknown Lua script in test: {script[:40]}")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_redis():
    return FakeRedis()


@pytest.fixture
def pool_of_four(fake_redis):
    zap_pool.init_zap_pool(fake_redis, members=["zap-1", "zap-2", "zap-3", "zap-4"])
    return fake_redis


# ---------------------------------------------------------------------------
# init_zap_pool
# ---------------------------------------------------------------------------

class TestInitZapPool:
    def test_registers_all_members(self, fake_redis):
        size = zap_pool.init_zap_pool(fake_redis, members=["zap-1", "zap-2"])
        assert size == 2
        assert fake_redis.smembers("zap:pool:available") == {"zap-1", "zap-2"}

    def test_idempotent(self, fake_redis):
        zap_pool.init_zap_pool(fake_redis, members=["zap-1"])
        zap_pool.init_zap_pool(fake_redis, members=["zap-1", "zap-2"])
        assert fake_redis.smembers("zap:pool:available") == {"zap-1", "zap-2"}

    def test_empty_members(self, fake_redis):
        assert zap_pool.init_zap_pool(fake_redis, members=[]) == 0
        assert fake_redis.smembers("zap:pool:available") == set()


# ---------------------------------------------------------------------------
# acquire / release
# ---------------------------------------------------------------------------

class TestAcquireRelease:
    def test_acquires_available_zap(self, pool_of_four):
        result = zap_pool.acquire_zap(pool_of_four, "order-A", "1.2.3.4", "worker-1")
        assert result is not None
        zap_id, lease_value = result
        assert zap_id in {"zap-1", "zap-2", "zap-3", "zap-4"}
        assert lease_value.startswith("order-A:1.2.3.4:worker-1:")

    def test_stats_incremented(self, pool_of_four):
        zap_pool.acquire_zap(pool_of_four, "order-A", "1.2.3.4", "w1")
        assert zap_pool.get_leases_total(pool_of_four) == 1
        samples = zap_pool.get_lease_wait_ms_samples(pool_of_four)
        assert len(samples) == 1

    def test_second_acquire_picks_different_zap(self, pool_of_four):
        r1 = zap_pool.acquire_zap(pool_of_four, "order-A", "1.1.1.1", "w1")
        r2 = zap_pool.acquire_zap(pool_of_four, "order-B", "2.2.2.2", "w2")
        assert r1 is not None and r2 is not None
        assert r1[0] != r2[0]

    def test_pool_exhaustion_times_out(self, fake_redis):
        zap_pool.init_zap_pool(fake_redis, members=["zap-1"])
        zap_pool.acquire_zap(fake_redis, "order-A", "1.1.1.1", "w1")
        result = zap_pool.acquire_zap(
            fake_redis, "order-B", "2.2.2.2", "w2", timeout_s=1
        )
        assert result is None

    def test_release_frees_zap(self, pool_of_four):
        r = zap_pool.acquire_zap(pool_of_four, "order-A", "1.1.1.1", "w1")
        assert r is not None
        zap_id, lease_value = r
        assert zap_pool.release_zap(pool_of_four, zap_id, lease_value) is True
        # Now we can acquire the same zap again
        again = zap_pool.acquire_zap(pool_of_four, "order-B", "2.2.2.2", "w2")
        assert again is not None

    def test_release_with_wrong_lease_value_is_noop(self, pool_of_four):
        r = zap_pool.acquire_zap(pool_of_four, "order-A", "1.1.1.1", "w1")
        assert r is not None
        zap_id, _ = r
        assert zap_pool.release_zap(pool_of_four, zap_id, "bogus-value") is False
        # Lease must still be held
        assert pool_of_four.get(f"zap:lease:{zap_id}") is not None


# ---------------------------------------------------------------------------
# heartbeat
# ---------------------------------------------------------------------------

class TestHeartbeat:
    def test_heartbeat_renews_ttl(self, pool_of_four):
        r = zap_pool.acquire_zap(pool_of_four, "order-A", "1.1.1.1", "w1")
        assert r is not None
        zap_id, lease_value = r
        # Pre-expire the lease manually so heartbeat would have been important
        ok = zap_pool.heartbeat_zap(pool_of_four, zap_id, lease_value)
        assert ok is True
        assert pool_of_four.get(f"zap:heartbeat:{zap_id}") == "1"

    def test_heartbeat_wrong_owner_fails(self, pool_of_four):
        r = zap_pool.acquire_zap(pool_of_four, "order-A", "1.1.1.1", "w1")
        assert r is not None
        zap_id, _ = r
        ok = zap_pool.heartbeat_zap(pool_of_four, zap_id, "foreign-value")
        assert ok is False


# ---------------------------------------------------------------------------
# active contexts
# ---------------------------------------------------------------------------

class TestActiveContexts:
    def test_reconstructs_context_names_from_leases(self, pool_of_four):
        zap_pool.acquire_zap(pool_of_four, "abcdefgh1234", "10.0.0.1", "w1")
        zap_pool.acquire_zap(pool_of_four, "ffeeddcc5678", "10.0.0.2", "w1")
        active = zap_pool.get_all_active_context_names(pool_of_four)
        assert "ctx-abcdefgh-10_0_0_1" in active
        assert "ctx-ffeeddcc-10_0_0_2" in active
        assert len(active) == 2

    def test_empty_when_no_leases(self, pool_of_four):
        assert zap_pool.get_all_active_context_names(pool_of_four) == set()


# ---------------------------------------------------------------------------
# Env-driven configuration
# ---------------------------------------------------------------------------

class TestConfig:
    def test_default_pool_members(self, monkeypatch):
        monkeypatch.delenv("ZAP_POOL", raising=False)
        assert zap_pool.get_pool_members() == ["zap-1", "zap-2", "zap-3", "zap-4"]

    def test_pool_override(self, monkeypatch):
        monkeypatch.setenv("ZAP_POOL", "alpha,beta,gamma")
        assert zap_pool.get_pool_members() == ["alpha", "beta", "gamma"]

    def test_max_parallel_default_is_pool_size_minus_one(self, monkeypatch):
        monkeypatch.setenv("ZAP_POOL", "a,b,c,d")
        monkeypatch.delenv("ZAP_MAX_PARALLEL_PER_ORDER", raising=False)
        assert zap_pool.get_max_parallel_per_order() == 3

    def test_max_parallel_override(self, monkeypatch):
        monkeypatch.setenv("ZAP_MAX_PARALLEL_PER_ORDER", "2")
        assert zap_pool.get_max_parallel_per_order() == 2

    def test_max_parallel_never_below_one(self, monkeypatch):
        monkeypatch.setenv("ZAP_POOL", "only-one")
        monkeypatch.delenv("ZAP_MAX_PARALLEL_PER_ORDER", raising=False)
        assert zap_pool.get_max_parallel_per_order() == 1
