"""
scan-worker/scanner/ai_cache.py

Redis-basierter Cache für Anthropic-API-Calls mit deterministischem
Input-Hashing.

Spec: docs/specs/2026-Q2-determinism/03-ai-determinism.md

Kapselt:
- Cache-Key-Generierung (sha256 über canonicalized Inputs)
- Redis GET/SET mit TTL
- Anthropic-Call mit temperature=0 + retry
- Telemetrie (cache_hit, cost_saved, age)

TODO(claude-code):
- POLICY_VERSION-Import-Pfad ggf. anpassen (report-worker package)
- Wenn euer Anthropic-Wrapper anders heißt (z.B. claude_client.py), den
  hier importieren statt anthropic-SDK direkt
- Wenn ihr ein zentrales Redis-Module habt, das nutzen statt direktem
  redis.Redis() instantiieren
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Optional

import redis

# TODO(claude-code): Pfad anpassen — POLICY_VERSION lebt in report-worker.
# Mögliche Lösungen:
#   a) shared package, beide importieren daraus
#   b) POLICY_VERSION zusätzlich in scan-worker aus ENV lesen (in Sync halten)
#   c) Aus DB lesen (dann braucht's einen DB-Roundtrip pro Cache-Key)
# Für jetzt: lokal definieren, mit ENV-Override
import os

POLICY_VERSION = os.environ.get("VECTISCAN_POLICY_VERSION", "2026-04-24.1")
CACHE_VERSION = "v1"  # Bumpen wenn Cache-Format inkompatibel wird

logger = logging.getLogger(__name__)


# ====================================================================
# REDIS-CLIENT (Lazy)
# ====================================================================
_redis_client: Optional[redis.Redis] = None


def _get_redis() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        host = os.environ.get("REDIS_HOST", "redis")
        port = int(os.environ.get("REDIS_PORT", "6379"))
        db = int(os.environ.get("REDIS_AI_CACHE_DB", "0"))
        _redis_client = redis.Redis(
            host=host, port=port, db=db,
            decode_responses=True,
            socket_connect_timeout=5.0,
        )
    return _redis_client


# ====================================================================
# CANONICALIZATION + HASHING
# ====================================================================
def _canonicalize(obj: Any) -> str:
    """
    Stable JSON serialization.
    sort_keys=True für reproduzierbare Reihenfolge.
    separators ohne Whitespace.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def cache_key(*,
              model: str,
              system: str,
              messages: list[dict],
              tools: Optional[list[dict]] = None,
              temperature: float = 0.0,
              max_tokens: int = 8192,
              namespace: str = "default") -> str:
    """
    Deterministischer Cache-Key.
    Nimmt ALLE Inputs auf, die das Output beeinflussen können.
    """
    payload = {
        "namespace": namespace,
        "model": model,
        "system": system,
        "messages": messages,
        "tools": tools,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "policy_version": POLICY_VERSION,
        "cache_version": CACHE_VERSION,
    }
    serialized = _canonicalize(payload)
    h = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return f"ai_cache:{namespace}:{h}"


# ====================================================================
# CACHED-CALL
# ====================================================================
@dataclass
class CacheStats:
    """Per-call Telemetrie."""
    hit: bool
    age_seconds: Optional[float] = None
    cost_estimated_usd: Optional[float] = None
    input_tokens: int = 0
    output_tokens: int = 0


# Anthropic Pricing (approx, Stand 2026 — TODO: aktualisieren wenn geändert)
PRICING = {
    "claude-haiku-4-5-20251001":  {"input": 1.00 / 1_000_000,  "output": 5.00 / 1_000_000},
    "claude-sonnet-4-6":          {"input": 3.00 / 1_000_000,  "output": 15.00 / 1_000_000},
    "claude-opus-4-7":            {"input": 15.00 / 1_000_000, "output": 75.00 / 1_000_000},
}


def _estimate_cost(model: str, in_tok: int, out_tok: int) -> float:
    p = PRICING.get(model, {"input": 0.0, "output": 0.0})
    return in_tok * p["input"] + out_tok * p["output"]


def cached_call(*,
                model: str,
                system: str,
                messages: list[dict],
                tools: Optional[list[dict]] = None,
                temperature: float = 0.0,
                max_tokens: int = 8192,
                cache_ttl_seconds: int = 86400,
                cache_namespace: str = "default",
                anthropic_client: Any = None,
                ) -> tuple[dict, CacheStats]:
    """
    Cached Anthropic call.

    Returns: (response_dict, cache_stats)
        response_dict ist die Anthropic-API-Response (oder gecachte Version)
        cache_stats hat hit/age/cost-Felder

    TODO(claude-code): anthropic_client-Parameter anpassen an euer Setup.
    Bei euch existiert (laut docs) `claude_client.py` im report-worker —
    ähnliches in scan-worker bauen oder hier den anthropic-SDK direkt nutzen.

    Pseudocode für Integration:
        from scanner.ai_cache import cached_call
        response, stats = cached_call(
            model="claude-haiku-4-5-20251001",
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_input}],
            cache_namespace="ki1_host_strategy",
        )
        if stats.hit:
            logger.info(f"Cache hit (age={stats.age_seconds:.0f}s)")
    """
    if anthropic_client is None:
        # TODO(claude-code): Default-Client lazy laden
        import anthropic
        anthropic_client = anthropic.Anthropic()

    key = cache_key(
        model=model, system=system, messages=messages, tools=tools,
        temperature=temperature, max_tokens=max_tokens, namespace=cache_namespace,
    )

    # 1) Cache lookup
    r = _get_redis()
    try:
        raw = r.get(key)
    except redis.RedisError as e:
        logger.warning("Redis GET failed: %s — falling through to API", e)
        raw = None

    if raw is not None:
        try:
            entry = json.loads(raw)
            cached_at = entry.get("cached_at_ts", 0)
            age = time.time() - cached_at
            stats = CacheStats(
                hit=True,
                age_seconds=age,
                cost_estimated_usd=_estimate_cost(
                    model, entry.get("input_tokens", 0), entry.get("output_tokens", 0)
                ),
                input_tokens=entry.get("input_tokens", 0),
                output_tokens=entry.get("output_tokens", 0),
            )
            logger.info("AI cache HIT [%s] age=%.0fs key=%s",
                        cache_namespace, age, key[:24])
            return entry["response"], stats
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("Corrupt cache entry %s: %s — refetching", key, e)

    # 2) Cache miss → Anthropic call
    logger.info("AI cache MISS [%s] key=%s", cache_namespace, key[:24])
    api_kwargs = {
        "model": model,
        "system": system,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if tools:
        api_kwargs["tools"] = tools

    # TODO(claude-code): Retry-Logik nach eurem bestehenden Pattern
    # (siehe report-worker/reporter/claude_client.py — JSONDecodeError Retry)
    response_obj = anthropic_client.messages.create(**api_kwargs)

    # Normalize response to dict (anthropic SDK gibt ein Pydantic-Modell zurück)
    response_dict = (
        response_obj.model_dump(mode="json")
        if hasattr(response_obj, "model_dump")
        else dict(response_obj)
    )

    in_tok = response_dict.get("usage", {}).get("input_tokens", 0)
    out_tok = response_dict.get("usage", {}).get("output_tokens", 0)

    # 3) Cache write
    entry = {
        "response": response_dict,
        "cached_at_ts": time.time(),
        "cached_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model": model,
        "input_tokens": in_tok,
        "output_tokens": out_tok,
        "policy_version": POLICY_VERSION,
        "cache_version": CACHE_VERSION,
    }
    try:
        r.setex(key, cache_ttl_seconds, _canonicalize(entry))
    except redis.RedisError as e:
        logger.warning("Redis SETEX failed: %s — continuing without cache", e)

    stats = CacheStats(
        hit=False,
        cost_estimated_usd=_estimate_cost(model, in_tok, out_tok),
        input_tokens=in_tok,
        output_tokens=out_tok,
    )
    return response_dict, stats


# ====================================================================
# AGGREGATE STATS (für Order-Telemetrie)
# ====================================================================
@dataclass
class OrderAIStats:
    """Aggregat über alle AI-Calls einer Order."""
    total_calls: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    total_cost_usd: float = 0.0
    cost_saved_usd: float = 0.0  # geschätzt = wäre angefallen ohne Cache
    total_input_tokens: int = 0
    total_output_tokens: int = 0

    def add(self, stats: CacheStats) -> None:
        self.total_calls += 1
        if stats.hit:
            self.cache_hits += 1
            if stats.cost_estimated_usd:
                self.cost_saved_usd += stats.cost_estimated_usd
        else:
            self.cache_misses += 1
            if stats.cost_estimated_usd:
                self.total_cost_usd += stats.cost_estimated_usd
        self.total_input_tokens += stats.input_tokens
        self.total_output_tokens += stats.output_tokens

    def to_dict(self) -> dict:
        return {
            "total_calls": self.total_calls,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": (self.cache_hits / self.total_calls
                               if self.total_calls else 0.0),
            "total_cost_usd": round(self.total_cost_usd, 4),
            "cost_saved_usd": round(self.cost_saved_usd, 4),
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
        }


# ====================================================================
# CACHE INVALIDATION HELPERS
# ====================================================================
def invalidate_namespace(namespace: str) -> int:
    """
    Löscht alle Cache-Entries für einen Namespace.
    Returns: Anzahl gelöschte Keys.
    Nutzt SCAN statt KEYS für Production-Sicherheit.
    """
    r = _get_redis()
    pattern = f"ai_cache:{namespace}:*"
    deleted = 0
    for key in r.scan_iter(match=pattern, count=500):
        r.delete(key)
        deleted += 1
    logger.info("Invalidated %d cache entries for namespace=%s", deleted, namespace)
    return deleted


def invalidate_all() -> int:
    """Löscht den gesamten AI-Cache. Vorsicht!"""
    r = _get_redis()
    deleted = 0
    for key in r.scan_iter(match="ai_cache:*", count=500):
        r.delete(key)
        deleted += 1
    logger.warning("Invalidated %d total cache entries", deleted)
    return deleted


# ====================================================================
# EXPORTS
# ====================================================================
__all__ = [
    "POLICY_VERSION",
    "CACHE_VERSION",
    "CacheStats",
    "OrderAIStats",
    "cache_key",
    "cached_call",
    "invalidate_namespace",
    "invalidate_all",
]
