"""Redis-basierter Cache fuer Reporter-Anthropic-Calls.

Klone von scan-worker/scanner/ai_cache.py — separater Container,
unterschiedlicher PYTHONPATH, daher minimale Duplikation statt shared module.

Spec: docs/deterministic/03-ai-determinism.md
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Optional

import structlog

log = structlog.get_logger()

POLICY_VERSION = os.environ.get("VECTISCAN_POLICY_VERSION", "2026-04-30.1")
CACHE_VERSION = "v1"

AI_PRICING: dict[str, dict[str, float]] = {
    "claude-haiku-4-5-20251001": {"input": 1.0, "output": 5.0},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-opus-4-6": {"input": 15.0, "output": 75.0},
    "claude-opus-4-7": {"input": 15.0, "output": 75.0},
}


def _get_redis():
    try:
        import redis
        return redis.from_url(
            os.environ.get("REDIS_URL", "redis://localhost:6379"),
            socket_connect_timeout=5.0,
        )
    except Exception as exc:
        log.warning("ai_cache_redis_unavailable", error=str(exc))
        return None


def _canonicalize(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def cache_key(*,
              model: str,
              system: str,
              messages: list[dict],
              tools: Optional[list[dict]] = None,
              temperature: float = 0.0,
              max_tokens: int = 8192,
              namespace: str = "default",
              order_scope: Optional[str] = None,
              host_scope: Optional[str] = None) -> str:
    """Order-Scope-Mode (M1): wenn order_scope gesetzt, basiert der Hash NUR
    auf (namespace, order_scope, host_scope?, policy_version, cache_version).
    Re-Scans / regenerate-report derselben Order treffen so garantiert den
    Cache. Ohne order_scope: legacy Inhalts-Hash."""
    if order_scope is not None:
        payload: dict = {
            "mode": "order_scope",
            "namespace": namespace,
            "order_scope": order_scope,
            "host_scope": host_scope,
            "model": model,
            "policy_version": POLICY_VERSION,
            "cache_version": CACHE_VERSION,
        }
    else:
        payload = {
            "mode": "input_hash",
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


@dataclass
class CacheStats:
    hit: bool = False
    age_seconds: Optional[float] = None
    cost_estimated_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_key_short: str = ""

    def to_dict(self) -> dict:
        return {
            "hit": self.hit,
            "age_seconds": self.age_seconds,
            "cost_estimated_usd": round(self.cost_estimated_usd, 4),
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_key_short": self.cache_key_short,
        }


def _estimate_cost(model: str, in_tok: int, out_tok: int) -> float:
    p = AI_PRICING.get(model, {"input": 0.0, "output": 0.0})
    return (in_tok / 1_000_000) * p["input"] + (out_tok / 1_000_000) * p["output"]


def get_cached_response(key: str) -> Optional[dict]:
    """Liest gecachten Eintrag. Returns None bei Miss/Fehler."""
    r = _get_redis()
    if r is None:
        return None
    try:
        raw = r.get(key)
    except Exception as exc:
        log.warning("ai_cache_get_failed", error=str(exc), key=key[:24])
        return None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        log.warning("ai_cache_corrupt", error=str(exc), key=key[:24])
        return None


def set_cached_response(key: str, *,
                        response_text: str,
                        model: str,
                        input_tokens: int,
                        output_tokens: int,
                        cache_ttl_seconds: int) -> None:
    """Schreibt Cache-Eintrag (best-effort)."""
    r = _get_redis()
    if r is None:
        return
    entry = {
        "response_text": response_text,
        "cached_at_ts": time.time(),
        "cached_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model": model,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "policy_version": POLICY_VERSION,
        "cache_version": CACHE_VERSION,
    }
    try:
        r.setex(key, cache_ttl_seconds, _canonicalize(entry))
    except Exception as exc:
        log.warning("ai_cache_set_failed", error=str(exc), key=key[:24])


def delete_cached(key: str) -> None:
    r = _get_redis()
    if r is None:
        return
    try:
        r.delete(key)
    except Exception as exc:
        log.warning("ai_cache_delete_failed", error=str(exc), key=key[:24])


def stats_from_cache_entry(entry: dict, model: str) -> CacheStats:
    in_tok = int(entry.get("input_tokens", 0) or 0)
    out_tok = int(entry.get("output_tokens", 0) or 0)
    cached_at = entry.get("cached_at_ts", 0)
    age = time.time() - cached_at if cached_at else None
    return CacheStats(
        hit=True,
        age_seconds=age,
        cost_estimated_usd=_estimate_cost(model, in_tok, out_tok),
        input_tokens=in_tok,
        output_tokens=out_tok,
    )


__all__ = [
    "POLICY_VERSION",
    "CACHE_VERSION",
    "AI_PRICING",
    "CacheStats",
    "cache_key",
    "get_cached_response",
    "set_cached_response",
    "delete_cached",
    "stats_from_cache_entry",
]
