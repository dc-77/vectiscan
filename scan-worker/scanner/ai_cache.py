"""Redis-basierter Cache fuer Anthropic-API-Calls mit deterministischem Input-Hashing.

Spec: docs/deterministic/03-ai-determinism.md

Kapselt:
- Cache-Key-Generierung (sha256 ueber canonicalisierte Inputs)
- Redis GET/SET mit TTL
- Anthropic-Call mit `temperature=0.0` und retry-faehigem Wrapper
- Telemetrie (cache_hit, cost_saved, age, tokens)

Default-Verhalten:
- Schlaegt Redis fehl (kein Daemon, Timeout) → Cache wird stillschweigend
  uebersprungen, Anthropic-Call laeuft direkt durch. NIEMALS Pipeline-Fail
  aus Cache-Gruenden.
- Schlaegt Anthropic fehl → wir caches NICHT, Caller bekommt {"_error": "..."}
  zurueck (gleiches Pattern wie ai_strategy._call_haiku).

POLICY_VERSION wird aus ENV gelesen (Default `2026-04-30.1`); bei Aenderung
wird der Cache automatisch invalidiert (Hash-Eingang).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
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


# ---------------------------------------------------------------------------
# Redis client (lazy, gleiches Pattern wie threat_intel._get_redis)
# ---------------------------------------------------------------------------

def _get_redis():
    """Lazy import + connection. Returns None on failure (graceful degradation)."""
    try:
        import redis
        return redis.from_url(
            os.environ.get("REDIS_URL", "redis://localhost:6379"),
            socket_connect_timeout=5.0,
        )
    except Exception as exc:
        log.warning("ai_cache_redis_unavailable", error=str(exc))
        return None


# ---------------------------------------------------------------------------
# Canonicalization + Hashing
# ---------------------------------------------------------------------------

def _canonicalize(obj: Any) -> str:
    """Stable JSON serialization (sort_keys + ohne Whitespace)."""
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
    """Deterministischer Cache-Key.

    Nimmt ALLE Inputs auf, die das Output beeinflussen koennen.
    Bei POLICY_VERSION-Bump invalidiert der Cache automatisch.
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


# ---------------------------------------------------------------------------
# Telemetrie
# ---------------------------------------------------------------------------

@dataclass
class CacheStats:
    """Per-call Telemetrie."""
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


@dataclass
class OrderAIStats:
    """Aggregat ueber alle AI-Calls einer Order."""
    total_calls: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    total_cost_usd: float = 0.0
    cost_saved_usd: float = 0.0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    per_namespace: dict[str, dict[str, Any]] = field(default_factory=dict)

    def add(self, namespace: str, stats: CacheStats) -> None:
        self.total_calls += 1
        ns = self.per_namespace.setdefault(namespace, {
            "calls": 0, "hits": 0, "cost_usd": 0.0, "saved_usd": 0.0,
        })
        ns["calls"] += 1
        if stats.hit:
            self.cache_hits += 1
            ns["hits"] += 1
            self.cost_saved_usd += stats.cost_estimated_usd
            ns["saved_usd"] += stats.cost_estimated_usd
        else:
            self.cache_misses += 1
            self.total_cost_usd += stats.cost_estimated_usd
            ns["cost_usd"] += stats.cost_estimated_usd
        self.total_input_tokens += stats.input_tokens
        self.total_output_tokens += stats.output_tokens

    def to_dict(self) -> dict:
        return {
            "total_calls": self.total_calls,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": (
                self.cache_hits / self.total_calls if self.total_calls else 0.0
            ),
            "total_cost_usd": round(self.total_cost_usd, 4),
            "cost_saved_usd": round(self.cost_saved_usd, 4),
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "per_namespace": {
                ns: {
                    "calls": d["calls"],
                    "hits": d["hits"],
                    "hit_rate": d["hits"] / d["calls"] if d["calls"] else 0.0,
                    "cost_usd": round(d["cost_usd"], 4),
                    "saved_usd": round(d["saved_usd"], 4),
                }
                for ns, d in self.per_namespace.items()
            },
        }


def _estimate_cost(model: str, in_tok: int, out_tok: int) -> float:
    p = AI_PRICING.get(model, {"input": 0.0, "output": 0.0})
    return (in_tok / 1_000_000) * p["input"] + (out_tok / 1_000_000) * p["output"]


# ---------------------------------------------------------------------------
# Cached call
# ---------------------------------------------------------------------------

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
    """Cached Anthropic call.

    Returns:
        (response_dict, cache_stats)
        response_dict ist die Anthropic-API-Response als dict (oder gecachte Version).
        Bei API-Fail liefert response_dict {"_error": "..."} und stats.hit=False.

    Konvention: temperature=0.0 forcieren wir (deterministisch). Caller darf
    explizit anders setzen, sollte aber wissen warum.
    """
    key = cache_key(
        model=model, system=system, messages=messages, tools=tools,
        temperature=temperature, max_tokens=max_tokens, namespace=cache_namespace,
    )
    short_key = key[:24]

    # 1) Cache lookup
    r = _get_redis()
    raw = None
    if r is not None:
        try:
            raw = r.get(key)
        except Exception as exc:
            log.warning("ai_cache_get_failed", error=str(exc), key=short_key)
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
                cache_key_short=short_key,
            )
            log.info("ai_cache_hit", namespace=cache_namespace,
                     age_s=round(age, 1), key=short_key)
            return entry["response"], stats
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            log.warning("ai_cache_corrupt", error=str(exc), key=short_key)

    # 2) Cache miss → Anthropic call
    log.info("ai_cache_miss", namespace=cache_namespace, key=short_key)

    if anthropic_client is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            return {"_error": "ANTHROPIC_API_KEY nicht gesetzt"}, CacheStats(
                hit=False, cache_key_short=short_key,
            )
        try:
            import anthropic
            anthropic_client = anthropic.Anthropic(api_key=api_key)
        except Exception as exc:
            log.error("ai_cache_anthropic_init_failed", error=str(exc))
            return {"_error": f"Anthropic-Init-Fehler: {exc}"}, CacheStats(
                hit=False, cache_key_short=short_key,
            )

    api_kwargs: dict[str, Any] = {
        "model": model,
        "system": system,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if tools:
        api_kwargs["tools"] = tools

    try:
        response_obj = anthropic_client.messages.create(**api_kwargs)
    except Exception as exc:
        log.error("ai_cache_anthropic_call_failed", error=str(exc),
                  namespace=cache_namespace)
        return {"_error": f"API-Fehler: {exc}"}, CacheStats(
            hit=False, cache_key_short=short_key,
        )

    # Response in dict konvertieren (anthropic SDK liefert Pydantic-Modell)
    if hasattr(response_obj, "model_dump"):
        response_dict = response_obj.model_dump(mode="json")
    else:
        try:
            response_dict = dict(response_obj)
        except Exception:
            response_dict = {"_error": "Response nicht serialisierbar"}

    usage = response_dict.get("usage") or {}
    in_tok = int(usage.get("input_tokens", 0) or 0)
    out_tok = int(usage.get("output_tokens", 0) or 0)
    cost = _estimate_cost(model, in_tok, out_tok)

    # 3) Cache write (best-effort)
    if r is not None:
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
        except Exception as exc:
            log.warning("ai_cache_set_failed", error=str(exc), key=short_key)

    stats = CacheStats(
        hit=False,
        cost_estimated_usd=cost,
        input_tokens=in_tok,
        output_tokens=out_tok,
        cache_key_short=short_key,
    )
    return response_dict, stats


# ---------------------------------------------------------------------------
# Hilfs-Funktion: Anthropic-Response → erster Text-Block
# ---------------------------------------------------------------------------

def extract_text(response_dict: dict) -> str:
    """Holt den ersten text-Block aus einer Anthropic-Response (dict).

    Anthropic liefert content als Liste von Blocks; bei einfachen Antworten
    ist [0]['text'] der gesuchte String.
    """
    if not response_dict or "content" not in response_dict:
        return ""
    content = response_dict.get("content") or []
    if not content:
        return ""
    first = content[0]
    if isinstance(first, dict):
        return first.get("text", "") or ""
    if hasattr(first, "text"):
        return getattr(first, "text", "") or ""
    return ""


# ---------------------------------------------------------------------------
# Cache invalidation helpers
# ---------------------------------------------------------------------------

def invalidate_namespace(namespace: str) -> int:
    """Loescht alle Cache-Entries fuer einen Namespace. SCAN-basiert."""
    r = _get_redis()
    if r is None:
        return 0
    pattern = f"ai_cache:{namespace}:*"
    deleted = 0
    try:
        for key in r.scan_iter(match=pattern, count=500):
            r.delete(key)
            deleted += 1
    except Exception as exc:
        log.warning("ai_cache_invalidate_failed", error=str(exc), namespace=namespace)
    log.info("ai_cache_invalidated", namespace=namespace, deleted=deleted)
    return deleted


def invalidate_all() -> int:
    """Loescht den gesamten AI-Cache. Vorsicht!"""
    r = _get_redis()
    if r is None:
        return 0
    deleted = 0
    try:
        for key in r.scan_iter(match="ai_cache:*", count=500):
            r.delete(key)
            deleted += 1
    except Exception as exc:
        log.warning("ai_cache_invalidate_all_failed", error=str(exc))
    log.warning("ai_cache_invalidated_all", deleted=deleted)
    return deleted


__all__ = [
    "POLICY_VERSION",
    "CACHE_VERSION",
    "AI_PRICING",
    "CacheStats",
    "OrderAIStats",
    "cache_key",
    "cached_call",
    "extract_text",
    "invalidate_namespace",
    "invalidate_all",
]
