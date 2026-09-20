# -*- coding: utf-8 -*-
"""Kostenrechnung und Ablage fuer die KI-Aufrufe des v3-Berichts.

Zwei Aufrufe teilen sich das: die Prosa-KI aus S3 (``prose.py``) und die
Recherche-KI aus S5 (``research.py``). Die Zahlen gehen ins Log und in
``ai_call_costs``; die Datenbank ist dabei optional, ein Fehler beim Schreiben
darf einen Bericht nie kippen.
"""
from __future__ import annotations

from typing import Any, Optional

import structlog

log = structlog.get_logger()

# Preise je Million Token, gleiche Quelle wie reporter/ai_cache.py.
# Die Websuche der Recherche-KI wird zusaetzlich je Anfrage abgerechnet und
# taucht in usage nicht als Token auf; sie steht deshalb nicht in dieser Tabelle.
PRICING: dict[str, tuple[float, float]] = {
    "claude-opus-5": (5.0, 25.0),
    "claude-opus-4-7": (15.0, 75.0),
    "claude-sonnet-4-6": (3.0, 15.0),
}


def cost_from_usage(model: str, usage: Any, ki_step: str, *,
                    cache_hit: bool = False) -> dict[str, Any]:
    """Kostenzeile aus der ``usage`` einer Antwort."""
    inp = int(getattr(usage, "input_tokens", 0) or 0)
    out = int(getattr(usage, "output_tokens", 0) or 0)
    cache_create = int(getattr(usage, "cache_creation_input_tokens", 0) or 0)
    cache_read = int(getattr(usage, "cache_read_input_tokens", 0) or 0)
    price_in, price_out = PRICING.get(model, (0.0, 0.0))
    total = ((inp + cache_create + cache_read) * price_in + out * price_out) / 1_000_000
    return {
        "model": model,
        "ki_step": ki_step,
        "input_tokens": inp,
        "output_tokens": out,
        "cache_creation_input_tokens": cache_create,
        "cache_read_input_tokens": cache_read,
        "total_cost_usd": round(total, 6),
        "cache_hit": cache_hit,
    }


def cost_from_cache(model: str, entry: dict[str, Any], ki_step: str) -> dict[str, Any]:
    """Kostenzeile fuer einen Cache-Treffer.

    Ein Treffer kostet nichts; die Tokenzahlen des urspruenglichen Aufrufs
    stehen trotzdem dabei, damit die Auswertung sieht, was gespart wurde.
    """
    return {
        "model": model,
        "ki_step": ki_step,
        "input_tokens": int(entry.get("input_tokens", 0) or 0),
        "output_tokens": int(entry.get("output_tokens", 0) or 0),
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "total_cost_usd": 0.0,
        "cache_hit": True,
    }


def persist(cost: dict[str, Any], order_id: Optional[str]) -> None:
    """Kostenzeile in ``ai_call_costs`` schreiben, best effort."""
    try:
        from reporter.ai_cost_persist import persist_ai_call_cost

        persist_ai_call_cost(
            order_id=order_id, ki_step=str(cost.get("ki_step", "")),
            model=str(cost.get("model", "")),
            input_tokens=int(cost.get("input_tokens", 0)),
            output_tokens=int(cost.get("output_tokens", 0)),
            cache_creation_tokens=int(cost.get("cache_creation_input_tokens", 0)),
            cache_read_tokens=int(cost.get("cache_read_input_tokens", 0)),
            total_cost_usd=float(cost.get("total_cost_usd", 0.0)),
            cache_hit=bool(cost.get("cache_hit")),
            duration_ms=cost.get("duration_ms"),
        )
    except Exception as exc:  # pragma: no cover - Datenbank ist optional
        log.warning("ai_cost_persist_failed", ki_step=cost.get("ki_step"), error=str(exc))
