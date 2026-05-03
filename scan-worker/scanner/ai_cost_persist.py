"""ai_call_costs DB-Persistierung (PR-KI-Optim, 2026-05-03).

Schreibt pro Anthropic-Call eine Zeile in `ai_call_costs` fuer Cost-
Tracking-Cockpit + Per-Subscription-Caps. Best-effort: bei DB-Fehlern
nur Logging, niemals Pipeline-Fail.

Aufruf nach jedem cached_call() / claude_client.call_claude():
    persist_ai_call_cost(
        order_id=..., subscription_id=...,
        ki_step="ki1_host_strategy",
        model="claude-haiku-4-5-20251001",
        input_tokens=1234, output_tokens=567,
        cache_creation_tokens=0, cache_read_tokens=0, thinking_tokens=0,
        total_cost_usd=0.0042, cache_hit=False, duration_ms=1234,
    )
"""

from __future__ import annotations

import os
from typing import Optional

import psycopg2
import structlog

log = structlog.get_logger()


def persist_ai_call_cost(
    *,
    order_id: Optional[str] = None,
    subscription_id: Optional[str] = None,
    ki_step: str,
    model: str,
    input_tokens: int = 0,
    output_tokens: int = 0,
    cache_creation_tokens: int = 0,
    cache_read_tokens: int = 0,
    thinking_tokens: int = 0,
    total_cost_usd: float = 0.0,
    cache_hit: bool = False,
    duration_ms: Optional[int] = None,
    batch_id: Optional[str] = None,
) -> None:
    """Persistiere einen AI-Call-Cost-Eintrag. No-op bei DB-Fehler."""
    if not order_id and not subscription_id:
        # Defensive: Caller hat keinen Bezug → wir loggen nichts in DB
        return
    try:
        conn = psycopg2.connect(
            os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan"),
            connect_timeout=5,
            options="-c statement_timeout=10000",
        )
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO ai_call_costs
                         (order_id, subscription_id, ki_step, model,
                          input_tokens, output_tokens,
                          cache_creation_tokens, cache_read_tokens, thinking_tokens,
                          total_cost_usd, cache_hit, duration_ms, batch_id)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (order_id, subscription_id, ki_step, model,
                     input_tokens, output_tokens,
                     cache_creation_tokens, cache_read_tokens, thinking_tokens,
                     float(total_cost_usd), cache_hit, duration_ms, batch_id),
                )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        log.warning("ai_cost_persist_failed", error=str(e), ki_step=ki_step)


__all__ = ["persist_ai_call_cost"]
