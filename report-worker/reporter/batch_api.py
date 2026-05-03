"""Anthropic Message Batches API Wrapper (PR-KI-Optim, 2026-05-03).

Batch-API: 50% Cost-Ersparnis bei +Latenz (typisch < 1h, max 24h).
Verwendung: Reporter-Calls fuer Subscriptions mit
`subscriptions.use_batch_api = true`.

Workflow:
  1. submit_batch([{custom_id, params}]) → batch_id
  2. poll_batch(batch_id) bis status='ended' (max 24h)
  3. fetch_results(batch_id) → liste von {custom_id, result}

Fallback wenn Batch-API nicht verfuegbar (alter SDK / disabled): None
zurueckgeben → Caller faellt auf realtime-Pfad zurueck.
"""

from __future__ import annotations

import os
import time
from typing import Any, Optional

import structlog

log = structlog.get_logger()


def submit_reporter_batch(
    *,
    custom_id: str,
    model: str,
    system_prompt: str,
    messages: list[dict],
    max_tokens: int,
    api_key: Optional[str] = None,
) -> Optional[str]:
    """Submit ein Single-Request-Batch fuer Reporter. Returns batch_id oder None."""
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        # Anthropic Batch API ist seit SDK 0.36 verfuegbar
        if not hasattr(client, "messages") or not hasattr(client.messages, "batches"):
            log.warning("batch_api_not_in_sdk")
            return None
        batch = client.messages.batches.create(
            requests=[{
                "custom_id": custom_id,
                "params": {
                    "model": model,
                    "max_tokens": max_tokens,
                    "system": system_prompt,
                    "messages": messages,
                    "temperature": 0.0,
                },
            }],
        )
        log.info("batch_submitted", batch_id=batch.id, custom_id=custom_id)
        return batch.id
    except Exception as e:
        log.warning("batch_submit_failed", error=str(e))
        return None


def wait_for_batch(
    batch_id: str,
    max_wait_seconds: int = 24 * 3600,
    poll_interval_seconds: int = 30,
    api_key: Optional[str] = None,
) -> Optional[str]:
    """Polled Batch bis 'ended' oder Timeout. Returns 'ended'/'failed'/None."""
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        deadline = time.monotonic() + max_wait_seconds
        while time.monotonic() < deadline:
            batch = client.messages.batches.retrieve(batch_id)
            status = getattr(batch, "processing_status", None) or getattr(batch, "status", None)
            log.info("batch_status_check", batch_id=batch_id, status=status)
            if status in ("ended", "completed"):
                return "ended"
            if status in ("failed", "expired", "cancelled"):
                return "failed"
            time.sleep(poll_interval_seconds)
        return None  # Timeout
    except Exception as e:
        log.warning("batch_poll_failed", error=str(e))
        return None


def fetch_batch_result(
    batch_id: str,
    custom_id: str,
    api_key: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """Holt das Ergebnis eines bestimmten custom_id aus dem Batch. Returns dict mit text+usage."""
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        for entry in client.messages.batches.results(batch_id):
            entry_id = getattr(entry, "custom_id", None)
            if entry_id != custom_id:
                continue
            result = getattr(entry, "result", None)
            if result is None or getattr(result, "type", "") != "succeeded":
                return None
            msg = getattr(result, "message", None)
            if not msg:
                return None
            text = ""
            for block in getattr(msg, "content", []) or []:
                if getattr(block, "type", None) == "text":
                    text = block.text
                    break
            usage = getattr(msg, "usage", None)
            return {
                "text": text,
                "input_tokens": getattr(usage, "input_tokens", 0) if usage else 0,
                "output_tokens": getattr(usage, "output_tokens", 0) if usage else 0,
                "cache_read_input_tokens": getattr(usage, "cache_read_input_tokens", 0) if usage else 0,
                "cache_creation_input_tokens": getattr(usage, "cache_creation_input_tokens", 0) if usage else 0,
            }
        return None
    except Exception as e:
        log.warning("batch_fetch_failed", error=str(e))
        return None


__all__ = ["submit_reporter_batch", "wait_for_batch", "fetch_batch_result"]
