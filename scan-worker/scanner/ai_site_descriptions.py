"""AI-Verfeinerung der Per-VHost-Beschreibungssaetze (Haiku 4.5, batched).

PR-E (Mai 2026): Nur fuer VHosts mit ``classification == "web_content"`` UND
nicht-leerem Title — fuer Panels/Parking/Error/Non-Web ist die Heuristik
schon perfekt deterministisch (keine AI noetig).

Wir machen genau einen batched Haiku-Call pro Order (Liste aller Kandidaten),
mit ``cached_call`` + ``order_scope=order_id`` und ``content_hash`` ueber den
Input. Damit:
- Re-Scan derselben Order: garantierter Cache-Hit.
- Anderer Scan mit gleichen FQDNs/Titles: content_hash matched → Cross-Order-Hit.
- POLICY_VERSION-Bump invalidiert automatisch.

Failure-Mode: Bei Anthropic-Errors/Timeout/Parse-Failures faellt die
Beschreibung silent zurueck auf die Heuristik (caller-Verantwortung — diese
Funktion liefert dann einfach ein leeres Dict).
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

import structlog

log = structlog.get_logger()

HAIKU_MODEL = "claude-haiku-4-5-20251001"
CACHE_TTL = 14 * 24 * 3600  # 14 Tage — kann lange leben, ist deskriptiv
MAX_TOKENS = 4096
NAMESPACE = "ki_site_summaries"

SYSTEM_PROMPT = """Du bist ein praeziser Security-Reporter. Du bekommst eine Liste von Websites und sollst pro Website **einen** sachlichen Satz auf Deutsch erzeugen — maximal 15 Woerter, der Zweck der Seite und die Haupttechnologie nennt.

REGELN:
- Keine Werbung, keine Bewertung, keine Konjunktive.
- Wenn der Zweck unklar ist, beschreibe nur Technologie und Titel.
- Keine Anfuehrungszeichen oder Sonderzeichen am Anfang/Ende.
- Antworte AUSSCHLIESSLICH mit JSON: {"summaries": {"<fqdn>": "<satz>"}}
- Kein Markdown, kein Pre/Postamble.
"""


def _strip_markdown_fences(text: str) -> str:
    """Entferne ```json ... ``` Wrapper falls vorhanden."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*\n?", "", text)
        text = re.sub(r"\n?```\s*$", "", text)
    return text.strip()


def _build_user_prompt(candidates: list[dict[str, Any]]) -> str:
    """Reduziere die Kandidaten auf die fuer den KI-Call relevanten Felder."""
    payload = [
        {
            "fqdn": c.get("fqdn"),
            "title": (c.get("title") or "")[:200],
            "status": c.get("status"),
            "tech": c.get("_tech_hint"),  # vom Caller vorberechnet
        }
        for c in candidates
    ]
    return (
        "Erzeuge fuer jede der folgenden Websites einen Satz wie beschrieben.\n\n"
        f"Websites ({len(payload)}):\n"
        f"{json.dumps(payload, indent=2, ensure_ascii=False)}\n\n"
        'Antwortformat: {"summaries": {"<fqdn>": "<satz>"}}'
    )


def _content_hash_for_candidates(candidates: list[dict[str, Any]]) -> str:
    """Stabiler Hash ueber (fqdn, title, tech)-Tripel — egal in welcher Reihenfolge."""
    from scanner.ai_cache import compute_content_hash

    rows = sorted(
        [
            (
                c.get("fqdn", ""),
                (c.get("title") or "").strip()[:200],
                c.get("_tech_hint", "") or "",
            )
            for c in candidates
        ],
        key=lambda t: t[0],
    )
    serialized = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    return compute_content_hash("ki_site_summaries", serialized)


def refine_with_ai(
    candidates: list[dict[str, Any]],
    order_id: str = "",
    tech_hint_by_fqdn: dict[str, str] | None = None,
) -> dict[str, str]:
    """Refine VHost-Beschreibungen via Haiku-Batch-Call.

    Args:
        candidates: Liste von VHost-Dicts (muessen ``fqdn`` und ``title``
            enthalten — alles andere optional).
        order_id: Fuer order_scope-Cache (M1). Empty string = nur content_hash.
        tech_hint_by_fqdn: Optionale ``{fqdn -> "WordPress 6.4 auf Apache"}``-Map,
            wird in den Prompt eingefuegt damit der KI-Output praezis bleibt.

    Returns:
        Dict ``{fqdn -> refined_description}``. Bei API-Fehlern oder leeren
        Inputs: leeres Dict. Der Caller mergt das ins Heuristik-Resultat.
    """
    if not candidates:
        return {}

    # Tech-Hint pro VHost in-place einfuegen (caller-friendly).
    hints = tech_hint_by_fqdn or {}
    for c in candidates:
        if "_tech_hint" not in c:
            c["_tech_hint"] = hints.get(c.get("fqdn", ""), "")

    try:
        from scanner.ai_cache import cached_call, extract_text
    except Exception as exc:  # pragma: no cover
        log.warning("ai_site_descriptions_import_failed", error=str(exc))
        return {}

    user_prompt = _build_user_prompt(candidates)
    content_hash = _content_hash_for_candidates(candidates)

    start = time.monotonic()
    try:
        response_dict, stats = cached_call(
            model=HAIKU_MODEL,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
            temperature=0.0,
            max_tokens=MAX_TOKENS,
            cache_ttl_seconds=CACHE_TTL,
            cache_namespace=NAMESPACE,
            order_scope=order_id or None,
            content_hash=content_hash,
        )
    except Exception as exc:  # pragma: no cover
        log.warning("ai_site_descriptions_call_failed", error=str(exc))
        return {}

    duration_ms = int((time.monotonic() - start) * 1000)
    if "_error" in response_dict:
        log.warning("ai_site_descriptions_api_error",
                    error=response_dict.get("_error"), duration_ms=duration_ms)
        return {}

    raw = extract_text(response_dict)
    cleaned = _strip_markdown_fences(raw)

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        log.warning("ai_site_descriptions_parse_failed",
                    error=str(exc), raw=cleaned[:300])
        return {}

    summaries = parsed.get("summaries") or {}
    if not isinstance(summaries, dict):
        log.warning("ai_site_descriptions_shape_invalid", got=type(summaries).__name__)
        return {}

    # Defensive sanitize: nur String-Values, max 200 Zeichen, keine Leerzeichen-Saetze.
    out: dict[str, str] = {}
    for fqdn, desc in summaries.items():
        if not isinstance(desc, str):
            continue
        desc = desc.strip().strip("\"'").strip()
        if not desc:
            continue
        if len(desc) > 200:
            desc = desc[:199].rstrip() + "…"
        out[str(fqdn)] = desc

    log.info("ai_site_descriptions_complete",
             cache_hit=stats.hit, refined=len(out), total=len(candidates),
             duration_ms=duration_ms,
             cost_usd=round(stats.cost_estimated_usd, 4))
    return out


__all__ = ["refine_with_ai", "HAIKU_MODEL", "NAMESPACE"]
