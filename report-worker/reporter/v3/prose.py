# -*- coding: utf-8 -*-
"""Ein KI-Aufruf für vier Prosa-Felder, mit Gate und Katalog-Fallback.

Eingabe sind fertige Befunde und aggregierte Fakten als JSON, nie Rohdaten und nie
Werkzeugausgaben. Ausgabe sind vier Felder:

* ``overall_text``   Zusammenfassung auf Seite 1 (``glance.overall_text``)
* ``implication``    Kontextabsatz "Was das für Sie bedeutet" (``business.implication``)
* ``observed``       ein Beobachtungssatz je System (``business.observed[].meaning``)
* ``impact``         Feinschliff der Bedeutungstexte je Befund (``findings[].impact``)

Jedes Feld läuft einzeln durch ``gate.check_field``. Fällt eines durch, bleibt der
deterministische Text stehen; die anderen dürfen trotzdem übernommen werden.

Abweichung von der Determinismus-Vorgabe: ``claude-opus-4-7`` nimmt keinen
``temperature``-Parameter mehr an (siehe reporter/claude_client.py). Determinismus
kommt deshalb aus dem Redis-Cache (Namensraum ``reporter_v3``, der Schlüssel enthält
CATALOG_VERSION und FACTS_SCHEMA_VERSION), dem Gate und dem Katalog-Fallback.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Optional

import structlog

from reporter import ai_cache
from reporter.catalog.version import CATALOG_VERSION
from reporter.facts.schema import FACTS_SCHEMA_VERSION
from reporter.v3 import gate
from reporter.v3.models import ReportData

log = structlog.get_logger()

OPUS_MODEL = "claude-opus-4-7"
MAX_TOKENS = 4096
CACHE_NAMESPACE = "reporter_v3"
CACHE_TTL_SECONDS = 24 * 3600
KI_STEP = "report_prose_v3"

# Preise je Million Token, gleiche Quelle wie reporter/ai_cache.py.
PRICING: dict[str, tuple[float, float]] = {
    "claude-opus-4-7": (15.0, 75.0),
    "claude-sonnet-4-6": (3.0, 15.0),
}

SYSTEM_PROMPT = """Du schreibst einzelne Absätze für einen deutschen Sicherheitsbericht.

Du bekommst fertige Befunde und aggregierte Fakten als JSON. Die Befunde stehen fest:
du bewertest nicht, du stufst nicht ein, du ergänzt keine Sachverhalte.

Harte Regeln:
- Verwende ausschließlich Angaben aus der Eingabe. Keine Zahl, kein Hostname, keine
  Domain, keine CVE-Nummer und keine Versionsangabe, die dort nicht steht.
- Keine Einstufungswörter (kritisch, erhöht, hoch, mittel, niedrig, CRITICAL, HIGH).
  Die Einstufung steht am Befund, nicht in deinem Text.
- Deutsch, Sie-Form, echte Umlaute, keine Gedankenstriche, keine Aufzählungszeichen.
- Keine Zusagen zu Vollständigkeit, kein Hinweis auf Werkzeuge oder Sprachmodelle.
- Keine Aufwände, keine Kosten, keine Fristen außer denen aus der Eingabe.

Antworte ausschließlich mit einem JSON-Objekt dieser Form:
{"overall_text": "...", "implication": "...",
 "observed": {"<system>": "..."}, "impact": {"<befund-id>": "..."}}

overall_text: höchstens vier Sätze, was der Bericht in der Summe zeigt und was zuerst
zu tun ist. implication: höchstens vier Sätze, was die Befunde für dieses Unternehmen
bedeuten; wenn die Eingabe keinen Kundenkontext enthält, bleibe allgemein und sage
nicht, dass er fehlt. observed: je genanntem System ein bis zwei Sätze, wofür es
steht. impact: je Befund ein bis drei Sätze Feinschliff des mitgelieferten Textes,
inhaltlich unverändert."""


# ---------------------------------------------------------------- Eingabe

def build_payload(data: ReportData, customer_context: dict[str, Any] | None = None) -> dict:
    """Fertige Befunde und Fakten als JSON. Keine Rohdaten, keine Werkzeugausgaben."""
    return {
        "scan": {
            "domains": list(data.meta.domains),
            "paket": data.meta.package,
            "datum": data.meta.scan_date,
            "hosts": data.meta.hosts_total,
            "hostnamen": data.meta.fqdns_total,
            "befunde": data.meta.consolidated,
            "positive": data.meta.positives,
        },
        "kunde": dict(customer_context or {}),
        "kategorien": [
            {"schluessel": c.key, "name": c.name, "status": c.status, "hinweis": c.note}
            for c in data.glance.categories
        ],
        "systeme": [{"system": o.system, "bedeutung": o.meaning} for o in data.business.observed],
        "hosts": [
            {"ip": h.ip, "hostnamen": h.fqdns, "betreiber": h.operator, "rolle": h.role,
             "abdeckung": h.cov}
            for h in data.scope.hosts
        ],
        "befunde": [
            {"id": f.id, "kategorie": f.cat, "titel": f.title, "betroffen": f.affected,
             "quelle": f.source, "beobachtung": f.found, "bedeutung": f.impact,
             "dringlichkeit": f.urgency,
             "fremdreferenzen": (f.threat.cves if f.threat else [])}
            for f in data.findings
        ],
        "positive": [{"kategorie": p.cat, "titel": p.title, "text": p.text}
                     for p in data.positives],
        "plan": [{"prioritaet": r.prio, "massnahme": r.action, "befunde": r.refs}
                 for r in data.plan],
    }


# ---------------------------------------------------------------- Aufruf

def _cost(model: str, usage: Any, cache_hit: bool) -> dict[str, Any]:
    inp = int(getattr(usage, "input_tokens", 0) or 0)
    out = int(getattr(usage, "output_tokens", 0) or 0)
    cache_create = int(getattr(usage, "cache_creation_input_tokens", 0) or 0)
    cache_read = int(getattr(usage, "cache_read_input_tokens", 0) or 0)
    price_in, price_out = PRICING.get(model, (0.0, 0.0))
    total = ((inp + cache_create + cache_read) * price_in + out * price_out) / 1_000_000
    return {
        "model": model,
        "ki_step": KI_STEP,
        "input_tokens": inp,
        "output_tokens": out,
        "cache_creation_input_tokens": cache_create,
        "cache_read_input_tokens": cache_read,
        "total_cost_usd": round(total, 6),
        "cache_hit": cache_hit,
    }


def available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def generate(payload: dict[str, Any], *, order_id: Optional[str] = None,
             model: str = OPUS_MODEL) -> tuple[dict[str, Any], dict[str, Any]]:
    """(Felder, Kosten). Ohne Zugangsschluessel oder bei einem Fehler leere Felder."""
    if not available():
        log.info("report_prose_skipped", reason="no_api_key")
        return {}, {}

    user = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    messages = [{"role": "user", "content": user}]
    content_hash = ai_cache.compute_content_hash(
        SYSTEM_PROMPT, user, CATALOG_VERSION, FACTS_SCHEMA_VERSION)
    key = ai_cache.cache_key(model=model, system=SYSTEM_PROMPT, messages=messages,
                             max_tokens=MAX_TOKENS, namespace=CACHE_NAMESPACE,
                             content_hash=content_hash)
    cached = ai_cache.get_cached_response(key)
    if cached:
        fields = _parse(cached.get("text", ""))
        cost = dict(cached.get("cost") or {})
        cost["cache_hit"] = True
        log.info("report_prose_cost", **cost)
        return fields, cost

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"], timeout=600.0)
        started = time.monotonic()
        response = client.messages.create(
            model=model,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=messages,
        )
    except Exception as exc:  # pragma: no cover - Netzwerkpfad
        log.warning("report_prose_failed", error=str(exc))
        return {}, {}

    text = "".join(getattr(block, "text", "") for block in response.content)
    cost = _cost(model, response.usage, cache_hit=False)
    cost["duration_ms"] = int((time.monotonic() - started) * 1000)
    log.info("report_prose_cost", **cost)
    ai_cache.set_cached_response(key, {"text": text, "cost": cost}, ttl=CACHE_TTL_SECONDS)
    _persist(cost, order_id)
    return _parse(text), cost


def _persist(cost: dict[str, Any], order_id: Optional[str]) -> None:
    try:
        from reporter.ai_cost_persist import persist_ai_call_cost

        persist_ai_call_cost(
            order_id=order_id, ki_step=KI_STEP, model=str(cost.get("model", "")),
            input_tokens=int(cost.get("input_tokens", 0)),
            output_tokens=int(cost.get("output_tokens", 0)),
            cache_creation_tokens=int(cost.get("cache_creation_input_tokens", 0)),
            cache_read_tokens=int(cost.get("cache_read_input_tokens", 0)),
            total_cost_usd=float(cost.get("total_cost_usd", 0.0)),
            cache_hit=bool(cost.get("cache_hit")),
            duration_ms=cost.get("duration_ms"),
        )
    except Exception as exc:  # pragma: no cover - Datenbank ist optional
        log.warning("report_prose_cost_persist_failed", error=str(exc))


def _parse(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1].rsplit("```", 1)[0]
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        log.warning("report_prose_unparsable")
        return {}
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        log.warning("report_prose_unparsable", error=str(exc))
        return {}
    return data if isinstance(data, dict) else {}


# ---------------------------------------------------------------- Uebernahme

def apply_prose(data: ReportData, fields: dict[str, Any],
                payload: dict[str, Any] | None = None) -> list[str]:
    """Uebernimmt die Felder, die das Gate passieren. Liefert die abgelehnten."""
    haystack = gate.corpus(payload if payload is not None else build_payload(data))
    rejected: list[str] = []

    def accept(name: str, text: Any) -> Optional[str]:
        if not isinstance(text, str):
            return None
        verdict = gate.check_field(name, text.strip(), haystack)
        if verdict.ok:
            return text.strip()
        log.warning("report_prose_rejected", field=name, reasons=verdict.reasons)
        rejected.append(f"{name}: {'; '.join(verdict.reasons)}")
        return None

    value = accept("overall_text", fields.get("overall_text"))
    if value:
        data.glance.overall_text = value

    value = accept("implication", fields.get("implication"))
    if value:
        data.business.implication = value

    observed = fields.get("observed") or {}
    if isinstance(observed, dict):
        for entry in data.business.observed:
            value = accept(f"observed[{entry.system}]", observed.get(entry.system))
            if value:
                entry.meaning = value

    impact = fields.get("impact") or {}
    if isinstance(impact, dict):
        for finding in data.findings:
            value = accept(f"impact[{finding.id}]", impact.get(finding.id))
            if value:
                finding.impact = value

    data.meta.prose_rejected = rejected
    return rejected
