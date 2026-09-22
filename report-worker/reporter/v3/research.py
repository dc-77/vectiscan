# -*- coding: utf-8 -*-
"""Recherche-KI fuer den Kundenkontext (S5).

Der zweite und letzte KI-Aufruf im Berichtspfad, nach der Prosa-KI aus S3. Er
sucht im Netz nach Firmenname, Branche, Mitarbeiterzahl und dem Zweck der
gefundenen Systeme und schlaegt sie vor. Drei Regeln stehen darueber:

* Er schreibt nur Vorschlaege. Jedes Feld traegt die Quelle ``recherche`` und
  eine Fundstellen-URL.
* Er ueberschreibt nie eine Kundenangabe (``kunde``) und nie eine Korrektur aus
  dem Admin-Review (``admin``).
* Ohne ``ANTHROPIC_API_KEY`` laeuft er leer durch, wie ``prose.py``.

Er erzeugt keinen Befund, keine Einstufung und keinen Satz, der im Bericht
steht. Was er liefert, ist Kontext fuer Kapitel 1 und die Nennung des
Auftraggebers auf dem Deckblatt.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Iterable, Optional

import structlog

from reporter import ai_cache
from reporter.v3.aicost import cost_from_cache, cost_from_usage, persist
from reporter.v3.orthography import DASHES, find_transliterations

log = structlog.get_logger()

OPUS_MODEL = "claude-opus-5"
MAX_TOKENS = 2048
MAX_CONTINUATIONS = 3
CACHE_NAMESPACE = "report_research_v3"
# Firmenangaben aendern sich langsam; ein Monat spart den Aufruf bei jedem
# Regenerieren und bei Folgeauftraegen derselben Domain.
CACHE_TTL_SECONDS = 30 * 24 * 3600
KI_STEP = "report_research_v3"

# Die Websuche laeuft auf Anthropics Servern; dynamische Filterung ist in dieser
# Werkzeugfassung enthalten, ein eigenes code_execution-Werkzeug waere schaedlich.
WEB_SEARCH_TOOL: dict[str, Any] = {
    "type": "web_search_20260209",
    "name": "web_search",
    "max_uses": 5,
}

# Felder, die die Recherche befuellen darf, mit Laengengrenze.
TEXT_LIMITS: dict[str, int] = {
    "firmenname": 120,
    "kurzname": 60,
    "branche": 80,
    "mitarbeiter": 40,
    "zweck": 120,
}

# S6 (spec/08 Punkt 8): Der Bericht nennt als Auftraggeber die Firma, nicht die
# Person dahinter. Der Recherche-Lauf gegen dortmund-beach lieferte
# "Dortmund Beach Design, Inhaber Christian Tacke" aus dem Impressum, und das
# stand danach auf dem Deckblatt, in jeder Kopfzeile und im PDF-Titel.
PERSONENZUSATZ = re.compile(
    r"\s*[,;(]?\s*\b(inh\.?|inhaber(in)?|gesch[äa]ftsf[üu]hrer(in)?|gf|"
    r"vertreten\s+durch|e\.?\s?K\.?\s*,)\b.*$", re.I)

# Rechtsformen, die im Kurznamen nichts verloren haben. Der Kurzname steht in der
# Fusszeile und im PDF-Titel; vorher war es das erste Wort des Firmennamens, und
# "Dortmund Beach Design" wurde zu "Dortmund" und las sich wie ein Ortsname.
RECHTSFORMEN = (
    "gmbh & co. kg", "gmbh & co kg", "ag & co. kg", "gmbh", "mbh", "ug (haftungsbeschränkt)",
    "ug", "aktiengesellschaft", "ag", "kgaa", "kg", "ohg", "gbr", "e.k.", "e. k.", "ek",
    "e.v.", "e. v.", "gemeinnützige gmbh", "ggmbh", "se", "partg", "mbb",
)

# Quellen, die ein Vorschlag nicht anfassen darf.
PROTECTED_SOURCES = frozenset({"kunde", "admin"})

SOURCE_RESEARCH = "recherche"

_URL = re.compile(r"^https?://\S+$", re.I)
_MITARBEITER = re.compile(r"^[\d.,]+(?:\s*(?:bis|-|–)\s*[\d.,]+)?$")

SYSTEM_PROMPT = """Du recherchierst oeffentlich verfuegbare Eckdaten zu einem Unternehmen.

Du bekommst die geprueften Domains und Hostnamen eines Auftrags. Suche im Netz nach
dem Unternehmen hinter diesen Domains und liefere nur, was du auf einer konkreten
Seite belegen kannst.

Harte Regeln:
- Jede Angabe braucht eine Fundstellen-URL, unter der sie wirklich steht.
- Was du nicht belegen kannst, laesst du weg. Rate nie und schaetze nie.
- Keine Aussagen zur Sicherheit, zu Schwachstellen, zu Technik oder zu Risiken.
- Deutsch, echte Umlaute, keine Gedankenstriche, keine Aufzaehlungszeichen.
- Kurze Angaben: Branche in wenigen Worten, Zweck eines Systems in einem Satz.

Antworte ausschliesslich mit einem JSON-Objekt dieser Form, Felder ohne Beleg
laesst du weg:
{"firmenname": {"wert": "...", "quelle": "https://..."},
 "branche": {"wert": "...", "quelle": "https://..."},
 "mitarbeiter": {"wert": "...", "quelle": "https://..."},
 "systeme": [{"fqdn": "...", "zweck": "...", "quelle": "https://..."}]}

firmenname ist die Firmierung mit Rechtsform, aber ohne Personenzusatz: kein
"Inhaber ...", kein "Geschaeftsfuehrer ...", kein "vertreten durch ...". Im Bericht
steht die Firma, nicht die Person. mitarbeiter ist eine Zahl oder eine Spanne, ohne
Zusatz. systeme nennt nur Hostnamen aus der Eingabe."""


def firmenname_ohne_person(text: str) -> str:
    """Personenzusatz aus einer Firmierung entfernen."""
    return PERSONENZUSATZ.sub("", (text or "").strip()).strip(" ,;·-").strip()


def kurzname_aus(firmenname: str) -> str:
    """Firmenname ohne Rechtsform; nie nur das erste Wort.

    Bleibt nach dem Kuerzen nichts uebrig (eine Firmierung, die nur aus der
    Rechtsform besteht), steht der volle Name da.
    """
    text = firmenname_ohne_person(firmenname)
    low = text.lower()
    for form in RECHTSFORMEN:
        if low.endswith(" " + form):
            gekuerzt = text[: len(text) - len(form)].strip(" ,-·")
            return gekuerzt or text
    return text


# ---------------------------------------------------------------- Eingabe

def build_payload(domains: Iterable[str], fqdns: Iterable[str]) -> dict[str, Any]:
    """Was die KI sehen darf: Domains und Hostnamen, sonst nichts."""
    return {
        "domains": sorted({d for d in domains if d}),
        "hostnamen": sorted({f for f in fqdns if f})[:40],
    }


def available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


# ---------------------------------------------------------------- Aufruf

def _text_of(response: Any) -> str:
    return "".join(getattr(block, "text", "") or ""
                   for block in getattr(response, "content", []) or []
                   if getattr(block, "type", "text") == "text")


def _parse(text: str) -> dict[str, Any]:
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1].rsplit("```", 1)[0]
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        log.warning("report_research_unparsable")
        return {}
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        log.warning("report_research_unparsable", error=str(exc))
        return {}
    return data if isinstance(data, dict) else {}


def suggest(payload: dict[str, Any], *, order_id: Optional[str] = None,
            model: str = OPUS_MODEL) -> tuple[dict[str, Any], dict[str, Any]]:
    """(Vorschlag, Kosten). Ohne Zugangsschluessel oder bei einem Fehler leer."""
    if not available():
        log.info("report_research_skipped", reason="no_api_key")
        return {}, {}
    if not payload.get("domains"):
        log.info("report_research_skipped", reason="no_domains")
        return {}, {}

    user = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    messages: list[dict[str, Any]] = [{"role": "user", "content": user}]
    content_hash = ai_cache.compute_content_hash(SYSTEM_PROMPT, user)
    key = ai_cache.cache_key(model=model, system=SYSTEM_PROMPT, messages=messages,
                             max_tokens=MAX_TOKENS, namespace=CACHE_NAMESPACE,
                             content_hash=content_hash)
    cached = ai_cache.get_cached_response(key)
    if cached:
        cost = cost_from_cache(model, cached, KI_STEP)
        log.info("report_research_cost", **cost)
        return _parse(cached.get("response_text", "")), cost

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"], timeout=600.0)
        started = time.monotonic()
        response = client.messages.create(
            model=model,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=messages,
            tools=[WEB_SEARCH_TOOL],
        )
        # Die serverseitige Werkzeugschleife pausiert nach einer festen Zahl von
        # Runden. Fortgesetzt wird, indem dieselbe Frage samt der bisherigen
        # Antwort erneut geschickt wird; ein zusaetzlicher Satz ("weiter") waere
        # falsch, der Server erkennt die Pause selbst.
        rounds = 0
        while getattr(response, "stop_reason", None) == "pause_turn" and rounds < MAX_CONTINUATIONS:
            rounds += 1
            response = client.messages.create(
                model=model,
                max_tokens=MAX_TOKENS,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user},
                          {"role": "assistant", "content": response.content}],
                tools=[WEB_SEARCH_TOOL],
            )
    except Exception as exc:  # pragma: no cover - Netzwerkpfad
        log.warning("report_research_failed", error=str(exc))
        return {}, {}

    text = _text_of(response)
    cost = cost_from_usage(model, response.usage, KI_STEP)
    cost["duration_ms"] = int((time.monotonic() - started) * 1000)
    log.info("report_research_cost", **cost)
    ai_cache.set_cached_response(
        key, response_text=text, model=model,
        input_tokens=int(cost["input_tokens"]), output_tokens=int(cost["output_tokens"]),
        cache_ttl_seconds=CACHE_TTL_SECONDS)
    persist(cost, order_id)
    return _parse(text), cost


# ---------------------------------------------------------------- Uebernahme

def _clean(value: Any, field: str) -> Optional[str]:
    """Ein Vorschlagstext, der die Hausregeln haelt, sonst None."""
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    if not text or len(text) > TEXT_LIMITS.get(field, 120):
        return None
    if any(dash in text for dash in DASHES):
        return None
    # Ohne Quelldaten und damit strenger als das Prosa-Gate: hier entsteht der
    # Firmenname, der auf dem Deckblatt steht. "Huendgen Entsorgung" waere dort ein
    # Fehler, auch wenn der Domainname die Umschrift traegt.
    if find_transliterations(text):
        return None
    if field == "mitarbeiter" and not _MITARBEITER.match(text):
        return None
    return text


def _source_of(context: dict[str, Any], field: str) -> str:
    entry = (context.get("sources") or {}).get(field) or {}
    return str(entry.get("source") or "")


def apply_suggestion(context: dict[str, Any] | None, suggestion: dict[str, Any],
                     *, fqdns: Iterable[str]) -> tuple[dict[str, Any], list[str]]:
    """Vorschlaege in den Kundenkontext uebernehmen.

    Liefert den neuen Kontext und die Liste der abgelehnten Felder mit Grund.
    Bereits belegte Felder bleiben unveraendert, egal von wem sie kommen.
    """
    result: dict[str, Any] = dict(context or {})
    sources: dict[str, Any] = dict(result.get("sources") or {})
    known = {f.lower() for f in fqdns if f}
    rejected: list[str] = []

    def take(field: str, entry: Any) -> None:
        if result.get(field):
            return  # belegt, wir fassen nichts an
        if _source_of(result, field) in PROTECTED_SOURCES:
            return
        if not isinstance(entry, dict):
            rejected.append(f"{field}: keine Angabe mit Quelle")
            return
        value = _clean(entry.get("wert"), field)
        url = str(entry.get("quelle") or "").strip()
        if value is None:
            rejected.append(f"{field}: Wert unbrauchbar")
            return
        if not _URL.match(url):
            rejected.append(f"{field}: keine Fundstellen-URL")
            return
        result[field] = value
        sources[field] = {"source": SOURCE_RESEARCH, "url": url}

    for field in ("firmenname", "branche", "mitarbeiter"):
        if field in suggestion:
            take(field, suggestion.get(field))

    # S6: Personenzusatz faellt weg, auch wenn die KI ihn entgegen dem Prompt
    # liefert; der Kurzname fuer Fusszeile und PDF-Titel ist ein eigenes Feld.
    if result.get("firmenname") and _source_of(result, "firmenname") not in PROTECTED_SOURCES:
        bereinigt = firmenname_ohne_person(str(result["firmenname"]))
        if bereinigt and bereinigt != result["firmenname"]:
            rejected.append("firmenname: Personenzusatz entfernt")
            result["firmenname"] = bereinigt
    if not result.get("kurzname") and result.get("firmenname"):
        kurz = kurzname_aus(str(result["firmenname"]))
        if kurz:
            result["kurzname"] = kurz
            sources["kurzname"] = {"source": _source_of(result, "firmenname") or SOURCE_RESEARCH,
                                   "url": ((result.get("sources") or {}).get("firmenname") or {}).get("url", "")}

    systeme = suggestion.get("systeme")
    if isinstance(systeme, list) and not result.get("systeme") \
            and _source_of(result, "systeme") not in PROTECTED_SOURCES:
        accepted: list[dict[str, str]] = []
        urls: list[str] = []
        for entry in systeme:
            if not isinstance(entry, dict):
                continue
            fqdn = str(entry.get("fqdn") or "").strip().lower()
            zweck = _clean(entry.get("zweck"), "zweck")
            url = str(entry.get("quelle") or "").strip()
            if fqdn not in known:
                rejected.append(f"systeme: {fqdn or 'ohne Namen'} nicht im Scan")
                continue
            if zweck is None:
                rejected.append(f"systeme: {fqdn} ohne brauchbaren Zweck")
                continue
            if not _URL.match(url):
                rejected.append(f"systeme: {fqdn} ohne Fundstellen-URL")
                continue
            accepted.append({"fqdn": fqdn, "zweck": zweck})
            urls.append(url)
        if accepted:
            result["systeme"] = accepted
            sources["systeme"] = {"source": SOURCE_RESEARCH, "url": urls[0]}

    if sources:
        result["sources"] = sources
    if rejected:
        log.info("report_research_rejected", fields=rejected)
    return result, rejected
