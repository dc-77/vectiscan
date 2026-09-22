# -*- coding: utf-8 -*-
"""Gate für die vier Prosa-Felder.

Die KI bekommt fertige Befunde und Fakten als JSON und schreibt daraus vier Absätze.
Sie darf dabei nichts behaupten, was nicht in ihrer Eingabe steht. Dieses Modul prüft
genau das und lässt einen Text nur durch, wenn jede Regel hält. Bei einem Verstoß bleibt
der deterministische Text stehen; welcher Text und welche Regel es war, steht im Log und
in ``meta.prose_rejected``.

Die Regeln kommen aus dem Auftrag S3: keine Zahlen, Hostnamen, CVE-IDs oder
Versionsangaben, die nicht in den Eingabedaten stehen; keine Severity-Wörter;
Längenlimit je Feld. Dazu die Hausregeln für Kundentexte: keine Gedankenstriche, keine
Zusagen, Sie-Form, echte Umlaute.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

from reporter.v3.orthography import DASHES, DU_FORM, FORBIDDEN_CLAIMS, find_transliterations

# Längenlimit je Feld in Zeichen.
LIMITS: dict[str, int] = {
    "overall_text": 900,
    "implication": 900,
    "observed": 400,
    "impact": 700,
}

NUMBER = re.compile(r"\d+(?:[.,]\d+)*")
VERSION = re.compile(r"\b\d+\.\d+(?:\.\d+)*\b")
CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
HOSTLIKE = re.compile(
    r"\b(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+)\b", re.I)
SEVERITY = re.compile(
    r"\b(kritisch|kritische[nrms]?|erhöht|erhoeht|hochgradig|schwerwiegend|gravierend|"
    r"CRITICAL|HIGH|MEDIUM|LOW|INFO)\b")
PLACEHOLDER = re.compile(r"\{.*?\}|\[Hinweis")

# Zahlen, die immer erlaubt sind: der Verweis auf die Meldepflicht.
ALWAYS_ALLOWED_NUMBERS = frozenset({"33", "72"})

# Wörter, die wie ein Hostname aussehen, aber keiner sind.
HOSTLIKE_ALLOWLIST = frozenset({"z.b", "u.a", "ggf.b", "bzw.b"})


@dataclass
class Verdict:
    ok: bool
    reasons: list[str]


def corpus(payload: Any) -> str:
    """Alles, was die KI als Eingabe gesehen hat, als ein durchsuchbarer Text."""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True).lower()


def _unknown(values: Iterable[str], haystack: str) -> list[str]:
    return sorted({v for v in values if v.lower() not in haystack})


def check_field(name: str, text: str, haystack: str) -> Verdict:
    """Prueft einen einzelnen Prosa-Text gegen die Eingabedaten."""
    reasons: list[str] = []
    if not text or not text.strip():
        return Verdict(False, ["leer"])

    limit = LIMITS.get(name.split("[", 1)[0], 900)
    if len(text) > limit:
        reasons.append(f"laenger als {limit} Zeichen")

    unknown_numbers = [n for n in NUMBER.findall(text)
                       if n not in ALWAYS_ALLOWED_NUMBERS and n.lower() not in haystack]
    if unknown_numbers:
        reasons.append(f"Zahl nicht in den Eingabedaten: {sorted(set(unknown_numbers))}")

    hosts = [h for h in HOSTLIKE.findall(text) if h.lower() not in HOSTLIKE_ALLOWLIST]
    unknown_hosts = _unknown(hosts, haystack)
    if unknown_hosts:
        reasons.append(f"Hostname nicht in den Eingabedaten: {unknown_hosts}")

    unknown_cves = _unknown(CVE.findall(text), haystack)
    if unknown_cves:
        reasons.append(f"CVE nicht in den Eingabedaten: {unknown_cves}")

    unknown_versions = _unknown(VERSION.findall(text), haystack)
    if unknown_versions:
        reasons.append(f"Versionsangabe nicht in den Eingabedaten: {unknown_versions}")

    severities = sorted({m.group(0) for m in SEVERITY.finditer(text)})
    if severities:
        reasons.append(f"Severity-Wort im Text: {severities}")

    if any(d in text for d in DASHES):
        reasons.append("Gedankenstrich")
    if PLACEHOLDER.search(text):
        reasons.append("Platzhalter oder interner Hinweis")
    if FORBIDDEN_CLAIMS.search(text):
        reasons.append("verbotene Zusage")
    if DU_FORM.search(text):
        reasons.append("keine Sie-Form")
    umlauts = find_transliterations(text, haystack)
    if umlauts:
        reasons.append(f"Umschrift statt Umlaut: {sorted(set(umlauts))}")

    return Verdict(not reasons, reasons)
