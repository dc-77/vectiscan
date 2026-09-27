# -*- coding: utf-8 -*-
"""Gate für die Prosa-Felder.

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

# S6b-3 (spec/10 R13): Aussagen, die einen Fakt voraussetzen, den die Eingabe nicht immer hat.
ANSCHLUSS = re.compile(r"Unternehmensnetz|\bAnschluss(?:es)?\b|dahinter liegende[nr]? Systeme", re.I)
MITARBEITER = re.compile(
    r"\b(?:\d+|zwei|drei|vier|fünf|sechs|sieben|acht|neun|zehn|elf|zwölf)\s+"
    r"(?:Mitarbeite\w*|Beschäftigte\w*)", re.I)
MFA = re.compile(r"\bMFA\b|Mehrfaktor\w*|(?:zusätzliche|zweite)[nrms]? Faktor", re.I)
# S6b-4 (spec/11 T10): "ob ... aktiv ist, ist von außen nicht feststellbar" ist eine Bedingung.
BEDINGUNG = re.compile(r"\b(?:sofern|falls|wenn|soweit|ob)\b|nicht feststellbar", re.I)
# S6b-4 (spec/11 T10): Formulareingaben setzen eine gelaufene Webanalyse voraus.
FORMULAR = re.compile(r"Formulareingabe\w*|Formulardaten", re.I)
RELATIVE_FRIST = re.compile(
    r"\bin (?:\d+|einem|einer|zwei|drei|vier|fünf|sechs|sieben|acht|neun|zehn|elf|zwölf) "
    r"(?:Tag|Tagen|Woche|Wochen|Monat|Monaten)\b", re.I)
SATZ = re.compile(r"[^.!?]+[.!?]?")

# Zahlen, die immer erlaubt sind: der Verweis auf die Meldepflicht.
ALWAYS_ALLOWED_NUMBERS = frozenset({"33", "72"})

# Wörter, die wie ein Hostname aussehen, aber keiner sind.
HOSTLIKE_ALLOWLIST = frozenset({"z.b", "u.a", "ggf.b", "bzw.b"})


# S6b-2 (Nachtrag S6b-1, spec/09 Teil 3): Zahlen mit Zaehleinheit. Die Einheit ist das
# System (Kapitel 2.1); Adressen und Hostnamen stehen mit ihrer eigenen Zahl daneben,
# "Host" ist keine Zaehleinheit mehr. "ein System" ist oft keine Gesamtzahl ("auf einem
# System laeuft ...") und wird deshalb nicht geprueft.
_ZAHLWORT = {"zwei": 2, "drei": 3, "vier": 4, "fünf": 5, "sechs": 6, "sieben": 7, "acht": 8,
             "neun": 9, "zehn": 10, "elf": 11, "zwölf": 12}
COUNT_PHRASE = re.compile(
    r"\b(\d+|zwei|drei|vier|fünf|sechs|sieben|acht|neun|zehn|elf|zwölf)\s+"
    r"(Systemen|Systeme|System|Hosts|Host|IP-Adressen|IP-Adresse|Adressen|Adresse|Hostnamen|Hostname)\b",
    re.I)
_EINHEIT = {"system": "systeme", "ip-adress": "ip_adressen", "adress": "ip_adressen",
            "hostname": "hostnamen"}


def count_mismatches(text: str, counts: dict[str, int]) -> list[str]:
    """Zahlen mit Einheit, die der Zaehlung in Kapitel 2.1 widersprechen."""
    out: list[str] = []
    for m in COUNT_PHRASE.finditer(text or ""):
        wort, einheit = m.group(1).lower(), m.group(2).lower()
        zahl = int(wort) if wort.isdigit() else _ZAHLWORT[wort]
        if einheit.startswith("host") and not einheit.startswith("hostname"):
            out.append(f"Zählung in Hosts statt Systemen: {m.group(0)}")
            continue
        key = next((v for k, v in _EINHEIT.items() if einheit.startswith(k)), None)
        if key is None or key not in counts:
            continue
        if zahl != counts[key]:
            out.append(f"{m.group(0)} widerspricht der Zählung in 2.1 ({counts[key]})")
    return out


def context_claims(text: str, haystack: str) -> list[str]:
    """S6b-3 (spec/10 R13): Aussagen ohne tragenden Fakt in der Eingabe.

    ``haystack`` ist die kleingeschriebene JSON-Eingabe der KI (``corpus``).
    """
    out: list[str] = []
    if ANSCHLUSS.search(text) and '"anschluss"' not in haystack:
        out.append("Unternehmensnetz oder Anschluss ohne System am Anschluss des Kunden")
    if FORMULAR.search(text) and "formulareingaben" not in haystack:
        out.append("Formulareingaben ohne gelaufene Webanalyse")
    if MITARBEITER.search(text) and '"mitarbeiter":' not in haystack:
        out.append("Mitarbeiterzahl ohne Quelle Kunde oder Admin")
    for satz in SATZ.findall(text):
        if MFA.search(satz) and not BEDINGUNG.search(satz):
            out.append("Aussage zur Mehrfaktor-Anmeldung ohne Bedingung")
            break
    if RELATIVE_FRIST.search(text):
        out.append("relative Frist statt Datum")
    return out


@dataclass
class Verdict:
    ok: bool
    reasons: list[str]


def corpus(payload: Any) -> str:
    """Alles, was die KI als Eingabe gesehen hat, als ein durchsuchbarer Text."""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True).lower()


def _unknown(values: Iterable[str], haystack: str) -> list[str]:
    return sorted({v for v in values if v.lower() not in haystack})


def check_field(name: str, text: str, haystack: str, *, role_keys=None,
                reference: str = "", counts: dict[str, int] | None = None) -> Verdict:
    """Prueft einen einzelnen Prosa-Text gegen die Eingabedaten.

    S6b-1 (spec/09 Q2): mit ``role_keys`` faellt ein Text durch, der einem System eine
    Aufgabe zuschreibt (Kalender, Korrespondenz, Datenbank ...), ohne dass eine Rolle
    dieser Art belegt ist. Woerter aus dem deterministischen Bezugstext ``reference``
    gelten nicht als neue Aussage.
    """
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
    if counts is not None:
        reasons.extend(count_mismatches(text, counts))
    reasons.extend(context_claims(text, haystack))
    if role_keys is not None:
        from reporter.v3.roles import role_words_without_fact

        ohne = role_words_without_fact(text, role_keys, reference)
        if ohne:
            reasons.append(f"Rolle ohne Fakt: {ohne}")

    return Verdict(not reasons, reasons)
