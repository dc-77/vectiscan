# -*- coding: utf-8 -*-
"""Umrechnungstabellen zwischen Katalog-Einstufung und Report-Darstellung.

Der Katalog stuft in zwei Skalen ein (``exposure`` kritisch/erhoeht, ``hygiene``
hoch/mittel/niedrig, siehe reporter/catalog/decisions.md). Der Report zeigt daraus die
Triage-Farbe (rot/gelb/blau/gruen), die Dringlichkeit und den Balkenwert der Ampel
(spec/03 Regel 2). Alle Abbildungen stehen hier als Tabelle, damit kein Modul eine
eigene Meinung dazu entwickelt.
"""
from __future__ import annotations

# Rangfolge der Einstufungen, hoechste zuerst. Exposition schlaegt Hygiene.
LEVEL_RANK: dict[str, int] = {
    "kritisch": 0,
    "erhoeht": 1,
    "hoch": 2,
    "mittel": 3,
    "niedrig": 4,
}
SCALE_RANK: dict[str, int] = {"exposure": 0, "hygiene": 1}

# Einstufung -> Triage-Farbe des Befunds.
STATUS_BY_LEVEL: dict[str, str] = {
    "kritisch": "rot",
    "erhoeht": "gelb",
    "hoch": "gelb",
    "mittel": "gelb",
    "niedrig": "blau",
}

# Triage-Farbe -> Balkenwert der Ampel auf Seite 2 (vier Segmente).
BAR_BY_STATUS: dict[str, int] = {"rot": 4, "gelb": 2, "blau": 1, "gruen": 0}

# Triage-Farbe -> Gesamtbewertung als Wort.
OVERALL_BY_STATUS: dict[str, str] = {
    "rot": "HOCH",
    "gelb": "MITTEL",
    "blau": "NIEDRIG",
    "gruen": "GERING",
}

STATUS_RANK: dict[str, int] = {"rot": 0, "gelb": 1, "blau": 2, "gruen": 3}

# Empfehlungsstufe des Katalogs -> Dringlichkeit im Report.
URGENCY_BY_STAGE: dict[str, str] = {
    "unverzueglich": "Unverzüglich",
    "in_kuerze": "In Kürze",
    "mittelfristig": "Mittelfristig",
    "strategisch": "Strategisch",
}
STAGE_ORDER: tuple[str, ...] = ("unverzueglich", "in_kuerze", "mittelfristig", "strategisch")
STAGE_RANK: dict[str, int] = {s: i for i, s in enumerate(STAGE_ORDER)}

# Farbe der Zeile im Massnahmenplan, abgeleitet aus der Dringlichkeit.
STATUS_BY_STAGE: dict[str, str] = {
    "unverzueglich": "rot",
    "in_kuerze": "gelb",
    "mittelfristig": "blau",
    "strategisch": "blau",
}

LEVEL_LABELS: dict[str, str] = {
    "kritisch": "kritisch",
    "erhoeht": "erhöht",
    "hoch": "hoch",
    "mittel": "mittel",
    "niedrig": "niedrig",
}
SCALE_LABELS: dict[str, str] = {"exposure": "Exposition", "hygiene": "Hygiene"}


def severity_key(scale: str, level: str) -> tuple[int, int]:
    """Sortierschluessel: kleiner ist schwerer."""
    return (SCALE_RANK.get(scale, 9), LEVEL_RANK.get(level, 9))


def worst(pairs: list[tuple[str, str]]) -> tuple[str, str]:
    """Schwerste Einstufung aus einer Liste von (scale, level)."""
    return min(pairs, key=lambda p: severity_key(*p))


def status_for(level: str) -> str:
    return STATUS_BY_LEVEL.get(level, "blau")


def urgency_for(stages: list[str]) -> str:
    """Dringlichkeit eines Befunds: die dringlichste seiner Empfehlungsstufen."""
    if not stages:
        return URGENCY_BY_STAGE["mittelfristig"]
    top = min(stages, key=lambda s: STAGE_RANK.get(s, 9))
    return URGENCY_BY_STAGE[top]


def top_stage(stages: list[str]) -> str:
    if not stages:
        return "mittelfristig"
    return min(stages, key=lambda s: STAGE_RANK.get(s, 9))
