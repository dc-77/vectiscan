# -*- coding: utf-8 -*-
"""Die eine Abbildungstabelle: Einstufung zu Dringlichkeit zu Ampelfarbe.

Der Katalog stuft in zwei Skalen ein (``exposure`` kritisch/erhoeht, ``hygiene``
hoch/mittel/niedrig, siehe reporter/catalog/decisions.md). Alles, was der Bericht
daraus macht, steht hier in genau einer Tabelle: die Ampelfarbe des Befunds, die
Dringlichkeit, der Balkenwert der Ampel auf Seite 2, die Farbe der Planzeile, der
Text in Anhang A.1 und die Stufe, die das Dashboard anzeigt.

Vorher gab es zwei unabhaengige Wege: die Farbe kam aus der Einstufung, die
Dringlichkeit aus der ersten Empfehlungsstufe des Katalogs. Beide konnten
auseinanderlaufen, und sie taten es: vier Befunde mit "Unverzueglich" standen in
gelben Kategorien, waehrend die Gesamtbewertung sagte, kein Befund erfordere
sofortiges Handeln (spec/08 Punkt 1). Entscheidung DC, Variante (a): Unverzueglich
und Rot nur fuer Exposition kritisch und fuer aktive Schwachstellen mit hoher
Konfidenz; alles andere bekommt die Dringlichkeit seiner Einstufung.

Die Empfehlungsstufe des Katalogs bleibt die Reihenfolge der Massnahmen innerhalb
eines Befunds. Sie darf die Dringlichkeit nur dort bestimmen, wo die Tabelle mehr
als eine Stufe zulaesst; ist sie dringlicher als erlaubt, wird sie gedeckelt.
"""
from __future__ import annotations

from dataclasses import dataclass

# Rangfolge der Einstufungen, hoechste zuerst. Exposition schlaegt Hygiene.
LEVEL_RANK: dict[str, int] = {
    "kritisch": 0,
    "erhoeht": 1,
    "hoch": 2,
    "mittel": 3,
    "niedrig": 4,
}
SCALE_RANK: dict[str, int] = {"exposure": 0, "hygiene": 1}

STAGE_ORDER: tuple[str, ...] = ("unverzueglich", "in_kuerze", "mittelfristig", "strategisch")
STAGE_RANK: dict[str, int] = {s: i for i, s in enumerate(STAGE_ORDER)}

# Empfehlungsstufe des Katalogs -> Dringlichkeit im Report.
URGENCY_BY_STAGE: dict[str, str] = {
    "unverzueglich": "Unverzüglich",
    "in_kuerze": "In Kürze",
    "mittelfristig": "Mittelfristig",
    "strategisch": "Strategisch",
}

# Zeitfenster je Stufe, einmal hier statt dreimal im Markup.
STAGE_WINDOW: dict[str, str] = {
    "unverzueglich": "24 bis 72 Stunden",
    "in_kuerze": "1 bis 2 Wochen",
    "mittelfristig": "nächster Wartungszyklus",
    "strategisch": "laufendes Quartal",
}


@dataclass(frozen=True)
class Triage:
    """Was eine Einstufung im Bericht auf jeder Ebene bedeutet."""

    status: str                      # Ampelfarbe des Befunds
    stages: tuple[str, ...]          # zulaessige Empfehlungsstufen, dringlichste zuerst
    severity: str                    # Stufe fuer das Dashboard (reports.findings_data)

    @property
    def stage(self) -> str:
        """Die Stufe, die gilt, wenn der Katalog keine zulaessige nennt."""
        return self.stages[0]

    @property
    def urgency(self) -> str:
        return URGENCY_BY_STAGE[self.stage]


# (Skala, Einstufung) -> Triage. Einzige Wahrheit; kein Modul leitet daneben
# eine eigene Farbe oder Dringlichkeit ab.
TRIAGE_BY_LEVEL: dict[tuple[str, str], Triage] = {
    ("exposure", "kritisch"): Triage("rot", ("unverzueglich",), "CRITICAL"),
    ("exposure", "erhoeht"): Triage("gelb", ("in_kuerze",), "HIGH"),
    ("hygiene", "hoch"): Triage("gelb", ("in_kuerze",), "HIGH"),
    ("hygiene", "mittel"): Triage("gelb", ("mittelfristig",), "MEDIUM"),
    ("hygiene", "niedrig"): Triage("blau", ("mittelfristig", "strategisch"), "LOW"),
}

# Ein aktiv nachgewiesener Befund (siehe catalog ``active_proof_when``) wird rot,
# unabhaengig von seiner Einstufung.
TRIAGE_ACTIVE_PROOF = Triage("rot", ("unverzueglich",), "CRITICAL")

# Rueckfall fuer eine Einstufung, die das Schema nicht kennt. Der Selbstcheck
# meldet sie ohnehin als Defekt; hier wird nur nichts erfunden.
TRIAGE_UNKNOWN = Triage("blau", ("mittelfristig",), "LOW")

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

STATUS_LABELS: dict[str, str] = {
    "rot": "Rot", "gelb": "Gelb", "blau": "Blau", "gruen": "Grün",
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


def triage_for(scale: str, level: str, active_proof: bool = False) -> Triage:
    if active_proof:
        return TRIAGE_ACTIVE_PROOF
    return TRIAGE_BY_LEVEL.get((scale, level), TRIAGE_UNKNOWN)


def status_for(scale: str, level: str, active_proof: bool = False) -> str:
    return triage_for(scale, level, active_proof).status


def severity_for(scale: str, level: str, active_proof: bool = False) -> str:
    """Stufe fuer die Dashboard-Befundliste (reports.findings_data)."""
    return triage_for(scale, level, active_proof).severity


def stage_for(scale: str, level: str, stages: list[str],
              active_proof: bool = False) -> str:
    """Wirksame Empfehlungsstufe eines Befunds.

    Der Katalog schlaegt mit seiner dringlichsten Stufe vor; zugelassen ist sie
    nur, wenn die Tabelle sie fuer diese Einstufung vorsieht. Sonst gilt der
    Tabellenwert. Damit kann keine Empfehlung einen gelben Befund als
    unverzueglich ausweisen.
    """
    tri = triage_for(scale, level, active_proof)
    if not stages:
        return tri.stage
    top = min(stages, key=lambda s: STAGE_RANK.get(s, 9))
    return top if top in tri.stages else tri.stage


def urgency_for(scale: str, level: str, stages: list[str],
                active_proof: bool = False) -> str:
    return URGENCY_BY_STAGE[stage_for(scale, level, stages, active_proof)]


def top_stage(stages: list[str]) -> str:
    """Dringlichste vom Katalog vorgeschlagene Stufe, ungedeckelt.

    Nur fuer die Auswahl des Massnahmentexts innerhalb eines Befunds; die
    Dringlichkeit der Planzeile kommt aus ``stage_for``.
    """
    if not stages:
        return "mittelfristig"
    return min(stages, key=lambda s: STAGE_RANK.get(s, 9))


def stages_for_status(status: str) -> list[str]:
    """Alle Stufen, die bei dieser Ampelfarbe vorkommen koennen, dringlichste zuerst."""
    out: list[str] = []
    for tri in TRIAGE_BY_LEVEL.values():
        if tri.status != status:
            continue
        for stage in tri.stages:
            if stage not in out:
                out.append(stage)
    if status == TRIAGE_ACTIVE_PROOF.status:
        for stage in TRIAGE_ACTIVE_PROOF.stages:
            if stage not in out:
                out.append(stage)
    return sorted(out, key=lambda s: STAGE_RANK[s])


def urgency_phrase(status: str) -> str:
    """Satzteil fuer Anhang A.1: welche Dringlichkeit diese Farbe traegt."""
    stages = stages_for_status(status)
    if not stages:
        return ""
    parts = [f"{URGENCY_BY_STAGE[s]} ({STAGE_WINDOW[s]})" for s in stages]
    if len(parts) == 1:
        return parts[0]
    return " oder ".join([", ".join(parts[:-1]), parts[-1]])
