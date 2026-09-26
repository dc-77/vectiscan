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

# S6b-2 (E2): benannte Ausnahmen der Tabelle. Eine Pruefung mit ``urgent_when`` wird bei
# Treffer rot mit Unverzueglich, obwohl ihre Einstufung Hygiene ist. Jede Ausnahme steht
# hier mit dem Satz, den Anhang A.1 dazu nennt; ein Test haelt Katalog und Tabelle gleich.
TRIAGE_URGENT = Triage("rot", ("unverzueglich",), "CRITICAL")
URGENT_EXCEPTIONS: dict[str, str] = {
    "cert_expiring": "ein Zertifikat mit einer Restlaufzeit von höchstens sieben Tagen",
}

# Rueckfall fuer eine Einstufung, die das Schema nicht kennt. Der Selbstcheck
# meldet sie ohnehin als Defekt; hier wird nur nichts erfunden.
TRIAGE_UNKNOWN = Triage("blau", ("mittelfristig",), "LOW")

# Triage-Farbe -> Balkenwert der Ampel auf Seite 2 (vier Segmente).
# S6b-3 (spec/10 R6): "grau" = nicht bewertbar (Kategorie B ohne bewertbare Version).
BAR_BY_STATUS: dict[str, int] = {"rot": 4, "gelb": 2, "blau": 1, "gruen": 0, "grau": 0}

# Triage-Farbe -> Gesamtbewertung als Wort.
OVERALL_BY_STATUS: dict[str, str] = {
    "rot": "HOCH",
    "gelb": "MITTEL",
    "blau": "NIEDRIG",
    "gruen": "GERING",
}

STATUS_RANK: dict[str, int] = {"rot": 0, "gelb": 1, "blau": 2, "gruen": 3, "grau": 4}

STATUS_LABELS: dict[str, str] = {
    "rot": "Rot", "gelb": "Gelb", "blau": "Blau", "gruen": "Grün", "grau": "Grau",
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


def triage_for(scale: str, level: str, active_proof: bool = False, urgent: bool = False) -> Triage:
    if active_proof:
        return TRIAGE_ACTIVE_PROOF
    if urgent:
        return TRIAGE_URGENT
    return TRIAGE_BY_LEVEL.get((scale, level), TRIAGE_UNKNOWN)


def status_for(scale: str, level: str, active_proof: bool = False, urgent: bool = False) -> str:
    return triage_for(scale, level, active_proof, urgent).status


def severity_for(scale: str, level: str, active_proof: bool = False, urgent: bool = False) -> str:
    """Stufe fuer die Dashboard-Befundliste (reports.findings_data)."""
    return triage_for(scale, level, active_proof, urgent).severity


def stage_for(scale: str, level: str, stages: list[str],
              active_proof: bool = False, urgent: bool = False) -> str:
    """Wirksame Empfehlungsstufe eines Befunds.

    Der Katalog schlaegt mit seiner dringlichsten Stufe vor; zugelassen ist sie
    nur, wenn die Tabelle sie fuer diese Einstufung vorsieht. Sonst gilt der
    Tabellenwert. Damit kann keine Empfehlung einen gelben Befund als
    unverzueglich ausweisen.
    """
    tri = triage_for(scale, level, active_proof, urgent)
    if not stages:
        return tri.stage
    top = min(stages, key=lambda s: STAGE_RANK.get(s, 9))
    return top if top in tri.stages else tri.stage


def urgency_for(scale: str, level: str, stages: list[str],
                active_proof: bool = False, urgent: bool = False) -> str:
    return URGENCY_BY_STAGE[stage_for(scale, level, stages, active_proof, urgent)]


def relative_stages(stages: list[str], effective: str) -> list[str]:
    """Empfehlungsstufen einer Regel, verschoben auf ihre wirksame Dringlichkeit (Q5).

    Die dringlichste Empfehlung einer Regel steht auf der Dringlichkeit, die die
    Abbildungstabelle ihr gibt; die weiteren behalten ihren Abstand zur ersten und enden
    spaetestens bei "Strategisch". Vorher begann ein gelber Befund "In Kuerze" mit
    "Unverzueglich:", weil der Katalog seine Stufen unabhaengig von der Einstufung setzte
    (spec/09 Q5).
    """
    if not stages:
        return []
    top = min(STAGE_RANK.get(s, len(STAGE_ORDER) - 1) for s in stages)
    shift = STAGE_RANK[effective] - top
    last = len(STAGE_ORDER) - 1
    return [STAGE_ORDER[max(0, min(last, STAGE_RANK.get(s, last) + shift))] for s in stages]


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
    for special in (TRIAGE_ACTIVE_PROOF, TRIAGE_URGENT):
        if status != special.status:
            continue
        for stage in special.stages:
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


# ---------------------------------------------------------------- Skalen (Anhang A.2)
# S6b-2 (spec/09 Q13, E1): A.2, diese Tabelle und die Einstufung der Verwaltungspruefungen
# im Katalog kommen aus einer Quelle. Vorher definierte A.2 "kritisch: ...
# Verwaltungsoberflaechen", waehrend die Regel "erhoeht" vergab. ``ADMIN_EXPOSURE`` nennt je
# Verwaltungspruefung Skala und Einstufung; ein Test gleicht die YAML-Dateien dagegen ab.

ADMIN_EXPOSURE: dict[str, tuple[str, str, str]] = {
    # Pruefung: (Skala, Einstufung, Fall fuer A.2)
    "admin_service_exposed": (
        "exposure", "kritisch",
        "Verwaltungsoberfläche mit Anmeldung ohne vorgelagerten Schutz auf einem System "
        "des Kunden"),
    # Titel einer Verwaltungsoberflaeche unter einem Hostnamen der Webseite, ohne belegte
    # Anmeldung: bleibt erhoeht (Entscheidung DC 25.09.: Fingerabdruck ohne Anmeldung).
    "admin_portal_exposed": (
        "exposure", "erhoeht",
        "Seitentitel einer Verwaltungsoberfläche unter einem Hostnamen der Webseite ohne "
        "belegte Anmeldung"),
    "admin_panel_hoster": (
        "exposure", "erhoeht",
        "Verwaltungsoberfläche des Hosters auf einem geteilten System, mit Empfehlung an "
        "den Hoster"),
    "admin_service_unconfirmed": (
        "exposure", "erhoeht",
        "Dienst auf einem üblichen Verwaltungsport oder mit der Kennung einer "
        "Verwaltungssoftware ohne belegte Anmeldung, dessen Zweck zu klären ist"),
    "admin_service_exposed_passive": (
        "exposure", "erhoeht",
        "Verwaltungsoberfläche, die nur eine Passivquelle mit Kennung meldet und die "
        "zuerst zu bestätigen ist"),
}


def exposure_scale() -> list[tuple[str, str]]:
    """Zeilen der Expositionsskala in A.2, Verwaltungsfaelle aus ``ADMIN_EXPOSURE``."""
    kritisch = sorted({fall for s, lvl, fall in ADMIN_EXPOSURE.values() if lvl == "kritisch"})
    erhoeht = sorted({fall for s, lvl, fall in ADMIN_EXPOSURE.values() if lvl == "erhoeht"})
    return [
        ("kritisch", "Dienst, der nicht an das öffentliche Interface gehört und aus dem "
                     "Internet erreichbar ist: Datenbanken, Fernwartung, "
                     + "; ".join(kritisch) + "."),
        ("erhöht", "Dienst mit legitimem Zweck, aber ohne erkennbare Zugriffsbeschränkung "
                   "oder mit ungeklärter Funktion, darunter: " + "; ".join(erhoeht) + "."),
    ]


def urgent_phrase() -> str:
    """Satz fuer Anhang A.1 zu den benannten Ausnahmen der Tabelle."""
    if not URGENT_EXCEPTIONS:
        return ""
    faelle = sorted(URGENT_EXCEPTIONS.values())
    return ("Ausnahme: Rot und Unverzüglich gelten auch für "
            + (" und ".join(faelle)) + ".")
