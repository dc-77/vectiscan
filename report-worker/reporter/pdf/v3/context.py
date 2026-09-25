# -*- coding: utf-8 -*-
"""Vom Datenmodell zu den Template-Variablen.

Hier entsteht alles, was eine *Darstellungs*entscheidung ist und deshalb nicht in die
Reportdaten gehoert: die Aufteilung von Kapitel 6 auf Hauptteil und Anhang, die
Verteilungszeile der Zusammenfassung, die Anhangsbuchstaben und die Saetze aus
``text.py``. Die Daten selbst werden nicht veraendert; ``findings`` bleibt vollstaendig
und wird von Kapitel 4 und Anhang A.2 weiterhin ganz durchlaufen.
"""
from __future__ import annotations

import re
from typing import Any

from reporter.v3 import levels as L
from reporter.v3.models import ReportData

from reporter.pdf.v3 import text as T
from reporter.pdf.v3.variants import Variant
from reporter.v3 import tables as V3T

# Darstellungsregel (Entscheidung DC, S4): bis zu dieser Zahl stehen alle Befunde im
# Hauptteil. Darueber stehen die dringendsten TOP_N_HAUPTTEIL dort und der Rest
# vollstaendig, mit denselben Feldern, im Anhang zu Kapitel 6.
TOP_N_SCHWELLE = 20
TOP_N_HAUPTTEIL = 15

# S6b-1 Nachtrag 3 (Entscheidung DC 25.09.): ein Kategorieblock in Kapitel 4 mit mehr
# Zeilen darf nach seiner Kopfzeile umbrechen. Als Ganzes liess er die Seite davor
# halb leer (f77ccff2 Seite 11: 129 mm frei, Block 140 mm hoch).
CAT_KEEP = 6

# Dringlichkeitswort -> Rang. Aus derselben Tabelle wie die Reportdaten, damit eine
# Umbenennung nicht an zwei Stellen gepflegt werden muss.
_URGENCY_RANK: dict[str, int] = {
    label: L.STAGE_RANK[stage] for stage, label in L.URGENCY_BY_STAGE.items()
}
_URGENCY_ORDER: tuple[str, ...] = tuple(L.URGENCY_BY_STAGE[s] for s in L.STAGE_ORDER)

_ID_NUM = re.compile(r"(\d+)$")


def _as_dict(data: ReportData | dict) -> dict:
    """Das Template ist fuer Dicts geschrieben (``blk['items']``), also normalisieren."""
    if isinstance(data, ReportData):
        return data.to_dict()
    return data


def id_num(finding: dict) -> int:
    m = _ID_NUM.search(finding.get("id") or "")
    return int(m.group(1)) if m else 0


def urgency_rank(finding: dict) -> tuple[int, int, int]:
    """Sortierschluessel fuer die Auswahl: kleiner ist dringender."""
    return (
        L.STATUS_RANK.get(finding.get("status") or "", 9),
        _URGENCY_RANK.get(finding.get("urgency") or "", 9),
        id_num(finding),
    )


def split_findings(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """Hauptteil und Anhang zu Kapitel 6.

    Ausgewaehlt wird nach Dringlichkeit, ausgegeben in ID-Reihenfolge: sonst springen
    die Nummern im Bericht und der Leser sucht.
    """
    if len(findings) <= TOP_N_SCHWELLE:
        return list(findings), []
    ranked = sorted(findings, key=urgency_rank)
    main_ids = {f["id"] for f in ranked[:TOP_N_HAUPTTEIL]}
    main = [f for f in findings if f["id"] in main_ids]
    more = [f for f in findings if f["id"] not in main_ids]
    return main, more


def urgency_counts(findings: list[dict]) -> list[tuple[str, int]]:
    """Verteilung nach Dringlichkeit in fester Reihenfolge."""
    seen: dict[str, int] = {}
    for f in findings:
        label = f.get("urgency") or ""
        seen[label] = seen.get(label, 0) + 1
    out = [(label, seen.pop(label, 0)) for label in _URGENCY_ORDER]
    # Unbekannte Dringlichkeiten nicht verschlucken.
    out.extend(sorted(seen.items()))
    return [(label, n) for label, n in out if n]


# Anhaenge in Reihenfolge des Dokuments. Der Schluessel ist der Name im Template, der
# zweite Eintrag sagt, ob der Anhang immer erscheint.
_APPENDIX_ORDER: tuple[tuple[str, str], ...] = (
    ("scales", "Bewertungsmaßstäbe"),
    ("inventory", "Service-Inventar"),
    ("tools", "Eingesetzte Werkzeuge"),
    ("filtering", "Methodische Filterung"),
    ("repeat", "Wiederholungsempfehlung"),
    ("disclaimer", "Geltung und Haftungsausschluss"),
)


def appendix_letters(present: set[str]) -> dict[str, str]:
    """Buchstaben an die tatsaechlich vorhandenen Anhaenge vergeben.

    Bei WebCheck faellt das Service-Inventar weg. Feste Buchstaben liessen dann eine
    Luecke (A, C, D, ...) im Kundenbericht, was wie ein Fehler aussieht. A bleibt in
    jedem Fall bei den Bewertungsmaßstäben, deshalb bleibt auch die im Fliesstext
    zitierte Referenz A.3 stabil.
    """
    out: dict[str, str] = {}
    for i, (key, _label) in enumerate(k for k in _APPENDIX_ORDER if k[0] in present):
        out[key] = chr(ord("A") + i)
    return out


def build_context(data: ReportData | dict, *, variant: Variant,
                  assets_url: str = "assets") -> dict[str, Any]:
    """Alle Variablen, die ``templates/report.html.j2`` erwartet."""
    d = _as_dict(data)
    m = d["meta"]
    a = d["architecture"]
    ap = d["appendix"]
    findings = d["findings"]

    runs = len(m.get("orders") or []) or 1
    main, more = split_findings(findings)

    show_screens = bool(variant.screens and a.get("screens"))
    show_inventory = bool(variant.inventory and ap.get("inventory"))
    show_tool_findings = bool(ap.get("tool_findings"))

    present = {"scales", "tools", "filtering", "repeat", "disclaimer"}
    if show_inventory:
        present.add("inventory")
    letters = appendix_letters(present)
    tail = [letters[k] for k in ("filtering", "repeat", "disclaimer")]

    return {
        # Prototyp-Variablen, unveraendert
        "m": m,
        "g": d["glance"],
        "b": d["business"],
        "s": d["scope"],
        "a": a,
        "landscape_lead": d["landscape_lead"],
        "positives": d["positives"],
        "plan": d["plan"],
        "findings": findings,
        "ap": ap,
        "assets": assets_url,
        # Darstellung
        "variant": variant,
        "findings_main": main,
        "findings_more": more,
        "runs": runs,
        "runs_line": T.runs_line(m.get("hosts_total") or 0, m.get("fqdns_total") or 0, runs),
        "period_note": T.period_note(m.get("scan_window") or "", runs),
        "distribution_line": T.distribution_line(len(findings), urgency_counts(findings)),
        "split_note": T.split_note(len(main), len(more), len(findings)) if more else "",
        # S6b-2 (Issue #28): ausgeschlossene Befunde erklaeren die Luecken der Nummerierung.
        "excluded_note": T.excluded_note(list(m.get("excluded_ids") or [])),
        "show_screens": show_screens,
        "show_inventory": show_inventory,
        "show_tool_findings": show_tool_findings,
        "ltr": letters,
        "ap_tail_range": f"{tail[0]} bis {tail[-1]}",
        "txt": T,
        # Zeitstufen unter dem Massnahmenplan kommen aus derselben Tabelle wie
        # die Dringlichkeiten der Befunde (S6, reporter/v3/levels.py).
        "stage_box": V3T.stage_box(),
        "cat_keep": CAT_KEEP,
    }
