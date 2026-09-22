# -*- coding: utf-8 -*-
"""Selbstcheck des Datenmodells.

Portierung von ``report-prototype/build/build_report.py::check_data``. Der Renderer (S4)
und das Gate (S5) rufen diese Funktion auf, statt die Prüfungen erneut zu schreiben.
Sie prüft nur Eigenschaften des Datenmodells, nicht die Fachlichkeit eines Befunds.

``check_report_data_detailed`` liefert je Defekt zusätzlich einen Prüfungsnamen und die
betroffene Befund-ID, weil das Admin-Review aus S5 drei Spalten zeigt.
``check_report_data`` bleibt die Satzliste, auf der der Renderer steht.
"""
from __future__ import annotations

import re
from typing import NamedTuple, Optional

from reporter.v3.models import ReportData

PLACEHOLDER = re.compile(r"\{.*?\}|\[Hinweis")
VERSION_IN_TOOL = re.compile(r"\d+\.\d+")
CVE_WITH_SCORE = re.compile(r"(CVE-\d{4}-\d+).*?Basiswert (\d+(?:\.\d+)?)")
CVE_ANY = re.compile(r"(CVE-\d{4}-\d+)")
# None, True, False als eigenstaendiges Wort oder eine Liste in eckigen
# Klammern: alles Spuren einer f-String-Formatierung ueber Python-Werte.
PYTHON_REPR = re.compile(r"(?<![\w-])(None|True|False)(?![\w-])|\['|\[\"")


class Befund(NamedTuple):
    """Ein Defekt mit Prüfungsname und betroffener Befund-ID."""

    check: str
    message: str
    finding_id: Optional[str]


def check_report_data_detailed(data: ReportData | dict) -> list[Befund]:
    """Defekte mit Prüfungsname; leere Liste heisst in Ordnung."""
    if isinstance(data, ReportData):
        d = data
    else:
        d = ReportData.model_validate(data)
    errors: list[Befund] = []

    def add(check: str, message: str, finding_id: Optional[str] = None) -> None:
        errors.append(Befund(check, message, finding_id))

    ids = [f.id for f in d.findings]
    nums = [int(i.rsplit("-", 1)[-1]) for i in ids] if ids else []
    if nums != list(range(1, len(nums) + 1)):
        add("ids_lueckenhaft", f"Befund-IDs nicht lueckenlos: {ids}")
    if len(set(ids)) != len(ids):
        add("ids_doppelt", "doppelte Befund-IDs")

    titles = [f.title for f in d.findings]
    if len(set(titles)) != len(titles):
        dupes = sorted({t for t in titles if titles.count(t) > 1})
        add("titel_doppelt", f"doppelte Titel: {dupes}")

    for f in d.findings:
        if PLACEHOLDER.search(f.title):
            add("titel_platzhalter", f"Platzhalter oder interner Hinweis im Titel {f.id}", f.id)
        if f.scale not in ("exposure", "hygiene") or not f.level:
            add("einstufung_fehlt", f"Einstufung fehlt oder unbekannt bei {f.id}", f.id)
        if f.status not in ("rot", "gelb", "blau", "gruen"):
            add("status_unbekannt", f"unbekannter Status {f.status!r} bei {f.id}", f.id)
        if not f.recommendation:
            add("empfehlung_fehlt", f"keine Empfehlung bei {f.id}", f.id)
        for text in (f.found, f.impact, f.verify):
            if PLACEHOLDER.search(text):
                add("text_platzhalter", f"Platzhalter im Text von {f.id}", f.id)
                break

    # Fremdwerte: jede zitierte CVE braucht einen Eintrag in Anhang A.3, mit gleichem
    # Score und einem Rueckverweis auf genau diesen Befund.
    # Eine Zeile in A.3 kann mehrere Kennungen desselben testssl-Tests tragen
    # (S6, spec/08 Punkt 18); jede davon muss den Befund wiederfinden.
    refs = {teil.strip(): c for c in d.appendix.cve_refs
            for teil in c.cve.split(",") if teil.strip()}
    for f in d.findings:
        for cited in (f.threat.cves if f.threat else []):
            match = CVE_ANY.search(cited)
            if not match or match.group(1) not in refs:
                add("cve_ohne_referenz", f"CVE ohne Referenzeintrag in {f.id}: {cited[:40]}", f.id)
                continue
            ref = refs[match.group(1)]
            score = CVE_WITH_SCORE.search(cited)
            if score and score.group(2) != ref.score:
                add("cve_score_abweichung",
                    f"CVE-Score weicht ab in {f.id}: {score.group(2)} statt {ref.score}", f.id)
            # Anhang A.3 fuehrt jede CVE einmal und nennt alle Befunde, in denen
            # sie zitiert wird; dieser Befund muss darunter sein.
            if f.id not in [x.strip() for x in ref.ref.split(",")]:
                add("cve_referenz_falsch",
                    f"CVE-Referenz zeigt auf {ref.ref}, zitiert wird sie in {f.id}", f.id)

    plan_refs = {r for row in d.plan for r in row.refs}
    unknown = plan_refs - set(ids)
    if unknown:
        add("plan_unbekannte_id", f"Plan verweist auf unbekannte IDs: {sorted(unknown)}")
    missing = set(ids) - plan_refs
    if missing:
        add("befund_ohne_massnahme", f"Befunde ohne Massnahme: {sorted(missing)}")

    # S6 (spec/08 Punkt 3): Python-Darstellungen gehoeren nicht in den
    # Kundentext. Sie entstanden in den Nachweiszeilen der Faktenschicht
    # ("x-feserver=None", "reachable=True", "dkim=False") und waren im PDF
    # sichtbar.
    for f in d.findings:
        treffer = PYTHON_REPR.search(f.evidence or "")
        if treffer:
            add("nachweis_python_darstellung",
                f"Python-Darstellung im Nachweis von {f.id}: {treffer.group(0)}", f.id)

    for tool in d.appendix.tools:
        if VERSION_IN_TOOL.search(tool.t):
            add("werkzeug_mit_version", f"Versionsnummer in der Werkzeugliste: {tool.t}")

    cats = {c.key for c in d.glance.categories}
    for f in d.findings:
        if f.cat not in cats:
            add("kategorie_unbekannt", f"unbekannte Kategorie {f.cat} bei {f.id}", f.id)

    if d.meta.consolidated != len(d.findings):
        add("zaehler_befunde", "meta.consolidated passt nicht zur Zahl der Befunde")
    if d.meta.positives != len(d.positives):
        add("zaehler_positive", "meta.positives passt nicht zur Zahl der Positivbefunde")

    lever_refs = {r for lev in d.glance.levers for r in lev.refs}
    unknown_levers = lever_refs - set(ids)
    if unknown_levers:
        add("hebel_unbekannte_id", f"Hebel verweist auf unbekannte IDs: {sorted(unknown_levers)}")

    if not d.scope.hosts:
        add("kapitel2_ohne_hosts", "Kapitel 2 ohne Hosts")
    if not d.appendix.tools:
        add("werkzeugliste_leer", "Werkzeugliste leer")

    return errors


def check_report_data(data: ReportData | dict) -> list[str]:
    """Liste der Defekte; leer heisst in Ordnung."""
    return [b.message for b in check_report_data_detailed(data)]
