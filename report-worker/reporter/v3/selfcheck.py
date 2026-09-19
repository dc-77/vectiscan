# -*- coding: utf-8 -*-
"""Selbstcheck des Datenmodells.

Portierung von ``report-prototype/build/build_report.py::check_data``. Der Renderer (S4)
und das Gate (S5) rufen diese Funktion auf, statt die Prüfungen erneut zu schreiben.
Sie prüft nur Eigenschaften des Datenmodells, nicht die Fachlichkeit eines Befunds.
"""
from __future__ import annotations

import re

from reporter.v3.models import ReportData

PLACEHOLDER = re.compile(r"\{.*?\}|\[Hinweis")
VERSION_IN_TOOL = re.compile(r"\d+\.\d+")
CVE_WITH_SCORE = re.compile(r"(CVE-\d{4}-\d+).*?Basiswert (\d+(?:\.\d+)?)")
CVE_ANY = re.compile(r"(CVE-\d{4}-\d+)")


def check_report_data(data: ReportData | dict) -> list[str]:
    """Liste der Defekte; leer heisst in Ordnung."""
    if isinstance(data, ReportData):
        d = data
    else:
        d = ReportData.model_validate(data)
    errors: list[str] = []

    ids = [f.id for f in d.findings]
    nums = [int(i.rsplit("-", 1)[-1]) for i in ids] if ids else []
    if nums != list(range(1, len(nums) + 1)):
        errors.append(f"Befund-IDs nicht lueckenlos: {ids}")
    if len(set(ids)) != len(ids):
        errors.append("doppelte Befund-IDs")

    titles = [f.title for f in d.findings]
    if len(set(titles)) != len(titles):
        dupes = sorted({t for t in titles if titles.count(t) > 1})
        errors.append(f"doppelte Titel: {dupes}")

    for f in d.findings:
        if PLACEHOLDER.search(f.title):
            errors.append(f"Platzhalter oder interner Hinweis im Titel {f.id}")
        if f.scale not in ("exposure", "hygiene") or not f.level:
            errors.append(f"Einstufung fehlt oder unbekannt bei {f.id}")
        if f.status not in ("rot", "gelb", "blau", "gruen"):
            errors.append(f"unbekannter Status {f.status!r} bei {f.id}")
        if not f.recommendation:
            errors.append(f"keine Empfehlung bei {f.id}")
        for text in (f.found, f.impact, f.verify):
            if PLACEHOLDER.search(text):
                errors.append(f"Platzhalter im Text von {f.id}")
                break

    # Fremdwerte: jede zitierte CVE braucht einen Eintrag in Anhang A.3, mit gleichem
    # Score und einem Rueckverweis auf genau diesen Befund.
    refs = {c.cve: c for c in d.appendix.cve_refs}
    for f in d.findings:
        for cited in (f.threat.cves if f.threat else []):
            match = CVE_ANY.search(cited)
            if not match or match.group(1) not in refs:
                errors.append(f"CVE ohne Referenzeintrag in {f.id}: {cited[:40]}")
                continue
            ref = refs[match.group(1)]
            score = CVE_WITH_SCORE.search(cited)
            if score and score.group(2) != ref.score:
                errors.append(f"CVE-Score weicht ab in {f.id}: {score.group(2)} statt {ref.score}")
            if ref.ref != f.id:
                errors.append(f"CVE-Referenz zeigt auf {ref.ref}, zitiert wird sie in {f.id}")

    plan_refs = {r for row in d.plan for r in row.refs}
    unknown = plan_refs - set(ids)
    if unknown:
        errors.append(f"Plan verweist auf unbekannte IDs: {sorted(unknown)}")
    missing = set(ids) - plan_refs
    if missing:
        errors.append(f"Befunde ohne Massnahme: {sorted(missing)}")

    for tool in d.appendix.tools:
        if VERSION_IN_TOOL.search(tool.t):
            errors.append(f"Versionsnummer in der Werkzeugliste: {tool.t}")

    cats = {c.key for c in d.glance.categories}
    for f in d.findings:
        if f.cat not in cats:
            errors.append(f"unbekannte Kategorie {f.cat} bei {f.id}")

    if d.meta.consolidated != len(d.findings):
        errors.append("meta.consolidated passt nicht zur Zahl der Befunde")
    if d.meta.positives != len(d.positives):
        errors.append("meta.positives passt nicht zur Zahl der Positivbefunde")

    lever_refs = {r for lev in d.glance.levers for r in lev.refs}
    unknown_levers = lever_refs - set(ids)
    if unknown_levers:
        errors.append(f"Hebel verweist auf unbekannte IDs: {sorted(unknown_levers)}")

    if not d.scope.hosts:
        errors.append("Kapitel 2 ohne Hosts")
    if not d.appendix.tools:
        errors.append("Werkzeugliste leer")

    return errors
