# -*- coding: utf-8 -*-
"""Textqualitaet der Reportdaten.

Geprueft wird der fertige Kundentext, nicht nur die Vorlage: echte Umlaute, keine
Gedankenstriche, keine Zusagen, Sie-Form, keine Platzhalterreste, Werkzeuge ohne
Versionsnummer. Damit deckt der Test auch die Stellen ab, an denen v3 Text aus den
Fakten uebernimmt.
"""
from __future__ import annotations

import re

import pytest

from reporter.v3 import narrative as N
from reporter.v3 import tables as T
from reporter.v3.golden import order_ids
from tests.textlint import DASHES, DU_FORM, FORBIDDEN_CLAIMS, find_ascii_umlauts
from tests.v3.conftest import data_for

ORDERS = order_ids()
PLATZHALTER = re.compile(r"\{[a-z_]+\}|\[Hinweis|TODO")

# Felder, die woertliche Werkzeugausgaben tragen und deshalb nicht der deutschen
# Rechtschreibung folgen muessen.
ROHTEXT_FELDER = {"evidence", "affected", "operator", "file", "src"}


def _texte(obj, pfad=""):
    if isinstance(obj, str):
        yield pfad, obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            if key in ROHTEXT_FELDER:
                continue
            yield from _texte(value, f"{pfad}.{key}")
    elif isinstance(obj, list):
        for value in obj:
            yield from _texte(value, pfad)


def _kundentexte(order_id: str):
    d = data_for(order_id).to_dict()
    # meta traegt IDs, Auftragsnummern und Versionsangaben, kein Fliesstext.
    d.pop("meta", None)
    return list(_texte(d))


@pytest.mark.parametrize("order_id", ORDERS)
def test_echte_umlaute_im_ganzen_bericht(order_id):
    treffer = [(pfad, sorted(set(find_ascii_umlauts(text))))
               for pfad, text in _kundentexte(order_id) if find_ascii_umlauts(text)]
    assert not treffer, treffer[:5]


@pytest.mark.parametrize("order_id", ORDERS)
def test_keine_gedankenstriche_und_keine_platzhalter(order_id):
    for pfad, text in _kundentexte(order_id):
        assert not any(d in text for d in DASHES), f"{pfad}: Gedankenstrich in {text[:60]!r}"
        assert not PLATZHALTER.search(text), f"{pfad}: Platzhalter in {text[:60]!r}"


@pytest.mark.parametrize("order_id", ORDERS)
def test_keine_zusagen_und_sie_form(order_id):
    for pfad, text in _kundentexte(order_id):
        assert not FORBIDDEN_CLAIMS.search(text), f"{pfad}: Zusage in {text[:60]!r}"
        assert not DU_FORM.search(text), f"{pfad}: keine Sie-Form in {text[:60]!r}"


@pytest.mark.parametrize("order_id", ORDERS)
def test_werkzeuge_ohne_versionsnummer(order_id):
    for tool in data_for(order_id).appendix.tools:
        assert not re.search(r"\d+\.\d+", tool.t), tool.t


def test_erzaehltexte_sind_sauber():
    """Die Vorlagen selbst, unabhaengig von einem Auftrag."""
    zahlen = N.Counts(domains=["example.test"], scan_date="01.01.2026", hosts_total=2,
                      fqdns_total=3, runs=1, tool_runs=10, raw_findings=5, findings=4,
                      positives=2, coverage_partial=1)
    texte = [
        N.context(zahlen), N.coverage_warning(zahlen, [["10.0.0.1"]]), N.scope_lead(zahlen),
        N.landscape_lead(zahlen), N.filtering(zahlen), N.BUSINESS_LEAD,
        N.BUSINESS_IMPLICATION_GENERIC, N.STANDARD_NOTE, N.AI_NOTE, N.ADVICE,
        N.SERVICES_NOTE, N.SCREENS_LEAD, N.architecture_lead(2, ["Website und Datenbanken"]),
        N.reputation_line(True, ["AbuseIPDB"]), N.disclaimer("01.01.2026", "Vectigal GmbH"),
        *N.CAN, *N.CANNOT, *N.OUT_OF_SCOPE_BASE, *N.repeat(zahlen, True, True),
        *[t for _, _, t in N.method_phases(zahlen)],
        N.PLAN_EFFECT_TOP,
    ]
    for text in texte:
        assert text.strip()
        assert not find_ascii_umlauts(text), (text, find_ascii_umlauts(text))
        assert not any(d in text for d in DASHES), text
        assert not FORBIDDEN_CLAIMS.search(text), text
        assert not DU_FORM.search(text), text
        assert not PLATZHALTER.search(text), text


def test_stammdaten_tabellen_sind_sauber():
    texte = [t for _, t in T.EXPOSURE_SCALE] + [t for _, t in T.HYGIENE_SCALE]
    texte += [t for _, _, t in T.triage_rows()]
    texte += [T.stage_box()]
    texte += [u for _, u, _, _ in T.TOOL_ROWS] + [t for t, _, _, _ in T.TOOL_ROWS]
    texte += list(T.TECH_NOTE_MAP.values())
    texte += [T.ROLE_FALLBACK]
    for text in texte:
        assert not find_ascii_umlauts(text), (text, find_ascii_umlauts(text))
        assert not any(d in text for d in DASHES), text
        assert not FORBIDDEN_CLAIMS.search(text), text
