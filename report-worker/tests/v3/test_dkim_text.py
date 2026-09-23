# -*- coding: utf-8 -*-
"""DKIM im Kundentext (S6a, #15 Teil 2).

Ohne Selektor aus einer echten E-Mail steht DKIM als Einschraenkung da, nie als Befund
"fehlt". Mit bekannter Liste nennt der Text Anzahl und sechs Beispiele, der Anhang die
volle Liste; ohne belegte Liste steht der allgemeine Text und kein Anhangsblock.
"""
from __future__ import annotations

from reporter.catalog import evaluate
from reporter.catalog import tables as CT
from reporter.v3 import chapters as C
from reporter.v3.report_data import build_report_data
from tests.catalog.conftest import make_facts
from tests.v3.conftest import data_for

DORTMUND = "14272c00-1145-4675-9b4c-19ce2ead403b"


def _daten(dkim: dict):
    facts = make_facts({"dns": [{"domain": "example.test", "mx": ["mx1.example.test"],
                                 "spf": {"raw": "v=spf1 mx -all", "all_qualifier": "-all"},
                                 "dkim": dkim}]}, coverage_default="ok")
    return build_report_data(facts, evaluate(facts), report_date="23.09.2026")


def _dkim_zeilen(data):
    return [z for z in data.scope.limitations if z.what.startswith("DKIM")]


def test_dortmund_beach_nennt_anzahl_und_sechs_beispiele():
    data = data_for(DORTMUND)
    (zeile,) = _dkim_zeilen(data)
    assert "unter 62 abgefragten gängigen Selektoren" in zeile.what
    assert "darunter default, selector1, selector2, google, k1, s1," in zeile.what
    assert "fehlt" not in zeile.what
    assert zeile.detail == "Betroffen: dortmund-beach.com."
    assert len(data.appendix.dkim_selectors) == 62
    assert not any("DKIM" in f.title for f in data.findings)


def test_ohne_belegte_liste_allgemeiner_text_und_kein_anhang():
    data = _daten({"present": False, "selectors": []})
    (zeile,) = _dkim_zeilen(data)
    assert zeile.what == CT.COVERAGE_REASONS["dkim_selector_unknown"][1].rstrip(".")
    assert "gängigen Selektoren" in zeile.what and "62" not in zeile.what
    assert data.appendix.dkim_selectors == []


def test_liste_aus_dem_scan_erscheint_im_anhang():
    data = _daten({"present": False, "selectors": [], "probed": ["zoho", "default", "mail"],
                   "probed_basis": "scan"})
    (zeile,) = _dkim_zeilen(data)
    assert "unter 3 abgefragten gängigen Selektoren, darunter default, mail, zoho," in zeile.what
    assert data.appendix.dkim_selectors == ["default", "mail", "zoho"]


def test_gefundener_selektor_ohne_einschraenkung_und_ohne_anhang():
    data = _daten({"present": True, "selectors": ["s1"], "probed": ["default", "s1"],
                   "probed_basis": "scan"})
    assert not _dkim_zeilen(data)
    assert data.appendix.dkim_selectors == []


def test_beispiele_folgen_der_vorzugsreihenfolge():
    assert C.dkim_beispiele(["zoho", "k1", "a1", "default", "b2", "c3", "s1", "x"]) == \
        ["default", "k1", "s1", "a1", "b2", "c3"]
