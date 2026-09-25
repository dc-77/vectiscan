# -*- coding: utf-8 -*-
"""Ursache je halbleerer Seite (Nachtrag 3 zu S6b-1, Entscheidung DC 25.09.).

WeasyPrint fehlt unter Windows; die Seitenboxen werden hier nachgebaut, damit die
Meldung ohne Setzlauf geprueft ist. Im CI-Abbild laeuft sie am echten Dokument
(``python -m reporter.pdf.v3 --update-pages`` gibt sie je Seite aus).
"""
from __future__ import annotations

import types
import xml.etree.ElementTree as ET

from reporter.pdf.v3 import checks


class _Box:
    def __init__(self, element=None, children=(), style=None, height=0.0, tag=""):
        self.element = element
        self.children = list(children)
        self.style = style or {}
        self._height = height
        self.element_tag = tag

    def margin_height(self):
        return self._height


class LineBox(_Box):
    pass


class ReplacedBox(_Box):
    pass


class MarginBox(_Box):
    pass


B = types.SimpleNamespace(LineBox=LineBox, ReplacedBox=ReplacedBox, MarginBox=MarginBox)


def _el(tag: str, klass: str = "", text: str = ""):
    e = ET.Element(tag, {"class": klass} if klass else {})
    e.text = text
    return e


def _page(*children):
    return _Box(children=[MarginBox(), *children])


def test_befundkarte_als_ursache():
    karte = _el("div", "fd s-gelb", "VS-2026-012 Sicherheits-Header fehlen")
    sperre = _Box(element=_el("div"), style={"break_inside": "avoid"}, height=96 * 140 / 25.4,
                  children=[LineBox()])
    seite = _page(_Box(element=_el("section", "sec"), children=[
        _Box(element=karte, style={"break_inside": "auto"}, children=[sperre])]))
    satz = checks.sparse_cause(25, 118.4, seite, B)
    assert satz.startswith("Seite 25: 118 mm frei")
    assert "Befundkarte, 140 mm hoch" in satz
    assert "VS-2026-012" in satz


def test_kapitelanfang_als_ursache():
    kopf = _Box(element=_el("div", "sec-head"), children=[
        _Box(element=_el("div", "kicker", "Kapitel 4"), children=[LineBox()])])
    satz = checks.sparse_cause(11, 90.0, _page(_Box(element=_el("section", "sec"), children=[kopf])), B)
    assert "erzwungenem Seitenwechsel" in satz


def test_umbrechbarer_inhalt():
    zeile = _Box(element=_el("p"), style={"break_inside": "auto"}, children=[LineBox()])
    satz = checks.sparse_cause(7, 100.0, _page(zeile), B)
    assert "umbrechbarem Inhalt" in satz


def test_ursache_kippt_die_pruefung_nicht():
    kaputt = types.SimpleNamespace()  # ohne _page_box
    assert "Ursache nicht bestimmbar" in checks._cause_safe(3, 50.0, kaputt, B)
