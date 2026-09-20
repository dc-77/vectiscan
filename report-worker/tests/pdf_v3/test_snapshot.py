# -*- coding: utf-8 -*-
"""Regressionsschnappschuss: das HTML eines Golden-Auftrags, Byte fuer Byte.

Ein Auftrag reicht und liegt gzip-gepackt bei rund 23 KB; git-extern weist groessere
Pushes und Artefakte mit HTTP 413 ab. Der Schnappschuss faengt jede Aenderung am
Markup, auch die unbeabsichtigte, und laesst sich im Fehlerfall lesen.

Neu schreiben nach einer gewollten Aenderung:

    python -m reporter.pdf.v3 --write-snapshot
"""
from __future__ import annotations

import difflib
import gzip

import pytest

from reporter.pdf.v3 import render_html
from reporter.v3.golden import build_golden_report_data
from tests.pdf_v3.conftest import RENDER_GOLDEN, JUNKERWERK_MULTI

SNAPSHOT = RENDER_GOLDEN / f"{JUNKERWERK_MULTI}.html.gz"


def test_schnappschuss_liegt_vor():
    assert SNAPSHOT.exists(), "python -m reporter.pdf.v3 --write-snapshot"
    assert SNAPSHOT.stat().st_size < 200_000, "zu gross fuer git-extern"


def test_html_entspricht_dem_schnappschuss():
    if not SNAPSHOT.exists():
        pytest.skip("kein Schnappschuss")
    soll = gzip.decompress(SNAPSHOT.read_bytes()).decode("utf-8")
    ist = render_html(build_golden_report_data(JUNKERWERK_MULTI))[0]
    if ist != soll:
        diff = list(difflib.unified_diff(soll.splitlines(), ist.splitlines(),
                                         "schnappschuss", "gerendert", lineterm="", n=1))
        pytest.fail("Markup weicht ab; gewollt? dann --write-snapshot\n"
                    + "\n".join(diff[:40]))


def test_render_ist_wiederholbar():
    """Zweimal dasselbe Ergebnis, sonst taugt der Schnappschuss nicht als Gate."""
    daten = build_golden_report_data(JUNKERWERK_MULTI)
    assert render_html(daten)[0] == render_html(daten)[0]


def test_render_haengt_nicht_am_betriebssystem():
    """Kein CR im Ergebnis, egal wie die Vorlage ausgecheckt ist.

    Die Vorlage liegt unter Windows mit CRLF und unter Linux mit LF auf der Platte.
    Jinja normalisiert die Zeilenenden beim Lesen (``newline_sequence`` ist ``\\n``),
    deshalb ist der byteweise Vergleich plattformunabhaengig. Dieselbe Falle hat in S1
    den EOL-Feed-Hash rot werden lassen; hier ist sie damit angenagelt.
    """
    html = render_html(build_golden_report_data(JUNKERWERK_MULTI))[0]
    assert "\r" not in html
