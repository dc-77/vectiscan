# -*- coding: utf-8 -*-
"""Das gerenderte HTML aller Golden-Auftraege.

Geprueft wird der Bericht, nicht die Vorlage: dass jeder Befund genau dort steht, wo er
hingehoert, dass nichts still weggelassen wird und dass die Paketvariante greift.
"""
from __future__ import annotations

import re

import pytest

from reporter.pdf.v3 import render_html
from reporter.pdf.v3.checks import dash_check, text_of
from reporter.pdf.v3.context import TOP_N_HAUPTTEIL, split_findings
from tests.pdf_v3.conftest import (
    CASTENOW, JUNKERWERK_MULTI, ORDERS, WEBCHECK, html_for,
)
from tests.v3.conftest import data_for

JINJA_REST = re.compile(r"\{\{|\{%|\{#")


def _ids(order_id: str) -> list[str]:
    return [f.id for f in data_for(order_id).findings]


def _abschnitt(html: str, von: str, bis: str | None) -> str:
    start = html.index(von)
    ende = html.index(bis, start) if bis else len(html)
    return html[start:ende]


@pytest.mark.parametrize("order_id", ORDERS)
def test_html_ist_vollstaendig_gerendert(order_id):
    html = html_for(order_id)
    assert html.startswith("<!doctype html>")
    assert html.rstrip().endswith("</html>")
    assert not JINJA_REST.search(html), JINJA_REST.search(html).group(0)


@pytest.mark.parametrize("order_id", ORDERS)
def test_keine_gedankenstriche_ausserhalb_der_nachweise(order_id):
    assert dash_check(html_for(order_id)) == []


@pytest.mark.parametrize("order_id", ORDERS)
def test_jeder_befund_genau_einmal_in_kapitel_4_und_anhang_a2(order_id):
    html = html_for(order_id)
    kap4 = _abschnitt(html, "Befund-Landschaft", "MASSNAHMENPLAN")
    a2 = _abschnitt(html, "A.2 Eigene Einstufung", "A.3 CVE-Referenzen")
    for fid in _ids(order_id):
        assert kap4.count(fid) == 1, f"{fid} in Kapitel 4"
        assert a2.count(fid) == 1, f"{fid} in Anhang A.2"


@pytest.mark.parametrize("order_id", ORDERS)
def test_jeder_befund_genau_einmal_im_detailteil(order_id):
    """Hauptteil oder Anhang zu Kapitel 6, nie beides und nie keines."""
    html = html_for(order_id)
    detail = _abschnitt(html, "Befunde im Detail", "ANHÄNGE")
    findings = [f.model_dump(mode="json") for f in data_for(order_id).findings]
    main, more = split_findings(findings)
    for f in main + more:
        # Die ID steht im Kopf des Blocks; Planbezuege und A.2 liegen ausserhalb.
        assert detail.count(f'<span class="id">{f["id"]}</span>') == 1, f["id"]


@pytest.mark.parametrize("order_id", ORDERS)
def test_planbezuege_zeigen_auf_bekannte_befunde(order_id):
    data = data_for(order_id)
    ids = {f.id for f in data.findings}
    for row in data.plan:
        assert set(row.refs) <= ids
        for ref in row.refs:
            assert ref in html_for(order_id)


def test_castenow_teilt_auf_und_laesst_nichts_weg():
    html = html_for(CASTENOW)
    assert "Weitere Sachverhalte" in html
    # S6b-1: 31 statt 29, weil Sachverhalte beim Hoster oder Plattformbetreiber eigene
    # Befunde sind (spec/09 Q3).
    assert "Dieses Kapitel zeigt die 15 dringendsten der 31 Befunde" in text_of(html)
    haupt = _abschnitt(html, "Befunde im Detail", "Weitere Sachverhalte")
    anhang = _abschnitt(html, "Weitere Sachverhalte", "ANHÄNGE")
    assert haupt.count('<span class="id">') == TOP_N_HAUPTTEIL
    assert anhang.count('<span class="id">') == 31 - TOP_N_HAUPTTEIL


def test_junkerwerk_braucht_keinen_anhang_zu_kapitel_6():
    html = html_for(JUNKERWERK_MULTI)
    assert "Weitere Sachverhalte" not in html
    assert "Dieses Kapitel zeigt die" not in text_of(html)


def test_anhaenge_ohne_luecke_in_beiden_paketen():
    for package, erwartet in (("perimeter", list("ABCDEF")), ("webcheck", list("ABCDE"))):
        html = html_for(JUNKERWERK_MULTI, package, with_shots=True)
        gefunden = re.findall(r'<div class="kicker">Anhang ([A-H])</div>|'
                              r"<h3>Anhang ([A-H]) · ", html)
        letters = [a or b for a, b in gefunden]
        assert letters == erwartet, (package, letters)


def test_webcheck_ohne_bildraster_und_ohne_inventar():
    html = html_for(JUNKERWERK_MULTI, "webcheck", with_shots=True)
    assert "3.4 Gesichtete Web-Oberflächen" not in html
    assert "Service-Inventar" not in html
    assert "WebCheck-Bericht" in html
    assert "WebCheck-Sicherheitsbewertung" in html
    # "Perimeter-Exposition" ist ein Kategoriename aus dem Pruefkatalog und bleibt.
    # Die Paketbezeichnung darf nirgends mehr auftauchen.
    assert "Perimeter-Bericht" not in html
    assert "Perimeter-Sicherheitsbewertung" not in html
    assert "Paket  WebCheck" in re.sub(r"<[^>]+>", " ", html)


def test_echter_webcheck_auftrag_laesst_dieselben_teile_weg():
    """Dasselbe an echten WebCheck-Daten statt am umetikettierten Auftrag (Issue #23).

    Der Auftrag bringt fuenf Bildnachweise mit; sie duerfen trotzdem nicht als
    Kapitel 3.4 erscheinen, sonst haengt die Variante am Datenbestand statt am
    Paket. Das Service-Inventar entfaellt ebenso, obwohl Dienste erkannt wurden.
    """
    data = data_for(WEBCHECK)
    assert data.meta.package == "WebCheck"
    assert data.architecture.screens, "Fixture ohne Bildnachweise, Gegenprobe wertlos"
    html = html_for(WEBCHECK, with_shots=True)
    assert "3.4 Gesichtete Web-Oberflächen" not in html
    assert "Service-Inventar" not in html
    assert "vectiscan-screenshot:" not in html
    assert "WebCheck-Bericht" in html
    assert "Perimeter-Bericht" not in html
    gefunden = re.findall(r'<div class="kicker">Anhang ([A-H])</div>|'
                          r"<h3>Anhang ([A-H]) · ", html)
    assert [a or b for a, b in gefunden] == list("ABCDE")


def test_echter_webcheck_auftrag_hat_keine_leeren_pflichtkapitel():
    """Die offene Frage aus Issue #23: reisst der kleinere Satz Luecken?"""
    data = data_for(WEBCHECK)
    text = text_of(html_for(WEBCHECK))
    assert data.scope.hosts, "Kapitel 2 ohne Hosts"
    assert all((h.coverage or "").strip() for h in data.scope.hosts)
    assert data.architecture.tech, "Kapitel 3.3 ohne Technologiezeilen"
    assert data.appendix.tools, "Anhang 'Eingesetzte Werkzeuge' leer"
    assert data.findings and data.positives
    assert "Platzhalter" not in text


def test_perimeter_zeigt_bildraster_und_inventar():
    html = html_for(JUNKERWERK_MULTI, "perimeter", with_shots=True)
    assert "3.4 Gesichtete Web-Oberflächen" in html
    assert "Service-Inventar" in html
    assert "vectiscan-screenshot:" in html


@pytest.mark.parametrize("order_id", ORDERS)
def test_werkzeugmeldungen_erscheinen_wenn_es_welche_gibt(order_id):
    data = data_for(order_id)
    html = html_for(order_id)
    if data.appendix.tool_findings:
        assert "Werkzeugmeldungen ohne eigene Einstufung" in html
        for eintrag in data.appendix.tool_findings[:3]:
            assert eintrag.what in html
    else:
        assert "Werkzeugmeldungen ohne eigene Einstufung" not in html


def test_fremdtext_mit_sonderzeichen_wird_maskiert():
    """Kundentext aus den Fakten enthaelt kaufmaennische Und und Pipes."""
    html = render_html(data_for(CASTENOW))[0]
    assert "&amp;" in html
    assert "<b>Markenführung" not in html
