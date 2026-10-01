# -*- coding: utf-8 -*-
"""S7a: Darstellung im gerenderten HTML (spec/prompts/S7a.md).

Geprueft wird das HTML aller Golden-Auftraege; die Seitenumbrueche selbst prueft
``test_pdf.py`` mit WeasyPrint gegen ``tests/golden/render/expected-pages.json``.
"""
from __future__ import annotations

import re

import pytest

from reporter.pdf.v3.context import TECH_PILLS
from tests.pdf_v3.conftest import ORDERS, html_for


def _abschnitt(html: str, von: str, bis: str) -> str:
    start = html.index(von)
    return html[start:html.index(bis, start)]


# ---------------------------------------------------------------- Punkt 2: Bildunterschriften

def test_unterschrift_nennt_weiterleitung_und_gleiche_seiten():
    from reporter.pdf.v3 import render_html
    from tests.pdf_v3.conftest import fake_screenshots
    from tests.v3.conftest import data_for

    hl = render_html(data_for("2e56abe1-c1a6-442e-b36a-dc9f83c81da8"), resolver=fake_screenshots)[0]
    kapitel = _abschnitt(hl, "3.4 Gesichtete Web-Oberflächen", "Befund-Landschaft")
    assert "<b>www.heuel.com</b><br>online.heuel.com, weitergeleitet auf www.heuel.com<br>" in kapitel
    ca = render_html(data_for("1f8bc977-39a7-47c7-b4ad-7b05dbac2d52"), resolver=fake_screenshots)[0]
    kapitel = _abschnitt(ca, "3.4 Gesichtete Web-Oberflächen", "Befund-Landschaft")
    assert "<b>mail, mail2 und owa zeigen dieselbe Anmeldeseite</b><br>Outlook (/owa/auth/logon.aspx)" in kapitel
    assert kapitel.count("vectiscan-screenshot:") == 5


# ---------------------------------------------------------------- Punkt 5: Plaketten

@pytest.mark.parametrize("order_id", ORDERS)
def test_technologietabelle_plakette_nur_veraltet_oder_lts(order_id):
    html = html_for(order_id)
    if "3.1 Erkannte Technologien" not in html:
        pytest.skip("ohne Technologietabelle")
    tabelle = _abschnitt(html, "3.1 Erkannte Technologien", "3.2 Service-Karte")
    plaketten = re.findall(r'<span class="pill p-\w+">([^<]*)</span>', tabelle)
    assert set(plaketten) <= set(TECH_PILLS), sorted(set(plaketten) - set(TECH_PILLS))
    assert "Erkennung (Quelle, Konfidenz)" in tabelle
