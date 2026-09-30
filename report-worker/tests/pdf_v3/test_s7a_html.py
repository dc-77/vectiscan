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
