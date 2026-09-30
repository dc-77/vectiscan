# -*- coding: utf-8 -*-
"""S7a: Darstellung des Perimeter-Berichts (spec/prompts/S7a.md).

Die Punkte 1 bis 9 aendern Darstellung, Reihenfolge, Umbrueche, Beschriftung und Anhaenge;
Befunde und Einstufungen bleiben gleich (tests/v3/test_befundzahlen_s7a.py).
"""
from __future__ import annotations

import pytest

from tests.v3.conftest import data_for, order_ids

CA = "cd28d260-cf49-4d17-a980-64a4b1951444"


# ---------------------------------------------------------------- Punkt 6: Anhang C

def _nebenpfad_zeilen(order_id: str):
    return [t for t in data_for(order_id).appendix.tool_findings if t.rule.startswith("zap_nebenpfad#")]


def test_anhang_c_castenow_nebenpfade_mit_pfad_und_status():
    zeilen = {t.rule: t for t in _nebenpfad_zeilen(CA)}
    server = zeilen["zap_nebenpfad#10036"]
    assert server.what.startswith("„Server Leaks Version Information")
    assert "an Nebenpfaden und Fehlerseiten" in server.what
    assert "mail.castenow.de/robots.txt (Status 302)" in server.where
    assert "mail.castenow.de/sitemap.xml (Status 302)" in server.where
    assert server.note.endswith("ohne eigenen Befund.")


@pytest.mark.parametrize("order_id", order_ids())
def test_nebenpfad_zeile_ist_eine_eigene_zeile_mit_hoechstens_sechs_orten(order_id):
    data = data_for(order_id)
    for t in _nebenpfad_zeilen(order_id):
        orte = t.where.split(" und ", 1)[0].split(", ")
        assert len(orte) <= 6
        assert sum(1 for o in data.appendix.tool_findings if o.rule == t.rule) == 1
