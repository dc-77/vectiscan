# -*- coding: utf-8 -*-
"""S6b-1 Nachtrag 3, Punkt 4 (Entscheidung DC 25.09.): halbleere Seiten.

Befund aus ``--update-pages`` (MR-Pipeline 3203):
- f77ccff2 Seite 11: 129 mm frei, die Folgeseite begann mit dem Kategorieblock D
  (16 Befunde, 140 mm hoch, nicht umbrechbar). Behoben: ein langer Kategorieblock darf
  nach seiner Kopfzeile umbrechen.
- 1f8bc977 Seite 25 und 2d2d4f39 Seite 27: je 165 mm frei vor einem Kapitelanfang mit
  erzwungenem Seitenwechsel. Kein einzelner Block; Merkposten fuer S7, nicht gebaut.

Nach dem Umbau (Pipeline 3204): 1f8bc977 ohne halbleere Seite (34 statt 35 Seiten);
bei f77ccff2 ist durch den Umfluss Seite 27 vor einem Kapitelanfang halbleer (192 mm
frei), ebenfalls Merkposten S7.
"""
from __future__ import annotations

import re

import pytest

from reporter.pdf.v3.context import CAT_KEEP
from tests.pdf_v3.conftest import html_for, weasyprint_or_skip
from tests.v3.conftest import data_for

F77 = "f77ccff2-fc7a-4488-a9ba-540a42a25056"
CAT = re.compile(r'<div class="(cat(?: lang)?)"><div class="h"><span class="k">(KATEGORIE [A-E]|POSITIV)</span>')


def test_langer_kategorieblock_darf_umbrechen():
    data = data_for(F77)
    je_kategorie = {c.key: sum(1 for f in data.findings if f.cat == c.key) for c in data.glance.categories}
    assert je_kategorie["D"] > CAT_KEEP
    klassen = {name: klasse for klasse, name in CAT.findall(html_for(F77))}
    for key, n in je_kategorie.items():
        assert klassen[f"KATEGORIE {key}"] == ("cat lang" if n > CAT_KEEP else "cat"), key
    assert klassen["POSITIV"] == ("cat lang" if len(data.positives) > CAT_KEEP else "cat")


def test_kopfzeile_bleibt_bei_der_ersten_zeile():
    from reporter.pdf.v3.render import TEMPLATE, env
    quelle = env().loader.get_source(env(), TEMPLATE)[0]
    assert ".cat.lang{break-inside:auto;}" in quelle
    kopf = next(z for z in quelle.splitlines() if z.startswith(".cat .h{"))
    assert "break-after:avoid" in kopf and "break-inside:avoid" in kopf


@pytest.mark.weasyprint
def test_f77ccff2_seite_11_nicht_mehr_halbleer(tmp_path):
    weasyprint_or_skip()
    from reporter.pdf.v3 import render_report_v3
    from reporter.v3.golden import build_golden_report_data

    result = render_report_v3(build_golden_report_data(F77), tmp_path / "f77.pdf")
    assert result.layout_ok
    assert not [c for c in result.sparse_causes if "Kategorieblock" in c], result.sparse_causes
