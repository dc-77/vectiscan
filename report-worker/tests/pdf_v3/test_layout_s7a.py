# -*- coding: utf-8 -*-
"""S7a Punkt 1: die neuen Umbruchpruefungen an kleinen, gezielt gebauten Seiten.

In den Golden-Auftraegen kommen die Faelle nach S7a nicht mehr vor; hier wird gezeigt, dass die
Pruefung sie erkennt, wenn die Regel in der Vorlage fehlt, und dass die Regel sie verhindert.
"""
from __future__ import annotations

import pytest

from reporter.pdf.v3.checks import layout_scan
from tests.pdf_v3.conftest import weasyprint_or_skip

pytestmark = pytest.mark.weasyprint

SEITE = "@page{size:100mm 120mm;margin:10mm;} body{font-size:10pt;line-height:1.4;margin:0;}"


@pytest.fixture(scope="module")
def weasy():
    weasyprint_or_skip()


def _layout(body: str, css: str = ""):
    from weasyprint import HTML
    html = f"<!doctype html><html><head><style>{SEITE}{css}</style></head><body>{body}</body></html>"
    return layout_scan(HTML(string=html).render())


def _abstand(mm: int) -> str:
    return f'<div style="height:{mm}mm"></div>'


EINLEITUNG = ('<h3>Maßnahmenplan</h3><p class="intro">Priorisiert nach Dringlichkeit.</p>'
              '<table><thead><tr><th>Priorität</th></tr></thead>'
              '<tr><td style="height:40mm">Zeile</td></tr></table>')


def test_ueberschrift_mit_einleitung_am_seitenende_wird_erkannt(weasy):
    layout = _layout(_abstand(70) + EINLEITUNG)
    assert layout.intro_pages == (1,)


def test_intro_bleibt_bei_der_tabelle(weasy):
    layout = _layout(_abstand(70) + EINLEITUNG, css=".intro{break-after:avoid;} h3{break-after:avoid;}")
    assert layout.intro_pages == ()


KARTE = ('<div class="fd"><div class="kopf"><div class="hd">VS-2026-003 Zertifikat</div>'
         '<div class="meta">GELB</div></div>'
         '<div class="bd"><div class="lab">Was wurde gefunden</div>'
         '<p style="height:30mm">Text</p></div></div>')


def test_befundkopf_allein_am_seitenfuss_wird_erkannt(weasy):
    layout = _layout(_abstand(80) + KARTE, css=".kopf{break-inside:avoid;} .lab{break-after:avoid;}"
                                                "p{break-inside:avoid;}")
    assert layout.card_head_pages == (1,)


def test_befundkopf_bleibt_beim_befundtext(weasy):
    layout = _layout(_abstand(80) + KARTE, css=".kopf{break-inside:avoid;break-after:avoid;} "
                                                ".lab{break-after:avoid;} p{break-inside:avoid;}")
    assert layout.card_head_pages == ()


HEBEL = ('<div class="hebel"><h3>Die drei wichtigsten Hebel</h3>'
         + "".join(f'<div class="lever" style="height:18mm">HEBEL {n}</div>' for n in (1, 2, 3))
         + "</div>")


def test_hebel_getrennt_von_der_ueberschrift_wird_erkannt(weasy):
    layout = _layout(_abstand(45) + HEBEL, css=".lever{break-inside:avoid;}")
    assert layout.lever_pages == (2,)


def test_hebelblock_bleibt_zusammen(weasy):
    layout = _layout(_abstand(45) + HEBEL, css=".lever{break-inside:avoid;} .hebel{break-inside:avoid;}")
    assert layout.lever_pages == ()


def test_vorlage_traegt_die_regeln():
    from reporter.pdf.v3.render import TEMPLATE, env
    quelle = env().loader.get_source(env(), TEMPLATE)[0]
    for regel in (".intro{break-after:avoid;}", ".hebel{break-inside:avoid;}",
                  ".fd .kopf{break-inside:avoid;break-after:avoid;}", ".ev.lang{break-inside:auto;"):
        assert regel in quelle, regel
