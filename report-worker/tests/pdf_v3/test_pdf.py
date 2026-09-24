# -*- coding: utf-8 -*-
"""Das fertige PDF. Braucht WeasyPrint samt Pango, laeuft also nicht unter Windows.

Damit eine Pipeline nicht gruen werden kann, ohne je ein PDF gebaut zu haben, setzt der
Abbild-Job ``VECTISCAN_REQUIRE_WEASYPRINT=1``; dann wird aus dem Ueberspringen ein
Fehlschlag (siehe conftest.weasyprint_or_skip).
"""
from __future__ import annotations

import json
import os

import pytest

from reporter.pdf.v3.checks import REQUIRED_FONTS, sparse_from_fill
from tests.pdf_v3.conftest import (CASTENOW, JUNKERWERK_MULTI, RENDER_GOLDEN,
                                   fake_screenshots, weasyprint_or_skip)

pytestmark = pytest.mark.weasyprint

PAGES_FILE = RENDER_GOLDEN / "expected-pages.json"


@pytest.fixture(scope="module")
def weasy():
    weasyprint_or_skip()


def _render(tmp_path, order_id: str, **kwargs):
    from reporter.pdf.v3 import render_report_v3
    from reporter.v3.golden import build_golden_report_data
    out = tmp_path / f"{order_id}.pdf"
    return render_report_v3(build_golden_report_data(order_id), out, **kwargs)


def test_pdf_entsteht_und_ist_vollstaendig(weasy, tmp_path):
    result = _render(tmp_path, JUNKERWERK_MULTI)
    roh = result.pdf_path.read_bytes()
    assert roh.startswith(b"%PDF-")
    assert roh.rstrip().endswith(b"%%EOF")
    assert result.pages > 10


def test_keine_defekte(weasy, tmp_path):
    assert _render(tmp_path, JUNKERWERK_MULTI).defects == []


def test_referenzauftrag_ohne_halbleere_seite(weasy, tmp_path):
    """Vorgabe aus S4, uebertragen auf die Golden-Daten.

    Der Junkerwerk-Lauf ist der Auftrag, gegen den der Prototyp entworfen wurde. Bei
    den uebrigen Auftraegen haengt die Seitenfuellung an der Datenmenge; dort wird der
    Ist-Stand festgeschrieben (test_halbleere_seiten_nur_die_bekannten).
    """
    result = _render(tmp_path, JUNKERWERK_MULTI)
    assert result.sparse_pages == (), f"halbleere Seiten {result.sparse_pages}"
    assert sparse_from_fill(result.fill) == result.sparse_pages


def test_schriften_sind_eingebettet(weasy, tmp_path):
    """Ohne Inter faellt WeasyPrint still auf eine Ersatzschrift zurueck (Falle R14)."""
    from reporter.pdf.v3.checks import embedded_fonts

    result = _render(tmp_path, JUNKERWERK_MULTI)
    fehlend = [w for w in result.warnings if "Schrift nicht eingebettet" in w]
    assert not fehlend, fehlend
    namen = embedded_fonts(result.pdf_path)
    assert any(n.startswith("Inter") for n in namen), namen
    assert any("DejaVu-Sans-Mono" in n for n in namen), namen


@pytest.mark.parametrize("font", REQUIRED_FONTS)
def test_verlangte_schriften_stehen_in_der_vorlage(font):
    from reporter.pdf.v3.render import TEMPLATE, env
    assert font in env().loader.get_source(env(), TEMPLATE)[0]


def test_seitenzahl_entspricht_dem_erwartungswert(weasy, tmp_path):
    from reporter.pdf.v3.__main__ import pruefe

    erwartet = json.loads(PAGES_FILE.read_text(encoding="utf-8"))
    assert erwartet, "python -m reporter.pdf.v3 --update-pages"
    fehler: list[str] = []
    for order_id, soll in erwartet.items():
        fehler += pruefe(order_id, _render(tmp_path, order_id), soll)
    assert not fehler, fehler


def test_halbleere_seiten_nur_die_bekannten(weasy, tmp_path):
    """Eine neue halbleere Seite ist ein Fehler, eine bekannte ist festgeschrieben."""
    erwartet = json.loads(PAGES_FILE.read_text(encoding="utf-8"))
    for order_id, soll in erwartet.items():
        ist = set(_render(tmp_path, order_id).sparse_pages)
        assert ist <= set(soll["sparse"]), (order_id[:8], sorted(ist - set(soll["sparse"])))


def test_bilder_werden_ueber_das_eigene_schema_geholt(weasy, tmp_path):
    """Der url_fetcher muss das Schema abfangen und alles andere durchreichen."""
    from reporter.pdf.v3.render import ASSETS, _url_fetcher

    gesehen: list[str] = []

    def resolver(key: str) -> bytes | None:
        gesehen.append(key)
        return fake_screenshots(key) if key != "gibtesnicht" else None

    fetch = _url_fetcher(resolver)
    treffer = fetch("vectiscan-screenshot:order/1.png")
    assert treffer.content_type == "image/png"
    assert gesehen == ["order/1.png"]

    fehlt = fetch("vectiscan-screenshot:gibtesnicht")
    assert fehlt.content_type == "image/svg+xml"
    assert b"nicht verf" in fehlt.read()

    schrift = fetch((ASSETS / "fonts" / "Inter-Regular.ttf").as_uri())
    assert schrift.read(4) == b"\x00\x01\x00\x00", "TrueType-Kennung"
    schrift.close()


def test_fetcher_laesst_kein_netz_zu(weasy):
    """Ein Bericht darf beim Setzen nichts nachladen."""
    from reporter.pdf.v3.render import _url_fetcher
    from reporter.pdf.v3.screenshots import no_screenshots

    fetch = _url_fetcher(no_screenshots)
    with pytest.raises(ValueError):
        fetch("https://example.invalid/bild.png")


def test_bericht_mit_bildern_hat_das_raster(weasy, tmp_path):
    result = _render(tmp_path, JUNKERWERK_MULTI, resolver=fake_screenshots)
    assert "3.4 Gesichtete Web-Oberflächen" in result.html
    assert result.sparse_pages == ()


def test_umlaute_stehen_im_pdf_text(weasy, tmp_path):
    from pypdf import PdfReader
    result = _render(tmp_path, JUNKERWERK_MULTI)
    text = "\n".join((p.extract_text() or "") for p in PdfReader(str(result.pdf_path)).pages)
    assert "ü" in text and "ä" in text
    assert "Pruefzeitraum" not in text and "fuer" not in text


def test_strict_meldet_defekte(weasy, tmp_path, monkeypatch):
    from reporter.pdf.v3 import render_report_v3
    from reporter.pdf.v3.render import RenderGateError
    from reporter.v3.golden import build_golden_report_data

    data = build_golden_report_data(JUNKERWERK_MULTI)
    kaputt = data.model_copy(update={
        "meta": data.meta.model_copy(update={"consolidated": 999})})
    with pytest.raises(RenderGateError):
        render_report_v3(kaputt, tmp_path / "x.pdf", strict=True)


def test_selftest_laeuft_durch(weasy):
    from reporter.pdf.v3.__main__ import main
    assert main(["--selftest"]) == 0
