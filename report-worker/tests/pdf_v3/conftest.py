# -*- coding: utf-8 -*-
"""Gemeinsame Helfer fuer die Renderer-Tests.

Die HTML-Tests brauchen kein WeasyPrint und laufen deshalb ueberall, auch unter
Windows. Nur ``test_pdf.py`` setzt PDF-Erzeugung voraus.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from reporter.pdf.v3 import render_html
from reporter.v3.golden import order_ids
from tests.v3.conftest import data_for

HERE = Path(__file__).resolve().parent
REPORT_WORKER = HERE.parents[1]
REPO = REPORT_WORKER.parent
PROTOTYPE = REPO / "report-prototype"
RENDER_GOLDEN = REPORT_WORKER / "tests" / "golden" / "render"

ORDERS = order_ids()
JUNKERWERK_MULTI = "0bf16342-ed96-4b0e-a596-05aee3a62cb5"
CASTENOW = "4e6b6883-a6c8-4204-8b13-b37f907322ca"

_HTML: dict[tuple[str, str | None, bool], str] = {}


def fake_screenshots(key: str) -> bytes | None:
    """Ein Byte reicht: geprueft wird die Einbindung, nicht das Bild."""
    return b"\x89PNG\r\n\x1a\n" if key else None


def as_package(order_id: str, package: str):
    """Denselben Auftrag als anderes Paket.

    Im Golden-Satz sind alle elf Auftraege Perimeter. Die WebCheck-Variante laesst sich
    deshalb nur synthetisch pruefen; dafuer wird das ganze Datenmodell umgestellt, nicht
    nur der Renderer uebersteuert, sonst widerspraeche die Meta-Angabe dem Deckblatt.
    """
    from reporter.v3.tables import package_labels

    data = data_for(order_id)
    name, badge = package_labels(package)
    return data.model_copy(update={
        "meta": data.meta.model_copy(update={"package": name, "package_label": badge})})


def html_for(order_id: str, package: str | None = None, *,
             with_shots: bool = False) -> str:
    cache_key = (order_id, package, with_shots)
    if cache_key not in _HTML:
        resolver = fake_screenshots if with_shots else None
        data = as_package(order_id, package) if package else data_for(order_id)
        _HTML[cache_key] = render_html(data, resolver=resolver)[0]
    return _HTML[cache_key]


def weasyprint_or_skip():
    """Ueberspringen, wo WeasyPrint fehlt. In CI ist das ein Fehler, kein Skip.

    Fehlende Pango-Bibliotheken melden sich beim Import als OSError, nicht als
    ImportError. Ohne VECTISCAN_REQUIRE_WEASYPRINT koennte eine Pipeline sonst gruen
    sein, ohne je ein PDF gebaut zu haben.
    """
    try:
        import weasyprint  # noqa: F401
    except (ImportError, OSError) as exc:
        if os.environ.get("VECTISCAN_REQUIRE_WEASYPRINT") == "1":
            pytest.fail(f"WeasyPrint ist in dieser Umgebung Pflicht: {exc}")
        pytest.skip(f"WeasyPrint nicht verfuegbar: {exc}")
