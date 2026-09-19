# -*- coding: utf-8 -*-
"""Gemeinsame Helfer fuer die Tests der Reportdaten v3.

Die Golden-Fakten sind eingecheckt (S1), der Katalog wertet sie deterministisch aus
(S2). Beides ist teuer genug, um es je Auftrag einmal zu berechnen und im Modul zu
halten.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from reporter.catalog import evaluate
from reporter.catalog.schema import CatalogOutput
from reporter.facts import schema as FS
from reporter.facts.golden import facts_path, golden_orders
from reporter.facts.serialize import load_json
from reporter.v3.models import ReportData
from reporter.v3.report_data import build_report_data

HERE = Path(__file__).resolve().parent
REPORT_WORKER = HERE.parents[1]
GOLDEN = REPORT_WORKER / "tests" / "golden"
REPORT_DATA_DIR = GOLDEN / "report-data"

JUNKERWERK = {
    "multi": "0bf16342-ed96-4b0e-a596-05aee3a62cb5",
    "de": "2572eebc-6135-40e6-b1d2-e9dfccc20ae6",
    "hu": "a6df9d9d-eccd-49d1-8dd3-b00a5e005108",
}

# Fester Berichtsstichtag, damit jeder Lauf dasselbe Ergebnis liefert.
REPORT_DATE = "19.09.2026"

JUNKERWERK_ORDER: dict[str, Any] = {
    "customer": "Junkerwerk Linder GmbH & Co. KG",
    "customer_short": "Junkerwerk",
    "orders": [
        {"label": "Lauf 1 (beide Domains)", "id": JUNKERWERK["multi"]},
        {"label": "Lauf 2 (junkerwerk.de)", "id": JUNKERWERK["de"]},
        {"label": "Lauf 3 (junkerwerk.hu)", "id": JUNKERWERK["hu"]},
    ],
}
JUNKERWERK_CONTEXT: dict[str, Any] = {"kuerzel": "JW", "source": {"kuerzel": "admin"}}

_FACTS: dict[str, FS.Facts] = {}
_OUTPUT: dict[str, CatalogOutput] = {}
_DATA: dict[str, ReportData] = {}


def order_ids() -> list[str]:
    """Alle Golden-Orders, fuer die Fakten eingecheckt sind."""
    return [e["order_id"] for e in golden_orders() if facts_path(e["order_id"]).exists()]


def facts_for(order_id: str) -> FS.Facts:
    if order_id not in _FACTS:
        _FACTS[order_id] = FS.Facts.from_dict(load_json(facts_path(order_id)))
    return _FACTS[order_id]


def output_for(order_id: str) -> CatalogOutput:
    if order_id not in _OUTPUT:
        _OUTPUT[order_id] = evaluate(facts_for(order_id))
    return _OUTPUT[order_id]


def data_for(order_id: str, **kwargs: Any) -> ReportData:
    """Reportdaten ohne KI, mit festem Stichtag."""
    if kwargs:
        return build_report_data(facts_for(order_id), output_for(order_id),
                                 report_date=REPORT_DATE, **kwargs)
    if order_id not in _DATA:
        _DATA[order_id] = build_report_data(facts_for(order_id), output_for(order_id),
                                            report_date=REPORT_DATE)
    return _DATA[order_id]


def junkerwerk_data() -> ReportData:
    return data_for(JUNKERWERK["multi"], order=JUNKERWERK_ORDER,
                    customer_context=JUNKERWERK_CONTEXT)


@pytest.fixture(scope="session")
def junkerwerk() -> ReportData:
    return junkerwerk_data()
