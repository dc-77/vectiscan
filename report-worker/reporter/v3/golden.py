# -*- coding: utf-8 -*-
"""Golden-Reportdaten: gebaut, eingecheckt, per Test gegen Drift gesichert.

Gleiches Muster wie ``reporter/facts/golden.py``. Die Dateien entstehen ausschliesslich
aus den eingecheckten Fakten und dem Katalog, ohne Auftragsdaten und ohne KI. Der
Berichtsstichtag ist festgenagelt, damit zwei Laeufe dasselbe ergeben.

Neu bauen nach jeder Aenderung an Katalog, Buendeln oder Reportdaten:

    python -m reporter.v3 --golden-all            # schreibt
    python -m reporter.v3 --golden-all --check    # vergleicht nur, Exit 1 bei Drift
"""
from __future__ import annotations

from pathlib import Path

from reporter.facts.golden import GOLDEN, facts_path, golden_orders
from reporter.facts.serialize import dumps, load_json
from reporter.v3.models import ReportData
from reporter.v3.report_data import build_report_data

REPORT_DATA_DIR = GOLDEN / "report-data"

# Fester Stichtag: der Berichtstag darf das Golden-Ergebnis nicht bewegen.
REPORT_DATE = "19.09.2026"


def report_data_path(order_id: str) -> Path:
    return REPORT_DATA_DIR / f"{order_id}.json"


def order_ids() -> list[str]:
    return [e["order_id"] for e in golden_orders() if facts_path(e["order_id"]).exists()]


def build_golden_report_data(order_id: str) -> ReportData:
    return build_report_data(load_json(facts_path(order_id)), report_date=REPORT_DATE)


def build_all_golden(check: bool = False) -> list[tuple[str, bool]]:
    """(order_id, unveraendert) je Auftrag. Ohne ``check`` wird geschrieben."""
    REPORT_DATA_DIR.mkdir(parents=True, exist_ok=True)
    out: list[tuple[str, bool]] = []
    for order_id in order_ids():
        text = dumps(build_golden_report_data(order_id).to_dict()) + "\n"
        path = report_data_path(order_id)
        same = path.exists() and path.read_text(encoding="utf-8") == text
        if not check and not same:
            path.write_text(text, encoding="utf-8", newline="")
        out.append((order_id, same))
    return out
