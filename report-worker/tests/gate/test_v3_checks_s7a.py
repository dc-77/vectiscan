# -*- coding: utf-8 -*-
"""Gate-Regeln aus S7a (spec/prompts/S7a.md): Punkt 8 (E27) als Warnung.

``werkzeugfehler_im_kundentext`` (Punkt 0) steht in ``tests/test_tool_errors_s7a.py``.
"""
from __future__ import annotations

import inspect
from datetime import date

import pytest

from reporter.gate import fristen as FR
from reporter.gate import v3_checks as VC
from reporter.gate.defects import payload
from tests.v3.conftest import data_for, facts_for, order_ids, output_for

HL = "2e56abe1-c1a6-442e-b36a-dc9f83c81da8"


def _hl_am(report_date: str):
    """Reportdaten heuel mit festgesetztem Berichtsdatum; Stufe und Befunde bleiben am Scantag."""
    from reporter.catalog import evaluate
    from reporter.v3.report_data import build_report_data

    facts = facts_for(HL)
    iso = "-".join(reversed(report_date.split(".")))
    return build_report_data(facts, evaluate(facts, report_date=iso), report_date=report_date)


@pytest.mark.parametrize("tage,art,regel", [
    (31, "tls", None), (30, "tls", "cert_expiring_later"), (15, "tls", "cert_expiring_later"),
    (14, "tls", "cert_expiring"), (8, "tls", "cert_expiring"), (7, "tls", "cert_expiring_sofort"),
    (0, "tls", "cert_expiring_sofort"), (-1, "tls", "cert_expired"),
    (3, "service_cert", None), (-1, "service_cert", "service_cert_expired"),
    (30, "domain", "domain_expiring"), (31, "domain", None),
])
def test_einordnung_nach_den_katalogschwellen(tage, art, regel):
    assert FR.klasse(art, tage) == regel


def test_heuel_online_warnung_am_berichtsdatum():
    """spec/11 Teil 6 E27: online.heuel.com am Scantag 31 Tage, Schwelle 30."""
    data = _hl_am("27.09.2026")
    defekte = VC.fristregel_am_berichtsdatum(data, facts_for(HL))
    assert [d.detail["subjekt"] for d in defekte] == ["online.heuel.com:443"]
    d = defekte[0]
    assert not d.is_error
    assert d.detail["tage_scantag"] == 31 and d.detail["regel_scantag"] is None
    assert d.detail["regel_stichtag"] == "cert_expiring_later"
    assert "Stufe und Regelauslösung bleiben am Scantag (E27)" in d.message
    # Die Stufe bleibt am Scantag: kein Befund zu online.heuel.com durch die Frist.
    assert not any("online.heuel.com" in f.affected and "cert_expiring_later" in f.checks for f in data.findings)


def test_am_scantag_keine_warnung():
    assert VC.fristregel_am_berichtsdatum(_hl_am("23.09.2026"), facts_for(HL)) == []


@pytest.mark.parametrize("order_id", order_ids())
def test_golden_stichtag_warnt_nur_nach_dem_scan(order_id):
    # Der Golden-Stichtag 19.09. liegt vor den Scans ab dem 20.09. (Scan-Runde, S6c-Proben); dort
    # verschiebt sich nichts. Bei den Auftraegen aus Mai und Juli liegt er Monate danach, dort ist
    # der Hinweis richtig (Zertifikate, die seitdem abgelaufen waeren).
    scan = FR._scan_tag(facts_for(order_id))
    defekte = VC.fristregel_am_berichtsdatum(data_for(order_id), facts_for(order_id))
    if scan >= date(2026, 9, 19):
        assert defekte == []
    assert all(not d.is_error for d in defekte)


def test_nutzlast_traegt_fristen_fuer_den_freigabetag():
    daten = payload([], engine="v3", level="strict", facts=facts_for(HL), output=output_for(HL))
    assert daten["fristen_scantag"] == "2026-09-23"
    assert daten["fristen_schwellen"] == {"sofort": 7, "bald": 14, "spaeter": 30, "domain": 30}
    online = next(f for f in daten["fristen"] if f["subjekt"] == "online.heuel.com:443")
    assert online == {"art": "tls", "subjekt": "online.heuel.com:443", "gueltig_bis": "2026-10-25",
                      "tage_scantag": 31}
    assert all(0 <= f["tage_scantag"] <= FR.VORLAUF_TAGE for f in daten["fristen"])


def test_abweichung_nur_nach_dem_scantag():
    assert FR.abweichungen(facts_for(HL), date(2026, 9, 20)) == []
    assert FR.abweichungen(facts_for(HL), date(2026, 10, 30))


def test_run_all_enthaelt_die_regel():
    assert "fristregel_am_berichtsdatum(data, facts)" in inspect.getsource(VC.run_all)
