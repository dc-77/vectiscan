# -*- coding: utf-8 -*-
"""Alle Golden-Auftraege: Datenmodell baubar, Selbstcheck leer, keine Drift."""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from reporter.facts.serialize import dumps, load_json
from reporter.v3.golden import REPORT_DATE, build_golden_report_data, order_ids, report_data_path
from reporter.v3.models import ReportData
from reporter.v3.selfcheck import check_report_data
from tests.v3.conftest import REPORT_WORKER, data_for

ORDERS = order_ids()


def test_es_gibt_golden_auftraege():
    assert len(ORDERS) >= 10


@pytest.mark.parametrize("order_id", ORDERS)
def test_datenmodell_baubar_und_selbstcheck_leer(order_id):
    data = data_for(order_id)
    assert isinstance(data, ReportData)
    assert check_report_data(data) == []


@pytest.mark.parametrize("order_id", ORDERS)
def test_keine_drift_gegen_die_eingecheckten_reportdaten(order_id):
    path = report_data_path(order_id)
    assert path.exists(), f"{path.name} fehlt; python -m reporter.v3 --golden-all"
    erwartet = load_json(path)
    gebaut = json.loads(dumps(build_golden_report_data(order_id).to_dict()))
    assert gebaut == erwartet, (
        f"{order_id}: Reportdaten weichen ab; nach gewollter Aenderung "
        "python -m reporter.v3 --golden-all")


@pytest.mark.parametrize("order_id", ORDERS)
def test_jeder_befund_steht_genau_einmal_im_plan(order_id):
    """S6b-3 (spec/10 R11, E8): jede getroffene Regel eines Befunds genau einmal im Plan.

    Ein Befund aus mehreren Regeln steht mit jeder Regel in einer Zeile; eine Regel steht
    nie in zwei Zeilen."""
    data = data_for(order_id)
    refs = {r for row in data.plan for r in row.refs}
    assert refs == {f.id for f in data.findings}
    quellen = [q for row in data.plan for q in row.sources]
    assert len(quellen) == len(set(quellen)), "eine Regel eines Befunds steht zweimal im Plan"
    erwartet = {f"{f.id}:{p.check}" for f in data.findings for p in f.plan_items}
    assert set(quellen) == erwartet


@pytest.mark.parametrize("order_id", ORDERS)
def test_keine_massnahme_steht_zweimal_im_plan(order_id):
    """S6a: gleicher Massnahmentext, eine Zeile (Huendgen Seite 11)."""
    texte = [" ".join(row.action.split()) for row in data_for(order_id).plan]
    doppelt = sorted({t[:60] for t in texte if texte.count(t) > 1})
    assert not doppelt, doppelt


@pytest.mark.parametrize("order_id", ORDERS)
def test_pflichtteile_des_berichts_sind_gefuellt(order_id):
    data = data_for(order_id)
    assert data.meta.domains and data.meta.scan_date
    assert len(data.glance.categories) == 5
    assert data.glance.context and data.scope.lead and data.architecture.lead
    assert data.scope.hosts and data.scope.method_phases and data.scope.numbers
    assert data.appendix.tools and data.appendix.disclaimer
    assert data.appendix.exposure_scale and data.appendix.hygiene_scale and data.appendix.triage


@pytest.mark.parametrize("order_id", ORDERS)
def test_ohne_fremdwert_kein_cve_zitat(order_id):
    """Anhang A.3 fuehrt nur Fremdwerte; ein Befund zitiert nur, was dort steht."""
    data = data_for(order_id)
    # Eine Zeile in A.3 kann seit S6 mehrere Kennungen desselben testssl-Tests
    # tragen (spec/08 Punkt 18).
    bekannt = {teil.strip() for c in data.appendix.cve_refs
               for teil in c.cve.split(",") if teil.strip()}
    for finding in data.findings:
        for cited in (finding.threat.cves if finding.threat else []):
            assert any(cve in cited for cve in bekannt), f"{finding.id}: {cited}"
        assert not any(k in finding.model_dump() for k in ("cvss", "vector"))


def test_golden_pruefung_ueber_die_cli():
    """python -m reporter.v3 --golden-all --check meldet keine Drift."""
    result = subprocess.run(
        [sys.executable, "-m", "reporter.v3", "--golden-all", "--check"],
        cwd=REPORT_WORKER, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr[-2000:]
    assert "DRIFT" not in result.stderr


def test_stichtag_ist_festgenagelt():
    assert REPORT_DATE == "19.09.2026"
