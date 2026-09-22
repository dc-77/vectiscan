# -*- coding: utf-8 -*-
"""Die Dashboard-Befundliste kommt aus denselben Befunden wie der Bericht (S6, A7).

Entscheidung DC: Severity aus der Abbildungstabelle von spec/08 Punkt 7, kein
CVSS, Positivbefunde getrennt. Der Test, den DC dazu genannt hat: die Zahlen je
Farbe im Dashboard sind die Zahlen je Farbe im Bericht.
"""
from __future__ import annotations

from collections import Counter

import pytest

from reporter.v3 import levels as L
from reporter.v3.dashboard import (SEVERITY_ORDER, findings_data_from_v3, policy_ids,
                                   severity_of)
from reporter.v3.golden import order_ids
from tests.v3.conftest import data_for

ORDERS = order_ids()

# Welche Dashboard-Stufe zu welcher Ampelfarbe gehoert. Eine Farbe kann zwei
# Stufen tragen (gelb: erhoeht und hoch ergeben HIGH, mittel ergibt MEDIUM).
STUFEN_JE_FARBE: dict[str, set[str]] = {
    "rot": {"CRITICAL"},
    "gelb": {"HIGH", "MEDIUM"},
    "blau": {"LOW"},
}


@pytest.mark.parametrize("order_id", ORDERS)
def test_zahlen_je_farbe_stimmen_mit_dem_bericht(order_id):
    data = data_for(order_id)
    dash = findings_data_from_v3(data, data.meta.package)

    je_farbe = Counter(f.status for f in data.findings)
    je_stufe = dash["severity_counts"]
    for farbe, stufen in STUFEN_JE_FARBE.items():
        assert sum(je_stufe[s] for s in stufen) == je_farbe[farbe], farbe
    assert sum(je_stufe.values()) == len(data.findings)


@pytest.mark.parametrize("order_id", ORDERS)
def test_kein_eigener_cvss_wert(order_id):
    data = data_for(order_id)
    dash = findings_data_from_v3(data, data.meta.package)
    for eintrag in dash["findings"]:
        assert "cvss_score" not in eintrag
        assert "cvss" not in eintrag


@pytest.mark.parametrize("order_id", ORDERS)
def test_positivbefunde_stehen_getrennt(order_id):
    data = data_for(order_id)
    dash = findings_data_from_v3(data, data.meta.package)
    assert len(dash["positive_findings"]) == len(data.positives)
    ids = {f["id"] for f in dash["findings"]}
    assert not (ids & {p["id"] for p in dash["positive_findings"]})


def test_stufe_folgt_der_abbildungstabelle():
    for (scale, level), tri in L.TRIAGE_BY_LEVEL.items():
        assert tri.severity in SEVERITY_ORDER
        assert tri.severity in STUFEN_JE_FARBE[tri.status]


@pytest.mark.parametrize("order_id", ORDERS)
def test_umschlag_hat_die_felder_der_alten_liste(order_id):
    data = data_for(order_id)
    dash = findings_data_from_v3(data, data.meta.package)
    for key in ("overall_risk", "overall_description", "severity_counts", "findings",
                "positive_findings", "recommendations", "package"):
        assert key in dash, key
    assert dash["engine"] == "catalog"
    if data.findings:
        assert policy_ids(data), "ohne Regel-IDs fehlt die Audit-Spur"


def test_aktiver_nachweis_ist_kritisch():
    """Ein rot gefaerbter Befund zaehlt im Dashboard als CRITICAL."""
    from reporter.v3.models import Finding

    finding = Finding(id="VS-1", cat="A", status="rot", urgency="Unverzüglich",
                      title="t", affected="a", source="aktiv", scale="exposure",
                      level="erhoeht", found="f", impact="i",
                      recommendation=[["Unverzüglich", "x"]], verify="v", policy="p")
    assert severity_of(finding) == "CRITICAL"
