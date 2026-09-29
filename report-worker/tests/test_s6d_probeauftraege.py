# -*- coding: utf-8 -*-
"""S6d: Abnahme an den drei S6c-Probeauftraegen (Startprompt S6d, Abschnitt Abnahme).

4394b0b7 (dortmund-beach.com), f9a2a2f6 (junkerwerk.de und junkerwerk.hu), cd28d260 (castenow.de)
vom 28.09.2026 sind die ersten Golden-Fixtures mit den S6c-Rohfeldern. Hier gilt: 0 Gate-Fehler,
0 Eintraege ``file_unknown_or_unparsable``, Netzbetreiber mit RIR-Quelle nur mit RDAP-Fixture (die
Proben liefen ohne rdap, S6c-Defekt, in S6d als C6 behoben), und die abgeleiteten Soll-Listen
(``scripts/golden/build-expected-order.py``, ``strict: false``) wirken als Regressionssperre.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporter.catalog import evaluate, load_catalog
from reporter.gate import v3_checks as VC
from tests.v3.conftest import data_for, facts_for, output_for

HERE = Path(__file__).parent
GOLDEN = HERE / "golden"
PROBEN = {
    "dortmund-beach-0928": "4394b0b7-5dc6-4e01-b700-2a4052a7bd4a",
    "junkerwerk-0928": "f9a2a2f6-a97f-47bf-9d7f-9afb3869f97c",
    "castenow-0928": "cd28d260-cf49-4d17-a980-64a4b1951444",
}
_RESULTS: dict[str, list] = {}


def _expected(name: str) -> dict:
    return json.loads((GOLDEN / "expected" / f"{name}.json").read_text(encoding="utf-8"))


def _results(name: str) -> list:
    if name not in _RESULTS:
        _RESULTS[name] = evaluate(facts_for(PROBEN[name]), load_catalog()).results
    return _RESULTS[name]


@pytest.mark.parametrize("order", PROBEN.values())
def test_null_gate_fehler(order):
    defekte = VC.run_all(data_for(order), facts_for(order), output_for(order))
    assert [d.message for d in defekte if d.severity == VC.SEVERITY_ERROR] == []


@pytest.mark.parametrize("order", PROBEN.values())
def test_keine_unbekannten_dateien(order):
    assert not [u for u in facts_for(order).unprocessed if u.kind == "file_unknown_or_unparsable"]


@pytest.mark.parametrize("order", PROBEN.values())
def test_netzbetreiber_ohne_rdap_laut_abuseipdb(order):
    data = data_for(order)
    assert data.scope.operator_header == "Netzbetreiber (laut AbuseIPDB)"
    assert not [h for h in data.scope.hosts if "laut RIPE" in h.operator]


@pytest.mark.parametrize("name", PROBEN)
def test_soll_befunde_werden_erzeugt(name):
    for entry in _expected(name)["findings"]:
        rows = [r for r in _results(name) if r.check_id == entry["check"] and r.status == "fail"]
        assert rows, f"{name} {entry['id']}: {entry['check']} liefert keinen Befund mehr"
        assert entry["group"] in {r.group_label for r in rows}, (name, entry["id"])
        betroffen = {a for r in rows for a in r.affected}
        assert set(entry["affected"]) <= betroffen, (name, entry["id"])


@pytest.mark.parametrize("name", PROBEN)
def test_soll_positive_werden_erzeugt(name):
    for entry in _expected(name)["positives"]:
        rows = [r for r in _results(name) if r.check_id == entry["check"] and r.status == "pass" and r.positive]
        assert rows and entry["group"] in {r.group_label for r in rows}, (name, entry["id"])


@pytest.mark.parametrize("name", PROBEN)
def test_keine_befunde_ausserhalb_der_liste(name):
    ist = {(r.check_id, r.group_label) for r in _results(name) if r.status == "fail" and r.kind == "check"}
    soll = {(e["check"], e["group"]) for e in _expected(name)["findings"]}
    assert not ist - soll, (
        f"Neue Befunde ohne Eintrag in der Soll-Liste {name}: {sorted(ist - soll)}. Wenn gewollt: "
        f"python3 scripts/golden/build-expected-order.py {PROBEN[name]} --name {name}")
