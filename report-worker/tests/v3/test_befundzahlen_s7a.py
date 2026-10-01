# -*- coding: utf-8 -*-
"""S7a: Darstellung aendert keine Befunde (spec/prompts/S7a.md, Abnahme).

``tests/golden/befundzahlen.json`` stammt aus den Reportdaten vor S7a
(``scripts/golden/build-befundzahlen.py``). Verglichen werden je Befund ID,
Pruefungen, Ampel, Dringlichkeit, Skala und Einstufung, die Positivbefunde, die
Kategorieampeln und die Gesamtbewertung. Der Drift-Test der Reportdaten deckt das
nicht ab, weil er fuer jede Darstellungsaenderung neu geschrieben wird.

Einzige gewollte Abweichung ist Punkt 0 (Werkzeug-Fehlertext als Dienstkennung) bei
cd28d260; sie steht unten ausdruecklich und in tests/golden/README.md, Abschnitt
"Darstellung nach S7a".
"""
from __future__ import annotations

import importlib.util
import json

import pytest

from tests.v3.conftest import GOLDEN, REPORT_WORKER, data_for, order_ids

ERWARTET = json.loads((GOLDEN / "befundzahlen.json").read_text(encoding="utf-8"))

_spec = importlib.util.spec_from_file_location(
    "build_befundzahlen", REPORT_WORKER.parent / "scripts" / "golden" / "build-befundzahlen.py")
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
summary = _mod.summary


# Punkt 0 (Entscheidung DC 30.09.): der nmap-Fehlertext an 92.205.163.53:8000 ist keine Kennung
# mehr; der Fingerprint nennt Shoutcast, der Port ist Fremddienst (wie bei 1f8bc977) und der
# blaue Befund http_alt_port entfaellt. Die IDs danach ruecken nach.
PUNKT_0 = {"cd28d260-cf49-4d17-a980-64a4b1951444": "http_alt_port"}


def _gebaut(order_id: str) -> dict:
    return summary(json.loads(json.dumps(data_for(order_id).to_dict(), default=str)))


def _erwartet(order_id: str) -> dict:
    erwartet = json.loads(json.dumps(ERWARTET[order_id]))
    entfaellt = PUNKT_0.get(order_id)
    if entfaellt:
        rest = [f for f in erwartet["findings"] if f[1] != entfaellt]
        assert len(rest) == len(erwartet["findings"]) - 1
        praefix = rest[0][0].rsplit("-", 1)[0]
        erwartet["findings"] = [[f"{praefix}-{i:03d}", *f[1:]] for i, f in enumerate(rest, start=1)]
    return erwartet


def test_alle_golden_auftraege_haben_einen_eintrag():
    assert set(ERWARTET) == set(order_ids())


@pytest.mark.parametrize("order_id", order_ids())
def test_befunde_und_einstufungen_unveraendert(order_id):
    assert _gebaut(order_id) == _erwartet(order_id), (
        f"{order_id}: Befunde oder Einstufungen weichen vom Stand vor S7a ab")
