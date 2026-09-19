# -*- coding: utf-8 -*-
"""Umrechnungstabellen und Befund-IDs."""
from __future__ import annotations

import pytest

from reporter.catalog.schema import LEVELS_BY_SCALE
from reporter.v3 import ids as IDS
from reporter.v3 import levels as L


def test_jede_einstufung_hat_eine_farbe():
    for scale, levels in LEVELS_BY_SCALE.items():
        for level in levels:
            assert L.status_for(level) in ("rot", "gelb", "blau")
            assert L.severity_key(scale, level)[1] < 9


def test_nur_kritisch_ist_rot():
    rot = [lvl for lvl, status in L.STATUS_BY_LEVEL.items() if status == "rot"]
    assert rot == ["kritisch"]


def test_exposition_wiegt_schwerer_als_hygiene():
    assert L.severity_key("exposure", "erhoeht") < L.severity_key("hygiene", "hoch")
    assert L.worst([("hygiene", "hoch"), ("exposure", "kritisch")]) == ("exposure", "kritisch")


@pytest.mark.parametrize("stages,erwartet", [
    (["mittelfristig", "unverzueglich"], "Unverzüglich"),
    (["strategisch", "mittelfristig"], "Mittelfristig"),
    (["in_kuerze"], "In Kürze"),
    ([], "Mittelfristig"),
])
def test_dringlichkeit_ist_die_dringlichste_stufe(stages, erwartet):
    assert L.urgency_for(stages) == erwartet


def test_ampelwert_folgt_der_farbe():
    assert L.BAR_BY_STATUS["rot"] > L.BAR_BY_STATUS["gelb"] > L.BAR_BY_STATUS["blau"] > 0
    assert L.BAR_BY_STATUS["gruen"] == 0


@pytest.mark.parametrize("kuerzel,erwartet", [
    ("JW", "VS-JW-2026-001"),
    ("jw", "VS-JW-2026-001"),
    (None, "VS-2026-001"),
    ("", "VS-2026-001"),
    ("nicht erlaubt", "VS-2026-001"),
])
def test_befund_id_mit_und_ohne_kuerzel(kuerzel, erwartet):
    assert IDS.finding_id(kuerzel, 2026, 1) == erwartet


def test_ids_sind_dreistellig_und_lueckenlos_formatiert():
    assert IDS.finding_id("JW", 2026, 9).endswith("-009")
    assert IDS.finding_id("JW", 2026, 15).endswith("-015")
    assert IDS.positive_id(None, 2026, 3) == "VS-2026-P03"


def test_berichtsnummer_traegt_datum():
    assert IDS.report_id("JW", 2026, "0831") == "VS-JW-2026-0831"
    assert IDS.report_id(None, 2026, "0831") == "VS-2026-0831"
