# -*- coding: utf-8 -*-
"""Umrechnungstabellen und Befund-IDs."""
from __future__ import annotations

import pytest

from reporter.catalog.schema import LEVELS_BY_SCALE
from reporter.v3 import ids as IDS
from reporter.v3 import levels as L


def test_jede_einstufung_steht_in_der_abbildungstabelle():
    """Keine Einstufung darf auf den Rueckfall laufen (S6, spec/08 Punkt 1)."""
    for scale, levels in LEVELS_BY_SCALE.items():
        for level in levels:
            assert (scale, level) in L.TRIAGE_BY_LEVEL
            assert L.status_for(scale, level) in ("rot", "gelb", "blau")
            assert L.severity_key(scale, level)[1] < 9


def test_nur_kritisch_und_aktiver_nachweis_sind_rot():
    rot = sorted(k for k, tri in L.TRIAGE_BY_LEVEL.items() if tri.status == "rot")
    assert rot == [("exposure", "kritisch")]
    assert L.status_for("hygiene", "hoch", active_proof=True) == "rot"


def test_dringlichkeit_passt_immer_zur_ampelfarbe():
    """Der Kern von spec/08 Punkt 1: A.1 und die Befundzeile duerfen sich nicht
    widersprechen. Jede Stufe, die eine Einstufung tragen kann, muss in der
    Dringlichkeitsliste ihrer Farbe stehen."""
    for (scale, level), tri in L.TRIAGE_BY_LEVEL.items():
        erlaubt = L.stages_for_status(tri.status)
        for stage in L.STAGE_ORDER:
            wirksam = L.stage_for(scale, level, [stage])
            assert wirksam in tri.stages
            assert wirksam in erlaubt


def test_unverzueglich_nur_bei_rot():
    for (scale, level), tri in L.TRIAGE_BY_LEVEL.items():
        if "unverzueglich" in tri.stages:
            assert tri.status == "rot"
        # Eine dringlichere Katalogstufe wird gedeckelt, nicht uebernommen.
        if tri.status != "rot":
            assert L.urgency_for(scale, level, ["unverzueglich"]) != "Unverzüglich"


def test_exposition_wiegt_schwerer_als_hygiene():
    assert L.severity_key("exposure", "erhoeht") < L.severity_key("hygiene", "hoch")
    assert L.worst([("hygiene", "hoch"), ("exposure", "kritisch")]) == ("exposure", "kritisch")


@pytest.mark.parametrize("scale,level,stages,erwartet", [
    # Exposition kritisch traegt die einzige unverzuegliche Stufe.
    ("exposure", "kritisch", ["mittelfristig", "unverzueglich"], "Unverzüglich"),
    # Der Fall aus spec/08: admin_service_exposed schlaegt unverzueglich vor,
    # ist aber Exposition erhoeht und damit gelb.
    ("exposure", "erhoeht", ["unverzueglich", "in_kuerze"], "In Kürze"),
    ("hygiene", "hoch", ["unverzueglich"], "In Kürze"),
    ("hygiene", "mittel", ["in_kuerze"], "Mittelfristig"),
    # Hygiene niedrig darf zwischen Mittelfristig und Strategisch waehlen.
    ("hygiene", "niedrig", ["strategisch"], "Strategisch"),
    ("hygiene", "niedrig", ["mittelfristig"], "Mittelfristig"),
    ("hygiene", "niedrig", [], "Mittelfristig"),
])
def test_dringlichkeit_kommt_aus_der_tabelle(scale, level, stages, erwartet):
    assert L.urgency_for(scale, level, stages) == erwartet


def test_aktiver_nachweis_wird_rot_und_unverzueglich():
    assert L.urgency_for("exposure", "erhoeht", ["mittelfristig"],
                         active_proof=True) == "Unverzüglich"
    assert L.severity_for("exposure", "erhoeht", active_proof=True) == "CRITICAL"


def test_dashboard_stufe_je_einstufung():
    assert L.severity_for("exposure", "kritisch") == "CRITICAL"
    assert L.severity_for("exposure", "erhoeht") == "HIGH"
    assert L.severity_for("hygiene", "hoch") == "HIGH"
    assert L.severity_for("hygiene", "mittel") == "MEDIUM"
    assert L.severity_for("hygiene", "niedrig") == "LOW"


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


def test_berichtsnummer_traegt_datum_und_auftrag():
    # S6a: Scantag allein war nicht eindeutig (Huendgen und castenow trugen
    # beide VS-2026-0917); die ersten vier Zeichen der Order-ID gehoeren dazu.
    oid = "0bf16342-ed96-4b0e-a596-05aee3a62cb5"
    assert IDS.report_id(oid, 2026, "0831") == "VS-2026-0831-0bf1"
    assert IDS.report_id(oid.upper(), 2026, "0831") == "VS-2026-0831-0bf1"
    assert IDS.report_id("62c1e866-1eae-451a-8b52-7bff591aad31", 2026, "0917")         != IDS.report_id("e6df3135-0000-4000-8000-000000000000", 2026, "0917")


def test_berichtsnummer_ohne_order_id_bleibt_lesbar():
    assert IDS.report_id(None, 2026, "0831") == "VS-2026-0831"
    assert IDS.report_id("", 2026, "0831") == "VS-2026-0831"
