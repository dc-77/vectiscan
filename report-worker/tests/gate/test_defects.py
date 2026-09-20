# -*- coding: utf-8 -*-
"""Die gemeinsame Defektliste beider Engines (S5).

Der Admin sieht eine Liste, nicht zwei. Geprueft wird, dass beide Formen
darin ankommen und dass am Eintrag steht, woher er kommt.
"""
from __future__ import annotations

from types import SimpleNamespace

from reporter.gate import defects as GD
from reporter.validation.gate import ValidationIssue, ValidationLevel, ValidationResult


def _v2_result() -> ValidationResult:
    return ValidationResult(
        passed=False,
        level=ValidationLevel.STRICT,
        errors=[ValidationIssue(check="ids", severity="error",
                                finding_id="VS-2026-004",
                                message="Luecke zwischen 003 und 005",
                                detail={"gap": 4})],
        warnings=[ValidationIssue(check="consistency", severity="warning",
                                  finding_id=None, message="Titel unklar")],
        checks_run=["ids", "consistency"],
    )


def test_v2_ergebnis_behaelt_check_und_befund_id() -> None:
    liste = GD.from_validation_result(_v2_result())

    assert [d.engine for d in liste] == ["v2", "v2"]
    fehler = [d for d in liste if d.is_error]
    assert len(fehler) == 1
    assert fehler[0].check == "ids"
    assert fehler[0].finding_id == "VS-2026-004"
    assert fehler[0].detail == {"gap": 4}


def test_selfcheck_strukturiert_und_als_satzliste() -> None:
    """Beide Formen kommen an; aus dem Satz wird die Befund-ID gelesen."""
    strukturiert = GD.from_selfcheck([("empfehlung_fehlt", "keine Empfehlung bei VS-JW-2026-003",
                                       "VS-JW-2026-003")])
    saetze = GD.from_selfcheck(["keine Empfehlung bei VS-JW-2026-003"])

    assert strukturiert[0].check == "empfehlung_fehlt"
    assert strukturiert[0].finding_id == "VS-JW-2026-003"
    assert saetze[0].check == "selfcheck"
    assert saetze[0].finding_id == "VS-JW-2026-003"
    assert all(d.engine == "v3" and d.is_error for d in strukturiert + saetze)


def test_halbleere_seiten_blockieren_nicht_fehlende_schriften_schon() -> None:
    """Halbleere Seiten sind je Auftrag bekannt (S4), eine fehlende Schrift nicht."""
    result = SimpleNamespace(warnings=[
        "halbleere Seiten [7, 19]",
        "Schrift nicht eingebettet: Inter",
        "2 Gedankenstrich(e) im Text",
    ], defects=["wird hier nicht gelesen"])

    liste = GD.from_render_result(result)

    schwere = {d.message for d in liste if d.is_error}
    leichte = {d.message for d in liste if not d.is_error}
    assert schwere == {"Schrift nicht eingebettet: Inter", "2 Gedankenstrich(e) im Text"}
    assert leichte == {"halbleere Seiten [7, 19]"}
    # RenderResult.defects ist dieselbe Selbstcheck-Liste, die der Worker schon
    # strukturiert erhebt; sie darf hier kein zweites Mal auftauchen.
    assert all("wird hier nicht gelesen" != d.message for d in liste)


def test_payload_zaehlt_und_fuehrt_beide_quellen_der_beobachtungen() -> None:
    facts = SimpleNamespace(unprocessed=[
        SimpleNamespace(model_dump=lambda mode: {"kind": "tool_ohne_leser", "what": "x", "count": 2})])
    output = SimpleNamespace(unprocessed=[
        SimpleNamespace(model_dump=lambda mode: {"kind": "service_unknown_port", "what": "y",
                                                 "count": 3})])
    liste = GD.from_validation_result(_v2_result())

    payload = GD.payload(liste, engine="v3", level="strict", facts=facts, output=output,
                         blocked=True)

    assert payload["engine"] == "v3"
    assert payload["counts"] == {"errors": 1, "warnings": 1, "unprocessed": 5}
    assert payload["blocked_at"] is not None
    assert [u["quelle"] for u in payload["unprocessed"]] == ["fakten", "katalog"]
    assert payload["defects"][0]["engine"] == "v2"


def test_payload_ohne_blockade_traegt_keinen_zeitpunkt() -> None:
    payload = GD.payload([], engine="v2", level="warn")

    assert payload["blocked_at"] is None
    assert payload["counts"] == {"errors": 0, "warnings": 0, "unprocessed": 0}
