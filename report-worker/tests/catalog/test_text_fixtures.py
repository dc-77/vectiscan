# -*- coding: utf-8 -*-
"""Jede Textbedingung hat ein Fixture (S6b-2, spec/09 Q4).

Eine Aussage im Katalog darf eine Fakten-Bedingung tragen (``when`` am Statement oder an
der Empfehlung). Fuer jede solche Bedingung liegt unter ``tests/catalog/text_fixtures/``
mindestens ein Fall, in dem sie fuer ein fehlgeschlagenes Mitglied gilt, und einer, in dem
sie nicht gilt. Die Engine schreibt das Ergebnis je Mitglied in ``Member.holds``; das Gate
(``aussage_ohne_fakt``) prueft den Bericht dagegen.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.catalog.conftest import get_catalog, make_facts, run_check

TEXT_FIXTURES = Path(__file__).parent / "text_fixtures"


def _fixtures() -> list[tuple[str, dict]]:
    out: list[tuple[str, dict]] = []
    for path in sorted(TEXT_FIXTURES.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        for case in data["cases"]:
            out.append((data["check"], case))
    return out


def _members(check_id: str, case: dict) -> dict[str, list[str]]:
    facts = make_facts(case["facts"], coverage_default=case.get("coverage_default"))
    out: dict[str, list[str]] = {}
    for result in run_check(check_id, facts):
        for m in result.members:
            if m.status == "fail":
                out[m.key] = list(m.holds)
    return out


@pytest.mark.parametrize("check_id,case", [pytest.param(c, k, id=f"{c}:{k['name'][:40]}")
                                          for c, k in _fixtures()])
def test_textbedingung(check_id, case):
    members = _members(check_id, case)
    for key, sids in case["expect"].get("holds", {}).items():
        assert key in members, f"{check_id}: Mitglied {key} nicht fehlgeschlagen; vorhanden {sorted(members)}"
        for sid in sids:
            assert sid in members[key], f"{check_id} {key}: {sid} sollte gelten"
    for key, sids in case["expect"].get("not_holds", {}).items():
        assert key in members, f"{check_id}: Mitglied {key} nicht fehlgeschlagen"
        for sid in sids:
            assert sid not in members[key], f"{check_id} {key}: {sid} sollte nicht gelten"


def test_jede_textbedingung_hat_beide_faelle():
    """Fuer jede bedingte Aussage je ein Fall mit wahr und mit falsch."""
    wahr: set[tuple[str, str]] = set()
    falsch: set[tuple[str, str]] = set()
    for check_id, case in _fixtures():
        for sids in case["expect"].get("holds", {}).values():
            wahr.update((check_id, s) for s in sids)
        for sids in case["expect"].get("not_holds", {}).values():
            falsch.update((check_id, s) for s in sids)
    fehlend: list[str] = []
    for cc in get_catalog().checks:
        for sid, _text, cond, _quantor in cc.spec.texts.all_statements():
            if not cond:
                continue
            if (cc.spec.id, sid) not in wahr:
                fehlend.append(f"{cc.spec.id}.{sid} (wahr)")
            if (cc.spec.id, sid) not in falsch:
                fehlend.append(f"{cc.spec.id}.{sid} (falsch)")
    assert not fehlend, "Text-Fixtures fehlen: " + ", ".join(fehlend)


def test_keine_verwaisten_text_fixtures():
    ids = {c for c, _ in _fixtures()}
    assert ids <= set(get_catalog().by_id), sorted(ids - set(get_catalog().by_id))
