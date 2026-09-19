"""Sicherheitsnetz: jedes Fixture unter tests/catalog/fixtures/ laeuft, jede Pruefung hat Fixtures.

Die Datei entdeckt alle ``<id>_<art>.json`` automatisch. Fehlt einer Pruefung das
``_fail``- oder ``_pass``-Fixture, ist das ein Testfehler (Auftrag S2: jede Regel hat ein
Fixture, positiv und negativ). Pruefungen ohne ``when`` (positiv-only) brauchen kein
``_fail``; Pruefungen mit ``not_testable_when`` brauchen ein ``_nt``.
"""
from __future__ import annotations

import pytest

from tests.catalog.conftest import FIXTURES, fixture_kinds, get_catalog, run_fixture


def _all_fixtures() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for p in sorted(FIXTURES.glob("*_*.json")):
        stem = p.stem
        for kind in ("pass", "fail", "nt", "na"):
            if stem.endswith("_" + kind):
                out.append((stem[: -len(kind) - 1], kind))
                break
    return out


@pytest.mark.parametrize("check_id,kind", [pytest.param(c, k, id=f"{c}_{k}") for c, k in _all_fixtures()])
def test_fixture(check_id, kind, catalog):
    assert check_id in catalog.by_id, f"Fixture {check_id}_{kind} ohne Pruefung im Katalog"
    run_fixture(check_id, kind, catalog)


def test_jede_pruefung_hat_fixtures(catalog):
    fehlend: list[str] = []
    for cc in catalog.checks:
        kinds = set(fixture_kinds(cc.spec.id))
        if "pass" not in kinds:
            fehlend.append(f"{cc.spec.id}_pass")
        if cc.spec.when and cc.spec.kind == "check" and "fail" not in kinds:
            fehlend.append(f"{cc.spec.id}_fail")
        if cc.spec.not_testable_when and "nt" not in kinds:
            fehlend.append(f"{cc.spec.id}_nt")
    assert not fehlend, "Fixtures fehlen: " + ", ".join(fehlend)


def test_keine_verwaisten_fixtures(catalog):
    ids = {c for c, _ in _all_fixtures()}
    verwaist = sorted(i for i in ids if i not in catalog.by_id)
    assert not verwaist, f"Fixtures ohne Pruefung: {verwaist}"
