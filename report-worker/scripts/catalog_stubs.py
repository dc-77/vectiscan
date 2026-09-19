#!/usr/bin/env python3
"""Test-Stubs fuer den Pruefkatalog aus decisions.md erzeugen.

    cd report-worker && python scripts/catalog_stubs.py [--check]

Liest die Entscheidungstabelle (reporter/catalog/decisions.md), legt fuer jede Pruefung
tests/catalog/test_<id>.py an, sofern die Datei fehlt, und ueberschreibt nie. ``--check``
schreibt nichts und meldet fehlende Stubs mit Exit 1.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DECISIONS = ROOT / "reporter" / "catalog" / "decisions.md"
TESTS = ROOT / "tests" / "catalog"

TEMPLATE = '''"""Pruefung {id}: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "{id}"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_{id}(kind):
    run_fixture(CHECK_ID, kind)
'''


def parse_decisions(path: Path = DECISIONS) -> list[dict[str, str]]:
    """Zeilen der Entscheidungstabelle als Dicts (Spaltennamen aus der Kopfzeile)."""
    rows: list[dict[str, str]] = []
    header: list[str] | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            header = None if header and not line.strip() else header
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if header is None:
            if cells and cells[0] == "id":
                header = cells
            continue
        if all(set(c) <= set("-: ") for c in cells):
            continue
        if len(cells) != len(header):
            raise SystemExit(f"decisions.md: Zeile mit {len(cells)} statt {len(header)} Spalten: {line[:80]}")
        rows.append(dict(zip(header, cells)))
    return rows


def main(argv: list[str] | None = None) -> int:
    check = "--check" in (argv or sys.argv[1:])
    missing: list[str] = []
    for row in parse_decisions():
        cid = row["id"].strip("`")
        target = TESTS / f"test_{cid}.py"
        if target.exists():
            continue
        missing.append(cid)
        if not check:
            target.write_text(TEMPLATE.format(id=cid), encoding="utf-8", newline="\n")
            print(f"angelegt {target.relative_to(ROOT)}")
    if check and missing:
        print("fehlende Stubs: " + ", ".join(missing), file=sys.stderr)
        return 1
    if not missing:
        print("alle Stubs vorhanden")
    return 0


if __name__ == "__main__":
    sys.exit(main())
