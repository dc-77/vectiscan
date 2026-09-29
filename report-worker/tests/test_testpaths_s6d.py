# -*- coding: utf-8 -*-
"""S6d (B3, Issue #4): alle Tests liegen in den testpaths und laufen damit in CI.

Bis S5 lagen die Gate-Tests unter ``reporter/validation/tests`` und wurden weder lokal noch in
der Pipeline gesammelt (``pytest.ini``: ``testpaths = tests``). S5 hat sie nach
``tests/validation`` verschoben (Commit 62848a3); diese Sperre verhindert den Rueckfall, fuer den
report-worker und den scan-worker.
"""
from __future__ import annotations

from pathlib import Path

REPORT_WORKER = Path(__file__).resolve().parents[1]
SCAN_WORKER = REPORT_WORKER.parent / "scan-worker"


def _testpaths(root: Path) -> list[str]:
    zeilen = (root / "pytest.ini").read_text(encoding="utf-8").splitlines()
    zeile = next(z for z in zeilen if z.strip().startswith("testpaths"))
    return zeile.split("=", 1)[1].split()


def _ausserhalb(root: Path, paket: str) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in (root / paket).rglob("test_*.py"))


def test_report_worker_testpaths_umfassen_die_validierungstests():
    assert _testpaths(REPORT_WORKER) == ["tests"]
    assert (REPORT_WORKER / "tests" / "validation" / "test_checks.py").exists()


def test_report_worker_keine_tests_im_paket():
    assert _ausserhalb(REPORT_WORKER, "reporter") == []


def test_scan_worker_keine_tests_im_paket():
    if not SCAN_WORKER.exists():
        return
    assert _testpaths(SCAN_WORKER) == ["tests"]
    assert _ausserhalb(SCAN_WORKER, "scanner") == []
