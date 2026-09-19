# -*- coding: utf-8 -*-
"""Zwei Prozesse, ein Ergebnis.

Gleiches Muster wie tests/test_facts_golden.py: der Bau laeuft in einem eigenen
Interpreter, damit Hash-Seed und Wörterbuchreihenfolge nicht zufaellig gleich sind.
Ohne diesen Nachweis waere die Zusage "zwei Laeufe, eine Befundliste" nicht belegt.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys

from tests.v3.conftest import JUNKERWERK, REPORT_WORKER

SKRIPT = (
    "import sys; sys.path.insert(0, '.');"
    "from reporter.facts.serialize import dumps;"
    "from reporter.v3.golden import build_golden_report_data;"
    "sys.stdout.write(dumps(build_golden_report_data(sys.argv[1]).to_dict()))"
)


def _digest(order_id: str, seed: str) -> str:
    result = subprocess.run(
        [sys.executable, "-c", SKRIPT, order_id],
        cwd=REPORT_WORKER, capture_output=True, text=True,
        env={**_env(), "PYTHONHASHSEED": seed})
    assert result.returncode == 0, result.stderr[-2000:]
    return hashlib.sha256(result.stdout.encode("utf-8")).hexdigest()


def _env() -> dict[str, str]:
    import os

    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)
    return env


def test_zwei_prozesse_liefern_dieselben_reportdaten():
    order_id = JUNKERWERK["multi"]
    assert _digest(order_id, "0") == _digest(order_id, "12345")


def test_drei_junkerwerk_laeufe_ergeben_dieselben_sachverhalte():
    """Die Befundfamilien der drei Laeufe unterscheiden sich nur dort, wo die
    Abdeckung sich unterscheidet. Der Drift-Test auf Pruefebene liegt in S2; hier
    zaehlt, dass die Konsolidierung daraus keine neuen Unterschiede macht."""
    from reporter.v3.bundles import consolidate
    from tests.v3.conftest import output_for

    keys = {}
    for lauf, order_id in JUNKERWERK.items():
        items, _ = consolidate(output_for(order_id))
        keys[lauf] = {i.key for i in items if i.target == "findings"}
    # Der Multi-Lauf deckt beide Domains ab und enthaelt deshalb alles aus dem
    # de-Lauf; der hu-Lauf sieht nur eine Teilmenge der Hosts.
    assert keys["de"] <= keys["multi"], keys["de"] - keys["multi"]
    assert keys["hu"] <= keys["multi"] | {"cert_health"}, keys["hu"] - keys["multi"]
