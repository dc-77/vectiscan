"""Abnahme S2: der Katalog laeuft fuer alle Orders im API-Snapshot ohne Fehler.

Facts kommen aus tests/golden/facts/<order>.json (Orders mit Tar) oder werden aus dem
Snapshot gebaut (Orders ohne Tar). Demo-Orders (d0000000...) sind ausgeschlossen.
"""
from __future__ import annotations

import json
import os
from collections import Counter

import pytest

from reporter.catalog.engine import evaluate
from reporter.facts.golden import SNAPSHOT, build_snapshot_facts, facts_path, golden_orders
from reporter.facts.serialize import dumps, load_json
from tests.catalog.conftest import get_catalog

_TAR_ORDERS = {o["order_id"] for o in golden_orders()}
_CACHE: dict[str, dict] = {}


def snapshot_orders() -> list[str]:
    out = []
    for name in sorted(os.listdir(SNAPSHOT)):
        d = SNAPSHOT / name
        if d.is_dir() and (d / "results.json").exists() and not name.startswith("d0000000"):
            out.append(name)
    return out


def facts_for(order_id: str) -> dict:
    if order_id not in _CACHE:
        if order_id in _TAR_ORDERS and facts_path(order_id).exists():
            _CACHE[order_id] = load_json(facts_path(order_id))
        else:
            _CACHE[order_id] = build_snapshot_facts(order_id).to_dict()
    return _CACHE[order_id]


@pytest.mark.parametrize("order_id", [pytest.param(o, id=o[:8]) for o in snapshot_orders()])
def test_katalog_laeuft_ohne_fehler(order_id):
    cat = get_catalog()
    out = evaluate(facts_for(order_id), cat)
    assert out.order_id == order_id
    assert out.summary.checks == len(cat.checks)
    ids = {r.check_id for r in out.results}
    rolled = {r.check_id for r in out.rollups}
    assert rolled == {c.spec.id for c in cat.checks}
    for r in out.results:
        assert r.status in ("pass", "fail", "not_applicable", "not_testable")
        if r.status == "fail":
            assert r.affected, (order_id, r.check_id, r.group_key)
            assert r.texts.observation and "{" not in r.texts.observation
        for label in r.affected:
            assert "{" not in label and "?" not in label and "[Hinweis" not in label
        if r.status in ("not_testable", "not_applicable"):
            assert r.reason_code and r.reason, (order_id, r.check_id, r.group_key)
    data = out.to_dict()
    text = dumps(data)
    assert json.loads(text)["order_id"] == order_id
    assert "\r\n" not in text


def test_unverarbeitete_beobachtungen_protokoll(capsys):
    """Zielwert aus spec/06: unter fuenf je Auftrag. Nur Protokoll, kein Fehler.

    Die Schwelle steht seit S5 im Gate (reporter/gate/v3_checks), das daraus eine
    Warnung im Admin-Review macht. Hier wird sie von dort gelesen, damit es die
    Zahl nur einmal gibt.
    """
    from reporter.gate.v3_checks import UNPROCESSED_WARN_THRESHOLD

    cat = get_catalog()
    rows = []
    for order_id in snapshot_orders():
        out = evaluate(facts_for(order_id), cat)
        kinds = Counter(u.kind for u in out.unprocessed)
        rows.append((order_id[:8], out.domain, sum(u.count for u in out.unprocessed), dict(kinds)))
    for r in sorted(rows, key=lambda x: -x[2]):
        print(f"unprocessed {r[0]} {r[1]}: {r[2]} {r[3]}")
    ueber = [r for r in rows if r[2] > UNPROCESSED_WARN_THRESHOLD]
    print(f"orders ueber Zielwert {UNPROCESSED_WARN_THRESHOLD}: {len(ueber)} von {len(rows)}")
