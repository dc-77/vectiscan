"""Soll-Listen der sieben Auftraege aus der Scan-Runde vom 23.09.2026 (S6a2).

Pilotkunden mit schriftlichem Einverstaendnis, Perimeter, Engine catalog, gegengelesen
in report-prototype/spec/09-gegenlesen-scanrunde.md. Die Listen sind wie bei
dortmund-beach und lumbeck-wolter aus dem Katalogergebnis abgeleitet
(``scripts/golden/build-expected-order.py``, ``strict: false``) und wirken als
Regressionssperre, nicht als Gegenprobe.

Was spec/09 als falsch belegt, steht trotzdem in der Liste, aber markiert: der
Eintrag in ``expected_map_<slug>.json`` traegt ``spec09`` (Q-Nummer) und ``warum``.
S6b aendert diese Eintraege bewusst; dann faellt der Test hier, die Liste wird neu
erzeugt, und das Skript meldet die entfallene Markierung. Still verschwindet nichts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from reporter.catalog import evaluate, load_catalog
from reporter.facts.schema import Facts

HERE = Path(__file__).parent
GOLDEN = HERE.parent / "golden"

NAMES = (
    "dortmund-beach-0923",
    "lumbeck-wolter-0923",
    "junkerwerk-0923",
    "huendgen-0923",
    "bergersysteme-0923",
    "castenow-0923",
    "heuel-0923",
)
# Eine oder mehrere Stellen aus spec/09, mit Komma getrennt ("Q13, Q3").
MARK_RE = re.compile(r"^(Q\d{1,2}|Teil 2)(, (Q\d{1,2}|Teil 2))*$")

_RESULTS: dict[str, list] = {}


def _expected(name: str) -> dict:
    return json.loads((GOLDEN / "expected" / f"{name}.json").read_text(encoding="utf-8"))


def _map(name: str) -> dict:
    return json.loads((HERE / f"expected_map_{name}.json").read_text(encoding="utf-8"))


def _results(name: str) -> list:
    if name not in _RESULTS:
        order = _map(name)["orders"]["main"]
        facts = Facts.from_dict(json.loads(
            (GOLDEN / "facts" / f"{order}.json").read_text(encoding="utf-8")))
        _RESULTS[name] = evaluate(facts, load_catalog()).results
    return _RESULTS[name]


def _entries(liste: str) -> list[tuple[str, dict]]:
    return [(name, e) for name in NAMES for e in _expected(name)[liste]]


def _id(param) -> str:
    return f"{param[0]}:{param[1]['id']}" if isinstance(param, tuple) else str(param)


@pytest.mark.parametrize("case", _entries("findings"), ids=_id)
def test_soll_befund_wird_erzeugt(case):
    name, entry = case
    rows = [r for r in _results(name) if r.check_id == entry["check"] and r.status == "fail"]
    assert rows, f"{name} {entry['id']}: {entry['check']} liefert keinen Befund mehr"
    labels = {r.group_label for r in rows}
    assert entry["group"] in labels, (
        f"{name} {entry['id']}: Gruppe {entry['group']} nicht mehr betroffen, sondern {labels}")
    betroffen = {a for r in rows for a in r.affected}
    for a in entry["affected"]:
        assert a in betroffen, f"{name} {entry['id']}: '{a}' steht nicht mehr in affected"


@pytest.mark.parametrize("case", _entries("positives"), ids=_id)
def test_soll_positiv_wird_erzeugt(case):
    name, entry = case
    rows = [r for r in _results(name)
            if r.check_id == entry["check"] and r.status == "pass" and r.positive]
    assert rows, f"{name} {entry['id']}: {entry['check']} liefert keine Positivaussage mehr"
    assert entry["group"] in {r.group_label for r in rows}


@pytest.mark.parametrize("name", NAMES)
def test_keine_neuen_befunde_ausserhalb_der_liste(name):
    """Ein neuer Befund ist kein Fehler, muss aber in der Liste nachgezogen werden."""
    ist = {(r.check_id, r.group_label) for r in _results(name)
           if r.status == "fail" and r.kind == "check"}
    soll = {(e["check"], e["group"]) for e in _expected(name)["findings"]}
    neu = ist - soll
    order = _map(name)["orders"]["main"]
    assert not neu, (
        f"Neue Befunde ohne Eintrag in der Soll-Liste {name}: {sorted(neu)}. Wenn gewollt: "
        f"python3 scripts/golden/build-expected-order.py {order} --name {name}")


@pytest.mark.parametrize("name", NAMES)
def test_markierungen_nach_spec09_sind_vollstaendig(name):
    """Jede Markierung nennt eine Q-Nummer aus spec/09 und einen Grund, und der
    markierte Eintrag steht in der Soll-Liste."""
    mapping, expected = _map(name), _expected(name)
    assert mapping["strict"] is False
    assert mapping.get("hinweis_spec09"), f"{name}: hinweis_spec09 fehlt"
    for liste in ("findings", "positives"):
        ids = {e["id"]: e for e in expected[liste]}
        assert set(mapping[liste]) == set(ids), f"{name}: Zuordnung und Liste {liste} weichen ab"
        for eid, entry in mapping[liste].items():
            if "spec09" not in entry:
                continue
            assert MARK_RE.match(entry["spec09"]), f"{name} {eid}: {entry['spec09']}"
            assert (entry.get("warum") or "").strip(), f"{name} {eid}: Grund fehlt"
            assert entry["checks"] == [ids[eid]["check"]]


# ---------------------------------------------------------------- S6b-1

_FACTS: dict[str, Facts] = {}


def _facts(name: str) -> Facts:
    if name not in _FACTS:
        order = _map(name)["orders"]["main"]
        _FACTS[name] = Facts.from_dict(json.loads(
            (GOLDEN / "facts" / f"{order}.json").read_text(encoding="utf-8")))
    return _FACTS[name]


@pytest.mark.parametrize("name", NAMES)
def test_zustaendigkeit_auf_geteilten_systemen(name):
    """spec/09 Q3 (Berichtsteil): ein Befund auf einem geteilten System, den der Kunde
    nicht selbst beheben kann, liegt beim Hoster oder Plattformbetreiber. Die Soll-Liste
    haelt die Zuordnung je Pruefung und Gruppe fest."""
    from reporter.v3.operators import hosts_by_ip, operator_for

    out = evaluate(_facts(name), load_catalog())
    scopes = {c.id: c.scope for c in out.checks}
    hosts = hosts_by_ip(_facts(name))
    ist = {}
    for r in out.results:
        if r.kind == "check" and r.status == "fail":
            op = operator_for(r, scopes[r.check_id], hosts)
            ist[(r.check_id, r.group_label)] = op.kind if op else None
    for e in _expected(name)["findings"]:
        assert ist.get((e["check"], e["group"])) == e.get("zustaendig"), (name, e["id"], e["check"], e["group"])


@pytest.mark.parametrize("name", NAMES)
def test_markierungen_q3_und_q9_sind_aufgeloest(name):
    """S6b-1 loest Q3 (Zustaendigkeit), Q9 (Hosts ohne Messergebnis) und den
    Drittanbieter-Eintrag auf; die uebrigen Markierungen bleiben fuer S6b-2."""
    mapping = _map(name)
    assert mapping.get("hinweis_s6b1"), f"{name}: hinweis_s6b1 fehlt"
    for liste in ("findings", "positives"):
        for eid, entry in mapping[liste].items():
            marks = {m.strip() for m in entry.get("spec09", "").split(",") if m.strip()}
            assert not marks & {"Q3", "Q9"}, f"{name} {eid}: {entry['spec09']}"
