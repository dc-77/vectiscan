"""Soll-Liste des elften Golden-Fixtures (Issue #14, dortmund-beach.com).

Order 14272c00 ist der erste Produktionslauf mit ``zap_active status=ok``. In
den zehn aelteren Fixtures hat das Werkzeug nie ein Ergebnis geliefert, deshalb
waren ``web_vulnerability_active`` und ``sensitive_path_exposed`` nur ueber
Fixtures gedeckt.

Unterschied zu test_golden_junkerwerk.py: dort kommt die Soll-Liste aus dem
handkuratierten Prototyp-Bericht und ist damit eine unabhaengige Gegenprobe.
Hier gibt es keinen solchen Bericht; die Liste ist aus dem Katalogergebnis
abgeleitet (``scripts/golden/build-expected-order.py``) und wirkt als
Regressionssperre. ``strict`` ist deshalb aus: die Liste behauptet keine
Vollstaendigkeit, sondern Stabilitaet. Die inhaltliche Pruefung liegt bei DC.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporter.catalog import evaluate, load_catalog
from reporter.facts.schema import Facts

HERE = Path(__file__).parent
GOLDEN = HERE.parent / "golden"
NAME = "dortmund-beach"

EXPECTED = json.loads((GOLDEN / "expected" / f"{NAME}.json").read_text(encoding="utf-8"))
MAP = json.loads((HERE / f"expected_map_{NAME}.json").read_text(encoding="utf-8"))
ORDER = MAP["orders"]["main"]


@pytest.fixture(scope="module")
def results():
    facts_path = GOLDEN / "facts" / f"{ORDER}.json"
    facts = Facts.from_dict(json.loads(facts_path.read_text(encoding="utf-8")))
    return evaluate(facts, load_catalog()).results


def _by_check(results, check_id):
    return [r for r in results if r.check_id == check_id]


# ------------------------------------------------------------- Soll-Liste

@pytest.mark.parametrize("entry", EXPECTED["findings"], ids=lambda e: e["id"])
def test_soll_befund_wird_erzeugt(entry, results):
    rows = [r for r in _by_check(results, entry["check"]) if r.status == "fail"]
    assert rows, f"{entry['id']}: {entry['check']} liefert keinen Befund mehr"
    labels = {r.group_label for r in rows}
    assert entry["group"] in labels, (
        f"{entry['id']}: Gruppe {entry['group']} nicht mehr betroffen, sondern {labels}")
    betroffen = {a for r in rows for a in r.affected}
    for a in entry["affected"]:
        assert a in betroffen, f"{entry['id']}: '{a}' steht nicht mehr in affected"


@pytest.mark.parametrize("entry", EXPECTED["positives"], ids=lambda e: e["id"])
def test_soll_positiv_wird_erzeugt(entry, results):
    rows = [r for r in _by_check(results, entry["check"])
            if r.status == "pass" and r.positive]
    assert rows, f"{entry['id']}: {entry['check']} liefert keine Positivaussage mehr"
    assert entry["group"] in {r.group_label for r in rows}


def test_keine_neuen_befunde_ausserhalb_der_liste(results):
    """Ein neuer Befund ist kein Fehler, muss aber in der Liste nachgezogen werden."""
    ist = {(r.check_id, r.group_label) for r in results
           if r.status == "fail" and r.kind == "check"}
    soll = {(e["check"], e["group"]) for e in EXPECTED["findings"]}
    neu = ist - soll
    assert not neu, (
        "Neue Befunde ohne Eintrag in der Soll-Liste: "
        f"{sorted(neu)}. Wenn gewollt: "
        "python3 scripts/golden/build-expected-order.py "
        f"{ORDER} --name {NAME}")


# ----------------------------------------------- Zweck des Fixtures (#14)

def test_zap_active_hat_abdeckung(results):
    """Der Grund, warum diese Order aufgenommen wurde."""
    facts_path = GOLDEN / "facts" / f"{ORDER}.json"
    facts = Facts.from_dict(json.loads(facts_path.read_text(encoding="utf-8")))
    zap_active = [c for c in facts.coverage if c.tool == "zap_active"]
    assert zap_active, "kein zap_active in der Abdeckung"
    assert any(c.status == "ok" for c in zap_active), (
        "zap_active ohne Status ok — dann taugt das Fixture nicht fuer #14")


def test_web_vulnerability_active_ist_an_echten_daten_entschieden(results):
    """Bis S2b war die Pruefung nur ueber Fixtures gedeckt.

    Seit S6 (Issue #15, spec/08 Punkt 2) entscheidet die Konfidenz: dieser Auftrag
    traegt eine Path-Traversal-Meldung auf dem oEmbed-Endpunkt von WordPress mit
    niedriger Konfidenz. Sie stand im ausgelieferten Bericht als "aktiv
    nachgewiesen" und ist ein bekannter Falschpositiv-Kandidat. Jetzt ist sie eine
    Werkzeugmeldung im Anhang und kein Befund.
    """
    rows = _by_check(results, "web_vulnerability_active")
    assert rows
    assert all(r.status in ("fail", "pass") for r in rows), (
        f"unentschieden: {[(r.status, r.reason_code) for r in rows]}")
    assert not any(r.status == "fail" for r in rows), (
        "keine Meldung dieses Auftrags hat Konfidenz High")

    gemeldet = _by_check(results, "web_vulnerability_reported")
    treffer = [r for r in gemeldet if r.status == "fail"]
    assert treffer, "die Meldung muss als Werkzeugmeldung erhalten bleiben"
    assert not any(r.active_proof for r in treffer)
    # S6b-2 (spec/09 Q14): die Quelle nennt den Lauf; Path Traversal (6) ist eine Regel
    # des aktiven Scanners, die Anti-CSRF-Meldung (10202) eine passive.
    nachweise = [e for r in treffer for e in r.evidence]
    (traversal,) = [e for e in nachweise if "Path Traversal" in e.excerpt]
    assert traversal.tool == "zap_active"
    assert "Konfidenz: niedrig" in traversal.excerpt
    assert all(e.tool == "zap" for e in nachweise if "Anti-CSRF" in e.excerpt)


def test_sensitive_path_exposed_ist_pruefbar(results):
    """feroxbuster lief; die Pruefung ist damit entschieden, nicht ungedeckt."""
    rows = _by_check(results, "sensitive_path_exposed")
    assert rows
    assert all(r.status in ("fail", "pass") for r in rows), (
        f"unentschieden: {[(r.status, r.reason_code) for r in rows]}")
