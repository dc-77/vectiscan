"""Soll-Liste des vierzehnten Golden-Fixtures (S5b, vectigal.tech und vectiscan.de).

Order 75338c97 ist der einzige WebCheck-Auftrag im Satz und damit der erste
Beleg fuer die Paketvariante an echten Daten (Issue #23). Bis dahin stellte
``tests/pdf_v3/conftest.py::as_package`` einen Perimeter-Auftrag im Datenmodell
auf WebCheck um; belegt war damit, dass der Renderer die richtigen Kapitel
weglaesst, nicht, was das Paket mit den Daten macht.

Beide Ziele sind eigene Domains hinter derselben Traefik-Instanz, der Lauf ist
ein interner Nachweis aus S2b und wird nicht ausgeliefert.

Wie bei dortmund-beach und lumbeck-wolter ist die Soll-Liste aus dem
Katalogergebnis abgeleitet (``scripts/golden/build-expected-order.py``) und
wirkt als Regressionssperre, nicht als unabhaengige Gegenprobe. ``strict`` ist
deshalb aus; die inhaltliche Pruefung liegt bei DC.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporter.catalog import evaluate, load_catalog
from reporter.facts.schema import Facts

HERE = Path(__file__).parent
GOLDEN = HERE.parent / "golden"
NAME = "vectigal-tech"

EXPECTED = json.loads((GOLDEN / "expected" / f"{NAME}.json").read_text(encoding="utf-8"))
MAP = json.loads((HERE / f"expected_map_{NAME}.json").read_text(encoding="utf-8"))
ORDER = MAP["orders"]["main"]


def _facts() -> Facts:
    path = GOLDEN / "facts" / f"{ORDER}.json"
    return Facts.from_dict(json.loads(path.read_text(encoding="utf-8")))


@pytest.fixture(scope="module")
def facts():
    return _facts()


@pytest.fixture(scope="module")
def results(facts):
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


# ------------------------------------------- Zweck des Fixtures: WebCheck

def test_der_auftrag_ist_webcheck_mit_zwei_zielen(facts):
    assert facts.scan.package == "webcheck"
    assert facts.scan.domains == ["vectigal.tech", "vectiscan.de"]


def test_hostgrenze_des_pakets_ist_eingehalten(facts):
    """WebCheck prueft hoechstens drei Hosts (catalog/packages.catalog.json)."""
    assert len(facts.hosts) <= 3, [h.ip for h in facts.hosts]


def test_der_kleinere_werkzeugsatz_steht_in_der_abdeckung(facts):
    """Was das Paket nicht enthaelt, ist als solches benannt, nicht als Luecke.

    Genau das ist der Unterschied zur synthetisch umetikettierten Variante:
    dort lief der volle Perimeter-Satz, hier fehlen zwoelf Werkzeuge mit Grund.
    """
    nicht_im_paket = {c.tool for c in facts.coverage
                      if c.status == "skipped" and c.reason == "not_in_package"}
    assert {"feroxbuster", "ffuf_param", "ffuf_sensitive", "shodan"} <= nicht_im_paket
    zap_active = [c for c in facts.coverage if c.tool == "zap_active"]
    assert zap_active and all(c.status == "skipped" for c in zap_active)
    assert all(c.reason == "package_webcheck" for c in zap_active), (
        [c.reason for c in zap_active])


def test_kein_host_ohne_abdeckungsangabe(facts):
    """Der Abnahmepunkt aus S5b, hier am kleinsten Paket."""
    ohne = [c for c in facts.coverage if c.status == "unknown"]
    assert not ohne, [c.id for c in ohne]
    assert {c.tool for c in facts.coverage} != {"scan_results"}


def test_zweites_ziel_bringt_keine_eigenen_hosts(facts):
    """Issue #17, hier an einem WebCheck-Auftrag.

    vectiscan.de zeigt auf dieselbe Traefik-Instanz wie vectigal.tech und
    bringt deshalb keinen eigenen Host mit. Der Bericht darf daraus keine
    getrennte Pruefung machen.
    """
    assert any("Multi-Target" in w for w in facts.warnings), facts.warnings
    ziele = {t.domain for t in facts.targets}
    assert ziele == {"vectigal.tech", "vectiscan.de"}
