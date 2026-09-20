"""Soll-Liste des zwoelften Golden-Fixtures (S2c, lumbeck-wolter.de).

Order 57b3ac85 ist der erste Fixture-Lauf nach den Scannerfixen aus S2b und
zugleich der Beleg fuer einen Defekt, der vorher an keinen echten Daten
sichtbar war: lumbeck-wolter.de und www tragen neben dem A-Record den AAAA
2a01:4f8:d0a:668b::2, im Lauf taucht aber nur die IPv4-Adresse auf. Die
Zusammenfassung gleicher Hosts in phase0 fasst Adressen mit identischem
FQDN-Satz zusammen und behaelt dabei IPv4. Der AAAA faellt damit vor
Phase 1 heraus, und ueber IPv6 erreichbare Dienste bleiben ungeprueft.

Wie bei dortmund-beach ist die Soll-Liste aus dem Katalogergebnis abgeleitet
(``scripts/golden/build-expected-order.py``) und wirkt als Regressionssperre,
nicht als unabhaengige Gegenprobe. ``strict`` ist deshalb aus; die inhaltliche
Pruefung liegt bei DC.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporter.catalog import evaluate, load_catalog
from reporter.facts.schema import Facts

HERE = Path(__file__).parent
GOLDEN = HERE.parent / "golden"
NAME = "lumbeck-wolter"

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


# --------------------------------------- Zweck des Fixtures: Dual-Stack

def test_lauf_kennt_genau_einen_host_und_der_ist_ipv4(facts):
    """Belegt den Ist-Stand, den der Dual-Stack-Defekt erzeugt.

    Sobald phase0 beide Adressfamilien behaelt, faellt dieser Test auf und
    muss zusammen mit der Soll-Liste nachgezogen werden. Genau das ist
    gewollt: der Defekt soll nicht unbemerkt verschwinden.
    """
    familien = sorted({h.family for h in facts.hosts})
    assert familien == [4], (
        f"Adressfamilien im Lauf: {familien}. Wenn hier eine 6 steht, ist der "
        "Dual-Stack-Defekt behoben; Soll-Liste neu ableiten und diesen Test "
        "auf den neuen Stand bringen.")
    assert len(facts.hosts) == 1, f"erwartet ein Host, gefunden {len(facts.hosts)}"


def test_keine_abdeckungszeile_behauptet_eine_ipv6_pruefung(facts):
    """Was nicht gescannt wurde, darf auch nicht als geprueft dastehen."""
    ipv6_zeilen = [c for c in facts.coverage if ":" in (c.host_ip or "")]
    assert not ipv6_zeilen, (
        f"Abdeckung fuer IPv6-Adressen, obwohl kein IPv6-Host im Lauf ist: "
        f"{[c.id for c in ipv6_zeilen]}")


def test_portscan_ist_fuer_den_vorhandenen_host_entschieden(facts):
    """Der IPv4-Host wurde wirklich gescannt, das Fixture taugt als Referenz."""
    nmap = [c for c in facts.coverage if c.tool == "nmap"]
    assert len(nmap) == 1, f"erwartet eine nmap-Zeile, gefunden {[c.id for c in nmap]}"
    assert nmap[0].status == "ok" and nmap[0].reason is None, (
        f"nmap steht auf {nmap[0].status}/{nmap[0].reason}")
    assert any(s.host_ip == "116.202.77.64" for s in facts.services), (
        "keine Dienste am gescannten Host")
