"""Soll-Liste des dreizehnten Golden-Fixtures (S2c, Junkerwerk-Rescan).

Order 860d0d5a ist der vierte Junkerwerk-Lauf, der erste mit beiden Domains
nach den Scannerfixen aus S2b und der erste Fixture-Lauf ueberhaupt mit einem
AAAA-Host. Er traegt drei Nachweise:

* Issue #12: DNS-, SPF- und DMARC-Zeilen liegen fuer junkerwerk.de und
  junkerwerk.hu getrennt vor.
* Issue #17: junkerwerk.hu bringt keine eigenen Hosts, es teilt 188.40.3.130
  mit junkerwerk.de. Der Fall tritt weiterhin auf.
* Issue #8: nmap laeuft jetzt mit ``-6`` gegen 2a01:4f8:d0a:3124::2, der alte
  Grund ``target_invalid_ipv6`` ist weg. Zurueck kommt trotzdem nichts, und
  die Abdeckung fuehrt den Host als ``ok`` mit ``no_open_ports``. Das ist
  eine Aussage ueber einen Host, der nie erreicht wurde. Der Test haelt
  diesen Ist-Stand fest, damit er nicht unbemerkt bestehen bleibt.

Die Soll-Liste ist aus dem Katalogergebnis abgeleitet
(``scripts/golden/build-expected-order.py``) und wirkt als Regressionssperre.
``strict`` ist aus, die inhaltliche Pruefung liegt bei DC.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporter.catalog import evaluate, load_catalog
from reporter.facts.schema import Facts

HERE = Path(__file__).parent
GOLDEN = HERE.parent / "golden"
NAME = "junkerwerk-rescan"
IPV6 = "2a01:4f8:d0a:3124::2"

EXPECTED = json.loads((GOLDEN / "expected" / f"{NAME}.json").read_text(encoding="utf-8"))
MAP = json.loads((HERE / f"expected_map_{NAME}.json").read_text(encoding="utf-8"))
ORDER = MAP["orders"]["main"]


@pytest.fixture(scope="module")
def facts():
    path = GOLDEN / "facts" / f"{ORDER}.json"
    return Facts.from_dict(json.loads(path.read_text(encoding="utf-8")))


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
    ist = {(r.check_id, r.group_label) for r in results
           if r.status == "fail" and r.kind == "check"}
    soll = {(e["check"], e["group"]) for e in EXPECTED["findings"]}
    neu = ist - soll
    assert not neu, (
        "Neue Befunde ohne Eintrag in der Soll-Liste: "
        f"{sorted(neu)}. Wenn gewollt: "
        "python3 scripts/golden/build-expected-order.py "
        f"{ORDER} --name {NAME}")


# ------------------------------------------ Issue #12: DNS je Domain

def test_dns_fakten_fuer_beide_domains(facts):
    """Vor S2b lief DNS nur fuer die erste Domain einer Multi-Target-Order."""
    domains = sorted({d.domain for d in facts.dns})
    assert domains == ["junkerwerk.de", "junkerwerk.hu"], domains


@pytest.mark.parametrize("domain", ["junkerwerk.de", "junkerwerk.hu"])
@pytest.mark.parametrize("feld", ["spf", "dmarc"])
def test_mailsicherheit_je_domain_entschieden(facts, domain, feld):
    """Ohne eigene Zeile je Domain waere jede SPF- oder DMARC-Aussage geraten."""
    zeilen = [d for d in facts.dns if d.domain == domain]
    assert zeilen, f"keine DNS-Zeile fuer {domain}"
    assert any(getattr(d, feld) is not None for d in zeilen), (
        f"{domain}: kein {feld.upper()}-Ergebnis, Aussage waere nicht belegt")


# ------------------------------- Issue #17: zweites Ziel ohne eigene Hosts

def test_zweites_ziel_ohne_eigene_hosts(facts):
    """Dokumentiert den offenen Fall, nicht eine gewuenschte Eigenschaft.

    junkerwerk.hu loest auf 188.40.3.130 auf, also auf denselben Host wie
    junkerwerk.de. Die Hostliste kennt danach keine Adresse mehr, die allein
    zur zweiten Domain gehoert.
    """
    ziele = sorted({t.domain for t in facts.targets})
    assert ziele == ["junkerwerk.de", "junkerwerk.hu"], ziele
    nur_hu = [f for f in facts.fqdns if (f.name or "").endswith("junkerwerk.hu")]
    assert not nur_hu, (
        "junkerwerk.hu hat jetzt eigene FQDN-Zeilen: "
        f"{[f.id for f in nur_hu]}. Issue #17 waere damit erledigt, der Test "
        "gehoert dann umgeschrieben.")


# ---------------------------------------- Issue #8: IPv6-Lauf am echten Ziel

def test_ipv6_host_ist_im_lauf(facts):
    """Erstes Fixture mit einem AAAA-Host, Grundlage fuer den #8-Nachweis."""
    v6 = [h for h in facts.hosts if h.family == 6]
    assert [h.id for h in v6] == [f"host:[{IPV6}]"], [h.id for h in facts.hosts]


def test_kein_target_invalid_ipv6_mehr(facts):
    """Der Schalter -6 greift: die alte Signatur ist verschwunden.

    In den Laeufen 0bf16342 und 2572eebc traegt derselbe Host
    ``failed / target_invalid_ipv6``, weil nmap ohne ``-6`` lief und das Ziel
    als ``invalid`` uebersprang.
    """
    gruende = [c.reason for c in facts.coverage if c.tool == "nmap"]
    assert "target_invalid_ipv6" not in gruende, gruende


def test_ipv6_portscan_bleibt_ohne_ergebnis(facts):
    """Ist-Stand, Issue #8 bleibt offen.

    nmap lief mit ``-6``, meldete ``exit=success`` und ``hosts up=1``, kam
    aber in 0,32 Sekunden ohne einen einzigen Hostblock zurueck; fuer den
    IPv4-Host desselben Auftrags dauerte derselbe Aufruf 85 Sekunden. Die
    Abdeckung macht daraus ``ok`` mit ``no_open_ports``, also eine Aussage
    ueber einen Host, der nie erreicht wurde.

    Am Tar ist dieser Lauf nicht von "Host lebt, kein Port offen" zu
    unterscheiden (vergleiche 217.243.248.27 in 0bf16342, gleiche XML-Form
    nach 23 Sekunden echtem Scan). Deshalb prueft seit S2c der Scanner selbst
    die Route und meldet ``no_ipv6_route``; dieses Fixture ist aelter als die
    Aenderung und zeigt den alten Stand.
    """
    nmap_v6 = [c for c in facts.coverage if c.tool == "nmap" and c.host_ip == IPV6]
    assert len(nmap_v6) == 1, [c.id for c in nmap_v6]
    assert (nmap_v6[0].status, nmap_v6[0].reason) == ("ok", "no_open_ports"), (
        f"Abdeckung des IPv6-Hosts ist jetzt {nmap_v6[0].status}/{nmap_v6[0].reason}. "
        "Wenn das eine Verbesserung ist, diesen Test nachziehen und Issue #8 "
        "neu bewerten.")
    assert not [s for s in facts.services if s.host_ip == IPV6], (
        "Dienste am IPv6-Host, obwohl der Portscan nichts geliefert hat")


def test_ipv4_gegenprobe_desselben_fqdn(facts):
    """nachhaltigkeit.junkerwerk.de ist ueber IPv4 voll geprueft.

    Der Vergleich der Portlisten, den S2c verlangt, hat damit auf der einen
    Seite 13 Ports und auf der anderen keine Messung. Ein Dienst, der nur
    ueber IPv6 erreichbar waere, liesse sich aus diesen Daten nicht zeigen.
    """
    v4 = [h for h in facts.hosts if h.id == "host:188.40.3.130"]
    assert v4 and (v4[0].ports_summary.open or 0) > 0, "IPv4-Gegenprobe fehlt"
