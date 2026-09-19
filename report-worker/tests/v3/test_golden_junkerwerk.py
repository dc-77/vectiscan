# -*- coding: utf-8 -*-
"""Abnahme gegen die Soll-Liste des Prototyps.

Die Soll-Liste (``tests/golden/expected/junkerwerk.json``) sind die 15 Befunde und 8
Positivbefunde des handkuratierten Prototyps. Die Zuordnung Soll-Befund zu Pruefung
steht in ``tests/catalog/expected_map.json`` und wird schon von S2 benutzt.

Geprueft wird Abdeckung, nicht Gleichheit: jeder Sachverhalt des Prototyps muss in den
Reportdaten v3 als Befund auftauchen. Wo v3 anders schneidet als die Handarbeit, steht
der Grund in ``reporter/v3/deltas.md``; die Abweichungen sind hier als Datenstruktur
festgehalten, damit eine neue Abweichung auffaellt.
"""
from __future__ import annotations

import json

import pytest

from reporter.facts.serialize import load_json
from reporter.v3.bundles import consolidate
from tests.v3.conftest import GOLDEN, JUNKERWERK, data_for, junkerwerk_data, output_for

EXPECTED_MAP = GOLDEN.parent / "catalog" / "expected_map.json"
SOLL = GOLDEN / "expected" / "junkerwerk.json"

# Soll-Befunde, die im Multi-Lauf nicht entstehen koennen, mit Grund.
NUR_IN_LAUF = {"VS-2026-010": "hu"}

# Soll-Befunde, die v3 bewusst auf mehrere Befunde verteilt, mit Begruendung.
# Jede weitere Aufteilung faellt hier auf und gehoert nach reporter/v3/deltas.md.
GETEILT = {
    "VS-2026-013": ("Der Prototyp fasst die Header-Luecken zweier Hosts in einem Befund "
                    "zusammen; das Buendel web_header_hygiene trennt nach Host, weil die "
                    "Massnahme je Host eine andere ist."),
}


@pytest.fixture(scope="module")
def soll():
    return json.loads(SOLL.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def mapping():
    return json.loads(EXPECTED_MAP.read_text(encoding="utf-8"))


def _checks_per_finding(order_id: str) -> list[tuple[set[str], set[str], object]]:
    """(beteiligte Pruef-IDs, beteiligte Hosts, Befund) je Befund."""
    output = output_for(order_id)
    items, _ = consolidate(output)
    finding_items = [i for i in items if i.target == "findings"]
    data = data_for(order_id)
    out = []
    for item, finding in zip(finding_items, data.findings):
        hosts = {str(r.vars.get("host_ip")) for r in item.results if r.vars.get("host_ip")}
        hosts |= {m.host_ip for r in item.results for m in r.members if m.host_ip}
        hosts.add(item.merge_key)
        out.append(({r.check_id for r in item.results}, hosts, finding))
    return out


def _appendix_checks(order_id: str) -> set[str]:
    items, _ = consolidate(output_for(order_id))
    return {r.check_id for i in items if i.target == "appendix" for r in i.results}


def _positive_checks(order_id: str) -> list[set[str]]:
    _, positives = consolidate(output_for(order_id))
    return [{r.check_id for r in p.results} for p in positives]


@pytest.mark.parametrize("vs_id", [f"VS-2026-{n:03d}" for n in range(1, 16)])
def test_jeder_prototyp_befund_ist_abgedeckt(vs_id, mapping):
    entry = mapping["findings"][vs_id]
    lauf = NUR_IN_LAUF.get(vs_id, "multi")
    order_id = JUNKERWERK[lauf]
    leitpruefung = entry["checks"][0]
    hosts = set(entry.get("hosts") or [])
    treffer = [
        finding for checks, befund_hosts, finding in _checks_per_finding(order_id)
        if leitpruefung in checks and (not hosts or hosts & befund_hosts)
    ]
    assert treffer, (
        f"{vs_id}: kein Befund v3 enthaelt die Pruefung {leitpruefung}"
        f"{' auf ' + ', '.join(sorted(hosts)) if hosts else ''}")
    if len(treffer) > 1:
        assert vs_id in GETEILT, (
            f"{vs_id}: {leitpruefung} unerwartet verteilt auf {[t.id for t in treffer]}; "
            "beabsichtigt? dann nach GETEILT und deltas.md eintragen")


def test_keine_pruefung_der_soll_liste_geht_verloren(mapping):
    """Jede in der Soll-Liste genannte Pruefung landet in einem Befund oder im Anhang."""
    order_id = JUNKERWERK["multi"]
    im_bericht = {c for checks, _, _ in _checks_per_finding(order_id) for c in checks}
    im_anhang = _appendix_checks(order_id)
    in_positiv = {c for s in _positive_checks(order_id) for c in s}
    fehlend: list[str] = []
    for vs_id, entry in mapping["findings"].items():
        if NUR_IN_LAUF.get(vs_id):
            continue
        for check in entry["checks"]:
            if check not in im_bericht | im_anhang | in_positiv:
                fehlend.append(f"{vs_id}/{check}")
    assert not fehlend, fehlend


@pytest.mark.parametrize("p_id", [f"VS-2026-P{n:02d}" for n in range(1, 9)])
def test_jeder_positivbefund_ist_abgedeckt(p_id, mapping):
    entry = mapping["positives"][p_id]
    leitpruefung = entry["checks"][0]
    treffer = [s for s in _positive_checks(JUNKERWERK["multi"]) if leitpruefung in s]
    assert treffer, f"{p_id}: kein Positivbefund v3 enthaelt {leitpruefung}"
    assert len(treffer) == 1, f"{p_id}: {leitpruefung} in mehreren Positivbefunden"


def test_kein_fehlgeschlagener_check_verschwindet():
    """Jede fehlgeschlagene Pruefgruppe steht in einem Befund oder im Anhang."""
    order_id = JUNKERWERK["multi"]
    output = output_for(order_id)
    fails = {r.check_id for r in output.results if r.status == "fail" and r.kind == "check"}
    im_bericht = {c for checks, _, _ in _checks_per_finding(order_id) for c in checks}
    assert fails - (im_bericht | _appendix_checks(order_id)) == set()


def test_ids_tragen_das_kuerzel_aus_dem_kundenkontext():
    data = junkerwerk_data()
    assert data.meta.report_id == "VS-JW-2026-0831"
    assert data.findings[0].id == "VS-JW-2026-001"
    assert [f.id for f in data.findings] == [
        f"VS-JW-2026-{n:03d}" for n in range(1, len(data.findings) + 1)]


def test_kopf_und_zahlen_stimmen_mit_der_soll_liste(soll):
    data = junkerwerk_data()
    assert data.meta.customer == soll["customer"]
    assert data.meta.domains == soll["domains"]
    assert data.meta.package.lower() == soll["package"]
    assert [o.id for o in data.meta.orders] == soll["order_ids"]
    assert data.meta.consolidated == len(data.findings)
    assert data.meta.positives == len(data.positives)


# Aus tests/golden/negative.json abgeleitete Textmuster, die in keinem Kundentext
# stehen duerfen. Die Eintraege selbst nennen ausgelieferte Titel der alten Pipeline;
# hier steht die kurze, pruefbare Form davon.
VERBOTENE_MUSTER: dict[str, tuple[str, ...]] = {
    "NEG-EXCHANGE-2016": ("exchange 2016",),
    "NEG-MARIADB-55": ("mysql 5.5", "mariadb 5.5"),
    "NEG-SPF-MISSING": ("spf-record fehlt", "spf fehlt"),
    "NEG-MAIL-PLAINTEXT": ("im klartext exponiert",),
    "NEG-TITLE-PLACEHOLDER": ("[hinweis", "{host}"),
}


def test_negativ_fixtures_erscheinen_nicht_im_bericht():
    """Die belegbaren Falschbefunde der alten Pipeline duerfen nicht zurueckkehren."""
    negative = load_json(GOLDEN / "negative.json")
    junkerwerk = [e for e in negative["entries"]
                  if str(e.get("order", "")).startswith(("0bf16342", "2572eebc", "a6df9d9d"))]
    assert junkerwerk, "keine Junkerwerk-Negativfixtures gefunden"
    patterns = {e["pattern"] for e in junkerwerk}
    assert patterns <= set(VERBOTENE_MUSTER), (
        f"neues Negativmuster ohne Textprobe: {sorted(patterns - set(VERBOTENE_MUSTER))}")
    data = junkerwerk_data()
    texte = " ".join(
        f"{f.title} {f.found} {f.impact} {f.affected}" for f in data.findings).lower()
    texte += " " + " ".join(
        f"{r.c} {r.v} {r.note}" for b in data.architecture.tech for r in b.rows).lower()
    for pattern in sorted(patterns):
        for muster in VERBOTENE_MUSTER[pattern]:
            assert muster not in texte, f"{pattern}: {muster!r} steht wieder im Bericht"
