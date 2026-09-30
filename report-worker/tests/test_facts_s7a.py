# -*- coding: utf-8 -*-
"""S7a: Fakten 1.5.0, Nebenpfad-Instanzen gemischter ZAP-Gruppen (Punkt 6).

Entscheidung DC (30.09.): additives Faktenfeld ``WebAlert.other_locations``. Bis S6d warf der
Faktenbau die Instanzen eines Meldungstyps an Nebenpfaden, Fehler- und Abwehrseiten weg, sobald
derselbe Typ auch an der Zielseite auftrat; Anhang C konnte sie nicht zeigen (README Golden,
Abgleich S6d A7).

Die Abnahme verlangt unveraenderte Golden-Facts ausser Punkt 0. ``tests/golden/facts-vor-s7a.json``
haelt deshalb je Auftrag die Pruefsumme der Fakten vor Punkt 6 (nach Punkt 0); der Test entfernt
das neue Feld und die Schemaversion und vergleicht.

Neu schreiben (nur vor einer Schemaaenderung, nie danach):
    python -m tests.test_facts_s7a
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from reporter.facts import schema as S
from reporter.facts.golden import facts_path, golden_orders
from reporter.facts.serialize import dumps, load_json

HERE = Path(__file__).resolve().parent
DIGESTS = HERE / "golden" / "facts-vor-s7a.json"
CA = "cd28d260-cf49-4d17-a980-64a4b1951444"

# Felder, die S7a der Faktenschicht hinzufuegt (additiv).
NEUE_FELDER = ("other_locations",)


def _ohne_neue_felder(obj):
    if isinstance(obj, dict):
        return {k: _ohne_neue_felder(v) for k, v in obj.items() if k not in NEUE_FELDER}
    if isinstance(obj, list):
        return [_ohne_neue_felder(v) for v in obj]
    return obj


def normalisiert(data: dict) -> str:
    """Pruefsumme der Fakten ohne die S7a-Felder und ohne Schemaversion."""
    rein = _ohne_neue_felder(data)
    rein.pop("schema_version", None)
    return hashlib.sha256(dumps(rein).encode("utf-8")).hexdigest()


def _orders() -> list[str]:
    return [e["order_id"] for e in golden_orders() if facts_path(e["order_id"]).exists()]


def test_schema_ist_1_5_0():
    assert S.FACTS_SCHEMA_VERSION == "1.5.0"


@pytest.mark.parametrize("order_id", _orders())
def test_fakten_ohne_neue_felder_unveraendert(order_id):
    erwartet = json.loads(DIGESTS.read_text(encoding="utf-8"))
    assert normalisiert(load_json(facts_path(order_id))) == erwartet[order_id], (
        f"{order_id}: Fakten weichen ueber das additive Feld hinaus vom Stand vor S7a ab")


# ---------------------------------------------------------------- Punkt 6: Nebenpfad-Instanzen

def _alert(order_id: str, fqdn: str, plugin: str):
    from tests.v3.conftest import facts_for
    return next(a for h in facts_for(order_id).http if h.fqdn == fqdn for a in h.alerts
                if a.plugin_id == plugin)


def test_castenow_mail_behaelt_die_nebenpfad_instanzen():
    a = _alert(CA, "mail.castenow.de", "10036")
    assert a.location == "target"
    andere = [(i.location, i.url, i.status) for i in a.other_locations]
    assert ("side_path", "https://mail.castenow.de/robots.txt", 302) in andere
    assert ("side_path", "https://mail.castenow.de/sitemap.xml", 302) in andere
    assert ("error_page", "https://mail.castenow.de/owa/auth/", 500) in andere
    rang = {"side_path": 0, "error_page": 1, "challenge": 2}
    assert [i.location for i in a.other_locations] == sorted((i.location for i in a.other_locations),
                                                             key=rang.__getitem__)


def test_gemischte_gruppe_im_faktenbau():
    from types import SimpleNamespace

    from reporter.facts.build import _zap_alerts_by_host

    class Ctx:
        def warn(self, *_):
            pass

        def add_unprocessed(self, *_, **__):
            pass

        def run_ref(self, *_):
            return None

    def meldung(url, status):
        return {"name": "Strict-Transport-Security Header Not Set", "pluginId": "10035", "risk": "Low",
                "confidence": "Medium", "url": url, "status": status, "sourceid": "3"}

    h = SimpleNamespace(ip="192.0.2.1", zap_summary=None, zap_alerts=[
        meldung("https://x.example/robots.txt", 302),
        meldung("https://x.example/", 200),
        meldung("https://x.example/sitemap.xml", 302),
        meldung("https://x.example/login", 429),
    ])
    (a,) = _zap_alerts_by_host(Ctx(), h)["x.example"]
    # Zielseite unveraendert: Adressen und Status nur von dort.
    assert a.location == "target" and a.urls_sample == ["https://x.example/"] and a.statuses == [200]
    assert [(i.location, i.url, i.status) for i in a.other_locations] == [
        ("side_path", "https://x.example/robots.txt", 302),
        ("side_path", "https://x.example/sitemap.xml", 302),
        ("challenge", "https://x.example/login", 429),
    ]


@pytest.mark.parametrize("order_id", _orders())
def test_nachrangige_fundorte_nie_der_eigene_und_hoechstens_zehn(order_id):
    from tests.v3.conftest import facts_for
    for h in facts_for(order_id).http:
        for a in h.alerts:
            assert all(i.location != a.location for i in a.other_locations)
            assert len(a.other_locations) <= 10


if __name__ == "__main__":
    out = {o: normalisiert(load_json(facts_path(o))) for o in _orders()}
    DIGESTS.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"{DIGESTS.name}: {len(out)} Auftraege")
