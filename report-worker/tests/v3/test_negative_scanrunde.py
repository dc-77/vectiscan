# -*- coding: utf-8 -*-
"""Negativ-Fixtures der Scan-Runde (S6b-2, spec/09) gegen den neu erzeugten Bericht.

``tests/golden/negative.json`` fuehrt je Falschaussage der sieben Auftraege der Scan-Runde
unter ``pruefung`` die maschinelle Fassung des Verbots (scripts/golden/build-negative-fixtures.py).
Dieser Test baut den Bericht aus den Golden-Fakten desselben Auftrags und wendet sie an:

* ``text``: das Muster steht in keinem Befund (Titel, Betroffen, Befundtext, Auswirkung,
  Empfehlung, Verifikation, Nachweis), Positivbefund oder Anhang, je nach ``bereich``;
  ``ausser_regeln`` erlaubt es an Befunden dieser Regeln, ``nur_regeln`` beschraenkt das
  Verbot auf Befunde dieser Regeln.
* ``dringlichkeit`` und ``skala``: der Befund mit dem genannten Betroffenen existiert und
  steht auf einem erlaubten Wert.
* ``regel``: kein Befund traegt die genannte Regel fuer den genannten Betroffenen.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests.v3.conftest import data_for

GOLDEN = Path(__file__).resolve().parents[1] / "golden"
NEGATIVE = json.loads((GOLDEN / "negative.json").read_text(encoding="utf-8"))
ENTRIES = [e for e in NEGATIVE["entries"] if e.get("pruefung")]


def _regeln(finding) -> set[str]:
    return {p.check for p in finding.provenance}


def _befundtext(f) -> str:
    teile = [f.title, f.affected, f.found, f.impact, f.verify, f.evidence or ""]
    teile += [text for _stufe, text in f.recommendation]
    return " ".join(t for t in teile if t)


def _verstoesse(entry: dict) -> list[str]:
    data = data_for(entry["order"])
    regel = entry["pruefung"]
    art = regel["art"]
    out: list[str] = []
    if art == "text":
        muster = re.compile(regel["muster"], re.I)
        bereich = regel["bereich"]
        ausser = set(regel.get("ausser_regeln") or [])
        nur = set(regel.get("nur_regeln") or [])
        if bereich in ("befunde", "alles"):
            for f in data.findings:
                regeln = _regeln(f)
                if ausser & regeln or (nur and not nur & regeln):
                    continue
                treffer = muster.search(_befundtext(f))
                if treffer:
                    out.append(f"{f.id}: {treffer.group(0)!r} in {f.title}")
        if bereich in ("positive", "alles"):
            for p in data.positives:
                treffer = muster.search(f"{p.title} {p.text}")
                if treffer:
                    out.append(f"Positiv {p.title}: {treffer.group(0)!r}")
        if bereich == "alles":
            for t in data.appendix.tool_findings:
                treffer = muster.search(f"{t.what} {t.note}")
                if treffer:
                    out.append(f"Anhang {t.what}: {treffer.group(0)!r}")
        return out
    if art == "regel":
        grenze = re.compile(rf"(?<![\w.-]){re.escape(regel['betroffen'])}(?![\w-])")
        for f in data.findings:
            if regel["regel"] in _regeln(f) and grenze.search(f.affected):
                out.append(f"{f.id}: {regel['regel']} fuer {regel['betroffen']}")
        return out
    betroffen = regel["betroffen"]
    # Genau dieser Name, nicht als Teil eines laengeren (castenow.de in mailstore.castenow.de).
    grenze = re.compile(rf"(?<![\w.-]){re.escape(betroffen)}(?![\w-])")
    passend = [f for f in data.findings if grenze.search(f.affected)]
    if not passend:
        return [f"kein Befund nennt {betroffen}"]
    for f in passend:
        wert = f.urgency if art == "dringlichkeit" else f.scale
        if wert not in regel["erlaubt"]:
            out.append(f"{f.id} {betroffen}: {wert} statt {regel['erlaubt']}")
    return out


@pytest.mark.parametrize("entry", ENTRIES, ids=[f"{e['pattern']}:{e['kuerzel']}:{e['finding_id']}" for e in ENTRIES])
def test_falschaussage_der_scanrunde_entsteht_nicht(entry: dict) -> None:
    verstoesse = _verstoesse(entry)
    assert not verstoesse, (entry["verbotene_aussage"], verstoesse)


def test_jedes_muster_der_scanrunde_hat_eine_pruefung() -> None:
    muster = {e["pattern"] for e in NEGATIVE["entries"] if e["pattern"].startswith("NEG-S6B2-")}
    mit_pruefung = {e["pattern"] for e in ENTRIES}
    assert muster and muster == mit_pruefung
    # Die sieben Auftraege der Scan-Runde (spec/09) kommen alle vor.
    assert len({e["order"] for e in ENTRIES}) == 7


def test_pruefung_greift_an_einer_beschaedigten_kopie() -> None:
    """Die Pruefung ist keine Attrappe: ein zurueckgeschriebener Altsatz faellt auf."""
    entry = next(e for e in ENTRIES if e["pattern"] == "NEG-S6B2-DMARC-FEHLT-TITEL")
    data = data_for(entry["order"])
    original = data.findings[0].title
    try:
        data.findings[0].title = "Richtlinie zur Absender-Authentizität nicht durchsetzend"
        assert _verstoesse(entry)
    finally:
        data.findings[0].title = original


def _alter_eintrag(entry: dict) -> dict:
    """Der Befund oder Positivbefund aus dem ausgelieferten Bericht (Version 1)."""
    doc = json.loads((GOLDEN / "api-snapshot" / entry["order"] / "findings.json").read_text(encoding="utf-8"))
    data = doc["data"]
    liste = data["positive_findings"] if entry.get("positiv") else data["findings"]
    return next(f for f in liste if f["id"] == entry["finding_id"])


def _alt_text(f: dict) -> str:
    teile = []
    for key in ("title", "description", "impact", "recommendation", "verification", "evidence", "affected"):
        wert = f.get(key)
        teile.append(wert if isinstance(wert, str) else json.dumps(wert, ensure_ascii=False))
    return " ".join(teile)


@pytest.mark.parametrize("entry", ENTRIES, ids=[f"{e['pattern']}:{e['kuerzel']}:{e['finding_id']}" for e in ENTRIES])
def test_pruefung_trifft_den_ausgelieferten_bericht(entry: dict) -> None:
    """Gegenprobe: dieselbe Pruefung haette die Falschaussage in Version 1 gefunden."""
    alt = _alter_eintrag(entry)
    regel = entry["pruefung"]
    if regel["art"] == "text":
        assert re.search(regel["muster"], _alt_text(alt), re.I), (entry["pattern"], alt["title"])
    elif regel["art"] == "regel":
        regeln = {r.strip() for r in str(alt.get("policy_id") or "").split(",")}
        assert regel["regel"] in regeln and regel["betroffen"] in _alt_text(alt), (entry["pattern"], alt["title"])
    elif regel["art"] == "dringlichkeit":
        assert alt["urgency"] not in regel["erlaubt"], (entry["pattern"], alt["urgency"])
    else:
        assert alt["scale"] not in regel["erlaubt"], (entry["pattern"], alt["scale"])
