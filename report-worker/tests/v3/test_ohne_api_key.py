# -*- coding: utf-8 -*-
"""Ohne Zugangsschluessel laeuft alles mit Katalogtexten durch.

Das ist die Zusage aus spec/05: der Bericht ist ohne KI vollstaendig und korrekt; die
KI macht ihn lesbarer, nicht richtiger. Ein fehlender Schluessel ist deshalb kein
Fehler, sondern der Normalfall im Test und in der Entwicklung.
"""
from __future__ import annotations

import pytest

from reporter.v3 import prose
from reporter.v3.selfcheck import check_report_data
from tests.v3.conftest import junkerwerk_data


@pytest.fixture
def ohne_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    return None


def test_prosa_meldet_sich_ab(ohne_key):
    assert not prose.available()
    fields, cost = prose.generate({"scan": {}})
    assert fields == {}
    assert cost == {}


def test_bericht_ist_ohne_ki_vollstaendig(ohne_key):
    data = junkerwerk_data()
    assert check_report_data(data) == []
    assert data.glance.overall_text
    assert data.business.implication
    assert all(o.meaning for o in data.business.observed)
    assert all(f.impact for f in data.findings)
    assert data.meta.prose_rejected == []


def test_eingabe_der_ki_traegt_keine_rohdaten(ohne_key):
    """Die Nutzlast besteht aus fertigen Befunden, nicht aus Werkzeugausgaben."""
    data = junkerwerk_data()
    payload = prose.build_payload(data, {"branche": "Maschinenbau"})
    assert set(payload) == {"scan", "kunde", "kategorien", "systeme", "systeme_2_1", "befunde",
                            "positive", "plan", "betriebsformen"}
    # S6b-3 (spec/10 R13, E9): Branche und Mitarbeiterzahl nur mit Quelle Kunde oder Admin.
    assert payload["kunde"] == {}
    belegt = {"branche": "Maschinenbau", "mitarbeiter": "40",
              "sources": {"branche": {"source": "kunde"}, "mitarbeiter": {"source": "recherche"}}}
    assert prose.build_payload(data, belegt)["kunde"] == {
        "branche": "Maschinenbau", "sources": belegt["sources"]}
    for befund in payload["befunde"]:
        assert set(befund) == {"id", "kategorie", "titel", "betroffen", "quelle",
                               "beobachtung", "bedeutung", "dringlichkeit", "fremdreferenzen"}
    text = str(payload)
    assert "nmap.xml" not in text and "evidence" not in text


def test_beide_ki_aufrufe_laufen_auf_demselben_modell() -> None:
    """Prosa und Recherche auf Opus 5 (S5-Nachtrag).

    Der Wechsel von Opus 4.7 war eine Kostenentscheidung: derselbe Aufruf kostet
    ein Drittel. Das Modell steht im Cache-Schluessel, ein Wechsel invalidiert
    die alten Eintraege von selbst.
    """
    from reporter.v3 import research
    from reporter.v3.aicost import PRICING

    assert prose.OPUS_MODEL == "claude-opus-5"
    assert research.OPUS_MODEL == prose.OPUS_MODEL
    # Ohne Preiseintrag rechnet die Kostenzeile still mit null.
    assert PRICING[prose.OPUS_MODEL] == (5.0, 25.0)
