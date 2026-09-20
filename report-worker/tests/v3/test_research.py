# -*- coding: utf-8 -*-
"""Die Recherche-KI fuer den Kundenkontext (S5).

Der Aufruf selbst wird hier nicht gefahren. Geprueft wird, was mit dem Vorschlag
passiert: Kundenangaben bleiben stehen, Angaben ohne Fundstelle fliegen raus, und
ohne Zugangsschluessel laeuft alles leer durch.
"""
from __future__ import annotations

import pytest

from reporter.v3 import research

FQDNS = ["www.beispiel.de", "shop.beispiel.de"]

VOLLSTAENDIG = {
    "firmenname": {"wert": "Beispiel Maschinenbau GmbH", "quelle": "https://beispiel.de/impressum"},
    "branche": {"wert": "Maschinenbau", "quelle": "https://beispiel.de/ueber-uns"},
    "mitarbeiter": {"wert": "120", "quelle": "https://beispiel.de/ueber-uns"},
    "systeme": [{"fqdn": "www.beispiel.de", "zweck": "Unternehmenswebsite",
                 "quelle": "https://beispiel.de"}],
}


def test_ohne_api_schluessel_laeuft_es_leer_durch(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    assert research.available() is False
    assert research.suggest({"domains": ["beispiel.de"]}) == ({}, {})


def test_ohne_domains_wird_gar_nicht_gefragt(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")

    assert research.suggest({"domains": [], "hostnamen": []}) == ({}, {})


def test_eingabe_traegt_nur_domains_und_hostnamen() -> None:
    payload = research.build_payload(["beispiel.de", ""], FQDNS + [""])

    assert set(payload) == {"domains", "hostnamen"}
    assert payload["domains"] == ["beispiel.de"]
    assert payload["hostnamen"] == sorted(FQDNS)


def test_vorschlag_wird_mit_quelle_uebernommen() -> None:
    kontext, abgelehnt = research.apply_suggestion({}, VOLLSTAENDIG, fqdns=FQDNS)

    assert kontext["firmenname"] == "Beispiel Maschinenbau GmbH"
    assert kontext["branche"] == "Maschinenbau"
    assert kontext["systeme"] == [{"fqdn": "www.beispiel.de", "zweck": "Unternehmenswebsite"}]
    assert abgelehnt == []
    for feld in ("firmenname", "branche", "mitarbeiter", "systeme"):
        assert kontext["sources"][feld]["source"] == "recherche"
        assert kontext["sources"][feld]["url"].startswith("https://")


def test_kundenangabe_wird_nie_ueberschrieben() -> None:
    vorher = {"firmenname": "Echte Firma GmbH",
              "sources": {"firmenname": {"source": "kunde"}}}

    kontext, _ = research.apply_suggestion(vorher, VOLLSTAENDIG, fqdns=FQDNS)

    assert kontext["firmenname"] == "Echte Firma GmbH"
    assert kontext["sources"]["firmenname"] == {"source": "kunde"}


def test_admin_korrektur_wird_nie_ueberschrieben() -> None:
    """Auch ein geleertes Feld bleibt leer, wenn ein Admin es geleert hat."""
    vorher = {"sources": {"branche": {"source": "admin"}}}

    kontext, _ = research.apply_suggestion(vorher, VOLLSTAENDIG, fqdns=FQDNS)

    assert "branche" not in kontext


@pytest.mark.parametrize("feld,eintrag,grund", [
    ("firmenname", {"wert": "Beispiel GmbH"}, "keine Fundstellen-URL"),
    ("firmenname", {"wert": "Beispiel GmbH", "quelle": "beispiel.de"}, "keine Fundstellen-URL"),
    ("branche", {"wert": "Maschinenbau – Sondermaschinen",
                 "quelle": "https://beispiel.de"}, "Wert unbrauchbar"),
    ("mitarbeiter", {"wert": "etwa 120", "quelle": "https://beispiel.de"}, "Wert unbrauchbar"),
    ("branche", {"wert": "Maschinenbau fuer Kunststoff",
                 "quelle": "https://beispiel.de"}, "Wert unbrauchbar"),
])
def test_unbrauchbare_angaben_werden_abgelehnt(feld, eintrag, grund) -> None:
    """Keine Quelle, ein Gedankenstrich, eine Umschrift oder eine Schaetzung."""
    kontext, abgelehnt = research.apply_suggestion({}, {feld: eintrag}, fqdns=FQDNS)

    assert feld not in kontext
    assert abgelehnt == [f"{feld}: {grund}"]


def test_fremdes_system_wird_nicht_uebernommen() -> None:
    """Ein Hostname, den der Scan nicht gesehen hat, gehoert nicht in den Bericht."""
    vorschlag = {"systeme": [
        {"fqdn": "fremd.example.org", "zweck": "Irgendwas", "quelle": "https://beispiel.de"},
        {"fqdn": "shop.beispiel.de", "zweck": "Onlineshop", "quelle": "https://beispiel.de/shop"},
    ]}

    kontext, abgelehnt = research.apply_suggestion({}, vorschlag, fqdns=FQDNS)

    assert kontext["systeme"] == [{"fqdn": "shop.beispiel.de", "zweck": "Onlineshop"}]
    assert abgelehnt == ["systeme: fremd.example.org nicht im Scan"]


def test_leerer_vorschlag_aendert_nichts() -> None:
    vorher = {"kuerzel": "BSP", "sources": {"kuerzel": {"source": "kunde"}}}

    kontext, abgelehnt = research.apply_suggestion(vorher, {}, fqdns=FQDNS)

    assert kontext == vorher
    assert abgelehnt == []


def test_websuche_ist_das_einzige_werkzeug() -> None:
    """Ein zweites Ausfuehrungswerkzeug daneben verwirrt das Modell (Doku Anthropic)."""
    assert research.WEB_SEARCH_TOOL["type"] == "web_search_20260209"
    assert research.OPUS_MODEL == "claude-opus-5"
