# -*- coding: utf-8 -*-
"""Kundenkontext im Worker (S5).

Der Firmenname soll ohne KI auskommen, wenn er schon in der Kundenanlage steht.
Die Recherche laeuft nur fuer die Felder, die dann noch leer sind.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from reporter.worker import (_load_customer_context, _research_customer_context,
                             _store_customer_context)

INVENTORY = {
    "domain": "beispiel.de",
    "hosts": [{"ip": "1.2.3.4", "fqdns": ["www.beispiel.de", "beispiel.de"]},
              {"ip": "1.2.3.5", "fqdns": []}],
}


def _conn(row) -> MagicMock:
    conn = MagicMock()
    conn.cursor.return_value.__enter__.return_value.fetchone.return_value = row
    return conn


def test_firmenname_kommt_aus_der_kundenanlage() -> None:
    """customers.company_name gilt als Kundenangabe, kein KI-Aufruf noetig."""
    context = _load_customer_context(_conn((None, "Beispiel Maschinenbau GmbH")), "o1")

    assert context["firmenname"] == "Beispiel Maschinenbau GmbH"
    assert context["sources"]["firmenname"] == {"source": "kunde"}


def test_gespeicherter_kontext_gewinnt_gegen_die_kundenanlage() -> None:
    gespeichert = {"firmenname": "Neu GmbH", "sources": {"firmenname": {"source": "admin"}}}

    context = _load_customer_context(_conn((gespeichert, "Alt GmbH")), "o1")

    assert context["firmenname"] == "Neu GmbH"
    assert context["sources"]["firmenname"] == {"source": "admin"}


def test_kontext_als_text_wird_gelesen() -> None:
    """Je nach Treiber kommt jsonb als dict oder als Zeichenkette zurueck."""
    context = _load_customer_context(
        _conn((json.dumps({"kuerzel": "BSP"}), None)), "o1")

    assert context["kuerzel"] == "BSP"


def test_ohne_zeile_bleibt_der_kontext_leer() -> None:
    assert _load_customer_context(_conn(None), "o1") == {}


def test_datenbankfehler_bleibt_folgenlos() -> None:
    """Fehlt die Spalte (alte Datenbank im Rolling-Deploy), laeuft es weiter."""
    import psycopg2

    conn = MagicMock()
    conn.cursor.side_effect = psycopg2.Error("column customer_context does not exist")

    assert _load_customer_context(conn, "o1") == {}
    conn.rollback.assert_called_once()


def test_ohne_api_schluessel_wird_nichts_recherchiert(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    conn = MagicMock()

    context = _research_customer_context(conn, "o1", {"kuerzel": "BSP"}, INVENTORY)

    assert context == {"kuerzel": "BSP"}
    conn.cursor.assert_not_called()


def test_vollstaendiger_kontext_loest_keinen_aufruf_aus(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    voll = {"firmenname": "Beispiel GmbH", "branche": "Maschinenbau",
            "mitarbeiter": "120", "systeme": [{"fqdn": "www.beispiel.de", "zweck": "Website"}]}

    with patch("reporter.v3.research.suggest") as suggest:
        context = _research_customer_context(MagicMock(), "o1", voll, INVENTORY)

    suggest.assert_not_called()
    assert context == voll


def test_vorschlag_wird_uebernommen_und_gespeichert(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    conn = MagicMock()
    vorschlag = {"branche": {"wert": "Maschinenbau", "quelle": "https://beispiel.de/ueber-uns"}}

    with patch("reporter.v3.research.suggest", return_value=(vorschlag, {})) as suggest:
        context = _research_customer_context(conn, "o1", {"firmenname": "Beispiel GmbH"},
                                             INVENTORY)

    # Die KI sieht nur Domains und Hostnamen, nichts aus dem Scan.
    payload = suggest.call_args[0][0]
    assert payload == {"domains": ["beispiel.de"],
                       "hostnamen": ["beispiel.de", "www.beispiel.de"]}
    assert context["branche"] == "Maschinenbau"
    assert context["sources"]["branche"]["source"] == "recherche"
    # Gespeichert wird genau einmal, mit dem ergaenzten Kontext.
    conn.cursor.assert_called()


def test_fehler_der_recherche_bleibt_folgenlos(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")

    with patch("reporter.v3.research.suggest", side_effect=RuntimeError("Netz weg")):
        context = _research_customer_context(MagicMock(), "o1", {"kuerzel": "BSP"}, INVENTORY)

    assert context == {"kuerzel": "BSP"}


def test_store_schreibt_json() -> None:
    conn = MagicMock()
    cur = conn.cursor.return_value.__enter__.return_value

    _store_customer_context(conn, "o1", {"firmenname": "Beispiel GmbH"})

    sql, params = cur.execute.call_args[0]
    assert "UPDATE orders SET customer_context" in sql
    assert json.loads(params[0]) == {"firmenname": "Beispiel GmbH"}
    conn.commit.assert_called_once()
