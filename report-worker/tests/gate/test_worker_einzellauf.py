# -*- coding: utf-8 -*-
"""Der Einzellauf ``--once`` (S5b).

Er faehrt den echten Produktionspfad, schreibt also PDF, ``reports``-Zeile und
Orderstatus. Deshalb zwei Sperren: nur interne Nachweisauftraege, und nur mit
ausdruecklicher Bestaetigung. Ein ausgelieferter Kundenauftrag bekommt keinen
Lauf von Hand (Entscheidung DC, S5b); fuer den gibt es den lesenden Weg.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from reporter import worker as W

INTERN = "14272c00-1145-4675-9b4c-19ce2ead403b"
KUNDE = "4e6b6883-a6c8-4204-8b13-b37f907322ca"


def test_kundenauftrag_wird_abgelehnt(monkeypatch, capsys):
    monkeypatch.setenv("VECTISCAN_ONCE_CONFIRM", "intern")
    assert W._einzellauf(KUNDE) == 2
    assert "INTERNE_ORDERS" in capsys.readouterr().err


def test_ohne_bestaetigung_kein_lauf(monkeypatch, capsys):
    monkeypatch.delenv("VECTISCAN_ONCE_CONFIRM", raising=False)
    assert W._einzellauf(INTERN) == 2
    assert "VECTISCAN_ONCE_CONFIRM" in capsys.readouterr().err


def test_beide_nachweisauftraege_stehen_in_der_liste():
    assert INTERN in W.INTERNE_ORDERS
    assert "75338c97-6707-4d11-92bf-bb3cd2e02cde" in W.INTERNE_ORDERS
    assert KUNDE not in W.INTERNE_ORDERS


class _Cursor:
    def __init__(self, antworten: list) -> None:
        self._antworten = antworten
        self._letzte = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql: str, params: tuple) -> None:
        self._letzte = self._antworten.pop(0)

    def fetchone(self):
        return self._letzte


class _Conn:
    def __init__(self, antworten: list) -> None:
        self._antworten = antworten

    def cursor(self):
        return _Cursor(self._antworten)

    def close(self):
        pass


def test_payload_entspricht_dem_regenerate_pfad():
    """Dieselben Zeilen wie api/src/routes/orders.ts, dieselben Schluessel."""
    antworten = [
        ("vectigal.tech", "webcheck"),                      # orders
        ('{"hosts": [{"ip": "1.2.3.4"}], "domain": "x"}',),  # ai_host_strategy
        ('[{"ip": "1.2.3.4"}]',),                           # ai_tech_analysis_debug
        ('{"cves_enriched": 0, "phase3_summary": {"a": 1}}',),  # phase3_correlation
    ]
    payload = W._job_payload_fuer(_Conn(antworten), "order-1")
    assert payload["orderId"] == "order-1"
    assert payload["rawDataPath"] == "order-1.tar.gz"
    assert payload["package"] == "webcheck"
    assert payload["hostInventory"]["hosts"] == [{"ip": "1.2.3.4"}]
    assert payload["techProfiles"] == [{"ip": "1.2.3.4"}]
    # Anreicherung fehlt in der Zeile, also leer und nicht erfunden.
    assert payload["enrichment"] == {}
    assert payload["phase3Summary"] == {"a": 1}


def test_leeres_phase3_objekt_setzt_keine_felder():
    """BEFUND 4 aus der API: raw_output '{}' heisst 'nicht vorhanden'."""
    antworten = [("x.test", None), (None,), (None,), ("{}",)]
    payload = W._job_payload_fuer(_Conn(antworten), "order-1")
    assert "enrichment" not in payload
    assert payload["package"] == "perimeter"
    assert payload["hostInventory"] == {"hosts": [], "domain": "x.test"}


def test_einzellauf_ruft_process_job(monkeypatch):
    monkeypatch.setenv("VECTISCAN_ONCE_CONFIRM", "intern")
    antworten = [("dortmund-beach.com", "perimeter"), (None,), (None,), (None,)]
    with patch.object(W, "_get_db_connection", return_value=_Conn(antworten)), \
            patch.object(W, "process_job") as job:
        assert W._einzellauf(INTERN) == 0
    assert job.call_args[0][0]["orderId"] == INTERN
