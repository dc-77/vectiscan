# -*- coding: utf-8 -*-
"""Berichtsdatum nach E15 (S6b-4, spec/11 T5): freigegebene Berichte tragen das Datum der
Freigabe (``orders.reviewed_at``) in Europe/Berlin, Entwuerfe den Tag der Erzeugung."""
from __future__ import annotations

from datetime import datetime, timezone

from reporter import worker as W
from reporter.v3.chapters import report_day


class _Cursor:
    def __init__(self, row) -> None:
        self.row = row
        self.sql = ""

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        return None

    def execute(self, sql, params=None) -> None:
        self.sql = sql

    def fetchone(self):
        return self.row


class _Conn:
    def __init__(self, row) -> None:
        self.cur = _Cursor(row)
        self.rolled_back = False

    def cursor(self):
        return self.cur

    def rollback(self) -> None:
        self.rolled_back = True


def test_freigabezeitpunkt_aus_reviewed_at(monkeypatch):
    monkeypatch.delenv("VECTISCAN_REPORT_DATE", raising=False)
    freigabe = datetime(2026, 9, 26, 23, 11, tzinfo=timezone.utc)
    conn = _Conn((freigabe,))
    assert W._approved_at(conn, "c3d5724c") == freigabe
    assert "reviewed_at" in conn.cur.sql
    # 01:11 Uhr Berliner Zeit am 27.09., nicht der UTC-Tag davor.
    assert report_day(W._approved_at(conn, "c3d5724c")) == "27.09.2026"


def test_ohne_freigabe_der_tag_der_erzeugung(monkeypatch):
    monkeypatch.delenv("VECTISCAN_REPORT_DATE", raising=False)
    assert W._approved_at(_Conn(None), "c3d5724c") is None
    jetzt = datetime(2026, 9, 27, 10, 0, tzinfo=timezone.utc)
    assert report_day(None, now=jetzt) == "27.09.2026"


def test_datenbankfehler_faellt_auf_den_tag_der_erzeugung_zurueck():
    class _Kaputt(_Conn):
        def cursor(self):
            raise RuntimeError("keine Verbindung")

    conn = _Kaputt(None)
    assert W._approved_at(conn, "c3d5724c") is None and conn.rolled_back
