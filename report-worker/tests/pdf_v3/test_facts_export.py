# -*- coding: utf-8 -*-
"""Der Hook VECTISCAN_FACTS_EXPORT (S5b).

Ohne Schalter passiert nichts, mit Schalter liegen ``facts.json`` und
``catalog.json`` neben dem Roh-Tar, und ein Fehler beim Hochladen haelt den
Bericht nie auf.
"""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from reporter.pdf.v3 import pipeline as P

REPO = Path(__file__).resolve().parents[3]
WORKER = (REPO / "report-worker" / "reporter" / "worker.py").read_text(encoding="utf-8")


class _Fakten:
    def __init__(self, inhalt: dict) -> None:
        self._inhalt = inhalt

    def to_dict(self) -> dict:
        return self._inhalt


class _Client:
    """Minio-Doppel, das sich merkt, was hochgeladen wurde."""

    def __init__(self, *, fehler: bool = False) -> None:
        self.objekte: dict[tuple[str, str], bytes] = {}
        self.buckets = {"scan-rawdata"}
        self.fehler = fehler

    def bucket_exists(self, bucket: str) -> bool:
        return bucket in self.buckets

    def make_bucket(self, bucket: str) -> None:
        self.buckets.add(bucket)

    def put_object(self, bucket: str, key: str, data: io.BytesIO, laenge: int,
                   content_type: str = "") -> None:
        if self.fehler:
            raise RuntimeError("MinIO weg")
        assert content_type == "application/json"
        roh = data.read()
        assert len(roh) == laenge
        self.objekte[(bucket, key)] = roh


@pytest.fixture()
def bundle():
    return _Fakten({"schema_version": "1.0.2", "b": 1, "a": 2}), _Fakten({"checks": []})


def test_ohne_schalter_passiert_nichts(bundle, monkeypatch):
    monkeypatch.delenv("VECTISCAN_FACTS_EXPORT", raising=False)
    client = _Client()
    assert P.export_facts_if_enabled(client, "order", *bundle) == []
    assert client.objekte == {}


def test_mit_schalter_liegen_beide_dateien_neben_dem_tar(bundle, monkeypatch):
    monkeypatch.setenv("VECTISCAN_FACTS_EXPORT", "1")
    client = _Client()
    keys = P.export_facts_if_enabled(client, "order-1", *bundle)
    assert keys == ["scan-rawdata/order-1/facts.json", "scan-rawdata/order-1/catalog.json"]
    roh = client.objekte[("scan-rawdata", "order-1/facts.json")]
    assert json.loads(roh)["schema_version"] == "1.0.2"
    # deterministisch: sortierte Schluessel, LF, UTF-8
    assert roh.decode("utf-8").startswith('{\n "a"')
    assert b"\r\n" not in roh


def test_zweiter_lauf_ist_byte_gleich(bundle, monkeypatch):
    monkeypatch.setenv("VECTISCAN_FACTS_EXPORT", "1")
    a, b = _Client(), _Client()
    P.export_facts_if_enabled(a, "order-1", *bundle)
    P.export_facts_if_enabled(b, "order-1", *bundle)
    assert a.objekte == b.objekte


def test_fehler_beim_hochladen_haelt_nichts_auf(bundle, monkeypatch):
    monkeypatch.setenv("VECTISCAN_FACTS_EXPORT", "1")
    assert P.export_facts_if_enabled(_Client(fehler=True), "order-1", *bundle) == []


@pytest.mark.parametrize("wert,erwartet", [
    ("1", True), ("true", True), ("ja", True), ("JA", True),
    ("", False), ("0", False), ("nein", False),
])
def test_schalterwerte(monkeypatch, wert, erwartet):
    monkeypatch.setenv("VECTISCAN_FACTS_EXPORT", wert)
    assert P.facts_export_enabled() is erwartet


def test_worker_ruft_den_export_im_v3_zweig():
    zweig = WORKER.split('if layout == "v3":')[1].split('elif layout == "v2":')[0]
    assert "export_facts_if_enabled(minio_client, order_id, v3_facts, v3_output)" in zweig
    # Der Waechter aus S4/S5 bleibt: keine Ausnahmebehandlung in diesem Zweig.
    assert "try:" not in zweig and "except" not in zweig
