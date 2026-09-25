# -*- coding: utf-8 -*-
"""``--kennzahlen`` laedt im Produktionspfad den Kundenkontext (offener Punkt nach S6a).

Ohne ihn meldete die Diagnose ``auftraggeber_fehlt``, obwohl der Bericht aus dem Worker
den Firmennamen traegt. Der Datenbank- und MinIO-Zugriff wird hier ersetzt; geprueft wird
nur, dass der Kontext dieselbe Strecke wie im Worker nimmt.
"""
from __future__ import annotations

import json

from reporter.pdf.v3 import __main__ as M
from reporter.pdf.v3 import pipeline as P
from tests.v3.conftest import JUNKERWERK, data_for, facts_for, output_for


def _patch(monkeypatch, gesehen: dict) -> None:
    order = JUNKERWERK["multi"]
    monkeypatch.setattr(P, "minio_client", lambda: object())
    monkeypatch.setattr(P, "fetch_rawdata", lambda client, oid, ziel: ziel)
    monkeypatch.setattr(P, "tool_runs_from_db", lambda oid: [])
    monkeypatch.setattr(M, "_kundenkontext", lambda oid: {"firmenname": "Junkerwerk Linder GmbH + Co. KG"})

    def bundle(quelle, **kwargs):
        gesehen.update(kwargs)
        return facts_for(order), output_for(order), data_for(order)

    monkeypatch.setattr(P, "report_bundle_from_source", bundle)


def test_kennzahlen_im_tar_pfad_mit_kundenkontext(monkeypatch, capsys):
    gesehen: dict = {}
    _patch(monkeypatch, gesehen)
    M._kennzahlen(JUNKERWERK["multi"], tar=True)
    assert gesehen["customer_context"] == {"firmenname": "Junkerwerk Linder GmbH + Co. KG"}
    bericht = json.loads(capsys.readouterr().out)
    assert bericht["order_id"] == JUNKERWERK["multi"]


def test_kennzahlen_aus_golden_ohne_datenbank(monkeypatch, capsys):
    gesehen: dict = {}
    _patch(monkeypatch, gesehen)
    M._kennzahlen(JUNKERWERK["multi"], tar=False)
    assert gesehen["customer_context"] is None
    capsys.readouterr()
