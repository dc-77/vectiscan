# -*- coding: utf-8 -*-
"""S6b-1 im Pruefkatalog: Drittanbieter, erklaerte Passivports, Numerus, Tagesangabe.

Faelle aus den Auftraegen der Scan-Runde (spec/09): bergersysteme (Microsoft-Autodiscover
als Drittanbieter, vier Hosts vom Pruefstand aus nicht erreichbar), Junkerwerk (Port 25
laut Shodan, IPv6 ohne Route), dortmund-beach (Port 25 nach E5).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporter.catalog import evaluate, load_catalog
from reporter.catalog import render
from reporter.catalog.catchall import PASSIVE_EXPLAINED
from reporter.facts.schema import Facts

GOLDEN = Path(__file__).parent.parent / "golden" / "facts"
BS = "68d59573-7a93-4efa-89cc-e7b10cc4d140"
JW = "31d67a02-b485-4d05-b228-dbdde092cc68"
DB = "1fbc92b9-34ab-414e-8843-a1f1e9f15431"


def output(order: str):
    facts = Facts.from_dict(json.loads((GOLDEN / f"{order}.json").read_text(encoding="utf-8")))
    return evaluate(facts, load_catalog())


def test_drittanbieter_liefert_keine_ergebnisse():
    out = output(BS)
    assert not [r for r in out.results if r.vars.get("host_ip") == "40.99.150.120"]
    assert not [u for u in out.unprocessed if u.host_ip == "40.99.150.120"]


@pytest.mark.parametrize("order", [BS, JW, DB])
def test_erklaerte_passivports_sind_keine_offene_beobachtung(order):
    out = output(order)
    assert not [u for u in out.unprocessed if u.kind == "passive_port_unverified"]
    gruende = {i.reason for i in out.ignored if i.kind == "passive_port"}
    assert gruende & set(PASSIVE_EXPLAINED.values())


def test_port_25_und_ipv6_bei_junkerwerk():
    out = output(JW)
    ignored = {i.what: i.reason for i in out.ignored if i.kind == "passive_port"}
    assert ignored["188.40.3.130:25"] == PASSIVE_EXPLAINED["smtp_25"]
    assert ignored["[2a01:4f8:d0a:3124::2]:443 (Apache httpd)"] == PASSIVE_EXPLAINED["no_ipv6_route"]


def test_nicht_erreichbarer_host_ohne_positivbefund():
    out = output(BS)
    for ip in ("62.217.52.162", "62.217.52.166", "62.217.52.171"):
        rows = [r for r in out.results if r.check_id == "db_exposed" and r.vars.get("host_ip") == ip]
        assert rows and all(r.status == "not_testable" for r in rows)
        assert rows[0].reason_code == "unreachable_from_scanner"
    rows = [r for r in out.results if r.check_id == "db_exposed" and r.vars.get("host_ip") == "79.140.188.181"]
    assert rows[0].status == "not_testable" and rows[0].reason_code == "no_open_ports"


@pytest.mark.parametrize("count,expected", [(1, "Der Host bietet"), (2, "Die Hosts bieten"), (7, "Die Hosts bieten")])
def test_numerus(count, expected):
    text = render.format_strict("{n:Der Host|Die Hosts} {n:bietet|bieten}", {"n": render.Numerus(count)}, "test")
    assert text == expected


def test_numerus_ohne_form_ist_die_zahl():
    assert render.format_strict("{n} Hosts", {"n": render.Numerus(3)}, "test") == "3 Hosts"


def test_ein_tag_nicht_ein_tage():
    labels = [a for r in output("1f8bc977-39a7-47c7-b4ad-7b05dbac2d52").results
              if r.check_id == "cert_expiring" for a in r.affected]
    assert any(a.endswith("(1 Tag)") for a in labels)
    assert not any("(1 Tage)" in a for a in labels)
