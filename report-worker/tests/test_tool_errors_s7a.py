# -*- coding: utf-8 -*-
"""S7a Punkt 0: keine Dienstkennung aus Fehlertexten eines Werkzeugs.

castenow cd28d260, 92.205.163.53:8000: nmap meldete fuer drei Skripte "ERROR: Script
execution failed (use -d to debug)", der Bericht zeigte den Text als Kennung in Kapitel 2
und in einer Betroffen-Zeile. Entscheidung DC (30.09.): der Text faellt weg, danach gilt der
normale Regelweg; hier nennt der Fingerprint Shoutcast, der Port ist ein Fremddienst wie bei
1f8bc977, und der blaue Befund http_alt_port entfaellt.
"""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from reporter.facts.build import service_kennung
from reporter.facts.nmap_parse import derive_service_flags, parse_nmap_text, parse_nmap_xml
from reporter.facts.tool_errors import is_tool_error
from reporter.gate import v3_checks as G
from tests.v3.conftest import data_for, facts_for, order_ids

FIXTURE = Path(__file__).parent / "fixtures" / "facts" / "nmap_tool_error_8000.xml"
CA = "cd28d260-cf49-4d17-a980-64a4b1951444"
FEHLER = "ERROR: Script execution failed (use -d to debug)"


@pytest.mark.parametrize("text", [
    FEHLER,
    "ERROR: Failed to connect",
    "ERROR: Timeout",
    "NSE: [http-title] failed",
    "Traceback (most recent call last):\n  File ...",
    "TIMEOUT",
    "timed out",
    "Failed to resolve",
])
def test_werkzeugmeldungen_sind_fehlertexte(text):
    assert is_tool_error(text)


@pytest.mark.parametrize("text", [
    # Echte Fehlerseiten eines Servers tragen eine Kennung (castenow, CloudFront; Azure).
    "ERROR: The request could not be satisfied",
    "Amazon CloudFront httpd, Titel „ERROR: The request could not be satisfied“",
    "Microsoft Azure Web App - Error 404",
    "403 Forbidden",
    "Login failed",
    "Shoutcast DNAS 2.6.1.777",
    None,
    "",
])
def test_serverantworten_sind_keine_fehlertexte(text):
    assert not is_tool_error(text)


def _port_8000():
    run = parse_nmap_xml(FIXTURE.read_bytes())
    host = run.host_for("92.205.163.53")
    return next(p for p in host.ports if p.port == 8000)


def test_xml_fehlerskripte_fallen_weg():
    port = _port_8000()
    assert [s.id for s in port.scripts] == ["http-title"]
    assert all(not is_tool_error(s.output) for s in port.scripts)


def test_kennung_kommt_aus_dem_fingerprint():
    port = _port_8000()
    flags = derive_service_flags(port)
    assert flags.fp_server == "Shoutcast DNAS 2.6.1.777"
    assert flags.fp_stream == "tonausstrom.de"
    assert service_kennung(port, flags) == ("Shoutcast DNAS 2.6.1.777, Stream tonausstrom.de", False)


def test_textausgabe_fehlerskripte_fallen_weg():
    text = ("Nmap 7.93 scan initiated\nNmap scan report for 92.205.163.53\nHost is up.\n"
            "PORT     STATE SERVICE  REASON  VERSION\n"
            "8000/tcp open  http-alt syn-ack\n"
            f"|_http-server-header: {FEHLER}\n"
            f"|_https-redirect: {FEHLER}\n"
            "8001/tcp open  http     syn-ack nginx\n"
            "|_http-server-header: nginx\n")
    run = parse_nmap_text(text, "92.205.163.53")
    ports = {p.port: p for p in run.hosts[0].ports}
    assert ports[8000].scripts == []
    assert [s.id for s in ports[8001].scripts] == ["http-server-header"]


def test_golden_castenow_8000_ist_fremddienst_mit_shoutcast_kennung():
    svc = next(s for s in facts_for(CA).services if s.host_ip == "92.205.163.53" and s.port == 8000)
    assert svc.kennung == "Shoutcast DNAS 2.6.1.777, Stream tonausstrom.de"
    assert svc.foreign is True
    assert not is_tool_error(svc.fp_server)


@pytest.mark.parametrize("order_id", order_ids())
def test_keine_kennung_aus_fehlertext_in_den_golden_fakten(order_id):
    for svc in facts_for(order_id).services:
        for wert in (svc.kennung, svc.fp_server, svc.fp_title, svc.product):
            assert not is_tool_error(wert), f"{svc.id}: {wert}"


def test_cloudfront_titel_bleibt_als_kennung_stehen():
    kennungen = [s.kennung for o in order_ids() for s in facts_for(o).services if s.kennung]
    assert any("ERROR: The request could not be satisfied" in k for k in kennungen)


def test_gate_regel_greift_im_nachweis_und_in_der_service_karte():
    data = data_for(CA).model_copy(deep=True)
    data.findings[0].evidence = f"Server-Kennung: {FEHLER}"
    data.architecture.services[0].ports[0].s = FEHLER
    defects = G.werkzeugfehler_im_kundentext(data)
    assert {d.check for d in defects} == {"werkzeugfehler_im_kundentext"}
    assert all(d.severity == "error" for d in defects)
    assert {d.detail["where"].split("[")[0] for d in defects} >= {".findings", ".architecture.services"}


@pytest.mark.parametrize("order_id", order_ids())
def test_gate_regel_ohne_treffer_in_den_golden_auftraegen(order_id):
    assert G.werkzeugfehler_im_kundentext(data_for(order_id)) == []


def test_run_all_enthaelt_die_regel():
    assert "werkzeugfehler_im_kundentext(data)" in inspect.getsource(G.run_all)
