# -*- coding: utf-8 -*-
"""S6b-2: neue Fakten 1.0.7 an kleinen Beispielen (spec/09 Q12, Q13, Q14, Q18, Teil 2).

Die Golden-Fakten decken dieselben Stellen an echten Tars ab (tests/test_facts_golden.py);
hier steht je Ableitung der Fall, an dem sie entschieden wird.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporter.facts import schema as S
from reporter.facts.build import (_banner_date, _mark_rejects_before_auth, _split_httpx_tech,
                                  released_after_eol)
from reporter.facts.nmap_parse import NmapPort, NmapScript, derive_service_flags
from reporter.facts.versions import (DEBIAN_LTS_END, EXCHANGE_LIFECYCLE, debian_eol, debian_release,
                                     exchange_edition)

GOLDEN = Path(__file__).parent / "golden" / "facts"


def _facts(order: str) -> S.Facts:
    return S.Facts.from_dict(json.loads((GOLDEN / f"{order}.json").read_text(encoding="utf-8")))


# ---------------------------------------------------------------- Q18 Lebenszyklus

@pytest.mark.parametrize("build,edition", [
    ("15.1.2507", "2016"), ("15.2.1748", "2019"), ("15.2.2562", "SE"), ("15.2.3000", "SE")])
def test_exchange_edition_aus_dem_build(build, edition):
    """Exchange SE traegt ebenfalls 15.2; die Grenze ist Build 2562 (castenow, Junkerwerk)."""
    assert exchange_edition(build)[0] == edition


def test_exchange_2016_und_2019_mit_supportende_und_quelle():
    for edition in ("2016", "2019"):
        datum, quelle = EXCHANGE_LIFECYCLE[edition]
        assert datum == "2025-10-14"
        assert quelle.startswith("Microsoft Lifecycle, https://learn.microsoft.com/")
    assert "SE" not in EXCHANGE_LIFECYCLE


def test_huendgen_exchange_2019_ist_eol():
    """HE 15.2.1748 (CU15) mit OWA: vorher Patch/EOL gruen (spec/09 Q18)."""
    exchange = [s for s in _facts("3cf01f8d-4d21-4e6d-bac2-7342f1a4d6c7").software if s.family == "exchange"]
    assert exchange and all(s.eol.status == "eol" and s.eol.date == "2025-10-14" for s in exchange)
    assert all("learn.microsoft.com" in (s.eol.source or "") for s in exchange)


@pytest.mark.parametrize("text,release", [
    ("OpenSSH 8.4p1 Debian 5+deb11u7", "11"), ("10.11.18-MariaDB-0+deb12u1", "12"),
    ("OpenSSH 9.2p1 Debian 2", None), (None, None)])
def test_debian_release_aus_dem_paketsuffix(text, release):
    assert debian_release(text) == release


def test_debian_eol_nach_lts_ende():
    """Massgeblich ist das LTS-Ende (Debian 11: 31.08.2026), nicht das Ende der regulaeren Pflege."""
    assert DEBIAN_LTS_END["11"] == "2026-08-31"
    assert debian_eol("11", "2026-09-23").status == "eol"
    assert debian_eol("11", "2026-08-01").status == "supported"
    assert debian_eol("12", "2026-09-23").status == "supported"
    assert debian_eol("7", "2026-09-23").status == "unknown"


def test_dortmund_beach_traegt_debian_11_als_betriebssystem():
    os_facts = [s for s in _facts("1fbc92b9-34ab-414e-8843-a1f1e9f15431").software if s.family == "debian"]
    assert [(s.kind, s.version_norm, s.eol.status) for s in os_facts] == [("os", "11", "eol")]


def test_release_nach_dem_eol_datum_ist_kein_eol():
    """WordPress 6.5.12 vom 22.09.2026, Zweig 6.5 mit Supportende 16.07.2024 (DB)."""
    eol = S.Eol(status="eol", date="2024-07-16", source="endoflife_date")
    neu = released_after_eol(eol, "2026-09-22")
    assert neu.status == "supported" and neu.date is None and neu.upstream_eol_date == "2024-07-16"
    assert released_after_eol(eol, "2024-01-10").status == "eol"
    assert released_after_eol(eol, None).status == "eol"


def test_dortmund_beach_wordpress_ohne_kern_schwachstelle():
    wp = [h.wordpress for h in _facts("1fbc92b9-34ab-414e-8843-a1f1e9f15431").http if h.wordpress and h.wordpress.version]
    assert wp and all(w.version == "6.5.12" and w.release_date == "2026-09-22" and w.core_vulnerabilities == 0
                      for w in wp)
    assert any("oembed" in u for w in wp for u in w.users_found_by)


# ---------------------------------------------------------------- Q13 Fingerabdruck

def _port(**kw) -> NmapPort:
    base = {"port": 10000, "proto": "tcp", "state": "open", "service": "snet-sensor-mgmt", "tunnel": "ssl"}
    base.update(kw)
    return NmapPort(**base)


def test_webmin_fingerabdruck_aus_dem_servicefp():
    fp = ('SF-Port10000-TCP:V=7.94%T=SSL%r(GetRequest,1F0,"HTTP/1\\.0\\x20200\\x20Document\\x20follows\\r\\n'
          'Server:\\x20MiniServ\\r\\n\\r\\n<form\\x20action=/session_login\\.cgi>")')
    flags = derive_service_flags(_port(servicefp=fp))
    assert flags.fp_server == "MiniServ" and flags.fp_login is True


def test_titel_aus_http_title_und_weiterleitung_ist_kein_titel():
    flags = derive_service_flags(_port(port=443, service="https", scripts=[
        NmapScript(id="http-title", output="Did not follow redirect to https://example.test/")]))
    assert flags.fp_title is None
    flags = derive_service_flags(_port(port=443, service="https", scripts=[
        NmapScript(id="http-title", output="Plesk Obsidian 18.0.81 &amp; mehr...")]))
    assert flags.fp_title == "Plesk Obsidian 18.0.81 & mehr (Auszug)"


def test_ohne_beleg_bleibt_die_anmeldung_offen():
    flags = derive_service_flags(_port(port=8443, service="https-alt", scripts=[
        NmapScript(id="http-title", output="Willkommen")]))
    assert flags.fp_login is None


# ---------------------------------------------------------------- Teil 2 LW, JW

def test_postgresql_weist_vor_der_anmeldung_ab():
    svc = S.ServiceFact(id="svc:1", source="nmap", mode="active", confidence=1.0, evidence=[],
                        host_ip="10.0.0.2", port=5432, proto="tcp", state="open", service="postgresql")
    other = S.ServiceFact(id="svc:2", source="nmap", mode="active", confidence=1.0, evidence=[],
                          host_ip="10.0.0.2", port=3306, proto="tcp", state="open", service="mysql")
    passive = [S.PassiveFact(id="p:1", source="shodan", mode="passive", confidence=0.5, evidence=[],
                             host_ip="10.0.0.2", port=5432,
                             banner_excerpt='FATAL:  no pg_hba.conf entry for host "1.2.3.4"')]
    _mark_rejects_before_auth([svc, other], passive)
    assert svc.rejects_before_auth is True and other.rejects_before_auth is None


@pytest.mark.parametrize("order", ["c3d5724c-bdbf-4da8-982f-4f1a52210e28", "31d67a02-b485-4d05-b228-dbdde092cc68"])
def test_scanrunde_postgresql_mit_abweisung(order):
    pg = [s for s in _facts(order).services if s.port == 5432]
    assert pg and all(s.rejects_before_auth is True for s in pg)


# ---------------------------------------------------------------- Q13 Datum des Dienstes

def test_banner_datum_aus_dem_http_kopf():
    banner = "HTTP/1.1 200 OK\r\nDate: Fri, 11 Sep 2026 17:52:16 GMT\r\nServer: xxxx\r\n"
    assert _banner_date(banner) == "2026-09-11T17:52:16Z"
    assert _banner_date("SSH-2.0-OpenSSH_9.2p1") is None


# ---------------------------------------------------------------- Q12 Reputation

def test_heuel_reputation_mit_meldungen_trotz_score_null():
    rep = {h.ip: h.reputation for h in _facts("2e56abe1-c1a6-442e-b36a-dc9f83c81da8").hosts}
    vercel = rep["216.150.1.65"]
    assert vercel.abuseipdb_score == 0 and vercel.abuseipdb_total_reports == 26
    assert vercel.abuseipdb_whitelisted is True and vercel.abuseipdb_last_reported_at.startswith("2026-09-21")


# ---------------------------------------------------------------- Q14 ZAP

def test_zap_konfidenz_und_lauf_der_scanrunde():
    """10202 (Anti-CSRF) ist eine passive Regel mit Konfidenz Low (DB, CA, HL)."""
    alerts = [a for h in _facts("1fbc92b9-34ab-414e-8843-a1f1e9f15431").http for a in h.alerts
              if a.plugin_id == "10202"]
    assert alerts and all(a.confidence == "Low" and a.run == "passive" for a in alerts)


# ---------------------------------------------------------------- Technik (Entscheidung DC 25.09.)

@pytest.mark.parametrize("raw,name,version", [
    ("Neos Flow:neos", "Neos Flow", None), ("jQuery:3.7.1", "jQuery", "3.7.1"),
    ("Nginx", "Nginx", None), ("Java/Servlet", "Java/Servlet", None)])
def test_httpx_suffix_ist_version_oder_variante(raw, name, version):
    assert _split_httpx_tech(raw) == (name, version)
