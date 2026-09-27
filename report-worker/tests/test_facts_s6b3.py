# -*- coding: utf-8 -*-
"""S6b-3: neue Fakten 1.1.0 an den sieben Auftraegen der Scan-Runde (spec/10).

Je Punkt der Fall aus spec/10: Messbasis der Sicherheits-Header (R1), Zertifikate an Mail-
und Dateiports und Hosts ohne Antwort (R3), belegte Sperre (R4), gefundene, nicht gepruefte
Namen (R5), CBC-Verfahren, URLhaus ohne Daten und Zonentransfer je Domain (R6), POP3 ohne
Anmeldung vor STLS (R7), Kennung eines Dienstes (R9), Betriebsform (R13), SMTP VRFY,
Widerspruch der Passivquelle und Ressourcen-Versionen (R19), Erneuerungsverlauf (E13).
Die Golden-Fakten sind eingecheckt und werden in ``test_facts_golden.py`` gegen den Neubau
geprueft; hier werden sie nur gelesen.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporter.facts import schema as S
from reporter.facts.nmap_parse import NmapPort, NmapScript, derive_service_flags

FACTS = Path(__file__).parent / "golden" / "facts"

DB = "1fbc92b9-34ab-414e-8843-a1f1e9f15431"
LW = "c3d5724c-bdbf-4da8-982f-4f1a52210e28"
JW = "31d67a02-b485-4d05-b228-dbdde092cc68"
HE = "3cf01f8d-4d21-4e6d-bac2-7342f1a4d6c7"
BS = "68d59573-7a93-4efa-89cc-e7b10cc4d140"
CA = "1f8bc977-39a7-47c7-b4ad-7b05dbac2d52"
HL = "2e56abe1-c1a6-442e-b36a-dc9f83c81da8"
CA_VORLAUF = "4e6b6883-a6c8-4204-8b13-b37f907322ca"

_CACHE: dict[str, S.Facts] = {}


def facts(order: str) -> S.Facts:
    if order not in _CACHE:
        _CACHE[order] = S.Facts.from_dict(json.loads((FACTS / f"{order}.json").read_text(encoding="utf-8")))
    return _CACHE[order]


def host(order: str, ip: str) -> S.HostFact:
    return next(h for h in facts(order).hosts if h.ip == ip)


def http(order: str, fqdn: str) -> S.HttpFact:
    return next(h for h in facts(order).http if h.fqdn == fqdn)


def service(order: str, ip: str, port: int) -> S.ServiceFact:
    return next(s for s in facts(order).services if s.host_ip == ip and s.port == port)


def test_schema_1_1_0():
    # S6b-4 hebt auf 1.2.0; die Felder aus 1.1.0 bleiben.
    assert tuple(int(x) for x in S.FACTS_SCHEMA_VERSION.split(".")) >= (1, 1, 0)


# ---------------------------------------------------------------- R1 Messbasis der Header

def test_jw_outlook_endseite_aus_redirect_probe():
    he = http(JW, "outlook.junkerwerk.de").header_eval
    assert he.basis == "final" and he.first.status_code == 302
    assert he.evaluated.tool == "redirect_probe" and he.complete is True
    assert "x-frame-options" not in he.missing
    assert he.missing == ["x-content-type-options", "referrer-policy", "permissions-policy",
                          "content-security-policy"]


def test_jw_autodiscover_nur_teilbeleg_aus_zap():
    he = http(JW, "autodiscover.junkerwerk.de").header_eval
    assert he.first.status_code == 302 and he.evaluated.tool == "zap"
    assert he.complete is False
    assert set(he.unknown) == {"x-frame-options", "referrer-policy", "permissions-policy"}


@pytest.mark.parametrize("order,fqdn,basis,status", [
    (CA, "mailstore.castenow.de", "client_error", 400),
    (BS, "ftp.bergersysteme.com", "client_error", 403),
    (HL, "edi.heuel.com", "client_error", 403),
    (HL, "online.heuel.com", "challenge", 429),
    (BS, "bergersysteme.com", "redirect", 301),
    (CA, "umfrage.castenow.de", "redirect", 301),
])
def test_keine_endseite(order, fqdn, basis, status):
    he = http(order, fqdn).header_eval
    assert he.basis == basis and he.first.status_code == status
    assert he.evaluated is None and he.missing == []


def test_ca_bitwarden_ueber_testssl():
    he = http(CA, "bitwarden.castenow.de").header_eval
    assert he.evaluated.tool == "testssl" and he.complete is True
    assert he.missing == ["permissions-policy"]


def test_hl_ose_clientseitige_weiterleitung():
    he = http(HL, "ose.heuel.com").header_eval
    assert he.evaluated.tool == "redirect_probe"


def test_snapshot_ohne_reachable_ist_eine_messung():
    """castenow-Vorlauf aus dem API-Snapshot: header_check ohne "reachable"."""
    he = http(CA_VORLAUF, "www.castenow.de").header_eval
    assert he.basis == "final" and he.evaluated.tool == "header_check"


def test_csp_je_direktive():
    csp = http(CA, "www.castenow.de").csp
    assert csp is not None and csp.script_unsafe_inline is True


# ---------------------------------------------------------------- R3 Abdeckung

@pytest.mark.parametrize("port", [110, 143, 465, 993, 995])
def test_bs_plesk_mailports_mit_abgelaufenem_zertifikat(port):
    cert = service(BS, "92.205.224.174", port).cert
    assert cert.cn == "Plesk" and cert.expired is True and cert.self_signed is True
    assert cert.not_after.startswith("2025-07-18")


@pytest.mark.parametrize("order,ip", [(HL, "195.225.241.75"), (BS, "79.140.188.181")])
def test_ohne_hostbericht_ohne_antwort(order, ip):
    h = host(order, ip)
    assert h.nmap_host_report is False and h.reach.status == "no_response"


def test_db_acht_tls_dienste_neben_443():
    tls_ports = sorted(s.port for s in facts(DB).services
                       if s.host_ip == "88.99.35.112" and (s.tunnel_ssl or s.starttls or s.cert is not None))
    assert tls_ports == [21, 110, 143, 443, 465, 587, 993, 995, 10000]


# ---------------------------------------------------------------- R4 Sperre nur mit Beleg

def test_bs_198_202_211_1_ohne_sperre():
    assert not host(BS, "198.202.211.1").blocked.detected


def test_testssl_gilt_fuer_alle_vhosts_eines_ports():
    tls = {t.fqdn: t for t in facts(CA).tls if t.host_ip == "195.50.179.4"}
    assert tls["mail.castenow.de"].cert_assigned_from == "mail2.castenow.de:443"
    assert tls["owa.castenow.de"].cbc_obsoleted_offered is True


# ---------------------------------------------------------------- R5 gefundene Namen

@pytest.mark.parametrize("order,erwartet", [
    (JW, {"archiv.junkerwerk.de"}),
    (HE, {"ftp.huendgen-entsorgung.de", "ftp.mail.huendgen-entsorgung.de"}),
    (HL, {"as2.heuel.com", "autodiscover.heuel.com", "control.heuel.com"}),
    (CA, {"autodiscover.castenow.de"}),
])
def test_gefundene_namen(order, erwartet):
    assert {d.fqdn for t in facts(order).targets for d in t.discovered} == erwartet


def test_bs_24_gefundene_namen():
    assert len({d.fqdn for t in facts(BS).targets for d in t.discovered}) == 24


def test_drittanbieter_autodiscover():
    ca = next(d for t in facts(CA).targets for d in t.discovered if d.fqdn == "autodiscover.castenow.de")
    assert ca.third_party == "Microsoft 365" and ca.ips


# ---------------------------------------------------------------- R6 tragende Fakten

def test_ca_cbc_angeboten():
    assert all(t.cbc_obsoleted_offered is True for t in facts(CA).tls if t.host_ip == "195.50.179.4")
    assert http(CA, "www.castenow.de") is not None
    assert next(t for t in facts(CA).tls if t.fqdn == "bitwarden.castenow.de").cbc_obsoleted_offered is False


@pytest.mark.parametrize("order", [DB, LW, JW, HE, BS, CA, HL])
def test_urlhaus_ohne_daten_ist_kein_negativergebnis(order):
    for p in facts(order).passive:
        if p.source == "urlhaus":
            assert p.details.get("compromised") is None


def test_zonentransfer_je_domain():
    zt = {d.domain: d.zone_transfer for d in facts(JW).dns}
    assert zt["junkerwerk.hu"].allowed is False and len(zt["junkerwerk.hu"].ns_tested) == 3


def test_debian_12_mit_lts_quelle():
    sw = next(s for s in facts(LW).software if s.product == "Debian GNU/Linux" and s.version_norm == "12")
    assert sw.eol.status == "supported" and sw.eol.date == "2028-06-30"
    assert sw.eol.source.startswith("Debian LTS")


# ---------------------------------------------------------------- R7 POP3

@pytest.mark.parametrize("order,ip", [(LW, "116.202.77.64"), (JW, "188.40.3.130"), (HL, "213.133.104.51")])
def test_pop3_ohne_user_und_sasl_vor_stls(order, ip):
    s = service(order, ip, 110)
    assert s.starttls is True and s.login_disabled is True and s.tls_required is True


def test_pop3_mit_user_ist_kein_tls_zwang():
    s = service(DB, "88.99.35.112", 110)
    assert s.tls_required is False


def test_pop3_regel_am_parser():
    port = NmapPort(port=110, proto="tcp", state="open", service="pop3",
                    scripts=[NmapScript(id="pop3-capabilities", output="CAPA STLS SASL() RESP-CODES PIPELINING")])
    flags = derive_service_flags(port)
    assert flags.starttls is True and flags.login_disabled is True


# ---------------------------------------------------------------- R9 Kennung

@pytest.mark.parametrize("port", [1000, 1001, 1002])
def test_he_dienste_ohne_kennung(port):
    s = service(HE, "80.90.145.166", port)
    assert s.unidentified is True and s.kennung is None


def test_ca_8001_ueber_das_zertifikat():
    s = service(CA, "92.205.163.53", 8001)
    assert s.unidentified is False and s.kennung == "TLS-Dienst, Zertifikat tonausstrom.de"


def test_ca_8000_shoutcast_und_db_webmin():
    assert service(CA, "92.205.163.53", 8000).kennung == "Shoutcast DNAS 2.6.1.777, Stream tonausstrom.de"
    assert service(DB, "88.99.35.112", 10000).kennung.startswith("Webmin")


def test_imaps_mit_protokollskript_braucht_keine_kennung():
    # S6b-4 (spec/11 T1): die Protokollskripte geben die Kennung, "nicht identifiziert" entfaellt.
    s = service(HL, "213.133.104.51", 995)
    assert s.unidentified is False and s.kennung.startswith("POP3 über TLS")


def test_he_444_voller_titel():
    assert "Web Applications Portal" in service(HE, "80.90.145.166", 444).kennung


# ---------------------------------------------------------------- R13 Betriebsform

@pytest.mark.parametrize("order,ip,form", [
    (DB, "88.99.35.112", "rechenzentrum"),
    (HE, "80.90.145.166", "anschluss"),
    (HE, "18.197.248.23", "plattform"),
    (HL, "216.150.1.65", "plattform"),
    (JW, "217.243.248.28", "anschluss"),
])
def test_betriebsform(order, ip, form):
    assert host(order, ip).betriebsform == form


def test_dient_kundenmail():
    assert host(LW, "116.202.77.64").serves_customer_web is True
    assert host(DB, "88.99.35.112").serves_customer_mail is True


# ---------------------------------------------------------------- R19

def test_db_vrfy_auf_465_und_587():
    assert service(DB, "88.99.35.112", 465).smtp_vrfy is True
    assert service(DB, "88.99.35.112", 587).smtp_vrfy is True


def test_passivquelle_widerspricht_fortissh():
    sw = next(s for s in facts(HL).software if s.product == "FortiSSH")
    assert sw.conflicts == ["Shodan 22/tcp: SSH-2.0-WingFTPServer"]


def test_unverarbeitete_beobachtungen():
    kinds = {u.kind for u in facts(HL).unprocessed}
    assert "resource_version" in kinds
    db = {u.kind for u in facts(DB).unprocessed}
    assert {"smtp_auth_before_starttls", "wpscan_readme", "wpscan_wp_cron"} <= db


# ---------------------------------------------------------------- E13

def test_erneuerungsverlauf_aus_crtsh():
    t = next(t for t in facts(DB).tls if t.fqdn == "dortmund-beach.com")
    ren = t.cert.renewal
    assert ren.source == "crtsh" and ren.certificates > 10 and ren.interval_days and ren.lead_days
