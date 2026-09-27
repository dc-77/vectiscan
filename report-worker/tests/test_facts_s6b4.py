# -*- coding: utf-8 -*-
"""S6b-4: Fakten 1.2.0 an den sieben Auftraegen der Scan-Runde (spec/11).

Je Punkt der Fall aus spec/11: Kennung aus Protokollskript, Banner und Passivquelle (T1),
Netzbetreiber laut AbuseIPDB mit Alias und Anschluss (T2), Messadresse und AAAA (T7),
Urteil der Pfadsuche (T8), fremde Domains und Dienste (T9), Langzeitpflege (T11),
Erneuerungslinie (T14), zweite Quelle der Technik (T15) und die Teil-3-Reste.
Die Golden-Fakten sind eingecheckt; hier werden sie nur gelesen.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporter.facts import schema as S
from reporter.facts import systems as SYS
from reporter.facts.nmap_parse import in_port_range

FACTS = Path(__file__).parent / "golden" / "facts"

DB = "1fbc92b9-34ab-414e-8843-a1f1e9f15431"
LW = "c3d5724c-bdbf-4da8-982f-4f1a52210e28"
JW = "31d67a02-b485-4d05-b228-dbdde092cc68"
HE = "3cf01f8d-4d21-4e6d-bac2-7342f1a4d6c7"
BS = "68d59573-7a93-4efa-89cc-e7b10cc4d140"
CA = "1f8bc977-39a7-47c7-b4ad-7b05dbac2d52"
HL = "2e56abe1-c1a6-442e-b36a-dc9f83c81da8"

_CACHE: dict[str, S.Facts] = {}


def facts(order: str) -> S.Facts:
    if order not in _CACHE:
        _CACHE[order] = S.Facts.from_dict(json.loads((FACTS / f"{order}.json").read_text(encoding="utf-8")))
    return _CACHE[order]


def host(order: str, ip: str) -> S.HostFact:
    return next(h for h in facts(order).hosts if h.ip == ip)


def service(order: str, ip: str, port: int) -> S.ServiceFact:
    return next(s for s in facts(order).services if s.host_ip == ip and s.port == port)


def test_schema_1_2_0():
    # S6b-4n: Schema 1.3.0 (tests/test_facts_s6b4n.py); 1.2.0 steht in der Historie.
    assert "1.2.0" in S.__doc__ or "1.2.0" in open(S.__file__, encoding="utf-8").read()
    assert all(facts(o).schema_version == S.FACTS_SCHEMA_VERSION for o in (DB, LW, JW, HE, BS, CA, HL))


# ---------------------------------------------------------------- T1 Kennung

@pytest.mark.parametrize("order,ip,port,kennung", [
    (DB, "88.99.35.112", 993, "IMAP über TLS (Dovecot)"),
    (DB, "88.99.35.112", 995, "POP3 über TLS (Dovecot)"),
    (LW, "116.202.77.64", 465, "SMTP über TLS (Exim)"),
    (JW, "188.40.3.130", 587, "SMTP (Exim)"),
    (JW, "188.40.3.130", 993, "IMAP über TLS"),
])
def test_kennung_aus_protokollskript_und_banner(order, ip, port, kennung):
    s = service(order, ip, port)
    assert s.kennung == kennung and s.unidentified is False


def test_he_ports_ohne_kennung_bleiben_nicht_identifiziert():
    for port in (1000, 1001, 1002):
        s = service(HE, "80.90.145.166", port)
        assert s.unidentified is True and s.kennung is None


def test_managesieve_laut_passivquelle_ausserhalb_des_portbereichs():
    pv = next(p for p in facts(LW).passive if p.port == 4190)
    assert pv.kennung == "ManageSieve (Dovecot Pigeonhole)"
    assert facts(LW).scan.scanned_port_count == 1000
    assert in_port_range(facts(LW).scan.scanned_ports, 4190) is False
    assert in_port_range(facts(LW).scan.scanned_ports, 993) is True


def test_exim_aus_dem_nmap_gruss_ohne_shodan_version():
    exim = [s for s in facts(JW).software if s.family == "exim"]
    assert exim and all("nmap" in s.detection_sources and s.version_norm is None for s in exim)


# ---------------------------------------------------------------- T2 Netzbetreiber

@pytest.mark.parametrize("order,ip,label", [
    (JW, "188.40.3.130", "Hetzner Online GmbH"),
    (CA, "195.50.179.4", "Castenow GmbH (Anschluss Vodafone)"),
    (BS, "198.202.211.1", "Webflow, Inc (CDN)"),
    (HE, "18.197.248.23", "A100 ROW GmbH (Amazon, CDN)"),
])
def test_netzbetreiber_laut_abuseipdb(order, ip, label):
    h = host(order, ip)
    platform = bool(h.cdn_provider or (h.shared and h.shared.kind == "platform"))
    got = SYS.network_operator_label(h.provider, platform=platform,
                                     customer_domains=list(facts(order).scan.domains) or [facts(order).scan.domain])
    assert got == label


# ---------------------------------------------------------------- T7 Messadresse und AAAA

@pytest.mark.parametrize("order,fqdn,inventar,messung", [
    (HE, "www.huendgen-entsorgung.de", "18.197.248.23", "52.59.120.70"),
    (HL, "online.heuel.com", "216.150.1.65", "216.150.1.129"),
    (CA, "umfrage.castenow.de", "3.174.98.120", "3.174.98.123"),
])
def test_tls_messadresse_je_lauf(order, fqdn, inventar, messung):
    t = next(t for t in facts(order).tls if t.fqdn == fqdn)
    assert t.host_ip == inventar and t.measured_ip == messung


def test_http_messadresse_aus_httpx():
    h = next(h for h in facts(HL).http if h.fqdn == "online.heuel.com")
    assert h.measured_ip == "216.150.16.65"


def test_aaaa_der_namen_als_weitere_adresse():
    lw = host(LW, "116.202.77.64").additional_ips
    assert [(a.ip, a.family, a.source) for a in lw] == [("2a01:4f8:d0a:668b::2", 6, "dnsx")]
    bs = {a.ip for h in facts(BS).hosts for a in h.additional_ips}
    assert bs == {"2620:cb:2000::1", "2a00:1169:118:23d0::"}
    # Drittanbieter bekommen keine weiteren Adressen (40.99.150.120, Microsoft 365).
    assert host(BS, "40.99.150.120").additional_ips == []


# ---------------------------------------------------------------- T8 Pfadsuche

@pytest.mark.parametrize("order,ip,urteil", [
    (DB, "88.99.35.112", "reliable"),
    (BS, "198.202.211.1", "aborted"),
    (BS, "92.205.224.174", "unreliable"),
    (BS, "62.217.52.166", "skipped"),
    (CA, "159.69.143.80", "unreliable"),
    (HE, "80.90.145.166", "unreliable"),
    (HL, "216.150.1.65", "unreliable"),
])
def test_urteil_der_pfadsuche(order, ip, urteil):
    p = next(p for p in facts(order).path_search if p.host_ip == ip)
    assert p.verdict == urteil


def test_pfadsuche_abbruch_mit_grund():
    p = next(p for p in facts(BS).path_search if p.host_ip == "198.202.211.1")
    assert p.abort_reason == "waf_body_marker"
    hl = next(p for p in facts(HL).path_search if p.host_ip == "216.150.1.65")
    assert hl.challenge is True and 403 in hl.status_codes


# ---------------------------------------------------------------- T9 fremde Domains

@pytest.mark.parametrize("order,ip,domains", [
    (LW, "116.202.77.64", ["flott.de"]),
    (JW, "188.40.3.130", ["erbbauverein.de", "toyota-motorsport.com"]),
    (BS, "92.205.224.174", ["dirak.de"]),
])
def test_fremde_domains_ohne_domains_des_hosters(order, ip, domains):
    assert SYS.foreign_domains(host(order, ip).shared) == domains


def test_betreiber_des_servers_aus_rdns():
    shared = host(CA, "159.69.143.80").shared
    assert shared.server_operator == "planwerk6.de" and shared.operator == "Hetzner Online GmbH"
    assert "planwerk6.de" not in SYS.foreign_domains(shared)


def test_dienste_weiterer_domains_auf_dem_hoster_server():
    fremd = sorted(s.port for s in facts(CA).services if s.foreign)
    assert fremd == [8000, 8001, 8800]
    assert not any(s.foreign for o in (DB, LW, JW, HE, BS, HL) for s in facts(o).services)


# ---------------------------------------------------------------- T11 Langzeitpflege

def test_debian_12_in_langzeitpflege():
    deb = next(s for s in facts(JW).software if s.family == "debian")
    assert deb.eol.status == "supported" and deb.eol.date == "2028-06-30" and deb.eol.lts_since == "2026-07-11"
    deb11 = next(s for s in facts(DB).software if s.family == "debian")
    assert deb11.eol.status == "eol" and deb11.eol.lts_since is None


# ---------------------------------------------------------------- T14 Erneuerungslinie

def test_erneuerungslinie_je_aussteller():
    t = next(t for t in facts(HE).tls if t.fqdn == "www.huendgen-entsorgung.de")
    r = t.cert.renewal
    assert r.issuer == "Let's Encrypt" and r.recent_leads == [30, 7, 7]
    assert r.expected_renewal == "2026-10-04"


def test_gueltiges_zertifikat_desselben_namens_an_anderer_adresse():
    t = next(t for t in facts(CA).tls if t.fqdn == "mailstore.castenow.de")
    # S6b-4n (spec/11 N8): .6 liefert eine unvollstaendige Kette (Chain of trust NOT ok) und ist
    # keine Vorlage mehr.
    assert t.cert.valid_elsewhere == ["195.50.179.4:443"]
    assert t.cert.valid_elsewhere_not_after.startswith("2027-03-14")


# ---------------------------------------------------------------- T15 Technik

def test_wpscan_status_je_erweiterung():
    wp = {s.product: s for s in facts(DB).software if s.outdated is not None}
    assert wp["betheme"].outdated is True and wp["betheme"].latest_version == "28.5.10"
    assert len(wp["betheme"].vulnerabilities) == 12
    assert wp["betheme-child"].outdated is False


def test_windows_mit_nmap_als_zweiter_quelle():
    win = [s for s in facts(JW).software if s.family == "windows_server" and s.host_ip == "217.243.248.29"]
    assert win and all("nmap" in s.detection_sources for s in win)


def test_skript_urls_als_versionsquelle():
    um = [s for s in facts(CA).software if s.family == "ultimate_member"]
    assert {s.version_norm for s in um} == {"2.13.1"}
    migrate = [s for s in facts(HE).software if s.family == "jquery_migrate"]
    assert any("redirect_probe" in s.detection_sources for s in migrate)


# ---------------------------------------------------------------- Teil 3

def test_x_powered_by_mit_version_von_der_endseite():
    h = next(h for h in facts(CA).http if h.fqdn == "ubb-wiki.castenow.de")
    assert h.powered_by == "PHP/8.4.25, PleskLin"


def test_titel_der_aufgenommenen_seite():
    fq = {f.name: f for f in facts(HL).fqdns}
    assert fq["online.heuel.com"].probe_final_url == "https://www.heuel.com/"
    assert fq["ose.heuel.com"].probe_title == "Webmodule"
