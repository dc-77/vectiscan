# -*- coding: utf-8 -*-
"""S6b-4n: Fakten 1.3.0 an den sieben Auftraegen der Scan-Runde (spec/11 Teil 6).

Je N-Nummer der Fakt, auf dem die Berichtsseite steht: Skriptregel der CSP (N1), HSTS nach
E24 (N2), Endantwort der Weiterleitungspruefung (N3), Technik und Anmeldung nur vom selben
Host (N4), weitere A-Eintraege (N5), Zonentransfer je Domain mit eigenem Lauf (N6),
DMARC-Delegation (N7), Zertifikatslinie (N8), Kindtheme (N9), Quelle je fremdem Namen und
fremdem Dienst (N11), ASP.NET aus httpx und Betriebssystem aus Shodan (N12), Laufergebnis
der aktiven Webanalyse und Urteil je Pfadsuche-Werkzeug (N13).
Die Golden-Fakten sind eingecheckt; hier werden sie nur gelesen.
"""
from __future__ import annotations

import pytest

from reporter.facts import http_headers as HH
from reporter.facts import schema as S
from reporter.facts import systems as SYS
from tests.test_facts_s6b4 import BS, CA, DB, HE, HL, JW, LW, facts, host, service


def http(order: str, fqdn: str) -> S.HttpFact:
    return next(h for h in facts(order).http if h.fqdn == fqdn)


def test_schema_mindestens_1_3_0():
    # S6d: das Schema steht seit S6d auf 1.4.0; die N-Felder aus 1.3.0 bleiben enthalten.
    assert tuple(int(x) for x in S.FACTS_SCHEMA_VERSION.split(".")) >= (1, 3, 0)
    assert all(facts(o).schema_version == S.FACTS_SCHEMA_VERSION for o in (DB, LW, JW, HE, BS, CA, HL))


# ---------------------------------------------------------------- N1 CSP

@pytest.mark.parametrize("wert,regel", [
    ("frame-ancestors 'self'", False),
    ("upgrade-insecure-requests", False),
    ("default-src 'none'; img-src 'self'", True),
    ("script-src 'self'", True),
])
def test_csp_skriptregel(wert, regel):
    assert HH.parse_csp(wert).script_rule is regel


def test_csp_nur_frame_ancestors_an_den_golden():
    """huendgen www und castenow ubb-wiki: nur frame-ancestors; castenow www mit default-src."""
    for order, name in ((HE, "www.huendgen-entsorgung.de"), (CA, "ubb-wiki.castenow.de")):
        csp = http(order, name).csp
        assert csp.present is True and csp.script_rule is False and csp.frame_ancestors == "'self'"
    assert http(CA, "www.castenow.de").csp.script_rule is True


# ---------------------------------------------------------------- N2 HSTS nach E24

@pytest.mark.parametrize("name,status", [("mailstore.castenow.de", 400), ("umfrage.castenow.de", 301),
                                         ("www.castenow.de", 200)])
def test_hsts_an_jeder_https_antwort(name, status):
    """RFC 6797 Abschnitt 8.1: HSTS gilt an jeder HTTPS-Antwort des Namens, auch an 301 und 400."""
    hsts = http(CA, name).hsts
    assert hsts.present is True and hsts.status_code == status and hsts.tool == "header_check"


def test_hsts_nie_an_der_sicherheitsabfrage():
    """heuel online: header_check sieht die 429 der Abwehr; die erste Antwort aus redirect_probe
    ist keine Messung am Namen (E24), also kein HSTS-Fakt."""
    h = http(HL, "online.heuel.com")
    assert h.header_eval.basis == "challenge" and h.hsts is None


# ---------------------------------------------------------------- N3 Endantwort

def test_gleiche_antwort_erkannt():
    a = {"etag": 'W/"8f-5f6f0769ae580-gzip"', "content-length": "132"}
    b = {"etag": '"8f-5f6f0769ae580"', "content-length": "143"}
    assert HH.same_response(a, b) is True
    assert HH.same_response({"last-modified": "Wed, 15 Mar 2023 10:00:00 GMT"},
                            {"last-modified": "Wed, 15 Mar 2023 10:00:00 GMT"}) is True
    assert HH.same_response({"etag": '"1"'}, {"etag": '"2"'}) is False
    assert HH.same_response({}, {}) is False


def test_hl_ose_ohne_endantwort():
    he = http(HL, "ose.heuel.com").header_eval
    assert he.final_response is False and he.client_redirect is True and he.complete is False
    assert he.evaluated.tool == "zap"
    assert he.unknown == ["referrer-policy", "permissions-policy"]


@pytest.mark.parametrize("name", ["mail.castenow.de", "mail2.castenow.de"])
def test_ca_mail_nur_die_302_gemessen(name):
    he = http(CA, name).header_eval
    assert he.final_response is False
    assert {"referrer-policy", "permissions-policy"} <= set(he.unknown)


@pytest.mark.parametrize("order,name,tool", [(JW, "outlook.junkerwerk.de", "redirect_probe"),
                                             (HE, "www.huendgen-entsorgung.de", "header_check")])
def test_endantwort_nach_http_weiterleitung_bleibt(order, name, tool):
    """Gegenprobe: bei HTTP-Weiterleitungen stimmen die Endseiten-Header (logon.aspx, www)."""
    he = http(order, name).header_eval
    assert he.final_response is True and he.complete is True and he.evaluated.tool == tool


# ---------------------------------------------------------------- N4 selber Host

def test_anmeldeform_nur_am_eigenen_host():
    """heuel webportal ist der 143-Byte-Redirector auf ose; die Anmeldemaske gehoert ose."""
    assert http(HL, "ose.heuel.com").login_form is True
    assert all(h.login_form is None for h in facts(HL).http if h.fqdn in ("webportal.heuel.com", "dl.heuel.com"))


def test_technik_des_weiterleitungsziels_nicht_am_redirector():
    """213.133.104.51 traegt nur die eigenen Dienste aus dem Portscan, nichts aus webtech."""
    quellen = {q for s in facts(HL).software if s.host_ip == "213.133.104.51" for q in s.detection_sources}
    assert quellen == {"nmap"}
    produkte = {s.product for s in facts(HL).software if s.host_ip == "213.133.104.51"}
    assert {"Courier", "Dovecot", "Exim", "ProFTPD"} <= produkte


def test_bs_plesk_server_ohne_webflow():
    """bergersysteme 92.205.224.174: Webflow und Cloudflare kamen vom Weiterleitungsziel www."""
    produkte = {s.product for s in facts(BS).software if s.host_ip == "92.205.224.174"}
    assert "Webflow" not in produkte and "Cloudflare" not in produkte
    assert {"Plesk", "Dovecot", "Postfix"} <= produkte


# ---------------------------------------------------------------- N5 weitere A-Eintraege

@pytest.mark.parametrize("order,ip,weitere", [
    (HE, "18.197.248.23", [("52.59.120.70", 4)]),
    (HL, "216.150.1.65", [("216.150.16.65", 4)]),
    (CA, "3.174.98.120", [("3.174.98.123", 4), ("3.174.98.30", 4), ("3.174.98.63", 4)]),
    (LW, "116.202.77.64", [("2a01:4f8:d0a:668b::2", 6)]),
])
def test_weitere_adressen_mit_familie(order, ip, weitere):
    assert [(a.ip, a.family) for a in host(order, ip).additional_ips] == weitere


# ---------------------------------------------------------------- N6 Zonentransfer je Domain

@pytest.mark.parametrize("domain,datei", [("junkerwerk.de", "phase0/zone_transfer.txt"),
                                          ("junkerwerk.hu", "phase0/zone_transfer_junkerwerk.hu.txt")])
def test_zonentransfer_mit_eigenem_lauf(domain, datei):
    """Abweichung zu spec/11 N6 (Entscheidung DC 27.09.): das Tar enthaelt fuer .hu einen eigenen
    AXFR-Lauf gegen alle drei Nameserver; der Nachweis zitiert je Domain die eigene Datei."""
    d = next(d for d in facts(JW).dns if d.domain == domain)
    assert d.zone_transfer is not None and d.zone_transfer.allowed is False
    assert ("zone_transfer", datei) in [(e.tool, e.ref) for e in d.evidence]


def test_cdn_adresse_mit_meldung_im_fenster():
    """bergersysteme 198.202.211.1: totalReports 0, aber lastReportedAt 21.09.2026."""
    h = host(BS, "198.202.211.1")
    assert h.shared is not None and h.shared.kind == "platform"
    assert h.reputation.abuseipdb_total_reports == 0
    assert h.reputation.abuseipdb_last_reported_at.startswith("2026-09-21")


# ---------------------------------------------------------------- N7 DMARC

def test_dmarc_delegation_aus_cname():
    d = next(d for d in facts(BS).dns if d.domain == "bergersysteme.com")
    assert d.dmarc.delegated_to == "bergersysteme.com.dmarc.hornetdmarc.com"
    assert d.dmarc.rua == ["mailto:a.jg23hj7j@reports.hornetdmarc.com", "mailto:dmarc@bergersysteme.com"]


def test_dmarc_ohne_delegation_mit_spf_mx():
    d = next(d for d in facts(DB).dns if d.domain == "dortmund-beach.com")
    assert d.dmarc.delegated_to is None
    assert "mx" in [m.kind for m in d.spf.mechanisms]


# ---------------------------------------------------------------- N8 Zertifikatslinie

def test_vorlage_nur_mit_vollstaendiger_kette():
    """castenow mailstore: .6 liefert Chain of trust NOT ok und faellt als Vorlage weg."""
    t = next(t for t in facts(CA).tls if t.fqdn == "mailstore.castenow.de")
    assert t.cert.valid_elsewhere == ["195.50.179.4:443"]


def test_keine_vorlage_aus_fremder_linie():
    """huendgen: die Sectigo-Wildcard der Exchange-Linie ist keine Vorlage fuer das
    Let's-Encrypt-Zertifikat der Plattform."""
    assert not any(t.cert and t.cert.valid_elsewhere for t in facts(HE).tls)


# ---------------------------------------------------------------- N9 Kindtheme

def test_kindtheme_mit_elterntheme():
    sw = {s.product: s for s in facts(DB).software if s.product.startswith("betheme")}
    assert sw["betheme-child"].child_of == "betheme"
    assert sw["betheme"].child_of is None
    rs = next(s for s in facts(DB).software if s.product == "revslider")
    assert rs.latest_version == "6.7.35"
    assert max((v.fixed_in for v in rs.vulnerabilities if v.fixed_in),
               key=lambda v: tuple(int(x) for x in v.split("."))) == "6.7.38"


# ---------------------------------------------------------------- N11 Fremdnamen

def test_fremdnamen_je_quelle():
    shared = host(CA, "92.205.163.53").shared
    assert shared.foreign_sources == {"certificate": ["tonausstrom.de"],
                                      "passive": ["jaguar.com", "netscope-media.de"]}
    assert SYS.foreign_domains_text(shared) == (
        "laut Passivquelle 2 weitere Domains und laut Zertifikat 1 weitere Domain", 3)
    # secureserver.net ist Hoster, kein Fremdkunde
    assert not any("secureserver" in n for n in shared.foreign_names)


def test_fremdnamen_eine_quelle_im_singular():
    shared = host(CA, "159.69.143.80").shared
    assert SYS.foreign_domains_text(shared) == ("laut Passivquelle 1 weitere Domain", 1)


@pytest.mark.parametrize("port,domain", [(8000, "tonausstrom.de"), (8001, "tonausstrom.de"), (8800, None)])
def test_fremddienst_nur_mit_domainfakt(port, domain):
    """8800 (Icecast) hat keinen Domainfakt: Zuordnung nicht belegt."""
    assert service(CA, "92.205.163.53", port).foreign_domain == domain


# ---------------------------------------------------------------- N12 zweite Quelle

@pytest.mark.parametrize("name,quelle", [("mail.castenow.de", "httpx"), ("mail2.castenow.de", "httpx"),
                                         ("owa.castenow.de", "redirect_probe")])
def test_aspnet_version_mit_quelle(name, quelle):
    h = http(CA, name)
    assert h.aspnet_version == "4.0.30319" and h.aspnet_source == quelle


@pytest.mark.parametrize("order,ip", [(HE, "80.90.145.166"), (CA, "195.50.179.4")])
def test_betriebssystem_aus_shodan_als_zweite_quelle(order, ip):
    win = [s for s in facts(order).software if s.host_ip == ip and s.family == "windows_server"]
    assert win and all("shodan" in s.detection_sources for s in win)


@pytest.mark.parametrize("ip,produkt,beleg", [
    ("217.72.203.132", "Google Tag Manager", "googletagmanager.com/gtm.js"),
    ("217.72.203.132", "Facebook Pixel", "fbevents.js"),
    ("20.79.218.75", "Java/Servlet", "Sitzungs-Cookie der Seite: JSESSIONID"),
])
def test_skript_und_cookie_als_zweite_quelle(ip, produkt, beleg):
    """heuel: Anhang C nannte GTM, Facebook Pixel und Java/Servlet "ohne zweite Quelle", obwohl die
    Skript-Adressen und der Sitzungs-Cookie der Seite in redirect_probe stehen (spec/11 N12)."""
    eintraege = [s for s in facts(HL).software if s.host_ip == ip and s.product == produkt]
    quellen = {q for s in eintraege for q in s.detection_sources}
    assert {"webtech", "redirect_probe"} <= quellen
    assert any(beleg in (e.excerpt or "") for s in eintraege for e in s.evidence)


# ---------------------------------------------------------------- N13 Laufergebnis

def test_zap_active_mit_laufergebnis():
    """huendgen: zap_active complete an beiden Adressen, ohne Meldungen."""
    zap = [c for c in facts(HE).coverage if c.tool == "zap_active"]
    assert {c.host_ip: c.run_status for c in zap} == {"18.197.248.23": "complete", "80.90.145.166": "complete"}


def test_pfadsuche_urteil_je_werkzeug():
    p = next(p for p in facts(DB).path_search if p.target_url == "https://dortmund-beach.com")
    assert p.tool_reasons == {"ffuf_sensitive": "timeout_after_180s"}
