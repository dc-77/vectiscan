# -*- coding: utf-8 -*-
"""S6b-4n (spec/11 Teil 6): Berichtsseite je N-Nummer an den sieben Auftraegen der Scan-Runde.

Jeder Test haelt eine Aussage aus spec/11 Teil 6 fest (N1 bis N15, E24 und E25 als Vorschlag
umgesetzt). Die Golden-Reportdaten laufen mit dem festen Stichtag 19.09.2026; wo das
Berichtsdatum zaehlt (N8), baut der Test die Reportdaten mit dem 27.09.2026.
"""
from __future__ import annotations

import pytest

from reporter.v3 import chapters as C
from reporter.v3 import levels as L
from reporter.v3 import tables as T
from tests.v3.conftest import data_for, facts_for
from tests.v3.test_s6b4 import (BS, CA, DB, HE, HL, JW, LW, SIEBEN, am_27, befund, grenze, karte,
                                posture)


def positiv(data, check: str):
    return next(p for p in data.positives if check in p.checks)


def hat_positiv(data, check: str) -> bool:
    return any(check in p.checks for p in data.positives)


def rolle(data, name: str):
    return next(o for o in data.business.observed if name in o.system)


def befund_an(data, check: str, name: str):
    return next(f for f in data.findings if check in f.checks and name in f.affected)


def tech(data) -> dict[tuple[str, str], object]:
    return {(b.host.split(" ", 1)[0], r.c): r for b in data.architecture.tech for r in b.rows}


# ---------------------------------------------------------------- N1 CSP-Positiv

def test_n1_csp_nur_frame_ancestors_ist_befund():
    data = data_for(HE)
    f = befund_an(data, "csp_missing", "www.huendgen-entsorgung.de")
    assert "Inhaltsrichtlinie nur mit frame-ancestors, keine Regel für Skriptquellen" in f.title
    assert "keine Regel für Skriptquellen" in f.found
    assert not any("csp_missing" in p.checks and "huendgen" in p.text for p in data.positives)


def test_n1_csp_positiv_nicht_neben_csp_weak():
    """castenow www traegt Gelb csp_weak; ubb-wiki hat nur frame-ancestors."""
    p = positiv(data_for(CA), "csp_missing")
    assert "www.castenow.de" not in p.text and "ubb-wiki" not in p.text
    assert p.text == "Auf bitwarden.castenow.de ist eine Content-Security-Policy gesetzt."
    assert befund_an(data_for(CA), "csp_missing", "ubb-wiki.castenow.de")


# ---------------------------------------------------------------- N2 HSTS nach E24

def test_n2_hsts_positiv_mit_messort():
    p = positiv(data_for(CA), "hsts_short")
    assert "mailstore.castenow.de (gemessen an der Fehlerseite mit Status 400)" in p.text
    assert "umfrage.castenow.de (beim Plattformbetreiber umfrageonline.com; gemessen an der Weiterleitung mit Status 301)" in p.text
    assert "((" not in p.text and "))" not in p.text


def test_n2_hsts_nicht_an_der_sicherheitsabfrage():
    """heuel online: nur die 429 der Plattform gemessen, weder Positiv noch Befund."""
    data = data_for(HL)
    assert "online.heuel.com" not in positiv(data, "hsts_short").text
    assert not any("hsts_missing" in f.checks and "online.heuel.com" in f.affected for f in data.findings)


def test_n2_hsts_nicht_unter_endseite_nicht_bewertet():
    """castenow mailstore (400) und umfrage (301): HSTS ist dort gemessen und steht nicht unter
    "Endseite nicht bewertet". Gegenprobe bergersysteme ftp (403) ohne HSTS: ein Fehlen an einer
    Fehlerseite bewertet hsts_missing nicht (S6b-4), HSTS bleibt dort in der Zeile."""
    for lim in data_for(CA).scope.limitations:
        if lim.code in ("headers_redirect_only", "headers_error_only"):
            assert "HSTS" not in lim.checks, lim
    ftp = next(lim for lim in data_for(BS).scope.limitations if lim.code == "headers_error_only")
    assert "HSTS" in ftp.checks


def test_n2_gruppenname_ohne_ungemessenen_alias():
    f = befund(data_for(BS), "hsts_missing")
    assert "cdn.bergersysteme.com" not in f.title and "cdn.bergersysteme.com" not in f.affected


# ---------------------------------------------------------------- N3 Endseite

def test_n3_ose_nicht_an_der_endseite_bewertet():
    data = data_for(HL)
    f = next(f for f in data.findings if "security_headers_incomplete" in f.checks and "ose.heuel.com" in f.affected)
    assert "bewertet an der Endseite" not in f.evidence
    assert "ose.heuel.com (fehlend: X-Frame-Options, X-Content-Type-Options)" in f.affected
    assert "ose.heuel.com (Referrer-Policy und Permissions-Policy nur an der Weiterleitungsseite gemessen)" \
        in grenze(data, "Sicherheits-Header an der Endseite nur einzeln belegt").detail


def test_n3_ca_mail_nicht_gemessen_statt_fehlend():
    lim = grenze(data_for(CA), "Sicherheits-Header an der Endseite nur einzeln belegt")
    assert ("mail.castenow.de (X-Frame-Options, Referrer-Policy und Permissions-Policy an der Endseite "
            "nicht gemessen)") in lim.detail


# ---------------------------------------------------------------- N4 selber Host

def test_n4_redirector_mit_eigenen_diensten():
    data = data_for(HL)
    o = rolle(data, "webportal.heuel.com")
    assert o.role_keys == ["dateiaustausch", "mail_dienste", "weiterleitung"]
    assert "Weiterleitung auf ose.heuel.com" in o.system
    assert "Webanwendung" not in o.system


def test_n4_bild_nur_am_eigenen_host():
    bilder = {s.host for s in data_for(HL).architecture.screens}
    assert bilder == {"edi.heuel.com", "ose.heuel.com", "www.heuel.com"}


def test_n4_scan_steuerung_mit_grund():
    lim = grenze(data_for(BS), "Von der Scan-Steuerung übersprungen")
    assert "wegen Weiterleitung auf die Webflow-Seite www.bergersysteme.com" in lim.detail


def test_n4_technik_des_ziels_nicht_am_redirector():
    t = tech(data_for(HL))
    assert not any(ip == "213.133.104.51" and name in ("Java/Servlet", "Google Tag Manager", "Facebook Pixel")
                   for ip, name in t)


# ---------------------------------------------------------------- N5 Messadresse

def test_n5_posture_am_namen_gemessen():
    assert posture(data_for(HL))[("Transportverschlüsselung", "216.150.1.65")] == "am Namen gemessen (216.150.1.129)"
    assert posture(data_for(CA))[("Transportverschlüsselung", "3.174.98.120")] == "am Namen gemessen (3.174.98.123)"
    # Befund am Host bleibt Handlungsbedarf (huendgen: Zertifikat laeuft ab).
    assert posture(data_for(HE))[("Transportverschlüsselung", "18.197.248.23")] == "Handlungsbedarf"


def test_n5_weitere_adresse_laut_dns():
    lim = grenze(data_for(HE), "Weitere Adresse laut DNS, nicht geprüft")
    assert lim.detail.startswith("Betroffen: 52.59.120.70 (huendgen-entsorgung.de, www.huendgen-entsorgung.de): "
                                 "dort am Namen gemessen Transportverschlüsselung")
    assert "216.150.16.65 (online.heuel.com)" in grenze(data_for(HL), "Weitere Adresse laut DNS").detail
    assert "3.174.98.30 (umfrage.castenow.de)" in grenze(data_for(CA), "Weitere Adresse laut DNS").detail


def test_n5_rotationszeile_mit_technologie_erkennung():
    lim = grenze(data_for(HL), "Messung an einer anderen Adresse desselben Namens")
    assert "Webabruf und Technologie-Erkennung an 216.150.16.65" in lim.detail


def test_n5_positiv_nennt_messadresse():
    p = next(p for p in data_for(CA).positives if "tls_no_13" in p.checks)
    assert "umfrage.castenow.de (beim Plattformbetreiber umfrageonline.com; gemessen an 3.174.98.123)" in p.text


# ---------------------------------------------------------------- N6 Gruen und Positiv nur mit Messung

def test_n6_kategorie_ohne_messung_grau():
    kat = {c.key: c for c in data_for(LW).glance.categories}
    assert kat["D"].status == "grau"
    assert kat["D"].note.startswith("Nicht bewertbar: Prüfung von Transportverschlüsselung und Sicherheits-Headern nicht möglich")


@pytest.mark.parametrize("order,ip", [(BS, "198.202.211.1"), (HE, "18.197.248.23"), (CA, "3.174.98.120")])
def test_n6_reputation_ohne_plattformadressen(order, ip):
    assert ip not in positiv(data_for(order), "ip_reputation").text


def test_n6_zonentransfer_je_domain_mit_eigenem_lauf():
    """Entscheidung DC 27.09.: .hu bleibt, der Nachweis zitiert die eigene AXFR-Datei."""
    p = positiv(data_for(JW), "dns_zone_transfer")
    assert "junkerwerk.de" in p.text and "junkerwerk.hu" in p.text


# ---------------------------------------------------------------- N7 DMARC

def test_n7_meldeadressen_je_domain_getrennt():
    f = befund(data_for(BS), "dmarc_none")
    assert ("Die Berichte gehen an dmarc@bergersysteme.com in der eigenen Domain und an "
            "a.jg23hj7j@reports.hornetdmarc.com außerhalb der eigenen Domain.") in f.impact
    assert "per CNAME an bergersysteme.com.dmarc.hornetdmarc.com übertragen" in f.impact
    assert "Eingehende E-Mail nimmt ein Mailserver" not in f.impact
    assert f.recommendation[0][1].startswith("Die Berichte an dmarc@bergersysteme.com auswerten, die Auswertung der "
                                             "Berichte an a.jg23hj7j@reports.hornetdmarc.com beim Dienstleister anfordern")


def test_n7_betreibersatz_aus_spf_mx():
    f = befund(data_for(DB), "dmarc_none")
    assert "Der SPF-Eintrag gibt ihn über den Mechanismus mx auch als Absender frei" in f.impact
    assert f.recommendation[0][1].startswith("Die Auswertung der Berichte an postmaster@spacekoeln.de beim "
                                             "Dienstleister anfordern")


# ---------------------------------------------------------------- N8 Zertifikatshinweis

def test_n8_kein_hinweis_aus_fremder_linie():
    f = befund(data_for(HE), "cert_expiring_later")
    assert not any("desselben Namens" in text or "80.90.145.166" in text for _, text in f.recommendation)


def test_n8_sofern_nicht_erneuert_in_hebel_effekt_und_auswirkung():
    data = am_27(CA)
    f = befund(data, "cert_expiring")
    assert "sofern es nicht erneuert wurde" in f.impact
    zeilen = [r for r in data.plan if f.id in r.refs]
    assert any("sofern nicht erneuert" in r.action or "sofern das Zertifikat nicht erneuert" in (r.effect or "")
               for r in zeilen), [(r.action, r.effect) for r in zeilen]
    assert not any("195.50.179.6" in text for _, text in f.recommendation)


# ---------------------------------------------------------------- N9 Zielversionen

def test_n9_zielversion_getrennt_und_verzeichnis_veraltet():
    data = data_for(DB)
    f = befund(data, "wordpress_plugin_vulnerable")
    assert ("Slider Revolution (fehlerbereinigt ab 6.7.38, neueste laut wpscan 6.7.35, Verzeichnis von wpscan "
            "veraltet)") in f.recommendation[0][1]
    assert "mindestens" not in f.recommendation[0][1]
    r = tech(data)[("88.99.35.112", "Slider Revolution")]
    assert r.status == "veraltet" and "fehlerbereinigt ab 6.7.38, neueste laut wpscan 6.7.35" in r.note


def test_n9_kindtheme_nicht_bestimmbar():
    data = data_for(DB)
    r = tech(data)[("88.99.35.112", "BeTheme Child")]
    wp = befund(data, "wordpress_plugin_vulnerable")
    assert r.status == "unbekannt"
    assert r.note == f"nicht bestimmbar (eigenes Kindtheme, Elterntheme BeTheme, siehe {wp.id})"


@pytest.mark.parametrize("order", SIEBEN)
def test_n9_plakette_nur_veraltet_oder_lts(order):
    for r in tech(data_for(order)).values():
        assert r.status in ("aktuell", "veraltet", "unbekannt", "LTS", "unsicher"), (r.c, r.status)


# ---------------------------------------------------------------- N10 Buendel-Dubletten

def test_n10_plesk_ein_titelbaustein_und_eine_stufe():
    f = befund(data_for(BS), "admin_panel_hoster")
    assert f.title.startswith("Verwaltungszugänge auf 92.205.224.174: Verwaltungsoberfläche Plesk auf 443, 8443 und "
                              "laut Passivquelle 8880")
    assert [s for s, _ in f.recommendation] == ["In Kürze", "Mittelfristig"]
    assert f.verify.count("erwartet wird") == 1
    assert "laut Passivquelle 1 weitere Domain" in f.found and "laut Zertifikat oder Passivquelle" not in f.found


def test_n10_ca_satzfolge_der_auswirkung():
    f = befund(data_for(CA), "admin_panel_hoster")
    saetze = f.impact.split(". ")
    assert saetze[0].startswith("Eine Übernahme der Verwaltungsoberfläche")
    assert f.impact.rstrip(".").endswith("Abschalten oder beschränken kann sie nur der Hoster")


def test_n10_vrfy_eine_auswirkung_und_passivport_im_ersten_satz():
    f = befund(data_for(DB), "smtp_vrfy_enabled")
    assert f.title.endswith("VRFY angeboten (laut EHLO) auf 465, 587 und laut Passivquelle 25")
    assert f.impact.count("Beantwortet der Mailserver VRFY") == 1
    assert len(f.recommendation) == 1


def test_n10_x_feserver_nicht_unter_version():
    f = befund(data_for(JW), "http_header_disclosure")
    assert "Version der eingesetzten Serversoftware: autodiscover.junkerwerk.de (Server: Microsoft-IIS/10.0, " \
           "X-AspNet-Version: 4.0.30319)" in f.found
    assert "Der Antwortheader X-FEServer nennt den internen Namen" in f.found
    assert f.impact.count("Eine sichtbare Versionskennung") == 1


def test_n10_zertifikat_einmal_und_mailclients():
    data = data_for(BS)
    f = befund(data, "service_cert_expired")
    assert f.found.count("Zertifikat Plesk") == 1 and "Zertifikat Plesk" not in f.affected
    assert f.impact.startswith("Mailclients warnen")
    assert any(r.effect == "Verhindert Zertifikatswarnungen an Mailclients" for r in data.plan if f.id in r.refs)


# ---------------------------------------------------------------- N11 Fremddomains

def test_n11_fremddomains_nach_quelle():
    f = befund(data_for(CA), "admin_panel_hoster")
    assert "laut Passivquelle 2 weitere Domains und laut Zertifikat 1 weitere Domain" in f.operator_note
    assert "Dienste weiterer Domains (Ports 8000, 8001)" in f.operator_note
    assert "Auf Port 8800 läuft Icecast streaming media server; die Zuordnung zu einer Domain ist nicht belegt" \
        in f.operator_note


def test_n11_fremddienste_grau_in_der_servicekarte():
    ports = karte(data_for(CA), "92.205.163.53")
    for p in ("8000", "8001", "8800"):
        assert ports[p][1] == "grau", (p, ports[p])


def test_n11_betreiber_des_servers():
    f = befund(data_for(CA), "spf_authorizes_shared_host")
    assert "Server von planwerk6.de" in f.affected and "laut Passivquelle 1 weitere Domain" in f.affected


# ---------------------------------------------------------------- N12 Anhang C und D

def test_n12_werkzeuge_ohne_daten():
    zeilen = [t.t for t in data_for(DB).appendix.tools]
    assert any(z.endswith("URLhaus (ohne Ergebnis)") for z in zeilen)
    assert any("SecurityTrails (ohne Ergebnis)" in z for z in zeilen)


def test_n12_anhang_d_aus_zusammengefuehrten_meldungen():
    text = data_for(DB).appendix.filtering
    assert "davon 531 gleiche Meldungen der Webanalyse zusammengeführt" in text
    assert "Doppelmeldungen mehrerer Werkzeuge und Durchgänge" not in text


def test_n12_keine_anhangzeile_zu_bewerteter_regel():
    """castenow: "CSP Header Not Set" steht nicht neben dem CSP-Positivbefund am selben Host."""
    for t in data_for(CA).appendix.tool_findings:
        if "Content Security Policy" in (t.message or "") or "CSP Header" in (t.message or ""):
            assert "bitwarden.castenow.de" not in t.where, t


def test_n12_neos_eine_zeile_mit_zweiter_quelle():
    t = tech(data_for(HL))
    assert t[("217.72.203.132", "Neos")].src == "cms_fingerprint, httpx"


# ---------------------------------------------------------------- N13 Einschraenkungen

def test_n13_zertifikat_aus_dem_portscan():
    lim = grenze(data_for(BS), "Transportverschlüsselung nur für einen Teil")
    assert "92.205.224.174 (Ports 21, 110, 143, 465, 993, 995, 8443: Protokolle und Verfahren nicht bewertet, " \
           "Zertifikat aus dem Portscan)" in lim.detail


def test_n13_pfadsuche_bei_zeitlimit():
    lim = grenze(data_for(DB), "Suche nach nicht verlinkten Pfaden nur teilweise")
    assert "dortmund-beach.com: Suche nach sensiblen Dateien abgebrochen (Zeitlimit)" in lim.detail


def test_n13_e4_ohne_eigene_messungen():
    lim = grenze(data_for(BS), "Vom Prüfstand aus nicht erreichbar")
    assert "Ergebnisse eigener Messungen liegen nicht vor" in lim.detail
    assert "Ergebnisse zu diesen Hosts liegen deshalb nicht vor" not in lim.detail


def test_n13_zap_ohne_meldungen():
    lim = grenze(data_for(HE), "Webanalyse ohne Meldungen")
    assert "aktive Prüfung abgeschlossen und ohne Meldungen" in lim.detail


def test_n13_kurzlauf_nicht_vollstaendig():
    lim = grenze(data_for(JW), "Aktive Webanalyse nur teilweise")
    assert "217.243.248.28 (autodiscover.junkerwerk.de, outlook.junkerwerk.de)" in lim.detail
    assert "aktive Webanalyse als Kurzlauf (10 Sekunden)" in lim.detail


def test_n13_ziel_der_aktiven_webanalyse_nach_art_der_antwort():
    """junkerwerk: "nur an cloud … ohne Seiteninhalt (Status 200)" war unverständlich."""
    assert ("aktive Webanalyse nur an cloud.junkerwerk.de, einer Seite ohne eigenen Inhalt (Titel „IIS Windows "
            "Server“, Status 200)") in grenze(data_for(JW), "Aktive Webanalyse nur teilweise").detail
    hl = grenze(data_for(HL), "Aktive Webanalyse nur teilweise").detail
    assert "aktive Webanalyse nur an edi.heuel.com, einer Fehlerseite (Status 403)" in hl
    assert "aktive Webanalyse nur an online.heuel.com, einer Sicherheitsabfrage (Status 429)" in hl
    assert "ohne Seiteninhalt" not in hl


def test_n13_zaehlung_nur_aus_dns():
    data = data_for(LW)
    assert "davon 1 nur aus DNS oder ohne Antwort" in data.scope.lead
    lim = grenze(data, "IPv6-Adresse vom Prüfstand aus nicht geprüft")
    assert "Die Adresse steht als AAAA-Eintrag" in lim.detail


def test_n13_waf_vermutung_bei_normaler_startseite():
    lim = grenze(data_for(BS), "Suche nach nicht verlinkten Pfaden abgebrochen")
    assert "der Scanner vermutete in der Startseite (200) ein Abwehrmerkmal" in lim.detail


# ---------------------------------------------------------------- N14 Rollen

def test_n14_rollen_aus_fakten():
    assert rolle(data_for(DB), "dortmund-beach.com").role_keys == [
        "fernzugang", "dateiaustausch", "mail_dienste", "website", "webanwendung"]
    assert "Mailabruf, Einlieferung und Versand laut SPF" in rolle(data_for(DB), "dortmund-beach.com").system
    assert rolle(data_for(JW), "www.junkerwerk.de").role_keys[0] == "datenbank"
    assert "Anmeldeportal (Port 444)" in rolle(data_for(HE), "exchange.huendgen-entsorgung.de").system
    assert "Mail-Webzugang laut Passivquelle" in rolle(data_for(BS), "owa.bergersysteme.com").system


def test_n14_rollenwoerter_der_mailabrufrolle():
    """Offene Abrufports belegen nicht, dass dort die Postfaecher des Unternehmens liegen."""
    assert T.ROLE_CATEGORIES["mail_dienste"] == frozenset()
    assert "postfach" not in T.ROLE_DEFS["mail_dienste"][1].lower()


# ---------------------------------------------------------------- N15 Kleinreste

def test_n15_referrer_policy_heutige_voreinstellung():
    f = next(f for f in data_for(DB).findings if "security_headers_incomplete" in f.checks)
    assert "Ohne Referrer-Policy gilt die Voreinstellung des Browsers" in f.impact


def test_n15_starttls_statt_tls_erzwungen():
    karten = {p.p: p.s for c in data_for(LW).architecture.services for p in c.ports}
    assert "TLS erzwungen" not in karten.get("587", "")


def test_n15_a1_ausnahme_nur_fuer_ablaufende_zertifikate():
    assert "cert_expiring" in L.URGENT_EXCEPTIONS and "service_cert_expired" not in L.URGENT_EXCEPTIONS


def test_n15_dienstnamen():
    assert C.SERVICE_NAMES == {"domain": "DNS", "tcpwrapped": "Dienst ohne Antwort"}
    namen = {p.p: p.s for c in data_for(BS).architecture.services for p in c.ports}
    assert "DOMAIN" not in namen.values() and "TCPWRAPPED" not in namen.values()


def test_n15_hosteintrag_statt_gesehen():
    f = befund(data_for(JW), "admin_service_exposed_passive")
    assert "Hosteintrag aktualisiert am 19.09.2026" in f.affected


def test_n15_doppeltes_praefix_im_plan():
    for order in SIEBEN:
        for r in data_for(order).plan:
            assert "einfordern: Beim" not in r.action and "erfragen: Beim" not in r.action, r.action


def test_n15_e25_anmeldenamen_nur_als_anzahl():
    f = befund(data_for(CA), "wordpress_user_enumeration")
    assert f.affected == ("ubb-wiki.castenow.de (1 Anmeldename, gefunden über "
                          "https://ubb-wiki.castenow.de/wp-json/oembed/1.0/embed)")
    namen = [u for h in facts_for(CA).http if h.wordpress for u in h.wordpress.users]
    assert namen and not any(n in f.found + f.evidence + f.affected for n in namen)


def test_n15_proftpd_eine_zeile_und_etracker_ausgeblendet():
    lw = [n for (ip, n) in tech(data_for(LW)) if ip == "116.202.77.64"]
    assert "ProFTPD mod_sftp" not in lw and "ProFTPD" in lw
    assert not any(n in ("Etracker", "etracker", "Cookiebot") for (_, n) in tech(data_for(HE)))


def test_n15_numerus_eines_namens():
    assert "1 weiterer gefundener Name ist nicht geprüft" in data_for(JW).glance.coverage_warning
