# -*- coding: utf-8 -*-
"""S6b-4 (spec/11): Berichtsseite je T-Nummer an den sieben Auftraegen der Scan-Runde.

Jeder Test haelt eine Aussage aus spec/11 fest (T1 bis T16, Teil 3, E15 bis E23). Die
Golden-Reportdaten laufen mit dem festen Stichtag 19.09.2026; wo das Berichtsdatum zaehlt
(T5, T14), baut der Test die Reportdaten mit dem Datum der Erzeugung (27.09.2026).
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from reporter.catalog import evaluate
from reporter.catalog import load_catalog
from reporter.v3 import chapters as C
from reporter.v3 import levels as L
from reporter.v3 import tables as T
from reporter.v3.report_data import build_report_data
from tests.v3.conftest import data_for, facts_for

DB = "1fbc92b9-34ab-414e-8843-a1f1e9f15431"
LW = "c3d5724c-bdbf-4da8-982f-4f1a52210e28"
JW = "31d67a02-b485-4d05-b228-dbdde092cc68"
HE = "3cf01f8d-4d21-4e6d-bac2-7342f1a4d6c7"
BS = "68d59573-7a93-4efa-89cc-e7b10cc4d140"
CA = "1f8bc977-39a7-47c7-b4ad-7b05dbac2d52"
HL = "2e56abe1-c1a6-442e-b36a-dc9f83c81da8"
SIEBEN = (DB, LW, JW, HE, BS, CA, HL)


def befund(data, check: str):
    return next(f for f in data.findings if check in f.checks)


def karte(data, ip: str) -> dict[str, tuple[str, str]]:
    return {p.p: (p.s, p.st) for c in data.architecture.services if c.host == ip for p in c.ports}


def posture(data) -> dict[tuple[str, str], str]:
    return {(b.name, i.l): i.v for b in data.architecture.posture for i in b.items}


def grenze(data, anfang: str):
    return next(lim for lim in data.scope.limitations if lim.what.startswith(anfang))


_AM_27: dict[str, object] = {}


def am_27(order: str):
    """Reportdaten mit dem Berichtsdatum der Erzeugung (spec/11 T5, T14)."""
    if order not in _AM_27:
        facts = facts_for(order)
        output = evaluate(facts, report_date="2026-09-27")
        _AM_27[order] = build_report_data(facts, output, report_date="27.09.2026")
    return _AM_27[order]


# ---------------------------------------------------------------- T1 Kennung

def test_imaps_und_pop3s_mit_kennung_statt_nicht_identifiziert():
    k = karte(data_for(DB), "88.99.35.112")
    assert k["993"] == ("IMAP über TLS (Dovecot)", "gruen")
    assert k["995"] == ("POP3 über TLS (Dovecot)", "gruen")
    assert not any("nicht identifiziert" in s for s, _ in karte(data_for(LW), "116.202.77.64").values())


def test_nicht_identifiziert_nur_mit_regel_und_nach_ampel():
    data = data_for(HE)
    k = karte(data, "80.90.145.166")
    f = befund(data, "service_unidentified")
    for port in ("1000", "1001", "1002"):
        assert k[port] == (f"nicht identifiziert (Port {port})", f.status)


def test_passivport_ausserhalb_des_portbereichs():
    data = data_for(LW)
    assert any("ManageSieve (Dovecot Pigeonhole)" in n and "außerhalb des geprüften Portbereichs" in n
               for n in data.architecture.notes)
    zeile = next(r for r in data.appendix.inventory if r.port == "4190")
    assert zeile.svc == "ManageSieve (Dovecot Pigeonhole), laut Passivquelle, außerhalb des geprüften Portbereichs"


# ---------------------------------------------------------------- T2 Netzbetreiber

@pytest.mark.parametrize("order,ip,beginn", [
    (JW, "188.40.3.130", "Hetzner Online GmbH"),
    (CA, "195.50.179.4", "Castenow GmbH (Anschluss Vodafone)"),
    (HE, "18.197.248.23", "A100 ROW GmbH (Amazon, CDN)"),
])
def test_netzbetreiber_in_2_1(order, ip, beginn):
    h = next(h for h in data_for(order).scope.hosts if h.ip == ip)
    assert h.operator.startswith(beginn)


# ---------------------------------------------------------------- T5 Berichtsdatum (E15)

def test_berichtsdatum_in_berliner_zeit(monkeypatch):
    monkeypatch.delenv("VECTISCAN_REPORT_DATE", raising=False)
    # Erzeugung 4 bei JW: 27.09.2026, 01:11 Uhr Berlin, 26.09.2026, 23:11 UTC.
    assert C.report_day(now=datetime(2026, 9, 26, 23, 11, tzinfo=timezone.utc)) == "27.09.2026"
    assert C.report_day("2026-09-26T23:11:00Z") == "27.09.2026"
    assert C.report_day("2026-09-26T21:00:00+00:00") == "26.09.2026"


def test_freigabe_geht_vor_erzeugung(monkeypatch):
    monkeypatch.delenv("VECTISCAN_REPORT_DATE", raising=False)
    freigabe = datetime(2026, 9, 28, 8, 0, tzinfo=timezone.utc)
    assert C.report_day(freigabe, now=datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)) == "28.09.2026"


def test_erzeugungsdatum_nur_mit_erzeugungsnummer():
    assert data_for(JW).meta.generated_on is None
    assert data_for(JW, generation=4).meta.generated_on


# ---------------------------------------------------------------- T6 E5 und Gesamtbewertung (E16)

def test_e5_datum_je_adresse():
    zeile = grenze(data_for(JW), "SMTP auf Port 25")
    # S6b-4n (spec/11 N15): Shodan last_update ist die Aktualisierung des Hosteintrags.
    assert "188.40.3.130 Hosteintrag der Passivquelle aktualisiert am 23.09.2026" in zeile.detail
    assert "217.243.248.28 Hosteintrag der Passivquelle aktualisiert am 19.09.2026" in zeile.detail


def test_gesamtbewertungsregel_in_a1():
    data = data_for(DB)
    assert data.appendix.overall_rule == L.OVERALL_RULE
    assert "schlechteste Ampel der fünf Kategorien" in L.OVERALL_RULE
    blau = next(t for t in data.appendix.triage if t.st == "blau")
    assert L.HINT_PHRASE in blau.t


@pytest.mark.parametrize("order,stufe", [(DB, "HOCH"), (LW, "HOCH"), (JW, "HOCH"), (HE, "MITTEL"),
                                         (BS, "MITTEL"), (CA, "HOCH"), (HL, "MITTEL")])
def test_gesamtbewertung_der_sieben(order, stufe):
    assert data_for(order).glance.overall == stufe


# ---------------------------------------------------------------- T7 Messadresse und AAAA

def test_dns_rotation_als_einschraenkung():
    zeile = grenze(data_for(HE), "Messung an einer anderen Adresse")
    assert "Transportverschlüsselung an 52.59.120.70" in zeile.detail


def test_aaaa_im_system_und_in_der_zaehlung():
    data = data_for(LW)
    h = next(h for h in data.scope.hosts if h.ip == "116.202.77.64")
    assert h.more_ips == ["2a01:4f8:d0a:668b::2"]
    assert data.meta.hosts_total == 2 and data.meta.hosts_ipv6 == 1
    assert grenze(data, "IPv6-Adresse vom Prüfstand aus nicht geprüft")


# ---------------------------------------------------------------- T8 Pfadsuche

def test_pfadsuche_mit_urteil():
    data = data_for(BS)
    # S6b-4n (spec/11 N13): die Startseite antwortete normal (200); der Scanner vermutete das Merkmal.
    assert ("abgebrochen, der Scanner vermutete in der Startseite (200) ein Abwehrmerkmal"
            in grenze(data, "Suche nach nicht verlinkten Pfaden abgebrochen").detail)
    assert "Weiterleitung 301" in grenze(data, "Suche nach nicht verlinkten Pfaden nur gegen").detail
    phase2 = next(m for m in data.scope.method_phases if m.n == "2")
    assert "nicht belastbar" in phase2.text
    db2 = next(m for m in data_for(DB).scope.method_phases if m.n == "2")
    assert "Verzeichnis-Enumeration" in db2.text


# ---------------------------------------------------------------- T9 fremde Domains (E18)

def test_zaehlung_und_wortlaut_ohne_andere_kunden():
    for order in SIEBEN:
        for f in data_for(order).findings:
            assert "anderer Kunden" not in f.operator_note
            assert "anderen Kunden" not in f.operator_note
    lw = befund(data_for(LW), "legacy_protocols_present")
    assert "laut Passivquelle 1 weitere Domain" in lw.operator_note


def test_fremdnamen_im_bericht_maskiert():
    data = data_for(CA)
    text = data.model_dump_json()
    assert "netscope-media.de" not in text and "tonausstrom.de" not in text
    assert "Fremddomain" in text


def test_fremde_dienste_im_zustaendigkeitskasten():
    data = data_for(CA)
    assert not any(f.checks == ["http_alt_port"] for f in data.findings)
    f = befund(data, "admin_panel_hoster")
    # S6b-4n (spec/11 N11): 8800 (Icecast) ohne Domainfakt ist kein Dienst einer weiteren Domain.
    assert "Dienste weiterer Domains (Ports 8000, 8001)" in f.operator_note
    assert "Auf Port 8800 läuft Icecast streaming media server; die Zuordnung zu einer Domain ist nicht belegt" \
        in f.operator_note


def test_spf_auf_geteilten_server_mit_mechanismus_und_betreiber():
    f = befund(data_for(CA), "spf_authorizes_shared_host")
    assert "Mechanismus: a" in f.evidence and "löst auf: 159.69.143.80" in f.evidence
    assert "Server von planwerk6.de im Rechenzentrum Hetzner Online GmbH" in f.affected


# ---------------------------------------------------------------- T10 Saetze mit Fakt

def test_kategorien_nur_aus_getroffenen_regeln():
    lw = data_for(LW)
    assert "preisgegebenen Angaben" not in lw.glance.overall_text
    assert lw.landscape_lead.startswith("5 Befunde in 3 von 5 Kategorien")
    assert "preisgegebenen Angaben" in data_for(DB).glance.overall_text


def test_rollentexte_am_fakt():
    # S6b-4n (spec/11 N14): LW traegt weitere belegte Rollen; die Website steht nicht mehr vorn.
    lw = next(o for o in data_for(LW).business.observed if "Website" in o.system)
    assert "Formulareingaben" not in lw.meaning
    db = data_for(DB).business.observed[0]
    assert "Unternehmensnetz" not in db.meaning
    ca = next(o for o in data_for(CA).business.observed if o.system.startswith("Mail-Webzugang"))
    assert "von außen nicht feststellbar" in ca.meaning


def test_mfa_empfehlung_prueft_zuerst():
    f = befund(data_for(HE), "login_portal_exposed")
    assert f.recommendation[0][1].startswith("Prüfen, ob die Anmeldung am Portal einen zusätzlichen Faktor verlangt")


# ---------------------------------------------------------------- T11 Lebenszyklus und E22

def test_langzeitpflege_mit_quelle_in_3_1():
    zeilen = [r for b in data_for(JW).architecture.tech for r in b.rows if r.c == "Debian GNU/Linux"]
    # S6b-4n (spec/11 N9): Plakette nur "LTS", Zeitraum und Quelle in der Hinweisspalte.
    assert zeilen and zeilen[0].status == "LTS" and zeilen[0].note == "in Langzeitpflege bis 30.06.2028 laut Debian"
    pos = next(p for p in data_for(JW).positives if p.title == "Serversoftware mit laufender Herstellerpflege")
    assert "Debian GNU/Linux 12 (in Langzeitpflege bis 30.06.2028 laut Debian)" in pos.text


def test_passivbefund_auf_e4_host_als_blauer_hinweis():
    data = data_for(BS)
    f = befund(data, "passive_service_version_unverified")
    assert f.status == "blau" and "nicht erreichbar" in f.found and "Mail-Webzugang (/owa/)" in f.found
    kat_b = next(c for c in data.glance.categories if c.key == "B")
    assert kat_b.status == "blau"


def test_hinweis_ausnahmen_gleich_den_pruefungen_mit_hint_when():
    mit_hint = {c.spec.id for c in load_catalog().checks if c.spec.hint_when}
    assert mit_hint == set(L.HINT_EXCEPTIONS)


# ---------------------------------------------------------------- T12 Dubletten und Plan

@pytest.mark.parametrize("order", SIEBEN)
def test_hebel_je_befund_hoechstens_einmal(order):
    refs = [lv.refs[0] for lv in data_for(order).glance.levers]
    assert len(refs) == len(set(refs))


def test_header_planzeile_je_regel_mit_allen_befunden():
    zeile = next(r for r in data_for(JW).plan if r.action.startswith("Die fehlenden Sicherheits-Header setzen"))
    assert set(zeile.refs) >= {"VS-2026-008", "VS-2026-009"}
    assert "outlook.junkerwerk.de (fehlend: X-Content-Type-Options, Referrer-Policy, Permissions-Policy)" in zeile.action


def test_dmarc_ohne_meldeadresse_zuerst_rua():
    f = befund(data_for(HE), "dmarc_quarantine")
    assert f.recommendation[0][1].startswith("Eine Meldeadresse (rua)")


def test_wordpress_erweiterungen_alle_cves_und_zielversionen():
    data = data_for(DB)
    f = befund(data, "wordpress_plugin_vulnerable")
    assert f.title == "WordPress-Erweiterungen mit bekannten Schwachstellen"
    # S6b-4n (spec/11 N9): fehlerbereinigte Version getrennt von der neuesten laut wpscan, Produktname.
    assert "BeTheme (fehlerbereinigt ab 28.5.8, neueste laut wpscan 28.5.10)" in f.recommendation[0][1]
    assert "Complianz (neueste und fehlerbereinigte Version laut wpscan 7.5.5)" in f.recommendation[0][1]
    assert "CVE-2026-83561" in f.evidence
    assert any("CVE-2026-83561" in r.cve for r in data.appendix.cve_refs)


def test_vrfy_angeboten_statt_beantwortet():
    f = befund(data_for(DB), "smtp_vrfy_enabled")
    assert "VRFY angeboten (laut EHLO)" in f.title and "VRFY in der EHLO-Liste: ja" in f.evidence


def test_he_hebelreihung_lebenszyklus_vor_zweck():
    hebel = [lv.title for lv in data_for(HE).glance.levers]
    assert hebel[0] == "Microsoft Exchange ohne Herstellerpflege ablösen"
    assert hebel[1] == "Zweck offener Dienste ohne Kennung klären"


# ---------------------------------------------------------------- T13 Einschraenkungszeilen

def test_ursache_aus_der_scan_steuerung():
    zeile = grenze(data_for(BS), "Von der Scan-Steuerung übersprungen: aktive Webanalyse, Regel hosted-cms-webflow")
    assert zeile.checks == ["Web-Prüfungen"]


def test_fremdbewertungszeile_nur_mit_version_ohne_abgleich():
    jw = grenze(data_for(JW), "Keine Fremdbewertung")
    assert "188.40.3.130" in jw.detail
    ca = grenze(data_for(CA), "Keine Fremdbewertung")
    assert "92.205.163.53" not in ca.detail


def test_vertrauenskette_nur_fuer_den_eigenen_namen():
    zeile = grenze(data_for(HL), "Vertrauenskette des Zertifikats nicht geprüft")
    assert zeile.detail == "Betroffen: www.heuel.com."


# ---------------------------------------------------------------- T14 Fristen

def test_erneuerungsmuster_im_nachweis():
    f = befund(data_for(HE), "cert_expiring_later")
    assert "zuletzt 7 Tage vor Ablauf erneuert" in f.evidence and "04.10.2026" in f.evidence


def test_am_berichtsdatum_abgelaufen_sofern_nicht_erneuert():
    f = befund(am_27(CA), "cert_expiring")
    assert "am Berichtsdatum abgelaufen, sofern nicht erneuert" in f.title
    # S6b-4n (spec/11 N8): 195.50.179.6 liefert eine unvollstaendige Kette und ist keine Vorlage.
    assert any("195.50.179.4:443 (gültig bis 14.03.2027)" in text for _, text in f.recommendation)
    assert not any("195.50.179.6" in text for _, text in f.recommendation)


def test_stufenwechsel_bis_zum_berichtsdatum():
    """Die Dringlichkeit bleibt am Scantag (E2); der Befund nennt, dass am Berichtsdatum
    hoechstens zwei Wochen bleiben, und die erste Empfehlung ist die Pruefung."""
    f = befund(am_27(HE), "cert_expiring_later")
    assert "Am Berichtsdatum liegt der Ablauf höchstens zwei Wochen entfernt" in f.found
    assert f.recommendation[0][1].startswith("Prüfen, ob die Erneuerung inzwischen erfolgt ist")
    assert "Am Berichtsdatum" not in befund(data_for(HE), "cert_expiring_later").found


# ---------------------------------------------------------------- T15 Technologietabelle

def tech(order):
    return {(b.host.split(" ")[0], r.c): r for b in data_for(order).architecture.tech for r in b.rows}


def test_eine_zeile_je_produkt_mit_wpscan_status():
    t = tech(DB)
    assert [k for k in t if "Slider" in k[1]] == [("88.99.35.112", "Slider Revolution")]
    assert t[("88.99.35.112", "BeTheme")].v == "27.5.3"
    # S6b-4n (spec/11 N9): Plakette nur "veraltet", Anzahl und Zielversionen in der Hinweisspalte.
    assert t[("88.99.35.112", "BeTheme")].status == "veraltet"
    assert t[("88.99.35.112", "BeTheme")].note == (
        "12 bekannte Lücken, fehlerbereinigt ab 28.5.8, neueste laut wpscan 28.5.10")
    assert t[("88.99.35.112", "WordPress")].status == "veraltet"


def test_fremde_und_eingebundene_dienste_nicht_in_3_1():
    assert not [k for k in tech(HE) if k[1] == "Cookiebot"]
    assert not [k for k in tech(CA) if k[1] == "Icecast"]
    assert [k for k in tech(BS) if "loudflare" in k[1]] == [("198.202.211.1", "Cloudflare")]
    assert tech(CA)[("92.205.163.53", "Ultimate Member")].v == "2.13.1"


def test_zweite_quelle_fuer_windows():
    assert "nmap" in tech(JW)[("217.243.248.29", "Windows Server")].src


# ---------------------------------------------------------------- T16 Posture und Service-Karte

def test_posture_aus_denselben_regeln():
    p = posture(data_for(CA))
    assert p[("E-Mail-Authentizität", "SPF")] == "Handlungsbedarf"
    assert p[("Transportverschlüsselung", "195.50.179.5")] == "Handlungsbedarf"
    assert p[("Transportverschlüsselung", "195.50.179.6")] == "Handlungsbedarf"
    assert posture(data_for(HL))[("Sicherheits-Header", "216.150.1.65")] == "nicht prüfbar"


def test_service_karte_ueber_den_softwareport():
    assert karte(data_for(DB), "88.99.35.112")["30000"] == ("OpenSSH", "gelb")
    zeile = next(r for r in data_for(DB).appendix.inventory if r.port == "30000")
    assert "VS-2026-003" in zeile.ref


# ---------------------------------------------------------------- Teil 3

def test_jw_sonicwall_mit_datum_und_portbereich():
    f = befund(data_for(JW), "admin_service_exposed_passive")
    assert "Hosteintrag aktualisiert am 19.09.2026" in f.affected and "außerhalb des geprüften Portbereichs" in f.found
    # T16: der Passivport mit Befund steht in dessen Ampel, nicht grau.
    assert karte(data_for(JW), "217.243.248.28")["4433"] == ("SonicWall", f.status)


def test_jw_p04_mit_hu_und_selektoren():
    p = next(p for p in data_for(JW).positives if p.title == "Absender-Authentizität mit SPF und DKIM hinterlegt"
             or "DKIM" in p.title)
    assert "junkerwerk.hu (Selektoren hse1, hse2)" in p.text


def test_jw_beast_vermutlich_abgeschwaecht_und_verwaiste_eintraege():
    data = data_for(JW)
    assert "BEAST, vermutlich abgeschwächt" in befund(data, "tls_weakness").affected
    assert posture(data)[("DNS-Hygiene", "Verwaiste Einträge")] == "unauffällig"


def test_jw_zusaetzliche_dienste_mit_tls_zwang():
    f = befund(data_for(JW), "legacy_protocols_present")
    # S6b-4n (spec/11 N15): Titelzusatz und Betreiber in einer Klammer.
    assert f.title == "Zusätzliche Mail- und Dateidienste erreichbar (TLS erzwungen; beim Hoster Hetzner Online GmbH)"
    assert "älteres Übertragungsprotokoll" not in f.found


def test_he_8443_als_plattformhinweis():
    f = befund(data_for(HE), "http_alt_port")
    assert "Port schließen" not in " ".join(t for _, t in f.recommendation)
    assert "Plattformbetreiber" in f.recommendation[0][1]


def test_ca_rollen_und_liesmich():
    data = data_for(CA)
    systeme = [o.system for o in data.business.observed]
    # S6b-4n (spec/11 N14): Dienste aus dem Portscan auch auf dem geteilten System.
    assert "Anmeldung zur Website, Dateiaustausch, Mailabruf und Einlieferung (ubb-wiki.castenow.de)" in systeme
    assert "Umfrageplattform (umfrageonline.com), leitet auf die Website weiter (umfrage.castenow.de)" in systeme
    assert any("liesmich.html der WordPress-Installation abrufbar" in n for n in data.architecture.notes)
    assert "X-Powered-By: PHP/8.4.25" in befund(data, "http_header_disclosure").affected


def test_hl_rolle_und_bildunterschriften():
    data = data_for(HL)
    assert any(o.system.startswith("Dateiaustausch (FTP, SFTP), Webanwendung mit Anmeldung")
               for o in data.business.observed)
    bilder = {s.host: s.what for s in data.architecture.screens}
    # S6b-4n (spec/11 N4): online leitet auf www (anderer Host) weiter; das Bild zeigt www und steht
    # nur dort.
    assert "online.heuel.com" not in bilder and "www.heuel.com" in bilder
    assert bilder["ose.heuel.com"] == "Webmodule (ose.heuel.com/webmodule-ee/login.seam)"


def test_lw_nachweis_und_hinweiskasten():
    data = data_for(LW)
    f = befund(data, "db_exposed")
    assert "Produkt: MariaDB" in f.evidence and "Produkt: MySQL" not in f.evidence
    assert "SASL (leer)" in befund(data, "legacy_protocols_present").evidence
    assert "3 weitere gefundene Namen sind nicht geprüft" in data.glance.coverage_warning


def test_bs_zertifikatsliste_einmal_und_reputation_mit_cdn():
    data = data_for(BS)
    f = befund(data, "service_cert_expired")
    assert f.found.count("92.205.224.174:110") == 1 and "587" not in f.verify
    rep = next(p for p in data.positives if p.title == "Keine Einträge in Reputationsquellen")
    # S6b-4n (spec/11 N6): die geteilte CDN-Kante ist nicht kundenbezogen und steht nicht im Positivbefund.
    assert "198.202.211.1" not in rep.text


def test_db_dmarc_beim_dienstleister_und_p05_nur_bei_hardfail():
    data = data_for(DB)
    f = befund(data, "dmarc_none")
    assert "postmaster@spacekoeln.de" in f.impact and "mail1.spacekoelnsrv1.de" in f.impact
    assert not [p for p in data.positives if p.title == "SPF-Eintrag vorhanden"]


# ---------------------------------------------------------------- Katalogtexte je Variante

def test_hsts_titel_je_variante():
    assert "HSTS abgeschaltet (max-age=0)" in befund(data_for(DB), "hsts_missing").title
    assert "HSTS fehlt" in befund(data_for(JW), "hsts_missing").title
    assert "oder ist abgeschaltet" not in befund(data_for(JW), "hsts_missing").title


def test_rollen_varianten_stehen_in_der_tabelle():
    assert ("website", "ohne_webanalyse") in T.ROLE_VARIANTS
    assert "Formulareingaben" not in T.ROLE_VARIANTS[("website", "ohne_webanalyse")]
    assert "Unternehmensnetz" not in T.ROLE_VARIANTS[("fernzugang", "rechenzentrum")]
