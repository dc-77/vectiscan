# -*- coding: utf-8 -*-
"""S6d: Berichtsseite auf den S6c-Rohfeldern (Reportdaten v3, Kapitel 2, Befunde, Anhaenge).

Je Punkt A1 bis A11 und #16 der Satz im Bericht, der aus dem neuen Fakt folgt; ohne das Rohfeld
bleibt der Bericht wie vorher (Rueckwaertskompatibilitaet). Fixtures: die drei S6c-Probeauftraege,
das RDAP-Fixture (lumbeck-wolter) und veraenderte Bundles fuer Faelle ohne echte Daten.
"""
from __future__ import annotations

import json

from reporter.catalog import evaluate
from reporter.facts.build import build_from_bundle
from reporter.gate import v3_checks as VC
from reporter.v3.golden import REPORT_DATE
from reporter.v3.report_data import build_report_data
from tests.test_facts_s6d import CA, DB, FIXTURES, JW, LW, bundle
from tests.v3.conftest import data_for

DB_ALT = "1fbc92b9-34ab-414e-8843-a1f1e9f15431"


def _data(facts):
    out = evaluate(facts)
    return build_report_data(facts, out, report_date=REPORT_DATE), out


def _lim(data, what: str):
    return next((lim for lim in data.scope.limitations if lim.what == what), None)


def _finding(data, check: str):
    return next((f for f in data.findings if any(p.check == check for p in f.provenance)), None)


# ---------------------------------------------------------------- A1

def test_a1_spaltenkopf_und_anhang_b_laut_ripe_mit_rdap():
    b = bundle(LW)
    rdap = json.loads((FIXTURES / "rdap_ripe_hetzner.json").read_text(encoding="utf-8"))
    b.rdap = {k: v for k, v in rdap.items() if isinstance(v, dict)}
    data, _ = _data(build_from_bundle(b))
    assert data.scope.operator_header == "Netzbetreiber (laut RIPE)"
    zeile = next(h for h in data.scope.hosts if h.ip == "116.202.77.64")
    assert zeile.operator.startswith("Hetzner Online GmbH") and zeile.operator_source == "RIPE"
    assert any(r.operator == "Hetzner Online GmbH, laut RIPE" for r in data.appendix.inventory if r.host == "116.202.77.64")


def test_a1_ohne_rdap_laut_abuseipdb_auch_im_anhang_b():
    data = data_for(LW)
    assert data.scope.operator_header == "Netzbetreiber (laut AbuseIPDB)"
    assert any(r.operator.endswith("laut AbuseIPDB") for r in data.appendix.inventory)


# ---------------------------------------------------------------- A2

def test_a2_gescheiterter_port_mit_ursache_in_der_einschraenkung():
    lim = _lim(data_for(DB), "Transportverschlüsselung nur für einen Teil der TLS-Dienste geprüft")
    assert lim is not None and "110 (Verbindung abgewiesen)" in lim.detail
    assert "Geprüft wurden die TLS-Dienste mit eigenem Lauf" in lim.detail


def test_a2_abdeckung_nennt_die_gemessenen_ports():
    zeile = next(h for h in data_for(DB).scope.hosts if h.ip == "88.99.35.112")
    assert "587 (SNI dortmund-beach.com)" in zeile.coverage and "nicht für Port 110" in zeile.coverage


def test_a2_alte_fixtures_behalten_den_satz_zu_port_443():
    lim = _lim(data_for("68d59573-7a93-4efa-89cc-e7b10cc4d140"),
               "Transportverschlüsselung nur für einen Teil der TLS-Dienste geprüft")
    assert lim is not None and "Geprüft wurde jeweils der Webdienst auf Port 443" in lim.detail


def test_a2_host_mit_gemessenen_mailports_vor_der_abweisung():
    zeile = next(h for h in data_for(JW).scope.hosts if h.ip == "188.40.3.130")
    assert "Transportverschlüsselung an Port 21, 110, 143, 465, 587, 993, 995 geprüft" in zeile.coverage


# ---------------------------------------------------------------- A4

def test_a4_auth_vor_starttls_als_gelber_befund_mit_passivport():
    f = _finding(data_for(DB), "smtp_auth_before_starttls")
    assert f is not None
    assert f.status == "gelb" and f.urgency == "Mittelfristig"
    assert "auf 587 und laut Passivquelle 25" in f.title
    assert "AUTH vor STARTTLS" in f.evidence


def test_a4_passivvariante_allein_bei_bergersysteme():
    f = _finding(data_for("68d59573-7a93-4efa-89cc-e7b10cc4d140"), "smtp_auth_before_starttls_passive")
    assert f is not None and "92.205.224.174" in f.title + f.found


# ---------------------------------------------------------------- A5

def test_a5_aktive_xmlrpc_sonde_traegt_den_befund():
    b = bundle(CA)
    b.hosts["92.205.163.53"].xmlrpc_probe = {**b.hosts["92.205.163.53"].xmlrpc_probe,
                                            "status": 405, "xmlrpc_enabled": True, "fault": False}
    data, _ = _data(build_from_bundle(b))
    f = _finding(data, "wordpress_xmlrpc_enabled")
    assert f is not None and "XML-RPC-Sonde" in f.evidence and "ubb-wiki.castenow.de" in f.title + f.found


def test_a5_abgelehnte_sonde_kein_befund():
    assert _finding(data_for(CA), "wordpress_xmlrpc_enabled") is None


# ---------------------------------------------------------------- A6

def test_a6_endseite_von_header_check_im_nachweis():
    """castenow mail: erste Antwort 302 auf /owa/, Endantwort logon.aspx mit 200 (S6c redirect_eval)."""
    f = next(f for f in data_for(CA).findings
             if any(p.check == "security_headers_incomplete" for p in f.provenance) and "mail.castenow.de" in f.evidence)
    zeile = next(z for z in f.evidence.splitlines() if z.startswith("mail.castenow.de"))
    erste = zeile.index("Antwort: 302")
    ende = zeile.index("bewertet an der Endseite: https://mail.castenow.de/owa/auth/logon.aspx")
    assert erste < ende < zeile.index("Antwort: 200")


# ---------------------------------------------------------------- A7

def test_a7_anhang_c_mit_adresse_je_meldung():
    zeilen = [t.where for t in data_for(CA).appendix.tool_findings]
    assert any("/" in w.split(" ", 1)[0] for w in zeilen), zeilen


# ---------------------------------------------------------------- A8

def test_a8_gemessene_sperre_mit_dauer_und_ports():
    b = bundle(JW)
    tp = b.hosts["188.40.3.130"].tech_profile
    tp["provider_block"] = {**tp["provider_block"], "blocked": True, "reachable": False,
                            "time_to_reachable_s": None, "waited_s": 117.4}
    data, out = _data(build_from_bundle(b))
    zeile = next(h for h in data.scope.hosts if h.ip == "188.40.3.130")
    assert zeile.coverage.startswith("Portscan vollständig; Transportverschlüsselung an Port")
    assert "danach abgewiesen, das Zielnetz sperrt die Prüfadresse" in zeile.coverage
    lim = _lim(data, "Zielnetz sperrt die Prüfadresse nach dem Portscan")
    assert lim is not None and "nach 117 Sekunden" in lim.detail and "an den Ports 21, 22, 80" in lim.detail


def test_a8_ohne_sperre_kein_sperrtext_aber_hinweis_auf_spaete_abweisung():
    data = data_for(JW)
    assert _lim(data, "Zielnetz sperrt die Prüfadresse nach dem Portscan") is None
    lim = _lim(data, "Verbindungen nach dem Portscan abgewiesen")
    assert lim is not None and "Die Sperrerkennung direkt nach dem Portscan fand 188.40.3.130 noch erreichbar" in lim.detail


# ---------------------------------------------------------------- A10

def test_a10_positivbefund_mit_abfragefenster():
    p = next(p for p in data_for(DB).positives if "Reputation" in p.title)
    assert "keine Meldungen in den letzten 90 Tagen vor" in p.text


def test_a10_ohne_feld_wie_bisher():
    p = next((p for p in data_for(DB_ALT).positives if "Reputation" in p.title), None)
    assert p is None or "in den letzten" not in p.text


# ---------------------------------------------------------------- A11

def test_a11_whois_und_ehlo_als_einschraenkung():
    data = data_for(DB)
    assert _lim(data, "Registrierungsdaten der Domain nicht abrufbar") is not None
    lim = _lim(data, "Ablehnung einer Anmeldung vor STARTTLS nicht belegt")
    assert lim is not None and "Port 465: Zeitlimit; Port 587: Zeitlimit" in lim.detail


def test_a11_neue_werkzeuge_ohne_sammelzeile():
    for order in (DB, JW, CA):
        assert _lim(data_for(order), "Prüfung ohne auswertbares Ergebnis") is None or all(
            "Weitere Prüfungen" not in lim.checks for lim in data_for(order).scope.limitations)


# ---------------------------------------------------------------- #16

def test_b1_schwere_im_feed_nicht_angegeben():
    f = _finding(data_for(DB), "wordpress_plugin_vulnerable")
    assert f is not None and "Schweregrad im Feed nicht angegeben" in f.evidence
    assert "bekannte Schwachstellen laut wpscan" in f.evidence


# ---------------------------------------------------------------- Gate

def test_gate_regelfakt_der_neuen_smtp_regeln():
    assert VC.REGELFAKT["smtp_auth_before_starttls"].pattern == "AUTH vor STARTTLS"
    assert "smtp_auth_before_starttls_passive" in VC.REGELFAKT
