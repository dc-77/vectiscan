# -*- coding: utf-8 -*-
"""Kapitel, Plan und Anhang: die Regeln, die nicht aus dem Katalog kommen."""
from __future__ import annotations

import pytest

from reporter.v3 import chapters as C
from reporter.v3 import levels as L
from reporter.v3.selfcheck import check_report_data
from tests.v3.conftest import JUNKERWERK, data_for, facts_for, junkerwerk_data

MULTI = JUNKERWERK["multi"]


@pytest.fixture(scope="module")
def data():
    return junkerwerk_data()


# ---------------------------------------------------------------- Kapitel 1

def test_ampel_folgt_dem_schwersten_befund_der_kategorie(data):
    for kategorie in data.glance.categories:
        befunde = [f for f in data.findings if f.cat == kategorie.key]
        if not befunde:
            assert kategorie.status == "gruen" and kategorie.level == 0
            continue
        schlimmster = min(befunde, key=lambda f: L.STATUS_RANK[f.status]).status
        assert kategorie.status == schlimmster
        assert kategorie.level == L.BAR_BY_STATUS[schlimmster]


def test_gesamtbewertung_folgt_der_schlechtesten_kategorie(data):
    schlimmste = min((c.status for c in data.glance.categories), key=lambda s: L.STATUS_RANK[s])
    assert data.glance.overall_status == schlimmste
    assert data.glance.overall == L.OVERALL_BY_STATUS[schlimmste]


def test_kontextabsatz_nennt_domains_und_zahlen(data):
    for domain in data.meta.domains:
        assert domain in data.glance.context
    assert str(data.meta.hosts_total) in data.glance.context


def test_abdeckungshinweis_nur_bei_luecken(data):
    luecken = [h for h in data.scope.hosts if h.cov != "voll"]
    assert bool(data.glance.coverage_warning) == bool(luecken)


# ---------------------------------------------------------------- Kapitel 2

def test_lead_und_hosttabelle_widersprechen_sich_nicht(data):
    # S6b-1: je System eine Zeile (IPv4 und IPv6 mit gleichem rDNS); Drittanbieter
    # stehen als "extern" da und zaehlen nicht mit.
    luecken = sum(1 for h in data.scope.hosts if h.cov not in ("voll", "extern"))
    if luecken:
        assert str(luecken) in data.scope.lead
        assert "Alle Systeme" not in data.scope.lead
    else:
        assert "Alle Systeme konnten aktiv geprüft werden" in data.scope.lead


def test_jeder_host_traegt_eine_abdeckung(data):
    for host in data.scope.hosts:
        assert host.cov in ("voll", "teil", "keine", "unerreichbar", "extern")
        assert host.coverage.strip()


def test_ipv6_host_ohne_portscan_ist_ohne_abdeckung(data):
    """S6b-1 (spec/09 Q16): IPv4 und IPv6 mit gleichem rDNS sind ein System mit zwei
    Adressen; die IPv6-Adresse steht in derselben Zeile und nennt ihren Grund."""
    ipv6 = [h for h in data.scope.hosts if any(":" in a for a in [h.ip, *h.more_ips])]
    assert ipv6, "der Junkerwerk-Auftrag hat einen IPv6-Host"
    assert ipv6[0].cov != "voll"
    assert "IPv6" in ipv6[0].coverage


def test_virustotal_ist_keine_einschraenkung(data):
    """Ein bewusst nicht eingesetztes Werkzeug ist keine Luecke der Pruefung."""
    text = " ".join(f"{x.what} {x.detail}" for x in data.scope.limitations).lower()
    assert "virustotal" not in text


def test_methodik_grenzt_ab_statt_zuzusagen(data):
    """Die Einordnung sagt, was der Scan nicht ist, und verspricht keinen Standard."""
    from tests.textlint import FORBIDDEN_CLAIMS

    note = data.scope.standard_note
    assert "Kein Penetrationstest" in note
    assert "keine Prüfung mit Zugangsdaten" in note
    assert not FORBIDDEN_CLAIMS.search(note)
    assert not FORBIDDEN_CLAIMS.search(data.scope.ai_note)
    assert "regelbasiert" in data.scope.ai_note


# ---------------------------------------------------------------- Kapitel 3

def test_technik_tabelle_ohne_doppelte_zeilen(data):
    for block in data.architecture.tech:
        paare = [(r.c, r.v) for r in block.rows]
        assert len(paare) == len(set(paare)), block.host


def test_technik_status_und_farbe_passen_zusammen(data):
    # S6b-4 (spec/11 T11, T15): Langzeitpflege mit Quelle ist gruen, eine laut wpscan veraltete
    # Erweiterung gelb ("veraltet, 12 bekannte Lücken, aktuell 28.5.10"), ein unsicherer Kern rot.
    erlaubt = {("aktuell", "gruen"), ("veraltet", "rot"), ("unbekannt", "grau"),
               ("in Langzeitpflege (LTS)", "gruen"), ("unsicher", "rot")}
    for block in data.architecture.tech:
        for row in block.rows:
            ok = (row.status, row.st) in erlaubt or (row.st == "gelb" and row.status.startswith("veraltet"))
            assert ok, (block.host, row.c, row.status, row.st)


def test_dienstkarten_faerben_befundports(data):
    rote_ports = set()
    for finding in data.findings:
        if finding.status != "rot":
            continue
        for token in finding.affected.split(", "):
            host, _, rest = token.partition(":")
            port = rest.split(" ", 1)[0]
            if port.isdigit():
                rote_ports.add((host, port))
    assert rote_ports, "der Junkerwerk-Auftrag hat einen roten Befund mit Ports"
    for card in data.architecture.services:
        for port in card.ports:
            if (card.host, port.p) in rote_ports:
                assert port.st == "rot", (card.host, port.p)


def test_screens_kommen_aus_den_faktenschluesseln(data):
    keys = {f.screenshot_key.rsplit("/", 1)[-1]
            for f in facts_for(MULTI).fqdns if f.screenshot_key}
    assert {s.file for s in data.architecture.screens} == keys


def test_posture_hat_vier_bloecke_mit_items(data):
    assert len(data.architecture.posture) == 4
    for block in data.architecture.posture:
        assert block.items
        for item in block.items:
            assert item.v.strip()


# ---------------------------------------------------------------- Plan

def test_plan_ist_nach_dringlichkeit_sortiert(data):
    reihenfolge = [L.URGENCY_BY_STAGE[s] for s in L.STAGE_ORDER]
    positionen = [reihenfolge.index(row.prio) for row in data.plan]
    assert positionen == sorted(positionen)


def test_erste_planzeile_traegt_die_wirkung_des_roten_befunds(data):
    """Spitzensatz, dann der Effekt der Regel (S6b-2, spec/09 Q6)."""
    from reporter.v3 import plan as P

    assert data.plan[0].st == "rot"
    teile = data.plan[0].effect.split(P.PLAN_EFFECT_SEP)
    assert teile[0] == "Beseitigt das dringlichste Risiko dieses Berichts"
    assert teile[1:] == ["Entzieht Angreifern den direkten Zugriff auf die Datenbanken"]


def test_hebel_zeigen_auf_bekannte_befunde(data):
    ids = {f.id for f in data.findings}
    assert 1 <= len(data.glance.levers) <= 3
    for lever in data.glance.levers:
        assert set(lever.refs) <= ids
        assert lever.title and lever.effect


# ---------------------------------------------------------------- Anhang

def test_inventar_enthaelt_jeden_offenen_dienst(data):
    offen = {(s.host_ip, str(s.port)) for s in facts_for(MULTI).services if s.state == "open"}
    im_anhang = {(r.host, r.port) for r in data.appendix.inventory}
    assert offen <= im_anhang


def test_werkzeugliste_nur_gelaufene_werkzeuge(data):
    gelaufen = {c.tool for c in facts_for(MULTI).coverage if c.status in ("ok", "empty")}
    from reporter.v3.tables import TOOL_ROWS

    for row in data.appendix.tools:
        tools = next(t for label, _, _, t in TOOL_ROWS if label == row.t)
        assert gelaufen & set(tools), row.t


def test_zap_active_steht_wieder_auf_der_methodikseite():
    """S0b-Nachweis vom 18.09.2026 liegt vor, deshalb ist das Werkzeug zurueck."""
    from reporter.report_mapper import SCAN_TOOLS
    from reporter.v3.tables import TOOL_ROWS

    assert any(t["tool"] == "ZAP Active Scan" for t in SCAN_TOOLS)
    assert any(label == "OWASP ZAP (Active Scan)" for label, _, _, _ in TOOL_ROWS)
    assert not any("ffuf" in t["tool"].lower() for t in SCAN_TOOLS)
    assert not any("virustotal" in t["tool"].lower() for t in SCAN_TOOLS)


def test_anhang_werkzeugbefunde_ohne_bewertung(data):
    assert data.appendix.tool_findings, "Junkerwerk hat ZAP-Informationsalerts"
    for item in data.appendix.tool_findings:
        assert item.what.strip() and item.note.strip()


def test_selbstcheck_findet_praeparierte_defekte(data):
    kaputt = data.model_copy(deep=True)
    kaputt.findings[0].id = kaputt.findings[1].id
    assert any("lueckenlos" in e or "doppelte" in e for e in check_report_data(kaputt))

    kaputt = data.model_copy(deep=True)
    kaputt.plan = kaputt.plan[:1]
    assert any("ohne Massnahme" in e for e in check_report_data(kaputt))

    kaputt = data.model_copy(deep=True)
    kaputt.appendix.tools[0].t = "nmap 7.93"
    assert any("Versionsnummer" in e for e in check_report_data(kaputt))

    kaputt = data.model_copy(deep=True)
    kaputt.meta.consolidated = 99
    assert any("consolidated" in e for e in check_report_data(kaputt))


def test_zeitfenster_in_ortszeit(data):
    assert data.meta.scan_date == "31.08.2026"
    assert data.meta.scan_window.startswith("31.08.2026, ")
    assert "Uhr (" in data.meta.scan_window


def test_paketname_und_label():
    assert C.UNKNOWN == "unbekannt"
    data = data_for(MULTI)
    assert data.meta.package == "Perimeter"
    assert data.meta.package_label == "PERIMETERSCAN"
