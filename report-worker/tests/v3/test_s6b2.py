# -*- coding: utf-8 -*-
"""S6b-2 an allen Golden-Auftraegen: Stufen (Q5), Plan (Q6), Nachweise (Q7),
Einstufungstabelle (E1, E2), Ausschluesse (#28), Auslieferungsversion, whois.

Die Einzelfaelle stehen in den Katalog-Fixtures und den Negativ-Fixtures der Scan-Runde
(tests/v3/test_negative_scanrunde.py); hier stehen die Regeln, die fuer jeden Bericht gelten.
"""
from __future__ import annotations

import re

import pytest

from reporter.catalog import load_catalog
from reporter.v3 import levels as L
from reporter.v3 import tables as T
from reporter.v3.selfcheck import check_report_data_detailed
from tests.v3.conftest import data_for, facts_for, order_ids, output_for

ORDERS = order_ids()
CASTENOW = "1f8bc977-39a7-47c7-b4ad-7b05dbac2d52"
DORTMUND = "1fbc92b9-34ab-414e-8843-a1f1e9f15431"


# ---------------------------------------------------------------- E1, E2: eine Tabelle

def test_verwaltungseinstufung_gleicht_katalog_und_anhang():
    """A.2, die Einstufung der Verwaltungspruefungen und der Katalog aus einer Quelle."""
    catalog = load_catalog()
    for check_id, (scale, level, fall) in L.ADMIN_EXPOSURE.items():
        spec = catalog.by_id[check_id].spec
        assert (spec.scale, spec.level) == (scale, level), check_id
        zeile = dict(T.EXPOSURE_SCALE)["kritisch" if level == "kritisch" else "erhöht"]
        assert fall in zeile, (check_id, fall)
    befund_mitglieder = {m for m in catalog.bundle_by_id["admin_access"].members}
    assert befund_mitglieder == set(L.ADMIN_EXPOSURE)


def test_webmin_mit_anmeldung_ist_kritisch():
    assert L.ADMIN_EXPOSURE["admin_service_exposed"][:2] == ("exposure", "kritisch")
    for check_id in ("admin_panel_hoster", "admin_service_unconfirmed", "admin_service_exposed_passive",
                     "admin_portal_exposed"):
        assert L.ADMIN_EXPOSURE[check_id][:2] == ("exposure", "erhoeht"), check_id


def test_benannte_ausnahmen_sind_genau_die_pruefungen_mit_urgent_when():
    mit_urgent = {cc.spec.id for cc in load_catalog().checks if cc.spec.urgent_when}
    assert mit_urgent == set(L.URGENT_EXCEPTIONS) == {"cert_expiring"}
    rot = next(text for label, status, text in T.triage_rows() if status == "rot")
    assert "Ausnahme" in rot and "höchstens sieben Tagen" in rot


def test_zertifikat_mit_einem_tag_ist_rot_und_unverzueglich():
    """E2 an castenow: mailstore laeuft am 24.09.2026 ab (testssl 1 Tag)."""
    (f,) = [f for f in data_for(CASTENOW).findings if "mailstore.castenow.de:443" in f.affected
            and "Zertifikat" in f.title]
    assert (f.status, f.urgency) == ("rot", "Unverzüglich")
    assert f.recommendation[0][0] == "Unverzüglich"


# ---------------------------------------------------------------- Q5 Stufen

@pytest.mark.parametrize("order", ORDERS)
def test_erste_empfehlung_steht_auf_der_dringlichkeit(order):
    for f in data_for(order).findings:
        assert f.recommendation, f.id
        assert f.recommendation[0][0] == f.urgency, (order, f.id, f.urgency, f.recommendation[0])
        rang = [L.STAGE_RANK[s] for s in L.STAGE_ORDER]
        stufen = [next(s for s in L.STAGE_ORDER if L.URGENCY_BY_STAGE[s] == st) for st, _ in f.recommendation]
        assert all(L.STAGE_RANK[s] >= L.STAGE_RANK[stufen[0]] for s in stufen), (order, f.id)
        assert rang  # Stufentabelle ist nicht leer


# ---------------------------------------------------------------- Q6 Plan

def _namen(order) -> set[str]:
    facts = facts_for(order)
    return {h.ip for h in facts.hosts} | {f.name for f in facts.fqdns}


@pytest.mark.parametrize("order", ORDERS)
def test_eine_planzeile_je_massnahmentext(order):
    data = data_for(order)
    texte = [z.action for z in data.plan]
    assert len(texte) == len(set(texte)), (order, [t for t in texte if texte.count(t) > 1])
    refs = {r for z in data.plan for r in z.refs}
    assert refs == {f.id for f in data.findings}
    for z in data.plan:
        assert z.effect, (order, z.action)


@pytest.mark.parametrize("order", ORDERS)
def test_hebel_ohne_hostnamen(order):
    namen = _namen(order)
    for hebel in data_for(order).glance.levers:
        assert not any(n and n in hebel.title for n in namen), (order, hebel.title)


def test_kein_mail_effekt_an_dnssec_und_caa():
    """spec/09 Q6: "Schützt die Authentizität der eigenen E-Mail" stand bei DNSSEC und CAA."""
    for order in ORDERS:
        data = data_for(order)
        for f in data.findings:
            regeln = {p.check for p in f.provenance}
            if regeln & {"dnssec_missing", "caa_missing"} and not regeln - {"dnssec_missing", "caa_missing"}:
                assert "E-Mail" not in (f.plan_effect or ""), (order, f.id, f.plan_effect)


# ---------------------------------------------------------------- Q7 Nachweise

@pytest.mark.parametrize("order", ORDERS)
def test_nachweise_ohne_rohbezeichner_kuerzung_und_dubletten(order):
    defekte = [d for d in check_report_data_detailed(data_for(order))
               if d.check in ("nachweis_rohbezeichner", "nachweis_gekuerzt", "nachweis_doppelt")]
    assert not defekte, [(d.check, d.message) for d in defekte]


def test_nachweis_dkim_ohne_selektor_in_kundensprache():
    """Offener Punkt nach S6a: "DKIM-Selektoren=keiner bekannt" hiess nichts."""
    for order in ORDERS:
        for f in data_for(order).findings:
            assert "keiner bekannt" not in (f.evidence or ""), (order, f.id)
            assert "DKIM-Selektoren=" not in (f.evidence or ""), (order, f.id)


# ---------------------------------------------------------------- #28 Ausschluesse

def test_ausschluss_ueber_den_schluessel_laesst_die_nummern_stehen():
    ohne = data_for(DORTMUND)
    ziel = ohne.findings[1]
    mit = data_for(DORTMUND, excluded_keys={ziel.key})
    assert [f.id for f in mit.findings] == [f.id for f in ohne.findings if f.id != ziel.id]
    assert mit.meta.excluded_ids == [ziel.id]
    assert ziel.id not in {r for z in mit.plan for r in z.refs}
    assert not [d for d in check_report_data_detailed(mit) if d.is_error], "Luecke an der Ausschlussstelle ist erlaubt"


def test_bericht_erklaert_den_ausschluss():
    """Issue #28 Punkt 4: ohne Satz waere die Luecke in der Nummerierung unerklaert."""
    from reporter.pdf.v3.render import render_html
    ohne = data_for(DORTMUND)
    ziel = ohne.findings[1]
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", render_html(data_for(DORTMUND, excluded_keys={ziel.key}))[0]))
    satz = f"Auf Wunsch des Auftraggebers ist ein Befund nicht aufgeführt ({ziel.id})"
    assert text.count(satz) == 2, "Kapitel 1 und Kapitel 6"
    assert "Auf Wunsch des Auftraggebers" not in render_html(ohne)[0]


def test_schluessel_ist_stabil_und_eindeutig():
    for order in ORDERS:
        keys = [f.key for f in data_for(order).findings]
        assert all(keys) and len(keys) == len(set(keys)), order
        assert all(k.count("/") >= 2 for k in keys)


# ---------------------------------------------------------------- Auslieferungsversion

def test_deckblatt_mit_auslieferungsversion_fusszeile_mit_erzeugung():
    from reporter.pdf.v3.render import render_html
    data = data_for(DORTMUND, report_version="2", generation=7)
    assert (data.meta.report_version, data.meta.generation) == ("2", 7)
    html = render_html(data)[0]
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))
    assert "Erzeugung 7" in text
    # Deckblatt: die Auslieferungsversion, nicht die Erzeugungsnummer; kein "1.0" mehr.
    assert re.search(r"Version\s*2\b", text), text[:400]
    assert "Version 7" not in text and "1.0" not in text.split("Erzeugung")[0][:2000]


def test_ohne_erzeugungsnummer_keine_leere_angabe():
    from reporter.pdf.v3.render import render_html
    assert "Erzeugung" not in render_html(data_for(DORTMUND))[0]


# ---------------------------------------------------------------- whois (spec/08 Punkt 21)

@pytest.mark.parametrize("order", ORDERS)
def test_whois_ohne_daten_steht_nicht_im_bericht(order):
    """S6b-2: kein Befund zur Laufzeit der Domain. S6d (A11): ein whois-Abruf ohne Daten, den der
    Scanner seit S6c ehrlich als ``failed`` fuehrt, steht als Einschraenkung; die alten ``ok``-Zeilen
    mit "no_data" nicht."""
    data = data_for(order)
    failed = any(c.tool == "whois" and c.status == "failed" for c in facts_for(order).coverage)
    zeilen = [lim for lim in data.scope.limitations if "Registrierungsdaten" in (lim.what + lim.detail)]
    if failed:
        assert [lim.what for lim in zeilen] == ["Registrierungsdaten der Domain nicht abrufbar"]
    else:
        assert not zeilen
    assert not [f for f in data.findings if any(p.check == "domain_expiring" for p in f.provenance)]


# ---------------------------------------------------------------- Q12 Positivbefunde

def test_bergersysteme_ohne_zertifikats_positiv_bei_ungeprueftem_mail_tls():
    positiv = [p.title for p in data_for("68d59573-7a93-4efa-89cc-e7b10cc4d140").positives]
    assert not [t for t in positiv if "Zertifikat" in t], positiv


@pytest.mark.parametrize("order", ORDERS)
def test_positivbefund_nur_aus_bestandenen_regeln(order):
    output = output_for(order)
    bestanden = {(r.check_id, r.group_key) for r in output.results if r.status == "pass" and r.positive}
    for p in data_for(order).positives:
        for prov in p.provenance:
            if prov.statement != "positive.text":
                continue
            for gruppe in prov.members:
                assert (prov.check, gruppe) in bestanden, (order, p.title, prov.check, gruppe)


# ---------------------------------------------------------------- Nachtrag 2 (Entscheidungen DC 26.09.)

CASTENOW_VORLAUF = "4e6b6883-a6c8-4204-8b13-b37f907322ca"


@pytest.mark.parametrize("order", [DORTMUND, "14272c00-1145-4675-9b4c-19ce2ead403b"])
def test_froxlor_titel_ueber_die_ip_ist_verwaltungsoberflaeche(order):
    """Frage 1: der Titel eines Hosting-Panels auf der Standardseite (IP:443) ist ein
    Fingerabdruck nach Q13; auf einem System des Kunden Exposition kritisch (E1)."""
    (f,) = [f for f in data_for(order).findings if "88.99.35.112:443 (froxlor)" in f.affected]
    assert (f.status, f.scale, f.level) == ("rot", "exposure", "kritisch")
    assert "88.99.35.112:10000 (Webmin)" in f.affected, "ein Befund je Host (admin_access)"
    assert "beim Aufruf über die IP-Adresse" in f.found
    assert any("Standardseite des Webservers" in text for _, text in f.recommendation)


def test_anhang_eine_zeile_je_meldung():
    """Frage 3: castenow-Vorlauf, vorher 46 Zeilen im Anhang."""
    ap = data_for(CASTENOW_VORLAUF).appendix
    # S6b-3 (spec/10 R15): dazu kommen die ZAP-Meldungen, deren abdeckende Regel am selben
    # Namen nicht angeschlagen hat (Header an Namen, die nur an einer Weiterleitung gemessen sind).
    # S6b-4n (spec/11 N12): Meldungen zu Headern, die ein Befund oder Positivbefund am selben Host
    # bewertet, entfallen (39 statt 40).
    assert len(ap.tool_messages) >= 39 and len(ap.tool_findings) <= 22
    # S6b-3 (spec/10 R15): die Anzahl ist die Zahl der betroffenen Adressen laut Werkzeug.
    assert sum(t.count for t in ap.tool_findings) == sum(max(m.count, 1) for m in ap.tool_messages)
    schluessel = [(t.rule, t.message) for t in ap.tool_findings]
    assert len(schluessel) == len(set(schluessel)), "eine Zeile je Meldung"
    for t in ap.tool_findings:
        namen = [n for n in t.where.split(" und ")[0].split(", ") if n]
        assert len(namen) <= 6, t.where
        orte = {m.where for m in ap.tool_messages if (_kennung(m.rule), m.message) == (_kennung(t.rule), t.message)}
        if len(orte) > 6:
            assert re.search(r" und \d+ weitere$", t.where), t.where
    zap = [t for t in ap.tool_findings if "ZAP-Regel" in t.what]
    assert zap and all(t.what.startswith("„") for t in zap), "Meldungsname als Zitat (Frage 6)"
    assert all(not t.note.startswith("„") for t in ap.tool_findings), "Hinweis ist der deutsche Regeltitel"


def _kennung(rule: str) -> str:
    """Meldungskennung einer Anhangzeile; ZAP-Zeilen heissen zusammengefasst "zap#<id>"."""
    return rule.split("#", 1)[1] if "#" in rule else rule


@pytest.mark.parametrize("order", ORDERS)
def test_anhang_zeilen_decken_alle_einzelmeldungen(order):
    ap = data_for(order).appendix
    assert sum(t.count for t in ap.tool_findings) == sum(max(m.count, 1) for m in ap.tool_messages)
