# -*- coding: utf-8 -*-
"""Gate-Regeln aus S6b-3 (spec/10): je Regel ein Nachweis, dass sie anschlaegt, und die
Gegenprobe an allen Golden-Auftraegen.

Die Fehlerbilder stammen aus den Berichten vom 26.09.2026 (spec/10). Sie werden hier an einer
Kopie der Reportdaten nachgestellt, weil die Reportdaten aus S6b-3 sie nicht mehr enthalten.
"""
from __future__ import annotations

import pytest

from reporter.gate import v3_checks as VC
from reporter.v3.models import Limitation, Provenance
from tests.v3.conftest import data_for, facts_for, order_ids, output_for

JW = "31d67a02-b485-4d05-b228-dbdde092cc68"
LW = "c3d5724c-bdbf-4da8-982f-4f1a52210e28"
DB = "1fbc92b9-34ab-414e-8843-a1f1e9f15431"
CA = "1f8bc977-39a7-47c7-b4ad-7b05dbac2d52"
HL = "2e56abe1-c1a6-442e-b36a-dc9f83c81da8"

NEUE_REGELN = ("header_nicht_fehlend", "einschraenkung_widerspricht_befund", "positiv_widerspricht_befund",
               "posture_widerspricht_befund", "e5_fehlt", "zusage_im_kundentext", "cve_ohne_a3",
               "namen_nicht_geprueft", "frist_vor_berichtsdatum")


def _kopie(order_id: str):
    return data_for(order_id).model_copy(deep=True)


def _befund(data, check: str):
    return next(f for f in data.findings if check in f.checks)


@pytest.mark.parametrize("order_id", order_ids())
def test_golden_ohne_fehler_aus_den_neuen_regeln(order_id: str) -> None:
    """Die Tests aus Paket A kehren sich um: an keinem der 21 Auftraege ein Fehler."""
    defekte = VC.run_all(data_for(order_id), facts_for(order_id), output_for(order_id))
    fehler = [d for d in defekte if d.check in NEUE_REGELN and d.is_error]
    assert not fehler, [d.message for d in fehler]


def test_run_all_enthaelt_die_neuen_regeln() -> None:
    import inspect

    quelle = inspect.getsource(VC.run_all)
    for regel in NEUE_REGELN:
        assert f"{regel}(" in quelle, regel


# ---------------------------------------------------------------- R2

def test_header_nicht_fehlend_greift() -> None:
    """castenow VS-007/009: X-Frame-Options im Text, obwohl die Endseite ihn setzte."""
    data = _kopie(JW)
    f = _befund(data, "security_headers_incomplete")
    assert "X-Frame-Options" not in f.missing_headers
    f.impact += " Ohne X-Frame-Options kann die Seite eingebettet werden."
    defekte = VC.header_nicht_fehlend(data)
    assert defekte and defekte[0].finding_id == f.id and defekte[0].is_error


def test_jw_outlook_nennt_x_frame_options_nicht() -> None:
    f = _befund(data_for(JW), "security_headers_incomplete")
    assert "X-Frame-Options" not in f.missing_headers
    assert "X-Frame-Options" not in f.found + f.impact
    assert not VC.header_nicht_fehlend(data_for(JW))


# ---------------------------------------------------------------- R4

def test_einschraenkung_widerspricht_befund_greift() -> None:
    """dortmund-beach: "DMARC nicht pruefbar" neben dem DMARC-Befund derselben Domain."""
    data = _kopie(DB)
    f = _befund(data, "dmarc_none")
    gruppe = next(s.split("|", 1)[1] for s in f.subjects if s.startswith("dmarc_none|"))
    data.scope.limitations.append(Limitation(
        what="Daten reichen für diese Prüfung nicht aus", checks=["DMARC"], detail="",
        code="insufficient_facts", refs=[f"dmarc_quarantine|{gruppe}"], subjects=[gruppe]))
    defekte = VC.einschraenkung_widerspricht_befund(data)
    assert defekte and defekte[0].detail["familie"] == "dmarc"


# ---------------------------------------------------------------- R7

def test_positiv_widerspricht_befund_greift() -> None:
    """lumbeck-wolter vor S6b-3: POP3 110 im Positivbefund und "ließ sich nicht feststellen"."""
    data = _kopie(LW)
    pos = next(p for p in data.positives if "mail_plaintext" in p.checks)
    ort = next(s for s in pos.subjects if s.endswith(":110"))
    f = _befund(data, "legacy_protocols_present")
    f.provenance.append(Provenance(
        field="observation", check="legacy_protocols_present", statement="observation[9]",
        members=[f"{ort.split(':')[0]}|{ort}"],
        text="Ob dort eine Anmeldung ohne Transportverschlüsselung abgelehnt wird, ließ sich von außen nicht feststellen."))
    defekte = VC.positiv_widerspricht_befund(data)
    assert defekte and ort in defekte[0].detail["orte"]


def test_lw_pop3_ohne_widerspruch() -> None:
    data = data_for(LW)
    assert any("mail_plaintext" in p.checks and any(s.endswith(":110") for s in p.subjects)
               for p in data.positives)
    assert not VC.positiv_widerspricht_befund(data)


# ---------------------------------------------------------------- R8

def test_posture_handlungsbedarf_ohne_befund_greift() -> None:
    """alle sieben vor S6b-3: DANE "Handlungsbedarf" ohne Befund (MX beim Dienstleister)."""
    data = _kopie(JW)
    item = next(i for b in data.architecture.posture for i in b.items if i.l == "DANE")
    assert item.v == "entfällt (MX beim Dienstleister)"
    item.v, item.ok = "Handlungsbedarf", False
    defekte = VC.posture_widerspricht_befund(data)
    assert defekte and defekte[0].detail["eintrag"] == "DANE"


def test_posture_unauffaellig_neben_befund_greift() -> None:
    data = _kopie(JW)
    item = next(i for b in data.architecture.posture for i in b.items if i.l == "DMARC")
    item.v, item.ok = "unauffällig", True
    assert VC.posture_widerspricht_befund(data)


# ---------------------------------------------------------------- R10

def test_e5_fehlt_greift() -> None:
    """lumbeck-wolter, junkerwerk 188.40.3.130, heuel 213.133.104.51: Passivport 25 ohne Zeile."""
    data = _kopie(JW)
    data.scope.limitations = [lim for lim in data.scope.limitations if lim.code != "e5"]
    defekte = VC.e5_fehlt(data, facts_for(JW))
    assert defekte and defekte[0].detail["host"] == "188.40.3.130"


@pytest.mark.parametrize("order_id", [LW, JW, HL])
def test_e5_zeile_je_adresse(order_id: str) -> None:
    assert not VC.e5_fehlt(data_for(order_id), facts_for(order_id))


# ---------------------------------------------------------------- R12

@pytest.mark.parametrize("satz", [
    "Sie erscheinen nicht als Befund; wir prüfen sie und nehmen wiederkehrende Fälle in den Katalog auf.",
    "Die vollständigen Werkzeugausgaben liegen vor und werden auf Anfrage bereitgestellt.",
])
def test_zusage_im_kundentext_greift(satz: str) -> None:
    data = _kopie(JW)
    data.appendix.filtering = satz
    defekte = VC.zusage_im_kundentext(data)
    assert defekte and defekte[0].detail["where"] == ".appendix.filtering"


# ---------------------------------------------------------------- R14

def test_cve_ohne_a3_greift() -> None:
    """dortmund-beach: 17 CVE aus wpscan im Nachweis, A.3 "Keine CVE-Referenzen"."""
    data = _kopie(DB)
    assert data.appendix.cve_refs, "A.3 fuehrt die zitierten wpscan-CVE"
    assert all(c.src == "wpscan" for c in data.appendix.cve_refs)
    data.appendix.cve_refs = []
    assert VC.cve_ohne_a3(data)


# ---------------------------------------------------------------- R5

def test_namen_nicht_geprueft_ist_eine_warnung() -> None:
    defekte = VC.namen_nicht_geprueft(facts_for(JW))
    assert len(defekte) == 1 and not defekte[0].is_error
    assert defekte[0].detail["namen"] == ["archiv.junkerwerk.de"]


# ---------------------------------------------------------------- R18

def test_frist_vor_berichtsdatum_castenow_mailstore() -> None:
    """castenow mailstore, gültig bis 24.09.2026; Bericht vom 26.09.2026 (spec/10 R18)."""
    from reporter.catalog import evaluate
    from reporter.v3.report_data import build_report_data

    facts = facts_for(CA)
    data = build_report_data(facts, evaluate(facts, report_date="2026-09-26"), report_date="26.09.2026")
    f = next(f for f in data.findings if "mailstore.castenow.de" in f.affected)
    assert "seit 24.09.2026" in f.affected and "abgelaufen, sofern nicht erneuert" in f.affected, f.affected
    defekte = [d for d in VC.frist_vor_berichtsdatum(data) if d.finding_id == f.id]
    assert defekte and not defekte[0].is_error
    # Am Stichtag der Golden-Daten (19.09.) steht noch die Restlaufzeit, und es gibt keinen Hinweis.
    vorher = next(x for x in data_for(CA).findings if "mailstore.castenow.de" in x.affected)
    assert "gültig bis 24.09.2026" in vorher.affected
    assert not VC.frist_vor_berichtsdatum(data_for(CA))


def test_frist_am_scantag_schon_abgelaufen_ist_keine_warnung() -> None:
    """bergersysteme: Plesk-Mailports seit 18.07.2025 abgelaufen; das sagt der Befund selbst."""
    data = data_for("68d59573-7a93-4efa-89cc-e7b10cc4d140")
    assert not VC.frist_vor_berichtsdatum(data)
