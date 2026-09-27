# -*- coding: utf-8 -*-
"""Gate-Regeln aus S6b-4 (spec/11): je Regel ein Nachweis, dass sie anschlaegt, und die
Gegenprobe an allen Golden-Auftraegen.

Die Fehlerbilder stammen aus den Berichten vom 27.09.2026 (spec/11). Sie werden an einer
Kopie der Reportdaten nachgestellt, weil die Reportdaten aus S6b-4 sie nicht mehr enthalten.
"""
from __future__ import annotations

import pytest

from reporter.gate import v3_checks as VC
from reporter.v3.models import Limitation
from tests.v3.conftest import data_for, facts_for, order_ids, output_for

DB = "1fbc92b9-34ab-414e-8843-a1f1e9f15431"
LW = "c3d5724c-bdbf-4da8-982f-4f1a52210e28"
HE = "3cf01f8d-4d21-4e6d-bac2-7342f1a4d6c7"
CA = "1f8bc977-39a7-47c7-b4ad-7b05dbac2d52"
HL = "2e56abe1-c1a6-442e-b36a-dc9f83c81da8"

NEUE_REGELN = ("nachweis_ohne_regelfakt", "ipv6_ohne_inventar", "messadresse_ausserhalb_inventar",
               "firmenname_nicht_bestaetigt")
ERWEITERT = ("einschraenkung_widerspricht_befund", "posture_widerspricht_befund")


def _kopie(order_id: str):
    return data_for(order_id).model_copy(deep=True)


def _befund(data, check: str):
    return next(f for f in data.findings if check in f.checks)


@pytest.mark.parametrize("order_id", order_ids())
def test_golden_ohne_fehler_aus_den_regeln_von_s6b4(order_id: str) -> None:
    defekte = VC.run_all(data_for(order_id), facts_for(order_id), output_for(order_id))
    fehler = [d for d in defekte if d.check in NEUE_REGELN + ERWEITERT and d.is_error]
    assert not fehler, [d.message for d in fehler]


def test_run_all_enthaelt_die_neuen_regeln() -> None:
    import inspect

    quelle = inspect.getsource(VC.run_all)
    for regel in NEUE_REGELN:
        assert f"{regel}(" in quelle, regel


# ---------------------------------------------------------------- T3

def test_nachweis_ohne_regelfakt_greift() -> None:
    """dortmund-beach VS-014 nannte fuer XML-RPC nur "Antwort: 200" (spec/11 T3)."""
    data = _kopie(DB)
    f = _befund(data, "wordpress_xmlrpc_enabled")
    assert VC.nachweis_ohne_regelfakt(data) == []
    f.evidence = "header_check · hosts/88.99.35.112/phase2/headers.json\ndortmund-beach.com · Antwort: 200"
    defekte = VC.nachweis_ohne_regelfakt(data)
    assert [d.finding_id for d in defekte] == [f.id] and defekte[0].is_error
    assert defekte[0].detail["regel"] == "wordpress_xmlrpc_enabled"


def test_vrfy_ohne_ehlo_liste_greift() -> None:
    data = _kopie(DB)
    f = _befund(data, "smtp_vrfy_enabled")
    f.evidence = f.evidence.replace("VRFY in der EHLO-Liste", "Befehle")
    assert any(d.detail["regel"] == "smtp_vrfy_enabled" for d in VC.nachweis_ohne_regelfakt(data))


# ---------------------------------------------------------------- T4

def test_hsts_neben_header_an_der_sicherheitsabfrage_greift() -> None:
    """heuel online: HSTS-Befund an der 429 neben "nur an einer Sicherheitsabfrage gemessen"."""
    data = _kopie(HL)
    ort = "online.heuel.com@216.150.1.65"
    data.findings[0].subjects = list(data.findings[0].subjects) + [f"hsts_missing|{ort}"]
    data.scope.limitations.append(Limitation(
        what="Sicherheits-Header nur an einer Sicherheitsabfrage der Plattform (429) gemessen, Endseite nicht bewertet",
        detail="Betroffen: online.heuel.com (429).", checks=["Sicherheits-Header"],
        refs=[f"security_headers_incomplete|{ort}"], code="headers_challenge_only"))
    defekte = VC.einschraenkung_widerspricht_befund(data)
    assert defekte and defekte[0].is_error and "http_antwort" in defekte[0].message


def test_hsts_an_der_weiterleitung_ist_eigene_messung() -> None:
    """Nach E20 misst HSTS die erste Antwort, auch eine Weiterleitung; die uebrigen Header die
    Endseite. Das ist kein Widerspruch (bergersysteme.com 301)."""
    data = _kopie(HL)
    ort = "weiter.heuel.com@216.150.1.65"
    data.findings[0].subjects = list(data.findings[0].subjects) + [f"hsts_missing|{ort}"]
    data.scope.limitations.append(Limitation(
        what="Sicherheits-Header nur an einer Weiterleitung (301) gemessen, Endseite nicht bewertet",
        detail="Betroffen: weiter.heuel.com (301).", checks=["Sicherheits-Header"],
        refs=[f"security_headers_incomplete|{ort}"], code="headers_redirect_only"))
    assert VC.einschraenkung_widerspricht_befund(data) == []


# ---------------------------------------------------------------- T16

def test_softfail_neben_gelbem_befund_greift() -> None:
    """castenow: "○ SPF softfail" neutral neben Gelb VS-005 (spf_softfail)."""
    data = _kopie(CA)
    item = next(i for b in data.architecture.posture for i in b.items if i.l == "SPF")
    assert item.v == "Handlungsbedarf"
    item.ok, item.v = None, "softfail"
    defekte = VC.posture_widerspricht_befund(data)
    assert defekte and "softfail" in defekte[0].message


def test_transport_unauffaellig_neben_zertifikatsbefund_greift() -> None:
    data = _kopie(CA)
    item = next(i for b in data.architecture.posture for i in b.items if i.l == "195.50.179.5")
    assert "cert_expiring" in item.pulls
    item.ok, item.v = True, "unauffällig"
    assert any("195.50.179.5" in d.message or d.detail.get("eintrag") == "195.50.179.5"
               for d in VC.posture_widerspricht_befund(data))


# ---------------------------------------------------------------- T7

def test_ipv6_ohne_inventar_ist_eine_warnung() -> None:
    defekte = VC.ipv6_ohne_inventar(facts_for(LW))
    assert len(defekte) == 1 and not defekte[0].is_error
    assert defekte[0].detail["adressen"] == ["2a01:4f8:d0a:668b::2"]


def test_messadresse_ausserhalb_inventar_ist_eine_warnung() -> None:
    defekte = VC.messadresse_ausserhalb_inventar(facts_for(HE))
    assert [d.detail["adresse"] for d in defekte] == ["52.59.120.70"]
    assert not defekte[0].is_error


# ---------------------------------------------------------------- E23

def test_firmenname_aus_der_recherche_ist_eine_warnung() -> None:
    data = _kopie(LW)
    assert VC.firmenname_nicht_bestaetigt(data) == []
    data.meta.context_sources = {"firmenname": "recherche", "kurzname": "recherche"}
    defekte = VC.firmenname_nicht_bestaetigt(data)
    assert len(defekte) == 1 and not defekte[0].is_error
    assert defekte[0].message.startswith("Firmenname nicht bestätigt")
    data.meta.context_sources = {"firmenname": "admin", "kurzname": "kunde"}
    assert VC.firmenname_nicht_bestaetigt(data) == []
