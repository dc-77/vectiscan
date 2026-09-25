# -*- coding: utf-8 -*-
"""Die vier Gate-Pruefungen aus S5.

Grundlage sind die Golden-Auftraege. Fuer den Defektfall wird ein Datensatz
kopiert und gezielt beschaedigt, kein neuer Scan gefahren (Vorgabe S5).
"""
from __future__ import annotations

import pytest

from reporter.gate import v3_checks as VC
from reporter.v3.models import Finding
from tests.v3.conftest import (JUNKERWERK, data_for, facts_for, junkerwerk_data,
                               order_ids, output_for)

HEUEL = "176db198-fa4a-4520-bf18-43cbc02a229d"


def _kopie(order_id: str):
    """Reportdaten als eigene Kopie, damit die Beschaedigung nicht abfaerbt."""
    return data_for(order_id).model_copy(deep=True)


# ---------------------------------------------------------------- Abdeckung

def test_abdeckung_vorhanden_ist_kein_defekt() -> None:
    assert VC.abdeckungskapitel_leer(data_for(JUNKERWERK["multi"])) == []


def test_abdeckung_ueberall_leer_ist_ein_fehler() -> None:
    """Ohne scan_results-Zeilen bleibt Kapitel 2 leer und behauptet Vollstaendigkeit."""
    data = _kopie(JUNKERWERK["multi"])
    for host in data.scope.hosts:
        host.coverage = ""

    defekte = VC.abdeckungskapitel_leer(data)

    assert len(defekte) == 1
    assert defekte[0].check == "abdeckungskapitel_leer"
    assert defekte[0].is_error


def test_eine_einzige_angabe_reicht() -> None:
    data = _kopie(JUNKERWERK["multi"])
    for host in data.scope.hosts:
        host.coverage = ""
    data.scope.hosts[0].coverage = "Portscan vollstaendig"

    assert VC.abdeckungskapitel_leer(data) == []


def test_ohne_hosts_meldet_der_selbstcheck_nicht_diese_pruefung() -> None:
    """"Kapitel 2 ohne Hosts" steht schon im Selbstcheck, hier nicht doppelt."""
    data = _kopie(JUNKERWERK["multi"])
    data.scope.hosts = []

    assert VC.abdeckungskapitel_leer(data) == []


# ---------------------------------------------------------------- Tech gegen Befund

def _befund(titel: str, betroffen: str) -> Finding:
    return Finding(id="VS-2026-099", cat="tech", status="rot", urgency="sofort",
                   title=titel, affected=betroffen, source="nmap",
                   scale="hygiene", level="hoch", found="", impact="",
                   recommendation=[["sofort", "pruefen"]], verify="")


def test_exchange_2016_gegen_build_15_2_2562_ist_ein_fehler() -> None:
    """Der Fall aus spec/05 B4: Tabelle sagt SE, der Befund sagt 2016."""
    order = JUNKERWERK["multi"]
    data = _kopie(order)
    data.findings.append(_befund(
        "Microsoft Exchange 2016 wird nicht mehr gepflegt",
        "217.243.248.28:443"))

    defekte = VC.tech_widerspricht_befund(data, facts_for(order))

    assert len(defekte) == 1
    assert defekte[0].check == "tech_widerspricht_befund"
    assert defekte[0].finding_id == "VS-2026-099"
    assert defekte[0].detail["produkt"] == "Microsoft Exchange"
    assert defekte[0].detail["befund"] == "2016"
    assert "15.2.2562" in defekte[0].detail["tabelle"]


def test_dieselbe_version_ist_kein_defekt() -> None:
    order = JUNKERWERK["multi"]
    data = _kopie(order)
    data.findings.append(_befund(
        "Microsoft Exchange 15.2 benoetigt Pflege", "217.243.248.28:443"))

    assert VC.tech_widerspricht_befund(data, facts_for(order)) == []


def test_kuerzere_version_passt_zur_laengeren() -> None:
    """OpenSSH 9.2 gegen 9.2p1 ist kein Widerspruch."""
    order = JUNKERWERK["multi"]
    data = _kopie(order)
    data.findings.append(_befund("OpenSSH 9.2 veraltet", "188.40.3.130:22"))

    assert VC.tech_widerspricht_befund(data, facts_for(order)) == []


def test_anderer_host_wird_nicht_verglichen() -> None:
    """Dieselbe Version auf einem Host sagt nichts ueber einen anderen."""
    order = JUNKERWERK["multi"]
    data = _kopie(order)
    data.findings.append(_befund(
        "Microsoft Exchange 2016 wird nicht mehr gepflegt", "188.40.3.130:443"))

    assert VC.tech_widerspricht_befund(data, facts_for(order)) == []


@pytest.mark.parametrize("order_id", order_ids())
def test_kein_golden_bericht_widerspricht_sich(order_id: str) -> None:
    """Fakten und Befunde kommen aus derselben Quelle; ein Widerspruch waere ein Fehler."""
    assert VC.tech_widerspricht_befund(data_for(order_id), facts_for(order_id)) == []


# ---------------------------------------------------------------- Beobachtungen

def test_unter_der_schwelle_keine_warnung() -> None:
    assert VC.unprocessed_ueber_schwelle(output_for(JUNKERWERK["multi"])) == []


def test_heuel_liegt_ueber_der_schwelle() -> None:
    """heuel.com ist der dokumentierte Fall ueber dem Zielwert (spec/07)."""
    defekte = VC.unprocessed_ueber_schwelle(output_for(HEUEL))

    assert len(defekte) == 1
    assert defekte[0].check == "unprocessed_ueber_schwelle"
    assert not defekte[0].is_error  # Warnung, kein Blocker
    assert defekte[0].detail["schwelle"] == VC.UNPROCESSED_WARN_THRESHOLD
    assert defekte[0].detail["unprocessed"] > VC.UNPROCESSED_WARN_THRESHOLD


# ---------------------------------------------------------------- Auftraggeber

def test_ohne_firmennamen_eine_warnung() -> None:
    defekte = VC.auftraggeber_fehlt(data_for(JUNKERWERK["multi"]))

    assert len(defekte) == 1
    assert defekte[0].check == "auftraggeber_fehlt"
    assert not defekte[0].is_error


def test_mit_firmennamen_keine_warnung() -> None:
    assert VC.auftraggeber_fehlt(junkerwerk_data()) == []


# ---------------------------------------------------------------- Zusammenspiel

def test_run_all_liefert_alle_pruefungen_in_fester_reihenfolge() -> None:
    order = JUNKERWERK["multi"]
    data = _kopie(order)
    for host in data.scope.hosts:
        host.coverage = ""
    data.findings.append(_befund(
        "Microsoft Exchange 2016 wird nicht mehr gepflegt", "217.243.248.28:443"))

    defekte = VC.run_all(data, facts_for(order), output_for(HEUEL))

    # Die fremde Katalogausgabe (Heuel) traegt keine Aussage der Junkerwerk-Befunde, und
    # der angehaengte Befund hat keine Herkunft: aussage_ohne_fakt meldet beides (S6b-2).
    erste = {}
    for d in defekte:
        erste.setdefault(d.check, d)
    assert list(erste) == [
        "abdeckungskapitel_leer", "tech_widerspricht_befund",
        "unprocessed_ueber_schwelle", "auftraggeber_fehlt", "aussage_ohne_fakt",
    ]
    assert [d.is_error for d in erste.values()] == [True, True, False, False, True]
    assert any(d.finding_id == "VS-2026-099" and "ohne Herkunft" in d.message
               for d in defekte if d.check == "aussage_ohne_fakt")

def test_run_all_unter_strict_haelt_den_bericht_auf() -> None:
    """Ohne Firmennamen wird der Bericht in der Produktion angehalten."""
    order = JUNKERWERK["multi"]
    defekte = VC.run_all(data_for(order), facts_for(order), output_for(HEUEL),
                         strict=True)

    fehlend = [d for d in defekte if d.check == "auftraggeber_fehlt"]
    assert len(fehlend) == 1
    assert fehlend[0].is_error


def test_kennzahlen_misst_mit_derselben_strenge(monkeypatch) -> None:
    """Ein gruenes --kennzahlen muss heissen, dass der Bericht durchgeht.

    Die Diagnose rief ``run_all`` ohne ``strict`` auf und meldete deshalb fuer
    62c1e866 "auftraggeber_fehlt: warning" und "fehler": 0, waehrend derselbe
    Bericht im Worker unter strict auf ``report_blocked`` gelaufen waere.
    """
    from reporter.pdf.v3 import __main__ as CLI

    gesehen: dict[str, object] = {}

    def merke(data, facts, output, *, strict=False):
        gesehen["strict"] = strict
        return []

    monkeypatch.setattr(VC, "run_all", merke)
    monkeypatch.setenv("VECTISCAN_VALIDATION_LEVEL", "strict")
    CLI._kennzahlen(JUNKERWERK["multi"], tar=False)
    assert gesehen["strict"] is True

    monkeypatch.setenv("VECTISCAN_VALIDATION_LEVEL", "warn")
    CLI._kennzahlen(JUNKERWERK["multi"], tar=False)
    assert gesehen["strict"] is False


# ---------------------------------------------------------------- S6b-2: Aussage ohne Fakt

@pytest.mark.parametrize("order", order_ids())
def test_aussage_ohne_fakt_ohne_treffer(order: str) -> None:
    assert VC.aussage_ohne_fakt(data_for(order), output_for(order)) == []


def _mit_bedingung(data):
    """Erster Befund mit einer bedingten Bedeutungsaussage (DMARC, Datenbank ...)."""
    for f in data.findings:
        for p in f.provenance:
            if p.field == "meaning":
                return f, p
    raise AssertionError("kein Befund mit Bedeutungsaussage")


def test_aussage_ohne_fakt_greift_bei_fremdem_satz() -> None:
    order = JUNKERWERK["multi"]
    data = _kopie(order)
    f = data.findings[0]
    f.impact = f"{f.impact} Rückmeldungen erreichen Sie nicht."
    defekte = VC.aussage_ohne_fakt(data, output_for(order))
    assert [(d.finding_id, d.detail.get("feld")) for d in defekte] == [(f.id, "impact")]
    assert defekte[0].is_error


def test_aussage_ohne_fakt_greift_bei_nicht_erfuellter_bedingung() -> None:
    """Eine Aussage, deren Bedingung fuer das Mitglied nicht gilt (holds), ist ein Fehler."""
    order = JUNKERWERK["multi"]
    data = _kopie(order)
    f, p = _mit_bedingung(data)
    p.statement = "meaning[99]"
    defekte = VC.aussage_ohne_fakt(data, output_for(order))
    assert defekte and all(d.finding_id == f.id for d in defekte)
    assert all("gilt nicht" in d.message for d in defekte)


def test_aussage_ohne_fakt_greift_bei_nicht_fehlgeschlagener_regel() -> None:
    order = JUNKERWERK["multi"]
    data = _kopie(order)
    f, p = _mit_bedingung(data)
    p.members = ["203.0.113.250:1"]
    defekte = VC.aussage_ohne_fakt(data, output_for(order))
    assert [d.finding_id for d in defekte] == [f.id]
    assert "nicht fehlgeschlagen" in defekte[0].message


def test_aussage_ohne_fakt_greift_bei_positivbefund_ohne_bestehen() -> None:
    order = JUNKERWERK["multi"]
    data = _kopie(order)
    pos = data.positives[0]
    for p in pos.provenance:
        if p.statement == "positive.text":
            p.members = ["gibt-es-nicht.example.test"]
    defekte = VC.aussage_ohne_fakt(data, output_for(order))
    assert defekte and all(d.finding_id is None for d in defekte)
    assert any("nicht bestanden" in d.message for d in defekte)


# ---------------------------------------------------------------- S6b-2: Zaehlung in Systemen

JW_RUNDE = "31d67a02-b485-4d05-b228-dbdde092cc68"


@pytest.mark.parametrize("order", order_ids())
def test_zaehlung_ohne_widerspruch(order: str) -> None:
    assert VC.zaehlung_widerspruch(data_for(order)) == []


def test_zaehlung_31d67a02_drei_systeme_vier_adressen_sieben_namen() -> None:
    data = data_for(JW_RUNDE)
    assert (data.meta.systems_total, data.meta.hosts_total, data.meta.fqdns_total) == (3, 4, 7)
    assert "3 Systeme" in data.architecture.lead


@pytest.mark.parametrize("satz", [
    "Geprüft wurden 5 Systeme mit 4 IP-Adressen.",
    "Die Prüfung umfasst 4 Hosts und 7 Hostnamen.",
    "Auf drei Systemen mit acht Hostnamen wurden Befunde erhoben.",
])
def test_zaehlung_greift(satz: str) -> None:
    data = _kopie(JW_RUNDE)
    data.glance.overall_text = satz
    defekte = VC.zaehlung_widerspruch(data)
    assert defekte and all(d.check == "zaehlung_widerspruch" and d.is_error for d in defekte)
