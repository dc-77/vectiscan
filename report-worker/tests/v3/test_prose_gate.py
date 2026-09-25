# -*- coding: utf-8 -*-
"""Das Gate der Prosa-KI: erfundene Angaben fallen auf den Katalogtext zurueck.

Je Regel ein Fall. Die praeparierten Antworten sind genau das, was in den 36
ausgewerteten Produktionsscans schiefgegangen ist (spec/06 Abschnitt 3): erfundene
CVE-Nummern, Hostnamen aus dem Nichts, Zahlen ohne Beleg, Severity-Woerter im Text.
"""
from __future__ import annotations

import pytest

from reporter.v3 import gate
from reporter.v3.prose import apply_prose, build_payload
from tests.v3.conftest import junkerwerk_data

GUT = ("Der Bericht zeigt Handlungsbedarf an den Zugangswegen in das Unternehmensnetz. "
       "Zuerst gehört der Datenbankzugriff aus dem Internet geschlossen.")


@pytest.fixture(scope="module")
def data():
    return junkerwerk_data()


@pytest.fixture(scope="module")
def haystack(data):
    return gate.corpus(build_payload(data))


def test_sauberer_text_geht_durch(haystack):
    assert gate.check_field("overall_text", GUT, haystack).ok


@pytest.mark.parametrize("text,regel", [
    ("Betroffen ist CVE-2021-44228 auf dem Webserver.", "CVE nicht in den Eingabedaten"),
    ("Der Server intranet.example-fremd.test antwortet aus dem Internet.",
     "Hostname nicht in den Eingabedaten"),
    ("Insgesamt wurden 4711 Schwachstellen gefunden.", "Zahl nicht in den Eingabedaten"),
    ("Die Lage ist kritisch und erfordert sofortiges Handeln.", "Severity-Wort im Text"),
    ("Im Einsatz ist Version 9.9 der Serversoftware.", "Versionsangabe nicht in den Eingabedaten"),
    ("Der Bericht ist vollständig geprüft und lückenlos.", "verbotene Zusage"),
    ("Du solltest deine Systeme prüfen.", "keine Sie-Form"),
    ("Die Zugaenge gehoeren geschlossen.", "Umschrift statt Umlaut"),
    ("Der Bericht zeigt Handlungsbedarf – und zwar sofort.", "Gedankenstrich"),
    ("Der Host {host} antwortet aus dem Internet.", "Platzhalter"),
])
def test_regel_schlaegt_an(haystack, text, regel):
    verdict = gate.check_field("overall_text", text, haystack)
    assert not verdict.ok
    assert any(regel in reason for reason in verdict.reasons), verdict.reasons


def test_laengenlimit(haystack):
    lang = "Der Bericht zeigt Handlungsbedarf an den Zugangswegen. " * 40
    verdict = gate.check_field("overall_text", lang, haystack)
    assert not verdict.ok
    assert any("laenger als" in r for r in verdict.reasons)


def test_leeres_feld_faellt_durch(haystack):
    assert not gate.check_field("overall_text", "   ", haystack).ok


def test_bekannte_angaben_sind_erlaubt(data, haystack):
    """Was in der Eingabe steht, darf im Text vorkommen."""
    host = data.scope.hosts[0].ip
    text = f"Der Host {host} braucht zuerst Aufmerksamkeit."
    assert gate.check_field("overall_text", text, haystack).ok


def test_meldepflicht_darf_zitiert_werden(haystack):
    text = ("Bei einem Vorfall mit personenbezogenen Daten gilt die Meldepflicht nach "
            "Art. 33 DSGVO innerhalb von 72 Stunden.")
    assert gate.check_field("implication", text, haystack).ok


def test_erfundene_cve_faellt_auf_den_katalogtext_zurueck(data):
    """Der Gate-Test aus dem Auftrag S3: praeparierte Antwort, Katalogtext bleibt."""
    original = data.model_copy(deep=True)
    rejected = apply_prose(data, {
        "overall_text": "Der Bericht zeigt CVE-2021-44228 auf dem Webserver.",
        "implication": GUT,
    })
    assert data.glance.overall_text == original.glance.overall_text
    assert data.business.implication == GUT
    assert any("overall_text" in r for r in rejected)
    assert data.meta.prose_rejected == rejected


def test_saubere_felder_werden_uebernommen(data):
    kopie = data.model_copy(deep=True)
    erster = kopie.findings[0]
    katalog = erster.impact
    rejected = apply_prose(kopie, {
        "overall_text": GUT,
        "impact": {erster.id: "Der Zugriff von außen macht jede spätere Lücke sofort nutzbar."},
    })
    assert kopie.glance.overall_text == GUT
    # S6b-2 (spec/09 Q4): die Bedeutung eines Befunds ist die Katalogaussage seiner Regeln
    # mit Fakten-Bedingung; ein KI-Feinschliff ersetzt sie nicht mehr.
    assert kopie.findings[0].impact == katalog
    assert rejected == []

ZITAT = ("Der Webauftritt huendgen-entsorgung.de ist aus dem Internet erreichbar "
         "und liefert das Zertifikat TRAEFIK DEFAULT CERT aus.")


def test_name_aus_den_eingabedaten_ist_zitat_und_keine_umschrift():
    """Ein Name aus dem Scan gehoert nicht dem Rechtschreibpruefer.

    Bei huendgen-entsorgung.de hat das Gate neun von zehn Feldern verworfen, jedes mit
    demselben Grund: der Domainname des Kunden traegt "ue". Damit stand der Bericht
    trotz Zugangsschluessel auf Katalogtexten.
    """
    eigen = gate.corpus({"hosts": ["huendgen-entsorgung.de"],
                         "tls": {"subject": "TRAEFIK DEFAULT CERT"}})
    verdict = gate.check_field("overall_text", ZITAT, eigen)
    assert verdict.ok, verdict.reasons


def test_derselbe_name_ohne_beleg_bleibt_ein_fehler(haystack):
    """Die Ausnahme haengt am Beleg, nicht am Wort."""
    verdict = gate.check_field("overall_text", ZITAT, haystack)
    assert not verdict.ok
    assert any("Umschrift statt Umlaut" in reason for reason in verdict.reasons), verdict.reasons


def test_wortliste_gilt_auch_als_zitat():
    """Ein deutsches Wort bleibt falsch geschrieben, auch wenn ein Werkzeug es so ausgibt."""
    satz = "Der Zugang gehoert geschlossen."
    eigen = gate.corpus({"evidence": satz})
    verdict = gate.check_field("overall_text", satz, eigen)
    assert not verdict.ok
    assert any("Umschrift statt Umlaut" in reason for reason in verdict.reasons), verdict.reasons
