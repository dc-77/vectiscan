# -*- coding: utf-8 -*-
"""Treue zum Prototyp, ohne ein Artefakt einzuchecken.

``report-prototype/out/`` steht in .gitignore, ein HTML-Schnappschuss des Prototyps
waere rund 100 KB und git-extern mag grosse Pushes nicht. Aber ``report_data.py`` und
``template.html.j2`` des Prototyps sind eingecheckt, und jinja2 ist ohnehin installiert.
Also werden beide Seiten zur Laufzeit erzeugt und verglichen: altes Template gegen neues
Template auf denselben Daten. Das ist genau die Aussage "Textunterschied nur an den
bekannten Stellen".

Im Docker-Abbild liegt ``report-prototype/`` nicht (eigener Build-Kontext), dort wird
uebersprungen.
"""
from __future__ import annotations

import difflib
import importlib.util
import re
import sys

import pytest
from jinja2 import Environment, FileSystemLoader

from reporter.pdf.v3 import render_html
from reporter.pdf.v3.checks import text_of
from reporter.v3.models import ReportData
from tests.pdf_v3.conftest import PROTOTYPE, fake_screenshots

pytestmark = pytest.mark.skipif(
    not (PROTOTYPE / "build" / "template.html.j2").exists(),
    reason="report-prototype liegt nicht vor (eigener Docker-Build-Kontext)")

# Zeilen, die sich unterscheiden duerfen, mit Grund. Alles andere ist eine
# ungewollte Abweichung vom abgenommenen Entwurf.
ERLAUBT: tuple[tuple[str, str], ...] = (
    ("Scandurchgänge", "Anzahl der Durchgaenge kommt jetzt aus den Daten"),
    ("Scandurchgang", "Anzahl der Durchgaenge kommt jetzt aus den Daten"),
    ("junkerwerk.de einzeln", "Prueflaufhinweis ist nicht mehr kundenspezifisch"),
    ("Durchgänge wurden zu einem Ergebnis", "derselbe Satz, jetzt generiert"),
    ("Befunde insgesamt:", "neue Verteilungszeile in Kapitel 1"),
    ("Befund insgesamt:", "neue Verteilungszeile in Kapitel 1"),
    ("Kein Befund. Kapitel 4", "neue Verteilungszeile in Kapitel 1"),
    ("VectiScan Perimeter Junkerwerk", "Dokumenttitel jetzt aus der Paketvariante"),
    ("VectiScan Perimeter-Bericht", "Dokumenttitel jetzt aus der Paketvariante"),
    # Defekt des Prototyps, den autoescape=True behebt: im Verifikationsbefehl steht
    # "</dev/null 2>/dev/null". Ohne Maskierung haelt der HTML-Parser "</dev/null 2>"
    # fuer ein Tag und wirft es weg, der Befehl im ausgelieferten PDF ist also
    # unvollstaendig. Neu steht er ganz da.
    ("</dev/null", "Prototyp verlor die Umleitung an den HTML-Parser"),
    ("openssl s_client -connect openotp", "siehe Zeile darueber"),
    # S5b: Anhang A.3 nennt jetzt auch CVEs, die ein Werkzeug genannt hat und zu
    # denen keine Fremdbewertung vorliegt. Ueberschrift, Vorspann und der
    # Verweissatz in A.2 sagen das ausdruecklich, damit ein leerer Basiswert
    # nicht als "unbewertet" gelesen wird.
    ("Ein CVSS-Basiswert erscheint nur dort", "A.3 fuehrt seit S5b zwei Faelle"),
    ("CVSS-Basiswerte erscheinen ausschließlich als Fremdreferenz",
     "Satz des Prototyps, ersetzt durch die Fassung mit beiden Faellen"),
    ("A.3 CVE-Referenzen", "A.3 fuehrt seit S5b zwei Faelle"),
    ("Schwachstellennummern, die in den Befunden zitiert werden",
     "neuer Vorspann zu A.3"),
    # S6: Die Zeitstufen stehen jetzt in derselben Form wie die Dringlichkeit am
    # Befund, damit A.1, Befundzeile und Plan nicht auseinanderlaufen
    # (spec/08 Punkt 1).
    ("Zeitstufen", "Zeitstufen kommen aus derselben Tabelle wie die Dringlichkeiten"),
    # S6 (spec/08 Punkt 19): Empfehlungsstufe und Text liefen ohne Trenner
    # ineinander ("MittelfristigDie Eintraege").
    ("Empfehlung", "Empfehlungsstufe ist jetzt mit Doppelpunkt vom Text getrennt"),
    # S6 (spec/08 Punkt 11): "Interne Referenz: Policy catalog_sim R-..." nennt
    # Begriffe aus der Entstehung des Katalogs; jetzt steht dort die Regel.
    ("Interne Referenz", "Referenzzeile nennt jetzt Pruefkatalog und Regel"),
    ("Prüfkatalog", "Referenzzeile nennt jetzt Pruefkatalog und Regel"),
    # S6 (Teil A Punkt 3): Das Impressum nennt Katalog- und Faktenversion
    # statt der Severity-Policy; die alte Kette liefert sie nicht mehr.
    ("Severity-Policy", "Impressum nennt jetzt Pruefkatalog und Faktenschema"),
    ("Scan-Orders", "Impressum nennt jetzt Pruefkatalog und Faktenschema"),
    # S6b-1 (spec/09 Q15): die Spalte nennt den Netzbetreiber laut Reputationsquelle,
    # nie den Kunden; (Q10) die Einschraenkungstabelle nennt die betroffenen Pruefungen.
    ("IP-Adresse Hostnamen Betrieb / Rolle", "Spalte heisst jetzt Netzbetreiber / Rolle"),
    ("IP-Adresse Hostnamen Netzbetreiber / Rolle", "Spalte heisst jetzt Netzbetreiber / Rolle"),
    # S6b-3 (spec/10 R16): die Quelle des Netzbetreibers steht im Spaltenkopf.
    ("IP-Adresse Hostnamen Netzbetreiber (laut AbuseIPDB) / Rolle", "Spalte nennt die Quelle AbuseIPDB (spec/11 T2, E17)"),
    ("Einschränkung Auswirkung auf die Ergebnisse", "neue Spalte Betroffene Pruefungen"),
    ("Einschränkung Betroffene Prüfungen Auswirkung", "neue Spalte Betroffene Pruefungen"),
)


def _prototype_data() -> dict:
    spec = importlib.util.spec_from_file_location(
        "prototyp_report_data", PROTOTYPE / "build" / "report_data.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.DATA


def _prototype_html(data: dict) -> str:
    env = Environment(loader=FileSystemLoader(str(PROTOTYPE / "build")),
                      autoescape=False, trim_blocks=False, lstrip_blocks=False)
    return env.get_template("template.html.j2").render(
        m=data["meta"], g=data["glance"], b=data["business"], s=data["scope"],
        a=data["architecture"], landscape_lead=data["landscape_lead"],
        positives=data["positives"], plan=data["plan"], findings=data["findings"],
        ap=data["appendix"], assets=str(PROTOTYPE / "build" / "assets"))


def _zeilen(html: str) -> list[str]:
    """Sichtbarer Text, normalisiert, eine Zeile je Absatz."""
    out = []
    for raw in text_of(html).splitlines():
        line = re.sub(r"\s+", " ", raw).strip()
        if line:
            out.append(line)
    return out


def test_prototyp_daten_passen_ins_modell():
    """Das Datenmodell aus S3 ist ein Superset der Prototyp-Fixture."""
    data = ReportData.model_validate(_prototype_data())
    assert len(data.findings) == 15
    assert len(data.positives) == 8


def test_gleicher_text_bis_auf_die_bekannten_stellen():
    data = _prototype_data()
    alt = _zeilen(_prototype_html(data))
    neu = _zeilen(render_html(ReportData.model_validate(data),
                              resolver=fake_screenshots)[0])

    unerwartet = []
    for zeile in difflib.unified_diff(alt, neu, lineterm="", n=0):
        if zeile[:1] not in ("+", "-") or zeile[:3] in ("+++", "---"):
            continue
        text = zeile[1:]
        if any(marker in text for marker, _grund in ERLAUBT):
            continue
        unerwartet.append(zeile)
    assert not unerwartet, "\n".join(unerwartet[:20])
