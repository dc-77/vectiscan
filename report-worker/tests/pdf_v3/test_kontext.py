# -*- coding: utf-8 -*-
"""Darstellungsregeln: Aufteilung von Kapitel 6, Paketvariante, Anhangsbuchstaben."""
from __future__ import annotations

import pytest

from reporter.pdf.v3 import text as T
from reporter.pdf.v3.context import (TOP_N_HAUPTTEIL, TOP_N_SCHWELLE, appendix_letters,
                                     split_findings, urgency_counts, urgency_rank)
from reporter.pdf.v3.render import css_string, dot_br
from reporter.pdf.v3.variants import key_for, variant_for
from tests.pdf_v3.conftest import CASTENOW, JUNKERWERK_MULTI
from tests.v3.conftest import data_for

URGENCIES = ["Unverzüglich", "In Kürze", "Mittelfristig", "Strategisch"]


def _finding(n: int, status: str = "gelb", urgency: str = "Mittelfristig") -> dict:
    return {"id": f"VS-2026-{n:03d}", "status": status, "urgency": urgency}


# ------------------------------------------------------------------ Aufteilung

@pytest.mark.parametrize("total,erwartet_haupt", [
    (0, 0), (1, 1), (19, 19), (TOP_N_SCHWELLE, TOP_N_SCHWELLE),
    (TOP_N_SCHWELLE + 1, TOP_N_HAUPTTEIL), (29, TOP_N_HAUPTTEIL),
])
def test_schwelle(total, erwartet_haupt):
    main, more = split_findings([_finding(i) for i in range(1, total + 1)])
    assert len(main) == erwartet_haupt
    assert len(main) + len(more) == total


def test_kein_befund_geht_verloren():
    findings = [_finding(i) for i in range(1, 30)]
    main, more = split_findings(findings)
    assert [f["id"] for f in main] + [f["id"] for f in more] != []
    assert sorted(f["id"] for f in main + more) == sorted(f["id"] for f in findings)
    assert not set(f["id"] for f in main) & set(f["id"] for f in more)


def test_auswahl_nach_dringlichkeit_ausgabe_nach_id():
    """Der dringende Befund mit hoher Nummer muss in den Hauptteil, aber in Reihenfolge."""
    findings = [_finding(i, "blau", "Strategisch") for i in range(1, 29)]
    findings.append(_finding(29, "rot", "Unverzüglich"))
    main, more = split_findings(findings)
    assert "VS-2026-029" in [f["id"] for f in main]
    assert [f["id"] for f in main] == sorted(f["id"] for f in main)
    assert [f["id"] for f in more] == sorted(f["id"] for f in more)


def test_rangfolge():
    rot = urgency_rank(_finding(1, "rot", "Unverzüglich"))
    gelb = urgency_rank(_finding(1, "gelb", "Unverzüglich"))
    gelb_spaet = urgency_rank(_finding(1, "gelb", "Mittelfristig"))
    assert rot < gelb < gelb_spaet
    assert urgency_rank(_finding(1)) < urgency_rank(_finding(2))


def test_verteilung_in_fester_reihenfolge():
    findings = [_finding(1, urgency="Mittelfristig"), _finding(2, urgency="Unverzüglich"),
                _finding(3, urgency="Unverzüglich")]
    assert urgency_counts(findings) == [("Unverzüglich", 2), ("Mittelfristig", 1)]


def test_verteilungszeile_nennt_die_gesamtzahl():
    zeile = T.distribution_line(29, [("Unverzüglich", 3), ("In Kürze", 13)])
    assert zeile.startswith("29 Befunde insgesamt")
    assert "in Kürze" in zeile   # Substantiv bleibt gross
    assert "unverzüglich" in zeile


# ------------------------------------------------------------------ Paket

@pytest.mark.parametrize("package,key", [
    ("Perimeter", "perimeter"), ("WebCheck", "webcheck"), ("Compliance", "compliance"),
    ("TLS-Compliance", "tlscompliance"),
])
def test_anzeigename_wird_zum_schluessel(package, key):
    assert key_for({"package": package}) == (key, None)


def test_legacy_alias_ueber_den_anzeigenamen():
    # tables.PACKAGE_LABELS bildet basic auf denselben Anzeigenamen ab wie webcheck.
    assert key_for({"package": "WebCheck"})[0] == "webcheck"
    assert key_for({}, override="basic")[0] == "webcheck"


def test_unbekanntes_paket_faellt_auf_perimeter_mit_warnung():
    key, warnung = key_for({"package": "Mondscan"})
    assert key == "perimeter"
    assert warnung and "Mondscan" in warnung


def test_webcheck_laesst_bilder_und_inventar_weg():
    variant, _ = variant_for({"package": "WebCheck"})
    assert variant.screens is False
    assert variant.inventory is False
    assert variant.report_title == "WebCheck-Bericht"
    perimeter, _ = variant_for({"package": "Perimeter"})
    assert perimeter.screens and perimeter.inventory


# ------------------------------------------------------------------ Anhaenge

def test_anhangsbuchstaben_ohne_luecke():
    voll = appendix_letters({"scales", "inventory", "tools", "filtering", "repeat",
                             "disclaimer"})
    assert voll == {"scales": "A", "inventory": "B", "tools": "C", "filtering": "D",
                    "repeat": "E", "disclaimer": "F"}
    ohne = appendix_letters({"scales", "tools", "filtering", "repeat", "disclaimer"})
    assert ohne == {"scales": "A", "tools": "B", "filtering": "C", "repeat": "D",
                    "disclaimer": "E"}
    # A bleibt in beiden Faellen bei den Bewertungsmassstaeben, deshalb bleibt die im
    # Fliesstext zitierte Referenz A.3 gueltig.
    assert voll["scales"] == ohne["scales"] == "A"


# ------------------------------------------------------------------ Filter

def test_css_string_maskiert_nur_css_sonderzeichen():
    assert str(css_string('Kunde " & <b>')) == 'Kunde \\" & <b>'
    assert str(css_string("Pfad\\neu")) == "Pfad\\\\neu"
    assert "\n" not in str(css_string("a\nb"))


def test_dot_br_maskiert_die_teile():
    assert str(dot_br("A & B · <c>")) == "A &amp; B<br>&lt;c&gt;"


# ------------------------------------------------------------------ echte Daten

def test_castenow_wird_aufgeteilt_junkerwerk_nicht():
    cast = [f.model_dump(mode="json") for f in data_for(CASTENOW).findings]
    jw = [f.model_dump(mode="json") for f in data_for(JUNKERWERK_MULTI).findings]
    assert len(split_findings(cast)[0]) == TOP_N_HAUPTTEIL
    assert len(split_findings(cast)[1]) == len(cast) - TOP_N_HAUPTTEIL
    assert split_findings(jw)[1] == []
