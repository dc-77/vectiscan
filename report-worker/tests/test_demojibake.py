"""Regression: der Report-Text-Sanitizer repariert Doppel-Encoding-Mojibake
(UTF-8-Bytes als Latin-1 gelesen -> 'Ã¤' statt 'ä') in Finding-Titeln/Descriptions,
ohne legitime Ã/Â-Zeichen zu zerstoeren (Juli 2026).

Realer Fall: der KI-Titel "Webmin-Verwaltungsoberfläche (Port 10000) öffentlich …"
kam mojibaked in reports.findings_data an.
"""
from reporter.report_mapper import _demojibake, _safe


def test_repairs_real_umlaut_mojibake():
    orig = "Webmin-Verwaltungsoberfläche (Port 10000) öffentlich erreichbar auf 88.99.35.112"
    mojibaked = orig.encode("utf-8").decode("latin-1")  # erzeugt 'Ã¤'/'Ã¶'
    assert mojibaked != orig
    assert _demojibake(mojibaked) == orig


def test_repairs_all_german_umlauts_and_sharp_s():
    orig = "Grüße: ä ö ü Ä Ö Ü ß €"
    mojibaked = orig.encode("utf-8").decode("latin-1")
    assert _demojibake(mojibaked) == orig


def test_leaves_correct_text_untouched():
    for s in [
        "Bereits korrekt: öffentliche Verwaltungsoberfläche",
        "DKIM-Record fehlt fuer example.com",
        "Pfeil → Ziel",  # non-Latin-1 -> encode('latin-1') schlaegt fehl -> Original
        "",
    ]:
        assert _demojibake(s) == s


def test_does_not_destroy_legitimate_accents():
    # Legitime akzentuierte Namen duerfen NICHT faelschlich "repariert" werden.
    for s in ["François Câté — Références", "Señor Núñez", "São Paulo"]:
        assert _demojibake(s) == s


def test_safe_applies_demojibake_end_to_end():
    mojibaked = "Webmin-Verwaltungsoberfläche".encode("utf-8").decode("latin-1")
    assert "Verwaltungsoberfläche" in _safe(mojibaked)
