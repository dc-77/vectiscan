# -*- coding: utf-8 -*-
"""S7a: Darstellung des Perimeter-Berichts (spec/prompts/S7a.md).

Die Punkte 1 bis 9 aendern Darstellung, Reihenfolge, Umbrueche, Beschriftung und Anhaenge;
Befunde und Einstufungen bleiben gleich (tests/v3/test_befundzahlen_s7a.py).
"""
from __future__ import annotations

import pytest

from tests.v3.conftest import data_for, order_ids

CA = "cd28d260-cf49-4d17-a980-64a4b1951444"


# ---------------------------------------------------------------- Punkt 6: Anhang C

def _nebenpfad_zeilen(order_id: str):
    return [t for t in data_for(order_id).appendix.tool_findings if t.rule.startswith("zap_nebenpfad#")]


def test_anhang_c_castenow_nebenpfade_mit_pfad_und_status():
    zeilen = {t.rule: t for t in _nebenpfad_zeilen(CA)}
    server = zeilen["zap_nebenpfad#10036"]
    assert server.what.startswith("„Server Leaks Version Information")
    assert "an Nebenpfaden und Fehlerseiten" in server.what
    assert "mail.castenow.de/robots.txt (Status 302)" in server.where
    assert "mail.castenow.de/sitemap.xml (Status 302)" in server.where
    assert server.note.endswith("ohne eigenen Befund.")


HE = "3cf01f8d-4d21-4e6d-bac2-7342f1a4d6c7"
KRAUSE = "fb13a98f-22c6-4d17-875c-eeeb14643beb"
CA_0923 = "1f8bc977-39a7-47c7-b4ad-7b05dbac2d52"
JW_0928 = "f9a2a2f6-a97f-47bf-9d7f-9afb3869f97c"
JW_0923 = "31d67a02-b485-4d05-b228-dbdde092cc68"
HL = "2e56abe1-c1a6-442e-b36a-dc9f83c81da8"


# ---------------------------------------------------------------- Punkt 2: Bilder

def _bilder(order_id: str) -> dict:
    return {s.host: s for s in data_for(order_id).architecture.screens}


def test_drei_owa_fotos_bei_castenow_werden_eins():
    owa = [s for s in _bilder(CA_0923).values() if "Anmeldeseite" in s.head]
    assert len(owa) == 1
    assert owa[0].head == "mail, mail2 und owa zeigen dieselbe Anmeldeseite"
    assert owa[0].what == "Outlook (/owa/auth/logon.aspx)"
    assert _bilder(CA)["mail.castenow.de"].head == "mail und mail2 zeigen dieselbe Anmeldeseite"


def test_owa_fotos_bei_junkerwerk_werden_eins():
    assert _bilder(JW_0928)["mail.junkerwerk.de"].head == (
        "autodiscover, mail und outlook zeigen dieselbe Anmeldeseite")
    assert _bilder(JW_0923)["outlook.junkerwerk.de"].head == (
        "autodiscover und outlook zeigen dieselbe Anmeldeseite")


def test_weiterleitung_steht_in_der_unterschrift_der_endadresse():
    bilder = _bilder(HL)
    # S6b-4n (N4) bleibt: das Bild gehoert dem Host, der antwortet; online bekommt kein eigenes Bild.
    assert set(bilder) == {"edi.heuel.com", "ose.heuel.com", "www.heuel.com"}
    assert bilder["www.heuel.com"].redirects == ["online.heuel.com, weitergeleitet auf www.heuel.com"]
    assert bilder["ose.heuel.com"].redirects == ["webportal.heuel.com, weitergeleitet auf ose.heuel.com"]
    for order_id in (CA, CA_0923):
        assert _bilder(order_id)["www.castenow.de"].redirects == [
            "umfrage.castenow.de, weitergeleitet auf www.castenow.de"]


@pytest.mark.parametrize("order_id", order_ids())
def test_jeder_name_und_jedes_bild_einmal(order_id):
    screens = data_for(order_id).architecture.screens
    assert len({s.file for s in screens}) == len(screens)
    namen = [n for s in screens for n in [s.host, *s.also]]
    namen += [r.split(",", 1)[0] for s in screens for r in s.redirects]
    assert len(namen) == len(set(namen)), namen


# ---------------------------------------------------------------- Punkt 3: Wortlaut

@pytest.mark.parametrize("order_id", order_ids())
def test_dkim_schluessel_statt_signatur(order_id):
    texte = [p.text for p in data_for(order_id).positives]
    assert not any("DKIM-Signatur veröffentlicht" in t for t in texte)


def test_dkim_schluessel_im_positivbefund():
    texte = [p.text for o in order_ids() for p in data_for(o).positives]
    assert any("ist ein DKIM-Schlüssel veröffentlicht" in t for t in texte)


@pytest.mark.parametrize("order_id", order_ids())
def test_betroffener_nicht_nach_doppelpunkt_wiederholt(order_id):
    import re

    from reporter.v3.findings import ohne_doppelten_betroffenen

    for f in data_for(order_id).findings:
        for text in (f.found, f.impact):
            for satz in re.split(r"(?<=\.)\s+(?=[A-ZÄÖÜ])", text or ""):
                assert ohne_doppelten_betroffenen(satz) == satz, f"{f.id}: {satz}"


def test_doppelpunkt_beispiele():
    from reporter.v3.findings import ohne_doppelten_betroffenen as f

    assert f("Auf ose.heuel.com ist keine Content-Security-Policy gesetzt: ose.heuel.com.") == (
        "Auf ose.heuel.com ist keine Content-Security-Policy gesetzt.")
    # Zusatzangaben bleiben, ebenso Namen, die im Satz davor nicht stehen.
    mit_klammer = "Auf 195.50.179.4 fehlen Header: mail.castenow.de (fehlend: X), mail2.castenow.de (fehlend: Y)."
    assert f(mit_klammer) == mit_klammer
    assert f("Auf www.x.de ist nichts gesetzt: x.de.") == "Auf www.x.de ist nichts gesetzt: x.de."


def test_titelzitat_vollstaendig():
    rollen = " ".join(s.fqdns + " " + s.role for s in data_for(HE).scope.hosts)
    assert "Swisttal / Bonn“" in rollen or "Swisttal / Bonn" in str(data_for(HE).model_dump())


def test_titelzitat_kuerzt_an_der_wortgrenze():
    from reporter.v3.roles import TITEL_MAX, titelzitat

    lang = "Wort " * 40
    zitat = titelzitat(lang)
    assert len(zitat) <= TITEL_MAX + 2 and zitat.endswith(" …") and "Wor …" not in zitat
    assert titelzitat("Containerdienst & Wertstoffhof | Hündgen Entsorgung Swisttal / Bonn").endswith("/ Bonn")


def test_smb_verifikation_ohne_feste_ports():
    verify = [f.verify for f in data_for(KRAUSE).findings if "smb_exposed" in f.checks]
    assert verify and all("genannten SMB-Ports" in v and "139" not in v for v in verify)


def test_anhang_e_nur_mit_vorhandenen_stufen():
    from reporter.v3 import narrative as N

    zahlen = data_for(HE).appendix  # nur fuer den Typ; Counts werden hier nicht gebraucht
    assert zahlen is not None
    assert "Stufe In Kürze" in N.repeat(None, False, False, ["In Kürze", "Mittelfristig"])[0]
    assert "Stufe Mittelfristig" in N.repeat(None, False, False, ["Mittelfristig", "Strategisch"])[0]
    assert N.repeat(None, False, False, ["Strategisch"])[0] == "Wiederholung des Scans spätestens in zwölf Monaten."


@pytest.mark.parametrize("order_id", order_ids())
def test_anhang_e_nennt_eine_stufe_des_plans(order_id):
    data = data_for(order_id)
    stufen = {p.prio for p in data.plan}
    satz = next(s for s in data.appendix.repeat if s.startswith("Wiederholung des Scans"))
    if "der Stufe " in satz:
        assert satz.split("der Stufe ", 1)[1].split(",", 1)[0] in stufen


@pytest.mark.parametrize("order_id", order_ids())
def test_nebenpfad_zeile_ist_eine_eigene_zeile_mit_hoechstens_sechs_orten(order_id):
    data = data_for(order_id)
    for t in _nebenpfad_zeilen(order_id):
        orte = t.where.split(" und ", 1)[0].split(", ")
        assert len(orte) <= 6
        assert sum(1 for o in data.appendix.tool_findings if o.rule == t.rule) == 1
