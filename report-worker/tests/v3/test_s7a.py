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


# ---------------------------------------------------------------- Punkt 4: Service-Karte, Posture, Anhang B

DB_0923 = "1fbc92b9-34ab-414e-8843-a1f1e9f15431"
DB_0928 = "4394b0b7-5dc6-4e01-b700-2a4052a7bd4a"


def _karte(order_id: str, host: str) -> dict[str, tuple[str, str]]:
    card = next(c for c in data_for(order_id).architecture.services if c.host == host)
    return {p.p: (p.st, p.s) for p in card.ports}


def test_gruen_nur_mit_messung_am_port():
    from reporter.v3 import coverage as COV
    from tests.v3.conftest import facts_for

    # Vor S6c ohne testssl je Port: IMAPS und POP3S nur im Portscan erfasst, grau.
    assert _karte(DB_0923, "88.99.35.112")["993"][0] == "grau"
    # Mit testssl je Port (S6c-Probe) sind 993 und 995 gemessen.
    assert {("88.99.35.112", 993), ("88.99.35.112", 995)} <= COV.measured_ports(facts_for(DB_0928))
    assert ("88.99.35.112", 993) not in COV.measured_ports(facts_for(DB_0923))


@pytest.mark.parametrize("order_id", order_ids())
def test_gruen_immer_mit_messung(order_id):
    from reporter.v3 import coverage as COV
    from tests.v3.conftest import facts_for

    gemessen = COV.measured_ports(facts_for(order_id))
    for card in data_for(order_id).architecture.services:
        for p in card.ports:
            if p.st == "gruen":
                ip = next((a for a in [card.host, *card.more_ips] if p.s.endswith(f", an {a}")), card.host)
                assert (ip, int(p.p)) in gemessen, (card.host, p.p, p.s)


def test_befundports_nach_t16():
    assert _karte(JW_0923, "217.243.248.28")["4433"][0] == "gelb"
    for port in ("1000", "1001", "1002"):
        assert _karte(HE, "80.90.145.166")[port][0] == "gelb"
    assert _karte(DB_0923, "88.99.35.112")["30000"][0] == "gelb"


@pytest.mark.parametrize("order_id", order_ids())
def test_ein_block_je_system(order_id):
    from reporter.v3.chapters import system_leads
    from tests.v3.conftest import facts_for

    leads = system_leads(facts_for(order_id))
    data = data_for(order_id)
    karten = [c.host for c in data.architecture.services]
    assert all(leads.get(h, h) == h for h in karten), karten
    for block in data.architecture.posture:
        for it in block.items:
            if leads.get(it.l, it.l) != it.l:
                assert it.ok is False, (block.short, it.l, it.v)
    zeilen = [r.host for r in data.appendix.inventory]
    for i, host in enumerate(zeilen):
        lead = leads.get(host, host)
        if lead != host and lead in zeilen:
            assert zeilen.index(lead) < i
            assert all(leads.get(h, h) == lead for h in zeilen[zeilen.index(lead):i + 1])


def test_ipv6_im_block_des_systems():
    card = next(c for c in data_for(JW_0923).architecture.services if c.host == "188.40.3.130")
    assert card.more_ips == ["2a01:4f8:d0a:3124::2"]
    assert card.notes == ["2a01:4f8:d0a:3124::2: Ports 80 und 443 laut Passivquelle (Apache httpd), nicht geprüft"]
    posture = [it for b in data_for(HL).architecture.posture for it in b.items if it.l == "213.133.104.51"]
    assert posture and all(it.more == ["2a01:4f8:d0a:2757::2: nicht prüfbar"] for it in posture)
    zeilen = [r for r in data_for(HL).appendix.inventory if r.host == "2a01:4f8:d0a:2757::2"]
    assert zeilen[0].operator == "IPv6-Adresse von 213.133.104.51"


# ---------------------------------------------------------------- Punkt 7: Hostsuche je Zieldomain

def _hostsuche(order_id: str) -> dict[str, str]:
    return {d.domain: d.search for d in data_for(order_id).scope.domains}


def test_hostsuche_je_domain_bei_mehrzielauftraegen():
    assert _hostsuche(JW_0928) == {
        "junkerwerk.de": "Hostsuche: 10 Namen gefunden, 10 geprüft, 0 gefunden und nicht geprüft.",
        "junkerwerk.hu": "Hostsuche: 2 Namen gefunden, 2 geprüft, 0 gefunden und nicht geprüft.",
    }


def test_hostsuche_ohne_lauf_der_zusatzdomain():
    # 23.09.: fuer junkerwerk.hu lief keine Hostsuche (spec/10 Teil 2 JW: "keine eigenen Hosts
    # ermittelt" war unscharf).
    assert _hostsuche(JW_0923)["junkerwerk.hu"] == "Hostsuche: für diese Domain nicht gelaufen."


def test_hostsuche_einzelziel_mit_drittanbieter_und_offenen_namen():
    assert _hostsuche(CA) == {"castenow.de": (
        "Hostsuche: 10 Namen gefunden, 9 geprüft, 1 beim Drittanbieter nicht geprüft, "
        "0 gefunden und nicht geprüft.")}
    bs = _hostsuche("68d59573-7a93-4efa-89cc-e7b10cc4d140")["bergersysteme.com"]
    assert bs.endswith("24 gefunden und nicht geprüft.")
    # Die Liste "gefunden, nicht geprüft" in 2.2 bleibt.
    zeilen = [l for l in data_for("68d59573-7a93-4efa-89cc-e7b10cc4d140").scope.limitations
              if "nicht geprüft" in l.what or "gefunden" in l.what.lower()]
    assert zeilen


def test_ohne_discovery_health_keine_hostsuche_zeile():
    assert data_for("45bb234c-d556-4a80-9c78-3ce221ea28a6").scope.domains == []


@pytest.mark.parametrize("order_id", order_ids())
def test_hostsuche_zaehlt_geprueft_wie_der_pruefumfang(order_id):
    import re

    for d in data_for(order_id).scope.domains:
        m = re.search(r"(\d+) geprüft", d.search)
        n = re.search(r"\((\d+) Hostnamen?\)", d.text)
        if m and n:
            assert m.group(1) == n.group(1), (d.domain, d.text, d.search)


# ---------------------------------------------------------------- Punkt 3: Legenden

def test_legende_nennt_nur_vorkommende_farben_und_die_gelb_stufe():
    from reporter.v3.narrative import glance_legend, services_note

    assert services_note({"gelb", "grau"}, {"Mittelfristig"}) == (
        "Farbe je Port nach Ampel des schwersten Befunds am Port: Gelb mittelfristig · Grau: nur im "
        "Portscan erfasst oder nur aus einer Passivquelle bekannt, ohne Befund.")
    assert services_note({"gelb"}, {"In Kürze"}).endswith(": Gelb in Kürze.")
    assert "Gelb in Kürze oder mittelfristig" in services_note({"gelb"}, {"In Kürze", "Mittelfristig"})
    assert glance_legend({"gelb", "blau"}, False) == (
        "Gelb = Handlungsbedarf im nächsten Wartungszyklus · Blau = geplante Verbesserung.")
    assert glance_legend({"rot", "gelb", "gruen"}, True).startswith("Rot = unverzüglich handeln · Gelb = Handlungsbedarf in Wochen")


@pytest.mark.parametrize("order_id", order_ids())
def test_legende_passt_zur_karte_und_zu_den_befunden(order_id):
    data = data_for(order_id)
    note = data.architecture.services_note
    farben = {p.st for c in data.architecture.services for p in c.ports}
    for farbe, wort in (("rot", "Rot "), ("gelb", "Gelb "), ("blau", "Blau "), ("gruen", "Grün:")):
        assert (wort in note) == (farbe in farben), (farbe, note)
    stufen = {p.stage for c in data.architecture.services for p in c.ports if p.st == "gelb"}
    if "gelb" in farben and "In Kürze" not in stufen:
        assert "Gelb in Kürze" not in note
    gelb_kurz = any(f.status == "gelb" and f.urgency == "In Kürze" for f in data.findings)
    if any(f.status == "gelb" for f in data.findings):
        assert ("Handlungsbedarf in Wochen" in data.glance.legend) == gelb_kurz


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
