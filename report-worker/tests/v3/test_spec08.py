# -*- coding: utf-8 -*-
"""Die Symptome aus spec/08 als Regressionssperre, über alle Golden-Aufträge.

Claude hat am 22.09.2026 die zwei ersten v3-Berichte aus der S5b-Abnahme
gegengelesen und 21 Punkte gefunden. Kein Test hatte davon etwas gesehen, weil
alles inhaltlich war: das Gate meldete 0 Defekte. Hier steht je Punkt aus Teil B
das Muster, an dem er im Bericht sichtbar war. Läuft eines davon wieder auf,
fällt dieser Test, und nicht erst der Kunde.

Geprüft wird der Text des gerenderten Berichts, nicht das Datenmodell: die
Punkte aus spec/08 waren im PDF sichtbar, teils erst durch die Vorlage.
"""
from __future__ import annotations

import re
from functools import lru_cache

import pytest

from reporter.facts import schema as FS
from reporter.facts.golden import facts_path
from reporter.facts.serialize import load_json
from reporter.pdf.v3 import render_html
from reporter.pdf.v3.checks import text_of
from reporter.v3.golden import build_golden_report_data, order_ids

ORDERS = order_ids()


@lru_cache(maxsize=None)
def _facts(order_id: str):
    """Golden-Fakten eines Auftrags, einmal geladen."""
    return FS.Facts.model_validate(load_json(facts_path(order_id)))


@pytest.fixture(scope="module")
def berichte() -> dict[str, tuple[str, str]]:
    """(HTML, Text) je Auftrag, einmal gerendert."""
    out: dict[str, tuple[str, str]] = {}
    for order in ORDERS:
        html = render_html(build_golden_report_data(order))[0]
        out[order] = (html, text_of(html))
    return out


@pytest.fixture(scope="module")
def daten() -> dict:
    return {order: build_golden_report_data(order) for order in ORDERS}


# --------------------------------------------------------------- Punkt 1 / 16

@pytest.mark.parametrize("order", ORDERS)
def test_dringlichkeit_widerspricht_nie_der_ampelfarbe(order, daten):
    """spec/08 Punkt 1: vier Befunde trugen "Unverzüglich" in gelben Kategorien."""
    falsch = [f"{f.id} {f.status}/{f.urgency}" for f in daten[order].findings
              if (f.urgency == "Unverzüglich") != (f.status == "rot")]
    assert not falsch, falsch


@pytest.mark.parametrize("order", ORDERS)
def test_planzeile_hat_die_farbe_ihres_befunds(order, daten):
    data = daten[order]
    nach_id = {f.id: f for f in data.findings}
    for row in data.plan:
        farben = {nach_id[r].status for r in row.refs if r in nach_id}
        assert row.st in farben or not farben, (row.prio, row.st, farben)


@pytest.mark.parametrize("order", ORDERS)
def test_gesamtbewertung_nennt_nur_kategorien_mit_befunden(order, daten):
    """spec/08 Punkt 16: der Festtext nannte Dienste, E-Mail und TLS immer."""
    from reporter.v3.chapters import CATEGORY_IN_SENTENCE

    data = daten[order]
    vorhanden = {f.cat for f in data.findings}
    text = data.glance.overall_text
    for cat, satzteil in CATEGORY_IN_SENTENCE.items():
        if cat in vorhanden:
            continue
        assert satzteil not in text, (cat, text)


# --------------------------------------------------------------- Punkt 3

# None, True, False als eigenes Wort oder eine Liste in eckigen Klammern.
PYTHON_REPR = re.compile(r"(?<![\w-])(None|True|False)(?![\w-])|\['|\[\"")
# Werkzeugmeldungen im Anhang zitieren den ZAP-Namen; "SameSite Attribute None" ist dort der
# Attributwert des Cookies, keine Python-Darstellung (S6b-2: ZAP-Cookie-Meldungen im Anhang).
ZITIERTE_WERKZEUGNAMEN = re.compile(r"SameSite Attribute None")


@pytest.mark.parametrize("order", ORDERS)
def test_keine_python_darstellung_im_bericht(order, berichte):
    """spec/08 Punkt 3: "x-feserver=None", "reachable=True", "dkim=False"."""
    treffer = PYTHON_REPR.findall(ZITIERTE_WERKZEUGNAMEN.sub("", berichte[order][1]))
    assert not treffer, sorted({t if isinstance(t, str) else t[0] for t in treffer})


def test_nachweis_nennt_die_fehlenden_header(daten):
    """spec/08 Punkt 3, VS-2026-012: kein einziger Header-Name im Nachweis."""
    data = daten["14272c00-1145-4675-9b4c-19ce2ead403b"]
    treffer = [f for f in data.findings if "Sicherheits-Header" in f.title]
    assert treffer, "Header-Befund fehlt im Fixture"
    # S6b-2 (spec/09 Q7): je Fakt "Bezeichnung: Wert", keine Rohschreibweise "Feld=".
    assert "fehlende Header: " in treffer[0].evidence
    # S6b-3 (spec/10 R14): Header in Anzeigeschreibweise ("Content-Security-Policy").
    assert "content-security-policy" in treffer[0].evidence.lower()
    # S6b-3 (Entscheidung DC 3): der HSTS-Wert "max-age=0" steht woertlich im Nachweis.
    assert "=" not in re.sub(r"max-age=\d+", "", treffer[0].evidence.replace("://", ""))


def test_nachweis_nennt_die_rest_adresse(daten):
    """spec/08 Punkt 3, VS-2026-015: die Fundstelle fehlte.

    S6b-2 (spec/09 Teil 2 DB): die Fundstelle kommt aus wpscan (``found_by``). Die fest
    eingesetzte REST-Adresse ``/wp-json/wp/v2/users`` stand in keinem Rohdatum; wpscan fand
    den Namen ueber oEmbed.
    """
    data = daten["14272c00-1145-4675-9b4c-19ce2ead403b"]
    treffer = [f for f in data.findings if "Benutzernamen" in f.title]
    assert treffer, "Benutzernamen-Befund fehlt im Fixture"
    assert "/wp-json/oembed/1.0/embed" in treffer[0].evidence
    assert "/wp-json/wp/v2/users" not in treffer[0].evidence


def test_nachweis_nennt_die_zertifikatsdaten(daten):
    """spec/08 Punkt 3, WebCheck VS-2026-004: nur die Protokollliste stand da."""
    data = daten["75338c97-6707-4d11-92bf-bb3cd2e02cde"]
    treffer = [f for f in data.findings if "Zertifikat" in f.title]
    assert treffer, "Zertifikatsbefund fehlt im Fixture"
    nachweis = treffer[0].evidence
    # S6b-2 (spec/09 Q7): Bezeichnungen in Kundensprache statt "CN=" und "Aussteller=".
    assert "Zertifikat für: " in nachweis and "Aussteller: " in nachweis
    assert "gültig bis: " in nachweis


# --------------------------------------------------------------- Punkte 9, 10

@pytest.mark.parametrize("order", ORDERS)
def test_keine_paketfremde_einschraenkung(order, daten):
    """spec/08 Punkt 9: Der WebCheck-Bericht nannte "Das Werkzeug zap_active hat
    kein Ergebnis geliefert", obwohl das Paket keine aktive Prüfung enthält.

    Der Sammelsatz darf weiterhin stehen, wenn ein Werkzeug des Pakets wirklich
    nichts geliefert hat; er darf nur kein Werkzeug nennen, das gar nicht
    vorgesehen war.
    """
    from reporter.catalog.scope import normalize_reason

    facts = _facts(order)
    ausserhalb = set()
    for tool in {c.tool for c in facts.coverage}:
        zeilen = [c for c in facts.coverage if c.tool == tool]
        if all(normalize_reason(c.reason, c.raw_status) == "not_in_package"
               for c in zeilen):
            ausserhalb.add(tool)
    for lim in daten[order].scope.limitations:
        for tool in ausserhalb:
            assert tool not in lim.what, (order, tool, lim.what)


def test_webcheck_nennt_die_aktive_pruefung_nicht(daten):
    """Der Fall aus spec/08 Punkt 9, an genau dem Auftrag, der ihn hatte."""
    data = daten["75338c97-6707-4d11-92bf-bb3cd2e02cde"]
    for lim in data.scope.limitations:
        assert "zap_active" not in lim.what, lim.what
    for zeile in data.appendix.tools:
        assert "Active Scan" not in zeile.t, zeile.t


@pytest.mark.parametrize("order", ORDERS)
def test_abdeckungshinweis_nur_bei_fehlendem_leitwerkzeug(order, daten, berichte):
    """spec/08 Punkt 10: ein fehlendes Nebenwerkzeug löste ihn aus."""
    from reporter.v3.chapters import hosts_ohne_leitwerkzeug

    data = daten[order]
    erwartet = bool(hosts_ohne_leitwerkzeug(_facts(order)))
    assert bool(data.glance.coverage_warning) == erwartet


@pytest.mark.parametrize("order", ORDERS)
def test_freischaltung_nur_bei_belegter_blockade(order, daten):
    """spec/08 Punkt 9: der Satz stand in jedem Bericht mit irgendeiner Lücke."""
    from reporter.v3.chapters import blockade_belegt

    satz = [z for z in daten[order].appendix.repeat if "Freischaltung" in z]
    assert bool(satz) == blockade_belegt(_facts(order))


# --------------------------------------------------------------- Punkt 11

@pytest.mark.parametrize("order", ORDERS)
def test_keine_internen_begriffe_im_kundentext(order, berichte):
    """spec/08 Punkt 11."""
    text = berichte[order][1]
    for begriff in ("catalog_sim", "Policy Prototyp", "Severity-Policy",
                    "(parking)", "zur Nachbearbeitung vorgemerkt"):
        assert begriff not in text, (order, begriff)
    for ascii_wort in ("erhoeht", "kritisch;", "Pruefkatalog"):
        assert ascii_wort not in text, (order, ascii_wort)


@pytest.mark.parametrize("order", ORDERS)
def test_referenzzeile_nennt_pruefkatalog_und_regel(order, daten, berichte):
    data = daten[order]
    if not data.findings:
        pytest.skip("Auftrag ohne Befund")
    text = berichte[order][1]
    assert f"Prüfkatalog {data.meta.catalog_version}, Regel" in text


# --------------------------------------------------------------- Punkt 13

@pytest.mark.parametrize("order", ORDERS)
def test_wildcard_ist_kein_hostname(order, daten, berichte):
    """spec/08 Punkt 13, Entscheidung DC: nicht gezählt, keine Betroffen-Liste,
    kein Bild; stattdessen ein Hinweis in Kapitel 2.1."""
    facts = _facts(order)
    wildcards = [f.name for f in facts.fqdns if f.wildcard]
    data = daten[order]
    html, text = berichte[order]
    for name in wildcards:
        assert f"Antwort von {name}" not in text, name
        for finding in data.findings:
            assert name not in finding.affected, (finding.id, name)
        assert any(name in zeile for zeile in data.scope.out_of_scope), name
    # S6b-1 (spec/09 Q16): Hostnamen eindeutig, ohne Drittanbieter-Adressen.
    eigene = {h.ip for h in facts.hosts if h.third_party is None}
    assert data.meta.fqdns_total == len({f.name.lower() for f in facts.fqdns
                                         if not f.wildcard and f.host_ip in eigene})


@pytest.mark.parametrize("order", ORDERS)
def test_nicht_beauftragt_nur_ausserhalb_aller_listen(order, daten):
    """spec/08 Punkt 13: pflege.dortmund-beach.com stand in beiden Listen."""
    data = daten[order]
    zeilen = [z for z in data.scope.out_of_scope if z.startswith("Sichtbar")]
    genannt = {f.affected for f in data.findings}
    for zeile in zeilen:
        name = zeile.split(":", 1)[1].split("(")[0].strip().rstrip(".")
        assert not any(name in a for a in genannt), (order, name)


@pytest.mark.parametrize("order", ORDERS)
def test_positivbefunde_ohne_wand_aus_hostnamen(order, daten):
    """spec/08 Punkt 13, zweite Haelfte (S6a): vectigal.tech schrieb alle 31 VHosts
    einer IP in die Positivbefunde; die Kuerzung aus S5b galt nur in Einschraenkungen."""
    for positiv in daten[order].positives:
        for klammer in re.findall(r"\(([^()]*)\)", positiv.text):
            namen = [n for n in klammer.split(",") if "." in n]
            assert len(namen) <= 3, (order, positiv.title, klammer[:120])


# --------------------------------------------------------------- Punkte 18, 19

@pytest.mark.parametrize("order", ORDERS)
def test_a3_ohne_leere_tabelle(order, daten, berichte):
    """spec/08 Punkt 18: A.3 stand als Tabelle nur mit Kopfzeile da."""
    data = daten[order]
    text = berichte[order][1]
    if data.appendix.cve_refs:
        assert "Keine CVE-Referenzen in diesem Bericht" not in text
    else:
        assert "Keine CVE-Referenzen in diesem Bericht" in text


@pytest.mark.parametrize("order", ORDERS)
def test_a3_nennt_eine_bezeichnung_je_testssl_test(order, daten):
    """spec/08 Punkt 18: die Spalte Bezeichnung war leer."""
    for ref in daten[order].appendix.cve_refs:
        if ref.src == "testssl":
            assert ref.name, ref.cve


@pytest.mark.parametrize("order", ORDERS)
def test_stufe_und_text_laufen_nicht_ineinander(order, berichte):
    """spec/08 Punkt 19: "MittelfristigDie Einträge"."""
    treffer = re.findall(r"(Unverzüglich|In Kürze|Mittelfristig|Strategisch)[A-ZÄÖÜ]",
                         berichte[order][1])
    assert not treffer, sorted(set(treffer))


@pytest.mark.parametrize("order", ORDERS)
def test_singular_bei_eins(order, berichte):
    """spec/08 Punkt 19: "1 IP-Adressen", "1 Beobachtungen der Werkzeuge"."""
    treffer = re.findall(
        r"\b1 (IP-Adressen|Hostnamen|Beobachtungen|Werkzeugläufe|Einzelbeobachtungen|"
        r"Befunde|Scandurchgänge|Feststellungen|Doppelmeldungen)",
        berichte[order][1])
    assert not treffer, sorted(set(treffer))


@pytest.mark.parametrize("order", ORDERS)
def test_service_karte_ohne_leeren_trenner(order, berichte):
    """spec/08 Punkt 19: "62.217.52.165 ·" mit leerem rDNS."""
    assert "· </span>" not in berichte[order][0], order
