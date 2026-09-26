# -*- coding: utf-8 -*-
"""S6b-1: Umfang, Rollen, Abdeckung, Einschraenkungen und Darstellung (spec/09).

Jede Regel hat hier ihren Fall aus den sieben Auftraegen der Scan-Runde vom 23.09.
Die Erwartungen stehen in spec/09; wo die Reportdaten eine Zahl oder einen Namen
tragen, prueft der Test genau diesen Wert.
"""
from __future__ import annotations

import re

import pytest

from reporter.catalog import tables as CT
from reporter.gate import v3_checks as V3
from reporter.v3 import coverage as COV
from reporter.v3 import gate as G
from reporter.v3 import tables as T
from reporter.v3.prose import apply_prose, build_payload
from reporter.v3.research import kurzname_aus
from tests.v3.conftest import data_for, facts_for, order_ids, output_for

CA = "1f8bc977-39a7-47c7-b4ad-7b05dbac2d52"   # castenow.de
DB = "1fbc92b9-34ab-414e-8843-a1f1e9f15431"   # dortmund-beach.com
HL = "2e56abe1-c1a6-442e-b36a-dc9f83c81da8"   # heuel.com
JW = "31d67a02-b485-4d05-b228-dbdde092cc68"   # junkerwerk.de + junkerwerk.hu
HE = "3cf01f8d-4d21-4e6d-bac2-7342f1a4d6c7"   # huendgen-entsorgung.de
BS = "68d59573-7a93-4efa-89cc-e7b10cc4d140"   # bergersysteme.com
LW = "c3d5724c-bdbf-4da8-982f-4f1a52210e28"   # lumbeck-wolter.de
RUNDE = (CA, DB, HL, JW, HE, BS, LW)


def _system(order: str, ip: str):
    data = data_for(order)
    hosts = {h.ip: h for h in data.scope.hosts}
    fqdns = [f.strip() for f in hosts[ip].fqdns.split(",") if f.strip()]
    for o in data.business.observed:
        if any(f in o.system for f in fqdns):
            return o
    raise AssertionError(f"kein System zu {ip}")


def _rows(data, ip: str):
    return [h for h in data.scope.hosts if h.ip == ip or ip in h.more_ips]


# ---------------------------------------------------------------- Q2 Rollen

def test_lw_hat_keine_mailrolle():
    # Lumbeck-Wolter: MX und SPF zeigen woanders hin, der Server traegt nur die Website.
    o = _system(LW, "116.202.77.64")
    assert o.role_keys == ["website"]
    assert not {"mail", "mail_versand", "mail_kalender", "webmail"} & set(o.role_keys)


def test_jw_kalender_nur_am_exchange_host():
    webhost = _system(JW, "188.40.3.130")
    exchange = _system(JW, "217.243.248.28")
    assert "mail_kalender" not in webhost.role_keys
    assert "mail_kalender" in exchange.role_keys
    assert any("autodiscover" in b.lower() for b in exchange.evidence)


def test_bs_mailrolle_ueber_spf_a_mechanismus():
    o = _system(BS, "62.217.52.166")
    assert "mail_versand" in o.role_keys
    assert any("a:mail.bergersysteme.com" in b for b in o.evidence)


def test_ca_bitwarden_ist_passwortverwaltung():
    o = _system(CA, "195.50.179.6")
    assert o.role_keys == ["passwort"]
    assert any("Bitwarden" in b for b in o.evidence)


def test_he_plattform_ohne_datenbank_und_fernzugang():
    o = _system(HE, "18.197.248.23")
    assert o.role_keys == ["website"]


def test_rolle_nie_ohne_beleg():
    for order in RUNDE:
        for o in data_for(order).business.observed:
            assert bool(o.role_keys) == bool(o.evidence), (order, o.system)
            if not o.role_keys:
                assert o.system.startswith(T.ROLE_FALLBACK)


def test_prosa_gate_lehnt_rolle_ohne_fakt_ab():
    haystack = "junkerwerk.de"
    abgelehnt = G.check_field("observed[x]", "Das System verwaltet Kalender und Termine.",
                              haystack, role_keys={"website"})
    assert not abgelehnt.ok
    assert any(r.startswith("Rolle ohne Fakt") for r in abgelehnt.reasons)
    erlaubt = G.check_field("observed[x]", "Das System verwaltet Kalender und Termine.",
                            haystack, role_keys={"mail_kalender"})
    assert erlaubt.ok, erlaubt.reasons


def test_prosa_systemsatz_nur_mit_eigener_rolle():
    data = data_for(JW).model_copy(deep=True)
    webhost = _system(JW, "188.40.3.130").system
    exchange = _system(JW, "217.243.248.28").system
    vorher = {o.system: o.meaning for o in data.business.observed}
    rejected = apply_prose(data, {"observed": {
        webhost: "Über dieses System laufen Kalender und Korrespondenz des Unternehmens.",
        exchange: "Über dieses System laufen Kalender und Korrespondenz des Unternehmens.",
    }}, build_payload(data))
    danach = {o.system: o.meaning for o in data.business.observed}
    assert danach[webhost] == vorher[webhost]
    assert danach[exchange].startswith("Über dieses System laufen Kalender")
    assert any(webhost in r and "Rolle ohne Fakt" in r for r in rejected)


def test_prosa_payload_nur_systeme_mit_rolle_und_netzbetreiber():
    payload = build_payload(data_for(BS))
    assert all(s["belege"] for s in payload["systeme"])
    # S6b-2: die Zeilen aus 2.1 heissen "systeme_2_1", eine Zeile je System.
    assert all("netzbetreiber" in h and "betreiber" not in h for h in payload["systeme_2_1"])


@pytest.mark.parametrize("order", RUNDE)
def test_gate_rolle_ohne_fakt_ohne_treffer(order):
    assert V3.rolle_ohne_fakt(data_for(order)) == []


def test_gate_rolle_ohne_fakt_greift():
    data = data_for(LW).model_copy(deep=True)
    data.business.observed[0].meaning = "Der Server ist das Postfach aller Mitarbeiter."
    defects = V3.rolle_ohne_fakt(data)
    assert [d.check for d in defects] == ["rolle_ohne_fakt"]
    assert defects[0].severity == "error"


# ---------------------------------------------------------------- Q3 Zustaendigkeit

def test_jede_betreiberpruefung_ist_eine_katalogpruefung():
    from reporter.catalog import load_catalog
    ids = {cc.spec.id for cc in load_catalog().checks}
    assert CT.SHARED_OPERATOR_CHECKS <= ids


@pytest.mark.parametrize("order,kind,name", [
    (CA, "Hoster", "Host Europe GmbH"),
    (CA, "Plattformbetreiber", "umfrageonline.com"),
    (BS, "Plattformbetreiber", "webflow.com"),
    (HE, "Plattformbetreiber", "eu-multiscreensite.com"),
    (JW, "Hoster", "Hetzner Online AG"),
    (LW, "Hoster", "Hetzner Online GmbH"),
])
def test_befund_beim_betreiber(order, kind, name):
    data = data_for(order)
    treffer = [f for f in data.findings if f.operator == f"beim {kind} {name}"]
    assert treffer
    for f in treffer:
        assert f.title.endswith(f"(beim {kind} {name})")
        assert name in f.operator_note
    plan = [r for r in data.plan if set(r.refs) & {f.id for f in treffer}]
    assert any(r.action.startswith(f"Beim {kind} einfordern:") for r in plan)


def test_betreibername_ohne_zusatz_nach_strich():
    for order in RUNDE:
        data = data_for(order)
        texte = [h.operator for h in data.scope.hosts] + [f.operator for f in data.findings]
        assert not [t for t in texte if " - " in t], order


def test_datenbank_und_tls_bleiben_beim_kunden():
    # Auf dem geteilten Server von Junkerwerk (188.40.3.130) liegt der Datenbankport
    # beim Kunden, nicht beim Hoster (Entscheidung DC 24.09.).
    data = data_for(JW)
    for f in data.findings:
        if "Datenbank" in f.title:
            assert not f.operator


# ---------------------------------------------------------------- Q9, E4 Abdeckung

def test_bs_drittanbieter_steht_extern_und_zaehlt_nicht():
    data = data_for(BS)
    extern = [h for h in data.scope.hosts if h.cov == "extern"]
    assert [h.ip for h in extern] == ["40.99.150.120"]
    assert extern[0].coverage == "Drittanbieter, nicht geprüft"
    assert data.meta.hosts_total == len(data.scope.hosts) - 1
    texte = [c.host for c in data.architecture.services] + [t.host for t in data.architecture.tech]
    texte += [i.l for b in data.architecture.posture for i in b.items]
    texte += [l.detail for l in data.scope.limitations] + [data.glance.coverage_warning]
    assert not [t for t in texte if "40.99.150.120" in t]


def test_bs_nicht_erreichbare_hosts():
    data = data_for(BS)
    status = {h.ip: h.cov for h in data.scope.hosts}
    assert [ip for ip, c in status.items() if c == "unerreichbar"] == [
        "62.217.52.162", "62.217.52.166", "62.217.52.171"]
    assert status["79.140.188.181"] == "keine"
    for block in data.architecture.posture:
        for item in block.items:
            if item.l in ("62.217.52.162", "62.217.52.166", "62.217.52.171"):
                assert item.v == "nicht prüfbar" and item.ok is None


@pytest.mark.parametrize("order", RUNDE)
def test_vollstaendig_nur_mit_offenem_port(order):
    facts = facts_for(order)
    model = COV.build_model(facts)
    for ip, hc in model.hosts.items():
        if hc.cov == "voll":
            assert any(s.host_ip == ip and s.state == "open" for s in facts.services), ip


@pytest.mark.parametrize("order", RUNDE)
def test_lead_hinweis_und_tabelle_aus_einem_modell(order):
    data = data_for(order)
    luecken = [h for h in data.scope.hosts if h.cov not in ("voll", "extern")]
    assert bool(data.glance.coverage_warning) == bool(luecken)
    for h in luecken:
        assert h.ip in data.glance.coverage_warning


# ---------------------------------------------------------------- E5 Port 25

@pytest.mark.parametrize("order,ip", [
    (CA, "195.50.179.4"), (DB, "88.99.35.112"), (JW, "217.243.248.28"), (BS, "92.205.224.174")])
def test_e5_port25_als_einschraenkung(order, ip):
    rows = [l for l in data_for(order).scope.limitations if l.what == COV.E5_CAUSE]
    assert len(rows) == 1
    assert ip in rows[0].detail
    assert "der Dienst SMTP" in rows[0].detail
    assert rows[0].checks == [COV.E5_CHECK]


@pytest.mark.parametrize("order", RUNDE)
def test_e5_ersetzt_passivbefund_port_25(order):
    offen = [u for u in output_for(order).unprocessed
             if u.kind == "passive_port_unverified" and u.port == 25]
    assert offen == []


# ---------------------------------------------------------------- Q10 Einschraenkungen

@pytest.mark.parametrize("order", RUNDE)
def test_einschraenkungen_nennen_pruefungen_ohne_werkzeug(order):
    data = data_for(order)
    assert V3.einschraenkung_ohne_pruefung(data) == []
    assert V3.werkzeugname_im_kundentext(data) == []
    whats = [l.what for l in data.scope.limitations]
    assert len(whats) == len(set(whats)), "eine Zeile je Ursache"
    for l in data.scope.limitations:
        assert T.TOOL_CHECKS_FALLBACK not in l.checks, (order, l.what)


def test_gate_einschraenkung_ohne_pruefung_greift():
    data = data_for(HL).model_copy(deep=True)
    data.scope.limitations[0].checks = []
    data.scope.limitations[1].detail += " (nmap)"
    checks = {d.check for d in V3.run_all(data, facts_for(HL), output_for(HL))}
    assert {"einschraenkung_ohne_pruefung", "werkzeugname_im_kundentext"} <= checks


def test_jedes_abdeckungswerkzeug_hat_einen_pruefungsnamen():
    ohne = set()
    for order in order_ids():
        for row in facts_for(order).coverage:
            if row.tool not in T.TOOL_CHECKS and row.tool not in COV.NO_LIMITATION_TOOLS \
                    and row.tool not in T.OUT_OF_PRODUCT_TOOLS:
                ohne.add(row.tool)
    assert ohne == set()


def test_jede_katalogfamilie_hat_einen_pruefungsnamen():
    assert set(CT.FAMILIES) - set(T.FAMILY_CHECKS) == set()


def test_folgezeilen_eines_hosts_mit_wurzelursache_entfallen():
    # Bergersysteme: die drei nicht erreichbaren Hosts stehen nur in ihrer eigenen Zeile.
    data = data_for(BS)
    for l in data.scope.limitations:
        # S6b-3 (spec/10 R5): "Gefunden, nicht geprüft" nennt je Name dessen Adresse.
        if l.what in ("Vom Prüfstand aus nicht erreichbar", "Gefunden, nicht geprüft"):
            continue
        assert not re.search(r"62\.217\.52\.(?:162|166|171)(?!\d)", l.detail), l.what


def test_keine_fremdbewertung_ohne_cvss_wort():
    for order in RUNDE:
        for l in data_for(order).scope.limitations:
            assert "CVSS" not in f"{l.what} {l.detail}"


def test_tls_teilweise_nur_fuer_ungepruefte_ports():
    """S6b-3 (spec/10 R3, R4): testssl gilt je Adresse und Port fuer alle virtuellen Hosts;
    die Zeile "nur über die ausgehandelte Verbindung" entfaellt bei Heuel und Bergersysteme.
    Teilweise geprueft ist, was an TLS-Ports ohne testssl-Lauf bleibt, mit den Ports."""
    for order in (HL, BS):
        rows = {l.what: l for l in data_for(order).scope.limitations}
        assert not [w for w in rows if w.startswith("Transportverschlüsselung nur über")]
        teil = rows["Transportverschlüsselung nur für einen Teil der TLS-Dienste geprüft"]
        assert "(Port " in teil.detail


# ---------------------------------------------------------------- Q16 Umfang

def test_jw_hostnamen_eindeutig_und_ipv6_in_einer_zeile():
    data = data_for(JW)
    assert data.meta.fqdns_total == 7
    rows = _rows(data, "188.40.3.130")
    assert len(rows) == 1 and rows[0].more_ips == ["2a01:4f8:d0a:3124::2"]
    assert not [t for t in data.architecture.tech if t.host.startswith("2a01:")]
    ipv6 = [l for l in data.scope.limitations if "IPv6" in l.what]
    assert len(ipv6) == 1 and "2a01:4f8:d0a:3124::2" in ipv6[0].detail


def test_jw_pruefumfang_je_zieldomain():
    domains = {d.domain: d.text for d in data_for(JW).scope.domains}
    assert set(domains) == {"junkerwerk.de", "junkerwerk.hu"}
    assert domains["junkerwerk.hu"].startswith("nur DNS- und E-Mail-Einträge")
    assert "7 Hostnamen" in domains["junkerwerk.de"]


def test_hl_ipv6_geschwister_in_einer_zeile():
    rows = _rows(data_for(HL), "213.133.104.51")
    assert len(rows) == 1 and rows[0].more_ips == ["2a01:4f8:d0a:2757::2"]


def test_eine_zieldomain_ohne_domainliste():
    assert data_for(LW).scope.domains == []


# ---------------------------------------------------------------- Q15 Kundenkontext

@pytest.mark.parametrize("name,kurz", [
    ("Junkerwerk Linder GmbH & Co. KG", "Junkerwerk Linder"),
    ("Junkerwerk Linder GmbH + Co. KG", "Junkerwerk Linder"),
    ("Hündgen Entsorgung GmbH u. Co. KG", "Hündgen Entsorgung"),
    ("Heuel Spedition GmbH & Co.KG", "Heuel Spedition"),
    ("Castenow GmbH", "Castenow"),
    ("Berger EDV-Systemberatungs GmbH", "Berger EDV-Systemberatungs"),
])
def test_kurzname_ohne_rechtsform(name, kurz):
    assert kurzname_aus(name) == kurz


def test_kurzname_aus_dem_kontext_gewinnt_und_quelle_steht_da():
    data = data_for(JW, customer_context={
        "firmenname": "Junkerwerk Linder GmbH + Co. KG", "kurzname": "Junkerwerk",
        "sources": {"firmenname": {"source": "recherche"}, "kurzname": {"source": "admin"}}})
    assert data.meta.customer_short == "Junkerwerk"
    assert data.meta.context_sources == {"firmenname": "recherche", "kurzname": "admin"}


@pytest.mark.parametrize("quelle,erwartet", [
    ("recherche", "Junkerwerk Linder"),
    ("admin", "Junkerwerk Linder GmbH + Co."),
])
def test_recherche_kurzname_ist_nur_vorschlag(quelle, erwartet):
    # Produktion 31d67a02 (25.09.): die Recherche hatte den Kurznamen vor S6b-1 mit der
    # alten Rechtsformliste gespeichert. Ein Admin-Wert bleibt, wie er ist.
    data = data_for(JW, customer_context={
        "firmenname": "Junkerwerk Linder GmbH + Co. KG", "kurzname": "Junkerwerk Linder GmbH + Co.",
        "sources": {"firmenname": {"source": "recherche"}, "kurzname": {"source": quelle}}})
    assert data.meta.customer_short == erwartet


def test_prosa_bekommt_den_wirksamen_kurznamen():
    # Produktion 31d67a02: die Prosa-KI schrieb "Junkerwerk Linder GmbH + Co. betreibt ...",
    # weil sie den gespeicherten Recherche-Vorschlag aus dem Kontext las.
    kontext = {"firmenname": "Junkerwerk Linder GmbH + Co. KG", "kurzname": "Junkerwerk Linder GmbH + Co.",
               "sources": {"kurzname": {"source": "recherche"}}}
    data = data_for(JW, customer_context=kontext)
    payload = build_payload(data, kontext)
    assert payload["kunde"]["kurzname"] == "Junkerwerk Linder"
    assert payload["kunde"]["firmenname"] == "Junkerwerk Linder GmbH + Co. KG"


def test_netzbetreiber_nie_als_kundenname():
    data = data_for(BS)
    assert data.meta.customer_short != "Berger EDV-Systemberatungs"
    assert "Berger EDV" not in data.glance.context


# ---------------------------------------------------------------- Teil 3 Darstellung

def _names(affected: str) -> list[str]:
    tiefe, teil, out = 0, "", []
    for ch in affected:
        if ch == "(":
            tiefe += 1
        elif ch == ")":
            tiefe -= 1
        if ch == "," and tiefe == 0:
            out.append(teil)
            teil = ""
            continue
        teil += ch
    out.append(teil)
    return [re.split(r" \(", t.strip())[0] for t in out if t.strip()]


@pytest.mark.parametrize("order", RUNDE)
def test_betroffen_ohne_doppelte_namen_und_platzhalter(order):
    data = data_for(order)
    for f in data.findings:
        names = _names(f.affected)
        assert len(names) == len(set(names)), (f.id, f.affected)
        assert "den geprüften Hosts" not in f"{f.affected} {f.found}"
        assert "(1 Tage)" not in f.affected


@pytest.mark.parametrize("order", RUNDE)
def test_bildschirmfotos_ohne_dubletten(order):
    screens = data_for(order).architecture.screens
    assert len({s.file for s in screens}) == len(screens)
    namen = [s.host for s in screens] + [a for s in screens for a in s.also]
    assert len(namen) == len(set(namen))


def test_bildschirmfoto_ohne_eigene_probe_wird_nicht_genannt():
    # dortmund-beach: pflege und www hatten keinen eigenen Abruf und erbten das Bild.
    screens = data_for(DB).architecture.screens
    assert [(s.host, s.also) for s in screens] == [("dortmund-beach.com", [])]


def test_bildschirmfoto_nennt_weitere_namen_derselben_seite():
    screens = {s.host: s.also for s in data_for(HL).architecture.screens}
    assert screens["ose.heuel.com"] == ["webportal.heuel.com"]


@pytest.mark.parametrize("order", RUNDE)
def test_servicekarte_legende_nach_ampel(order):
    data = data_for(order)
    assert "Altprotokoll" not in data.architecture.services_note
    assert data.architecture.services_note.startswith("Farbe je Port nach Ampel")
    farben = {p.st for c in data.architecture.services for p in c.ports}
    assert farben <= {"rot", "gelb", "blau", "gruen", "grau"}


@pytest.mark.parametrize("order", RUNDE)
def test_anhang_b_nennt_jeden_portbefund(order):
    data = data_for(order)
    refs = {r for row in data.appendix.inventory for r in row.ref.split(", ") if r}
    karte = {(c.host, p.p) for c in data.architecture.services for p in c.ports}
    inventar = {(row.host, row.port) for row in data.appendix.inventory}
    assert karte <= inventar
    assert refs <= {f.id for f in data.findings}


def test_bs_redirect_software_bleibt_beim_ziel():
    # Issue #33: 92.205.224.174 leitet auf www (Webflow) weiter und erbt dessen Technik nicht.
    tech = {t.host.split(" ")[0]: [r.c for r in t.rows] for t in data_for(BS).architecture.tech}
    assert "Webflow" not in tech["92.205.224.174"]
    assert "Webflow" in tech["198.202.211.1"]
    assert "Plesk" in tech["92.205.224.174"]


def test_jw_exchange_nur_am_eigenen_host():
    tech = {t.host.split(" ")[0]: [r.c for r in t.rows] for t in data_for(JW).architecture.tech}
    assert not [c for c in tech["188.40.3.130"] if "Exchange" in c]
    assert [c for c in tech["217.243.248.28"] if "Exchange" in c]


def test_technik_ohne_schreibvarianten():
    for order in RUNDE:
        for block in data_for(order).architecture.tech:
            keys = [(r.c.lower(), r.v) for r in block.rows]
            assert len(keys) == len(set(keys)), (order, block.host)


# ---------------------------------------------------------------- Nachtrag 3 (DC 25.09.)

def test_kapitel2_einheit_system_jw():
    data = data_for(JW)
    # S6b-3 (spec/10 R3): 217.243.248.29 ist teilweise geprueft (TLS-Port 8443 ohne testssl,
    # aktive Webanalyse nur an der IIS-Standardseite von cloud.junkerwerk.de).
    assert data.scope.lead.startswith(
        "Der Scan hat 3 Systeme mit 4 IP-Adressen und 7 Hostnamen erfasst. Für 2 Systeme "
        "(3 Adressen) war die aktive Prüfung nur teilweise möglich; diese Lücken sind unten benannt")
    assert data.glance.coverage_warning.startswith(
        "Für 2 Systeme (188.40.3.130 mit 2a01:4f8:d0a:3124::2 und 217.243.248.29) liegt nur "
        "eine teilweise aktive Prüfung vor.")
    assert len([h for h in data.scope.hosts if h.cov != "extern"]) == 3


@pytest.mark.parametrize("order", RUNDE)
def test_satz_hinweis_und_tabelle_zaehlen_systeme(order):
    data = data_for(order)
    zeilen = [h for h in data.scope.hosts if h.cov != "extern"]
    luecken = [h for h in zeilen if h.cov != "voll"]
    n = len(zeilen)
    assert data.scope.lead.startswith(f"Der Scan hat {n} {'System' if n == 1 else 'Systeme'} mit ")
    if luecken:
        g = len(luecken)
        adressen = sum(1 + len(h.more_ips) for h in luecken)
        assert f"Für {g} {'System' if g == 1 else 'Systeme'} ({adressen} " in data.scope.lead
        assert data.glance.coverage_warning.startswith(f"Für {g} {'System' if g == 1 else 'Systeme'} (")
        for h in luecken:
            assert all(ip in data.glance.coverage_warning for ip in [h.ip, *h.more_ips])
    else:
        assert "Alle Systeme konnten aktiv geprüft werden." in data.scope.lead


def test_dashboard_ipv6_in_der_karte_des_systems():
    from reporter.v3.dashboard import tech_profiles_from_facts
    profile = tech_profiles_from_facts(facts_for(JW), [
        {"ip": "188.40.3.130"}, {"ip": "2a01:4f8:d0a:3124::2"}, {"ip": "217.243.248.28"}])
    ips = [p["ip"] for p in profile]
    assert "2a01:4f8:d0a:3124::2" not in ips
    lead = next(p for p in profile if p["ip"] == "188.40.3.130")
    assert lead["additional_ips"] == [
        {"ip": "2a01:4f8:d0a:3124::2", "note": "über IPv6 vom Prüfstand aus nicht erreichbar"}]
    assert lead["tech_rows"]
    assert "additional_ips" not in next(p for p in profile if p["ip"] == "217.243.248.28")


def test_dashboard_ipv6_heuel_ohne_scannerprofil():
    from reporter.v3.dashboard import tech_profiles_from_facts
    profile = {p["ip"]: p for p in tech_profiles_from_facts(facts_for(HL), None)}
    assert "2a01:4f8:d0a:2757::2" not in profile
    assert [e["ip"] for e in profile["213.133.104.51"]["additional_ips"]] == ["2a01:4f8:d0a:2757::2"]
