# -*- coding: utf-8 -*-
"""S6b-1: neue Fakten aus den sieben Auftraegen der Scan-Runde (spec/09).

Jede Regel mit ihrem Fall: geteiltes System (Q3), Drittanbieter (Teil 2), Erreichbarkeit
vom Pruefstand (Q9, E4), Dienstname aus der Passivquelle (E5), TLS-Zuordnung ueber das
Zertifikat (Q10), SPF-Mechanismen (Q2), Technologien nach Host (Issue #33) und die
Herkunft des Kundenkontexts (Q15). Die Golden-Fakten sind eingecheckt und werden in
``test_facts_golden.py`` gegen den Neubau geprueft; hier werden sie nur gelesen.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporter.facts import schema as S
from reporter.facts import systems as SYS
from reporter.facts.build import context_from_customer_context

FACTS = Path(__file__).parent / "golden" / "facts"

DB = "1fbc92b9-34ab-414e-8843-a1f1e9f15431"
LW = "c3d5724c-bdbf-4da8-982f-4f1a52210e28"
JW = "31d67a02-b485-4d05-b228-dbdde092cc68"
HE = "3cf01f8d-4d21-4e6d-bac2-7342f1a4d6c7"
BS = "68d59573-7a93-4efa-89cc-e7b10cc4d140"
CA = "1f8bc977-39a7-47c7-b4ad-7b05dbac2d52"
HL = "2e56abe1-c1a6-442e-b36a-dc9f83c81da8"
SECURESS = "ae8d1d70-7925-4e3c-84de-3113f3e57b60"


def facts(order: str) -> S.Facts:
    return S.Facts.from_dict(json.loads((FACTS / f"{order}.json").read_text(encoding="utf-8")))


def host(f: S.Facts, ip: str) -> S.HostFact:
    return next(h for h in f.hosts if h.ip == ip)


# ---------------------------------------------------------------- Q3 geteiltes System

SHARED = {
    # Hoster: fremde Namen, rDNS beim Betreiber, kein eigener Anschluss
    (LW, "116.202.77.64"): ("hoster", "flott.de"),
    (JW, "188.40.3.130"): ("hoster", "erbbauverein.de"),
    (JW, "2a01:4f8:d0a:3124::2"): ("hoster", "erbbauverein.de"),
    (BS, "92.205.224.174"): ("hoster", "dirak.de"),
    (CA, "92.205.163.53"): ("hoster", "netscope-media.de"),
    (HL, "213.133.104.51"): ("hoster", "service.help-ev.de"),  # fremder Name nur am IPv6-Geschwister
    # Plattform: Kundenname per CNAME nach draussen
    (BS, "198.202.211.1"): ("platform", None),
    (HE, "18.197.248.23"): ("platform", None),
    (CA, "3.174.98.120"): ("platform", None),
    (HL, "216.150.1.65"): ("platform", None),
}
OWN = [
    (JW, "217.243.248.28"),   # junkerwerk-solingen.de auf eigener Leitung
    (JW, "217.243.248.29"),
    (HL, "20.79.218.75"),     # Azure, fremder Shodan-Name, kein rDNS
    (HE, "80.90.145.166"),
    (DB, "88.99.35.112"),     # vsrv2.spacekoeln.de, nur der eigene rDNS-Name
    (CA, "195.50.179.4"),
]


@pytest.mark.parametrize("order,ip", sorted(SHARED))
def test_geteiltes_system(order, ip):
    kind, fremd = SHARED[(order, ip)]
    h = host(facts(order), ip)
    assert h.shared is not None and h.shared.kind == kind
    assert h.shared.evidence, "ein geteiltes System braucht einen Beleg"
    if fremd:
        assert fremd in h.shared.foreign_names


@pytest.mark.parametrize("order,ip", OWN)
def test_eigenes_system_nicht_geteilt(order, ip):
    assert host(facts(order), ip).shared is None


def test_plattformbetreiber_aus_cname():
    assert host(facts(BS), "198.202.211.1").shared.operator == "webflow.com"
    assert host(facts(CA), "3.174.98.120").shared.operator == "umfrageonline.com"
    assert host(facts(HL), "216.150.1.65").shared.operator == "funnelcockpit.com"


def test_zertifikatsetiketten_sind_keine_fremden_namen():
    f = facts(HL)
    names = host(f, "217.72.203.132").shared.foreign_names
    assert "ingress.local" not in names
    assert not any(" " in n for n in names)
    assert "plesk" not in host(facts(BS), "92.205.224.174").shared.foreign_names


# ---------------------------------------------------------------- Teil 2 Drittanbieter

def test_drittanbieter_nur_mit_cname_nach_draussen():
    f = facts(BS)
    tp = host(f, "40.99.150.120").third_party
    assert tp is not None and tp.operator == "Microsoft Corporation"
    assert [h.ip for h in f.hosts if h.third_party] == ["40.99.150.120"]


def test_uebersprungenes_eigenes_exchange_ist_kein_drittanbieter():
    # securess: ai_host_skip auf dem eigenen Exchange, kein CNAME
    f = facts(SECURESS)
    assert any(d.source == "ai_host_skip" and d.host_ip == "85.22.47.43" for d in f.decisions)
    assert host(f, "85.22.47.43").third_party is None


# ---------------------------------------------------------------- Q9, E4 Erreichbarkeit

def test_vom_pruefstand_nicht_erreichbar():
    f = facts(BS)
    for ip, ports in (("62.217.52.162", [80, 443]), ("62.217.52.166", [25, 443]), ("62.217.52.171", [443])):
        r = host(f, ip).reach
        assert r is not None and r.status == "unreachable_from_scanner"
        assert r.passive_ports == ports and r.passive_source == "shodan"
    # S6b-3 (spec/10 R3): ohne nmap-Hostbericht ist der Host ohne Antwort, nicht "ohne offenen
    # Port"; mit --open ist beides nicht zu unterscheiden, der Bericht sagt "ohne Antwort".
    assert host(f, "79.140.188.181").reach.status == "no_response"
    assert host(f, "92.205.224.174").reach is None


def test_nmap_ohne_port_ist_kein_messergebnis():
    f = facts(BS)
    rows = {c.host_ip: (c.status, c.reason) for c in f.coverage if c.tool == "nmap"}
    assert rows["62.217.52.166"] == ("empty", "unreachable_from_scanner")
    assert rows["79.140.188.181"] == ("empty", "no_response")
    assert rows["92.205.224.174"][0] == "ok"
    hl = {c.host_ip: (c.status, c.reason) for c in facts(HL).coverage if c.tool == "nmap"}
    assert hl["195.225.241.75"] == ("empty", "no_response")


def test_ipv6_ohne_route():
    assert host(facts(JW), "2a01:4f8:d0a:3124::2").reach.status == "no_ipv6_route"
    assert host(facts(HL), "2a01:4f8:d0a:2757::2").reach.status == "no_ipv6_route"


def test_system_aus_ipv4_und_ipv6_mit_gleichem_rdns():
    assert SYS.system_of(facts(JW).hosts)["2a01:4f8:d0a:3124::2"] == ["188.40.3.130", "2a01:4f8:d0a:3124::2"]
    assert SYS.system_of(facts(HL).hosts)["213.133.104.51"] == ["213.133.104.51", "2a01:4f8:d0a:2757::2"]
    assert SYS.system_of(facts(JW).hosts)["217.243.248.28"] == ["217.243.248.28"]


# ---------------------------------------------------------------- E5 Dienstname

def test_port_25_mit_dienstname_aus_dem_passivmodul():
    p = [x for x in facts(DB).passive if x.port == 25]
    assert p and p[0].service == "smtp" and p[0].verified is False


# ---------------------------------------------------------------- Q10 TLS ueber das Zertifikat

@pytest.mark.parametrize("order,fqdn,donor", [
    (JW, "autodiscover.junkerwerk.de", "outlook.junkerwerk.de:443"),
    (HE, "www.huendgen-entsorgung.de", "huendgen-entsorgung.de:443"),
    (CA, "www.castenow.de", "castenow.de:443"),
    (CA, "mail.castenow.de", "mail2.castenow.de:443"),
    (HL, "ose.heuel.com", "edi.heuel.com:443"),
])
def test_tls_ueber_zertifikat_zugeordnet(order, fqdn, donor):
    t = next(t for t in facts(order).tls if t.fqdn == fqdn and t.port == 443)
    assert t.assigned_from == donor
    assert t.protocols["TLS1.0"] is not None and t.protocols["TLS1.1"] is not None
    assert "geprüft über" in t.evidence[0].excerpt


# ---------------------------------------------------------------- Q2 SPF

def test_spf_mechanismen():
    spf = facts(BS).dns[0].spf
    assert ("a", "mail.bergersysteme.com") in [(m.kind, m.value) for m in spf.mechanisms]
    assert ("redirect", "bergersysteme.com.spf.hornetdmarc.com") in [(m.kind, m.value) for m in spf.mechanisms]
    lw = facts(LW).dns[0].spf
    assert ("ip4", "85.22.176.0/24") in [(m.kind, m.value) for m in lw.mechanisms]
    assert ("mx", None) in [(m.kind, m.value) for m in lw.mechanisms]


def test_cname_aus_dnsx():
    fq = {f.name: f.cname for f in facts(BS).fqdns}
    assert fq["www.bergersysteme.com"] == ["cdn.webflow.com"]
    assert fq["autodiscover.bergersysteme.com"][0] == "autodiscover.outlook.com"


# ---------------------------------------------------------------- Issue #33 Technologien

def software(order: str, ip: str) -> set[tuple[str, str]]:
    return {(s.product, s.version_norm or "") for s in facts(order).software if s.host_ip == ip}


def test_exchange_nur_am_host_im_namen_der_spider_url():
    assert not any("Exchange" in p for p, _ in software(JW, "188.40.3.130"))
    assert ("Microsoft Exchange", "SE") in software(JW, "217.243.248.28")


def test_weiterleitungsziel_gehoert_dem_ziel():
    bs = {p for p, _ in software(BS, "92.205.224.174")}
    assert not bs & {"Webflow", "cloudflare", "Cloudflare", "jQuery"}
    assert "Webflow" in {p for p, _ in software(BS, "198.202.211.1")}
    ca = {p for p, _ in software(CA, "3.174.98.120")}
    assert not ca & {"Drupal", "PHP", "jQuery"}
    assert "Drupal" in {p for p, _ in software(CA, "159.69.143.80")}


@pytest.mark.parametrize("order,ip,version", [(BS, "92.205.224.174", "18.0.80"), (CA, "92.205.163.53", "18.0.81")])
def test_plesk_version_aus_dem_nmap_titel(order, ip, version):
    plesk = [s for s in facts(order).software if s.host_ip == ip and s.family == "plesk" and s.fqdn is None]
    assert [s.version_norm for s in plesk] == [version]
    assert "nmap" in plesk[0].detection_sources


def test_eintraege_ohne_software_entfallen():
    for order in (DB, BS, CA, HL):
        names = {s.product.lower() for s in facts(order).software}
        assert not names & {"hsts", "debian", "unpkg", "http"}, order


# ---------------------------------------------------------------- Q15 Kundenkontext

def test_kontext_mit_quelle_je_feld():
    ctx = context_from_customer_context({
        "firmenname": "Junkerwerk Linder GmbH + Co. KG", "kurzname": "Junkerwerk Linder",
        "branche": "Metallverarbeitung", "mitarbeiter": "120",
        "systeme": [{"fqdn": "outlook.junkerwerk.de", "zweck": "E-Mail"}],
        "sources": {"firmenname": {"source": "recherche", "url": "https://www.junkerwerk.de/impressum"},
                    "kurzname": {"source": "admin"}, "systeme": {"source": "kunde"}},
    })
    by = {f.name: f for f in ctx.fields}
    assert by["firmenname"].source == "recherche" and by["firmenname"].url.endswith("/impressum")
    assert by["kurzname"].source == "admin"
    assert by["branche"].source is None
    assert ctx.systeme[0].fqdn == "outlook.junkerwerk.de" and ctx.systeme_source == "kunde"


def test_ohne_kontext_kein_faktenteil():
    assert context_from_customer_context(None) is None
    assert context_from_customer_context({"sources": {}}) is None
    assert facts(JW).context is None
