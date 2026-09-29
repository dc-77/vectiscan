# -*- coding: utf-8 -*-
"""S6d: Fakten 1.4.0 aus den S6c-Rohfeldern (docs/S6C-NEW-RAW-FIELDS.md).

Grundlage sind die drei S6c-Probeauftraege 4394b0b7 (dortmund-beach.com), f9a2a2f6 (junkerwerk.de
und junkerwerk.hu) und cd28d260 (castenow.de) als Golden-Fixtures, dazu das RDAP-Fixture aus den
scan-worker-Tests (lumbeck-wolter 116.202.77.64) und kleine Faelle, die an echten Daten nicht
vorkommen (Sperre, NAT64, EHLO-Sonde mit Antwort, XML-RPC aktiv).
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from reporter.facts import schema as S
from reporter.facts import systems as SYS
from reporter.facts.build import build_from_bundle
from reporter.facts.golden import SNAPSHOT, results_path, tar_path
from reporter.facts.sources import attach_orders_json, load_from_tar, load_tool_runs, merge_tool_runs
from reporter.facts.tool_coverage import PROVIDER_BLOCK_REASON
from tests.v3.conftest import facts_for

DB = "4394b0b7-5dc6-4e01-b700-2a4052a7bd4a"
JW = "f9a2a2f6-a97f-47bf-9d7f-9afb3869f97c"
CA = "cd28d260-cf49-4d17-a980-64a4b1951444"
LW = "c3d5724c-bdbf-4da8-982f-4f1a52210e28"
PROBEN = (DB, JW, CA)
FIXTURES = Path(__file__).parent / "fixtures" / "facts"


def bundle(order: str):
    """Bundle wie im Golden-Pfad (Tar, Zeilen, Zielliste), zum Veraendern vor dem Bau."""
    b = load_from_tar(tar_path(order))
    runs, name, sha = load_tool_runs(results_path(order))
    merge_tool_runs(b, runs, name=name, sha256=sha)
    attach_orders_json(b, SNAPSHOT / "orders.json")
    return b


def tls(facts: S.Facts, ip: str, port: int, fqdn: str | None = None) -> S.TlsFact:
    return next(t for t in facts.tls if t.host_ip == ip and t.port == port and (fqdn is None or t.fqdn == fqdn))


def cov(facts: S.Facts, tool: str, ip: str | None = None) -> list[S.CoverageFact]:
    return [c for c in facts.coverage if c.tool == tool and (ip is None or c.host_ip == ip)]


def test_schema_1_4_0():
    assert S.FACTS_SCHEMA_VERSION == "1.4.0"
    assert all(facts_for(o).schema_version == "1.4.0" for o in PROBEN)


# ---------------------------------------------------------------- A12 bekannte Dateien

@pytest.mark.parametrize("order", PROBEN)
def test_a12_keine_unbekannten_dateien_an_den_probeauftraegen(order):
    """S6c-Proben: vorher 9 (DB) und je 13 (JW, CA) Eintraege file_unknown_or_unparsable."""
    assert [u.what for u in facts_for(order).unprocessed if u.kind == "file_unknown_or_unparsable"] == []


# ---------------------------------------------------------------- A2 TLS je Port und SNI

def test_a2_eigener_eintrag_je_port_mit_starttls():
    f = facts_for(DB)
    t587 = tls(f, "88.99.35.112", 587)
    assert (t587.source, t587.run, t587.starttls, t587.service_name) == ("testssl", "testssl_587", True, "smtp")
    assert t587.assigned_from is None
    assert t587.protocols["TLS1.0"] is True and t587.protocols["TLS1.3"] is True
    t993 = tls(f, "88.99.35.112", 993)
    assert (t993.starttls, t993.service_name) == (False, "imap")


def test_a2_vollstaendiger_lauf_trotz_exit_code_ist_ok():
    """testssl gibt die Befundzahl als Exit-Code zurueck (dortmund-beach testssl_587: 8)."""
    zeile = cov(facts_for(DB), "testssl_587", "88.99.35.112")[0]
    assert (zeile.status, zeile.exit_code) == ("ok", 8)


def test_a2_gescheiterter_lauf_ohne_fakt_mit_grund():
    f = facts_for(DB)
    zeile = cov(f, "testssl_110", "88.99.35.112")[0]
    assert (zeile.status, zeile.reason) == ("failed", "tls_connect_refused")
    assert not [t for t in f.tls if t.host_ip == "88.99.35.112" and t.port == 110]


def test_a2_sni_lauf_eigener_eintrag():
    f = facts_for(JW)
    mail = tls(f, "217.243.248.28", 443, "mail.junkerwerk.de")
    assert (mail.run, mail.sni, mail.source) == ("testssl_sni_mail.junkerwerk.de", "mail.junkerwerk.de", "testssl")
    assert mail.assigned_from is None


def test_a2_mailport_mit_tls_fakt_wird_kein_webserver():
    for s in facts_for(DB).services:
        if s.port in (110, 143, 465, 587, 993, 995):
            assert s.kennung != "Webserver", (s.port, s.kennung)


def test_a2_alte_fixtures_behalten_die_zuordnung_ueber_das_zertifikat():
    alt = facts_for("1f8bc977-39a7-47c7-b4ad-7b05dbac2d52")
    assert any(t.assigned_from for t in alt.tls)
    assert not any(t.run and t.run != "testssl" for t in alt.tls)


# ---------------------------------------------------------------- A1 Netzbetreiber aus RDAP

def _rdap() -> dict:
    return json.loads((FIXTURES / "rdap_ripe_hetzner.json").read_text(encoding="utf-8"))


def test_a1_netzbetreiber_laut_rir_mit_rdap_fixture():
    b = bundle(LW)
    b.rdap = {k: v for k, v in _rdap().items() if isinstance(v, dict)}
    f = build_from_bundle(b)
    h = next(h for h in f.hosts if h.ip == "116.202.77.64")
    p = h.provider
    assert (p.netblock_owner, p.rir, p.netname, p.cidr) == ("Hetzner Online GmbH", "RIPE", "HETZNER-nl",
                                                            ["116.202.0.0/15"])
    assert SYS.network_operator_source(p) == "RIPE"
    assert SYS.network_operator_label(p).startswith("Hetzner Online GmbH")


def test_a1_ohne_rdap_bleibt_abuseipdb():
    for order in (LW, *PROBEN):
        for h in facts_for(order).hosts:
            if h.provider is not None and h.provider.isp:
                assert h.provider.rir is None
                assert SYS.network_operator_source(h.provider) == "AbuseIPDB"


def test_a1_rir_schreibweise_afrinic():
    from reporter.facts.build import _rir_name
    assert (_rir_name("AfriNIC"), _rir_name("RIPE NCC"), _rir_name("arin"), _rir_name(None)) == \
        ("AFRINIC", "RIPE", "ARIN", None)


# ---------------------------------------------------------------- A3 Dienstkennung

def test_a3_versionall_mit_kennung_ersetzt_die_tabellenangabe():
    b = bundle(JW)
    xml = b.hosts["188.40.3.130"].nmap_versionall_xml
    b.hosts["188.40.3.130"].nmap_versionall_xml = xml.replace(
        '<service name="pop3s" method="table" conf="3"/>',
        '<service name="pop3" product="Dovecot pop3d" tunnel="ssl" method="probed" conf="10"/>')
    f = build_from_bundle(b)
    s995 = next(s for s in f.services if s.host_ip == "188.40.3.130" and s.port == 995)
    assert (s995.product, s995.kennung_source, s995.unidentified) == ("Dovecot pop3d", "nmap_versionall", False)


def test_a3_versionall_ohne_ergebnis_aendert_nichts():
    """junkerwerk 993/995 blieben im Nachlauf "imaps?"/"pop3s?" (Tabellenangabe)."""
    s993 = next(s for s in facts_for(JW).services if s.host_ip == "188.40.3.130" and s.port == 993)
    assert s993.kennung_source != "nmap_versionall"


# ---------------------------------------------------------------- A4 SMTP

def test_a4_ehlo_sonde_ersetzt_nmap():
    b = bundle(DB)
    b.hosts["88.99.35.112"].smtp_ehlo[587] = {
        "capabilities": ["PIPELINING", "SIZE 10240000", "VRFY", "STARTTLS", "AUTH PLAIN LOGIN"],
        "starttls": True, "vrfy": True, "auth_before_starttls": True, "auth_mechanisms": ["PLAIN", "LOGIN"],
        "evidence": "250-AUTH PLAIN LOGIN"}
    f = build_from_bundle(b)
    s = next(s for s in f.services if s.host_ip == "88.99.35.112" and s.port == 587)
    assert (s.smtp_source, s.auth_before_starttls, s.smtp_vrfy) == ("smtp_ehlo", True, True)
    assert s.evidence[0].tool == "smtp_ehlo"


def test_a4_ohne_ehlo_antwort_bleibt_nmap():
    s = next(s for s in facts_for(DB).services if s.host_ip == "88.99.35.112" and s.port == 587)
    assert (s.smtp_source, s.auth_before_starttls) == ("nmap", True)


def test_a4_keine_unverarbeitete_beobachtung_mehr():
    assert not [u for o in PROBEN for u in facts_for(o).unprocessed if u.kind == "smtp_auth_before_starttls"]


# ---------------------------------------------------------------- A5 XML-RPC

def test_a5_sonde_bei_castenow_mit_ablehnung():
    h = next(h for h in facts_for(CA).http if h.fqdn == "ubb-wiki.castenow.de")
    assert (h.xmlrpc_probe.status, h.xmlrpc_probe.enabled) == (403, False)


# ---------------------------------------------------------------- A6 Endantwort

def test_a6_endantwort_von_header_check_nach_http_weiterleitung():
    h = next(h for h in facts_for(CA).http if h.fqdn == "mail.castenow.de")
    he = h.header_eval
    assert he.basis == "final" and he.complete
    assert he.evaluated.status_basis == "redirect_eval" and he.evaluated.status_code == 200
    assert "logon.aspx" in (he.evaluated.url or "")
    assert he.first.status_code == 302


def test_a6_endantwort_der_weiterleitungspruefung_nur_mit_kennzeichen():
    """castenow mail: final_response_headers sind die einer Schriftdatei (S6c, kein Kennzeichen)."""
    from reporter.facts import http_headers as HH
    rd = {"final_url": "https://mail.castenow.de/owa/auth/logon.aspx", "status_code": 200, "page_title": "Outlook",
          "final_response_headers": {"content-type": "text/html", "x-frame-options": "SAMEORIGIN"},
          "final_status": 200}
    assert HH._rd_document_final("mail.castenow.de", rd, {}) is None
    rd["final_response_source"] = "document"
    assert HH._rd_document_final("mail.castenow.de", rd, {})["x-frame-options"] == "SAMEORIGIN"


# ---------------------------------------------------------------- A7 ZAP

def test_a7_fundort_aus_dem_statuscode():
    from reporter.facts.build import _zap_location
    assert _zap_location("https://x.de/login", 429) == "challenge"
    assert _zap_location("https://x.de/nix", 404) == "error_page"
    assert _zap_location("https://x.de/robots.txt", 200) == "side_path"
    assert _zap_location("https://x.de/robots.txt", None) == "side_path"
    assert _zap_location("https://x.de/", None) == "target"


def test_a7_castenow_meldungen_tragen_status():
    alerts = [a for h in facts_for(CA).http for a in h.alerts]
    assert any(a.statuses for a in alerts)
    assert {a.location for a in alerts} <= {"target", "side_path", "error_page", "challenge"}


# ---------------------------------------------------------------- A8 Sperre

def test_a8_sperrerkennung_ohne_sperre_kein_block_aus_dem_fakt():
    h = next(h for h in facts_for(JW).hosts if h.ip == "188.40.3.130")
    assert (h.provider_block.blocked, h.provider_block.reachable) == (False, True)
    assert h.blocked.reason != PROVIDER_BLOCK_REASON


def test_a8_gemessene_sperre_ist_blockade():
    b = bundle(JW)
    tp = b.hosts["188.40.3.130"].tech_profile
    tp["provider_block"] = {**tp["provider_block"], "blocked": True, "reachable": False,
                            "time_to_reachable_s": None, "waited_s": 117.4}
    f = build_from_bundle(b)
    h = next(h for h in f.hosts if h.ip == "188.40.3.130")
    assert (h.blocked.detected, h.blocked.reason, h.provider_block.waited_s) == (True, PROVIDER_BLOCK_REASON, 117.4)


# ---------------------------------------------------------------- A9 Zonentransfer, gefundene Namen

def test_a9_zonentransfer_ohne_lauf_mit_grund():
    b = bundle(JW)
    b.zone_transfer_by_domain["junkerwerk.hu"] = "=== junkerwerk.hu: keine Nameserver ermittelt ===\n"
    f = build_from_bundle(b)
    zt = next(d for d in f.dns if d.domain == "junkerwerk.hu").zone_transfer
    assert (zt.allowed, zt.not_tested_reason) == (None, "keine Nameserver ermittelt")


def test_a9_zonentransfer_je_domain_mit_eigenem_lauf():
    """f9a2a2f6: fuer junkerwerk.hu lief der AXFR (drei Nameserver, Transfer failed)."""
    zt = next(d for d in facts_for(JW).dns if d.domain == "junkerwerk.hu").zone_transfer
    assert zt.allowed is False and len(zt.ns_tested) == 3


def test_a9_gefundene_namen_aus_discovery_health():
    b = bundle(JW)
    b.host_inventory["discovery_health"]["found_not_in_inventory"] = ["archiv.junkerwerk.de"]
    b.dns_a["archiv.junkerwerk.de"] = ["188.40.3.131"]
    f = build_from_bundle(b)
    d = next(d for t in f.targets for d in t.discovered if d.fqdn == "archiv.junkerwerk.de")
    assert (d.source, d.ips) == ("discovery_health", ["188.40.3.131"])


def test_a9_keine_veraltete_mehrziel_warnung():
    assert not any("Multi-Target" in w for w in facts_for(JW).warnings)


# ---------------------------------------------------------------- A10 Abfragefenster

def test_a10_abfragefenster_aus_dem_rohdatum():
    assert all(h.reputation.abuseipdb_max_age_days == 90 for h in facts_for(DB).hosts if h.reputation)


# ---------------------------------------------------------------- #16 wpscan

def test_b1_zahl_und_kennungen_aus_dem_feed():
    for sw in facts_for(DB).software:
        if sw.vulnerabilities:
            assert sw.vulnerabilities_count == len(sw.vulnerabilities)
            assert all(c.startswith("CVE-") for v in sw.vulnerabilities for c in v.cves)


# ---------------------------------------------------------------- #18 httpx je VHost

def test_b2_httpx_abdeckung_je_vhost():
    zeilen = [c for c in facts_for(CA).coverage if c.tool == "httpx" and c.host_ip == "195.50.179.4"]
    assert zeilen and all(c.scope == "fqdn" and c.fqdn for c in zeilen)
    assert {c.fqdn for c in zeilen} >= {"mail.castenow.de"}


# ---------------------------------------------------------------- C1, C2 auf der Berichtsseite

def test_c1_otx_und_securitytrails_je_domain():
    b = bundle(JW)
    b.passive_by_domain.setdefault("junkerwerk.hu", {})["otx"] = {"domain": {"domain": "junkerwerk.hu",
                                                                             "pulse_count": 0}}
    b.passive_by_domain["junkerwerk.hu"]["securitytrails"] = {"domain": {"a_records": ["188.40.3.130"]}}
    f = build_from_bundle(b)
    ids = {p.id for p in f.passive}
    assert {"passive:otx:junkerwerk.hu", "passive:securitytrails:junkerwerk.hu"} <= ids


def test_c1_domaindateien_werden_gelesen(tmp_path):
    """phase0a/otx_<slug>.json mit _domain (S6d C1) landet bei der Domain, nicht in unprocessed."""
    import tarfile
    src = tar_path(JW)
    ziel = tmp_path / "jw.tar.gz"
    with tarfile.open(src) as alt, tarfile.open(ziel, "w:gz") as neu:
        for m in alt.getmembers():
            neu.addfile(m, alt.extractfile(m) if m.isfile() else None)
        data = json.dumps({"_domain": "junkerwerk.hu", "domain": {"domain": "junkerwerk.hu", "pulse_count": 2}}).encode()
        info = tarfile.TarInfo(f"{JW}/phase0a/otx_junkerwerk.hu.json")
        info.size = len(data)
        import io
        neu.addfile(info, io.BytesIO(data))
    b = load_from_tar(ziel)
    assert b.passive_by_domain["junkerwerk.hu"]["otx"]["domain"]["pulse_count"] == 2


def test_c2_nat64_adresse_ist_kein_ipv6_des_systems():
    b = bundle(DB)
    b.dns_aaaa["dortmund-beach.com"] = ["64:ff9b::5863:2370"]
    b.host_inventory = copy.deepcopy(b.host_inventory)
    b.host_inventory["synthetic_ipv6"] = [{"ip": "64:ff9b::5863:2370", "embedded_ipv4": "88.99.35.112",
                                           "fqdns": ["dortmund-beach.com"], "reason": "nat64_synthesized"}]
    f = build_from_bundle(b)
    assert not [a for h in f.hosts for a in h.additional_ips if a.ip.startswith("64:ff9b")]
    syn = next(t for t in f.targets if t.is_primary).synthetic_ipv6
    assert [(s.ip, s.embedded_ipv4, s.reason) for s in syn] == [("64:ff9b::5863:2370", "88.99.35.112",
                                                                  "nat64_synthesized")]
