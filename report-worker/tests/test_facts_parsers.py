"""S1: nmap-, testssl- und Coverage-Leser sowie Threat-Durchreichung mit Fixtures."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from reporter.facts import schema as S
from reporter.facts.build import build_from_bundle
from reporter.facts.nmap_parse import derive_service_flags, parse_nmap_text, parse_nmap_xml
from reporter.facts.sources import ScanBundle, ToolRun, tool_run_from_row
from reporter.facts.testssl_parse import parse_testssl
from reporter.facts.tool_coverage import HostSignals, classify_run, derive_blocked

FIXTURES = Path(__file__).parent / "fixtures" / "facts"


def _ansi(text: str) -> str:
    """Fixture ohne ESC-Bytes lesbar halten; hier werden sie wieder eingesetzt."""
    return re.sub(r"\[(\d[\d;]*)?m", lambda m: "\x1b" + m.group(0), text)


# ------------------------------------------------------------------ nmap

def test_nmap_xml_capabilities():
    run = parse_nmap_xml((FIXTURES / "nmap_capabilities.xml").read_text(encoding="utf-8"))
    assert run.version == "7.93" and run.hosts_total == 1
    host = run.host_for("203.0.113.10")
    assert host.state == "up" and host.extraports == {"filtered": 990, "closed": 3}
    by_port = {p.port: p for p in host.ports}
    f21 = derive_service_flags(by_port[21])
    assert f21.tls_required is True and f21.cert_cn == "*.example.test"
    assert f21.cert_san == ["*.example.test", "example.test"]
    assert f21.cert_not_after == "2026-11-02T23:59:59Z"
    f110 = derive_service_flags(by_port[110])
    assert f110.starttls is True and f110.login_disabled is None
    f143 = derive_service_flags(by_port[143])
    assert f143.starttls is True and f143.login_disabled is True and f143.tls_required is True
    f443 = derive_service_flags(by_port[443])
    assert f443.tunnel_ssl is True and f443.tls_required is True
    f465 = derive_service_flags(by_port[465])
    assert f465.tunnel_ssl is True and f465.starttls is False
    assert f465.auth_mechanisms == ["LOGIN", "PLAIN"] and f465.egress_ip == "198.51.100.7"
    f587 = derive_service_flags(by_port[587])
    assert f587.starttls is True and f587.login_disabled is True and f587.tls_required is True
    assert f587.auth_mechanisms == []
    f993 = derive_service_flags(by_port[993])
    assert f993.tls_required is True and f993.auth_mechanisms == ["PLAIN"]
    f3306 = derive_service_flags(by_port[3306])
    assert f3306.auth_mechanisms == ["mysql_native_password"] and f3306.auth_required is True
    f8443 = derive_service_flags(by_port[8443])
    assert "METHOD:TRACE" in f8443.capabilities
    assert by_port[80].extrainfo == "Ubuntu" and by_port[80].version == "1.24.0"


def test_nmap_xml_ipv6_uebersprungen():
    run = parse_nmap_xml((FIXTURES / "nmap_ipv6_skipped.xml").read_text(encoding="utf-8"))
    assert run.hosts == [] and run.hosts_total == 0
    assert run.targets_skipped == [("2001:db8::2", "invalid")]
    assert run.host_for("2001:db8::2") is None


def test_nmap_xml_host_ohne_offene_ports():
    run = parse_nmap_xml((FIXTURES / "nmap_no_open_ports.xml").read_text(encoding="utf-8"))
    assert run.hosts == [] and run.hosts_up == 1
    host = run.host_for("203.0.113.27")
    assert host is not None and host.state == "up" and host.ports == [] and host.reason == "runstats"


NMAP_TEXT = """Starting Nmap 7.93 ( https://nmap.org )
Nmap scan report for 203.0.113.10
Host is up, received user-set (0.020s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE    REASON  VERSION
21/tcp   open  ftp        syn-ack ProFTPD (requires SSL)
110/tcp  open  pop3       syn-ack Courier pop3d
|_pop3-capabilities: STLS SASL PIPELINING UIDL RESP-CODES CAPA TOP
143/tcp  open  imap       syn-ack Dovecot imapd
|_imap-capabilities: OK LOGIN-REFERRALS LITERAL+ IMAP4rev1 STARTTLS Pre-login LOGINDISABLEDA0001 ENABLE ID IDLE
993/tcp  open  imaps?     syn-ack
3306/tcp open  mysql      syn-ack MySQL 5.5.5-10.11.18-MariaDB-0+deb12u1
5432/tcp open  postgresql syn-ack PostgreSQL DB 9.6.0 or later
"""


def test_nmap_text_fallback():
    run = parse_nmap_text(NMAP_TEXT, "203.0.113.10")
    host = run.host_for("203.0.113.10")
    assert host.state == "up" and host.extraports == {"closed": 995}
    by_port = {p.port: p for p in host.ports}
    assert by_port[21].extrainfo == "requires SSL" and derive_service_flags(by_port[21]).tls_required is True
    assert derive_service_flags(by_port[110]).starttls is True
    f143 = derive_service_flags(by_port[143])
    assert f143.login_disabled is True and f143.tls_required is True
    assert by_port[993].service == "imaps" and by_port[993].conf == 3
    assert derive_service_flags(by_port[993]).tls_required is True
    assert by_port[3306].product == "MySQL" and by_port[3306].version == "5.5.5-10.11.18-MariaDB-0+deb12u1"
    assert by_port[5432].product == "PostgreSQL DB" and by_port[5432].version == "9.6.0 or later"


def test_nmap_text_nur_banner_ipv6():
    run = parse_nmap_text("Starting Nmap 7.93 ( https://nmap.org )\n", "2001:db8::2")
    assert run.hosts == [] and run.hosts_total == 0
    assert run.targets_skipped == [("2001:db8::2", "invalid")]


# ------------------------------------------------------------------ testssl

def test_testssl_text_legacy_protokolle():
    raw = _ansi((FIXTURES / "testssl_legacy_tls10.txt").read_text(encoding="utf-8"))
    r = parse_testssl(None, raw, host_ip="203.0.113.29")
    assert r.fqdn == "cloud.example.test" and r.port == 443
    assert r.protocols == {"SSLv2": False, "SSLv3": False, "TLS1.0": True, "TLS1.1": True, "TLS1.2": True, "TLS1.3": True}
    assert r.ciphers_weak == ["cbc"]
    assert r.vulns == {"BEAST": "vulnerable", "LUCKY13": "potential"}
    assert r.fallback_scsv is False and r.grade == "B"
    assert r.cert["cn"] == "*.example.test" and r.cert["mismatch"] is False and r.cert["chain_ok"] is True
    assert r.cert["not_after"] == "2026-12-11T23:59:00Z" and r.cert["expired"] is False
    assert r.hsts["present"] is False
    assert r.started_at == "2026-08-31T14:31:32Z" and r.json_filtered is False


def test_testssl_json_gefiltert_ohne_rohtext():
    entries = [{"id": "BEAST_CBC_TLS1", "ip": "cloud.example.test/203.0.113.29", "port": "443",
                "severity": "MEDIUM", "cve": "CVE-2011-3389", "finding": "ECDHE-RSA-AES256-SHA"},
               {"id": "fallback_SCSV", "ip": "cloud.example.test/203.0.113.29", "port": "443",
                "severity": "MEDIUM", "finding": "NOT supported"}]
    r = parse_testssl(entries, None)
    assert r.json_filtered is True
    assert all(v is None for v in r.protocols.values())
    assert r.fallback_scsv is False and r.vulns == {"BEAST": "vulnerable"}
    assert r.entries[0]["cve"] == "CVE-2011-3389"


def test_testssl_json_und_text_zusammen():
    entries = [{"id": "cipherlist_3DES_IDEA", "ip": "x/1.1.1.1", "port": "443", "severity": "MEDIUM", "finding": "offered"},
               {"id": "HSTS_time", "ip": "x/1.1.1.1", "port": "443", "severity": "MEDIUM",
                "finding": "max-age too short. 1 days (=86400 seconds) < 15552000 seconds"},
               {"id": "X-Frame-Options_multiple", "ip": "x/1.1.1.1", "port": "443", "severity": "MEDIUM", "finding": "Multiple"}]
    raw = _ansi((FIXTURES / "testssl_legacy_tls10.txt").read_text(encoding="utf-8"))
    r = parse_testssl(entries, raw)
    assert "3des" in r.ciphers_weak and "cbc" in r.ciphers_weak
    assert r.hsts["max_age"] == 86400 and r.duplicate_headers == ["x-frame-options"]
    assert r.protocols["TLS1.0"] is True and r.json_filtered is False


def test_testssl_statusmarker_ist_kein_lauf():
    r = parse_testssl(None, "SKIPPED: no_ssl")
    assert r.has_data is False


def test_testssl_connect_fehler():
    entries = [{"id": "scanProblem", "ip": "a/1.2.3.4", "port": "443", "severity": "FATAL",
                "finding": "Can't connect to '1.2.3.4:443' Make sure a firewall is not between you and your scanning target!"}]
    r = parse_testssl(entries, None)
    assert r.connect_failed is True


def test_testssl_warn_ist_nicht_geprueft():
    """WARN heisst weder verwundbar noch in Ordnung (S5b)."""
    entries = [{"id": "heartbleed", "ip": "a/1.2.3.4", "port": "443", "severity": "WARN",
                "finding": "Test failed (timeout)"}]
    r = parse_testssl(entries, None)
    assert r.vulns == {"Heartbleed": "not_tested"}


def test_testssl_fund_schlaegt_nicht_geprueft():
    entries = [{"id": "heartbleed", "ip": "a/1.2.3.4", "port": "443", "severity": "WARN",
                "finding": "Test failed (timeout)"},
               {"id": "heartbleed", "ip": "a/1.2.3.4", "port": "443", "severity": "CRITICAL",
                "finding": "VULNERABLE (NOT ok)"}]
    assert parse_testssl(entries, None).vulns == {"Heartbleed": "vulnerable"}
    assert parse_testssl(list(reversed(entries)), None).vulns == {"Heartbleed": "vulnerable"}


# -------------------------------------- testssl-CVE nur bei echtem Urteil (S5b)

_TESTSSL_CVE_ENTRIES = [
    # Regressionssperre: die CVE im Feld ``cve`` ist die Nummer, GEGEN die
    # geprueft wurde. Ein "not vulnerable" darf keinen Fakt erzeugen, sonst
    # steht Heartbleed im Bericht eines Hosts, der es nie hatte.
    ({"id": "heartbleed", "severity": "OK", "cve": "CVE-2014-0160",
      "finding": "not vulnerable, no heartbeat extension"}, False),
    ({"id": "heartbleed", "severity": "CRITICAL", "cve": "CVE-2014-0160",
      "finding": "VULNERABLE (NOT ok)"}, True),
    ({"id": "BEAST_CBC_TLS1", "severity": "MEDIUM", "cve": "CVE-2011-3389",
      "finding": "ECDHE-RSA-AES256-SHA"}, True),
    ({"id": "LUCKY13", "severity": "INFO", "cve": "CVE-2013-0169",
      "finding": "potentially vulnerable, uses cipher block chaining (CBC) ciphers"}, False),
    ({"id": "CCS", "severity": "WARN", "cve": "CVE-2014-0224",
      "finding": "Test failed (timeout)"}, False),
]


@pytest.mark.parametrize("entry,erwartet", _TESTSSL_CVE_ENTRIES)
def test_testssl_cve_nur_bei_urteil(entry, erwartet):
    from reporter.facts.build import _testssl_verwundbar
    assert _testssl_verwundbar(entry) is erwartet


# ------------------------------------------------------------------ Coverage

def _row(**kw) -> ToolRun:
    base = {"toolName": "x", "hostIp": None, "phase": 2, "status": None, "skipReason": None,
            "exitCode": 0, "durationMs": 0, "createdAt": "2026-08-31T14:00:00Z", "rawOutput": ""}
    base.update(kw)
    return tool_run_from_row(base, 0)


@pytest.mark.parametrize("row,expected", [
    (dict(toolName="virustotal", status="skipped", skipReason="no_api_key", exitCode=-3, rawOutput="SKIPPED: no_api_key"), ("skipped", "no_api_key")),
    (dict(toolName="gobuster_dns", status="timeout", skipReason="timeout_after_180s", exitCode=-1, rawOutput="TIMEOUT after 180s"), ("failed", "timeout_after_180s")),
    (dict(toolName="ffuf_sensitive", status=None, exitCode=-3, rawOutput="SKIPPED: wordlist_missing:/x"), ("skipped", "wordlist_missing:/x")),
    (dict(toolName="testssl", status=None, exitCode=246, rawOutput="\x1b[7m Start 2026-08-31 14:29:32 -->> 1.2.3.4:443 (a) <<--\x1b[m\n Testing protocols\n TLS 1.2 offered (OK)\n Done 2026-08-31 14:30:00 [ 28s] -->> 1.2.3.4:443 (a) <<--"), ("ok", None)),
    (dict(toolName="testssl", status=None, exitCode=10, rawOutput="Fatal error: Can't connect"), ("failed", "exit_10")),
    (dict(toolName="feroxbuster", status=None, exitCode=1, rawOutput='{"type":"configuration"}\n{"type":"statistics"}'), ("ok", None)),
    (dict(toolName="httpx", status="ok", rawOutput=""), ("empty", None)),
    (dict(toolName="urlhaus", status=None, exitCode=0, rawOutput="OK: no_data"), ("ok", "no_data")),
    (dict(toolName="zap_active", status="failed", skipReason="ZAP API error 400", exitCode=-2, rawOutput="FAILED: ZAP API error 400"), ("failed", "ZAP API error 400")),
    (dict(toolName="wpscan", status=None, exitCode=5, rawOutput='{"scan_aborted":"x"}'), ("ok", None)),
])
def test_classify_run(row, expected):
    status, reason, _raw = classify_run(_row(**row))
    assert (status, reason) == expected


def test_blockade_reihenfolge():
    sig = HostSignals(ip="1.2.3.4", web_ports_open=True, headers_reachable={"a": False, "b": False},
                      httpx_has_output=False, testssl_connect_failed=True)
    assert derive_blocked(sig, []).source == "derived"
    runs = [_row(toolName="header_check", hostIp="1.2.3.4", status="blocked", skipReason="429_burst(4)")]
    assert derive_blocked(sig, runs).source == "scan_results"
    sig.inventory_blocked = S.Blocked(detected=True, reason="waf_body_marker", source="inventory")
    assert derive_blocked(sig, runs).source == "inventory"
    clean = HostSignals(ip="1.2.3.4", web_ports_open=True, headers_reachable={"a": True}, httpx_has_output=True)
    assert derive_blocked(clean, []).detected is False


# ------------------------------------------------------------------ Threat-Durchreichung und Builder auf synthetischem Bundle

def _bundle() -> ScanBundle:
    b = ScanBundle(order_id="test-order", source_kind="dir", source_name="test",
                   meta={"orderId": "test-order", "domain": "example.test", "package": "perimeter",
                         "startedAt": "2026-08-31T14:00:00Z", "finishedAt": "2026-08-31T14:30:00Z",
                         "toolVersions": ["nmap 7.93", "gobuster (installed)"]})
    b.host_inventory = {"domain": "example.test", "hosts": [
        {"ip": "203.0.113.10", "fqdns": ["example.test"], "rdns": "h.example.test",
         "vhosts": [{"fqdn": "example.test", "status": 200, "title": "Home", "is_primary": True, "aliases": []}],
         "passive_intel": {"abuseipdb_score": 0, "is_tor": False}}],
        "dns_findings": {"spf": "v=spf1 mx -all", "dmarc": "v=DMARC1; p=reject; rua=mailto:a@example.test",
                         "dkim": True, "mx": ["mx.example.test"], "ns": ["ns1.example.test"],
                         "zone_transfer": False, "dangling_cnames": []}}
    h = b.host("203.0.113.10")
    h.nmap_xml = (FIXTURES / "nmap_capabilities.xml").read_text(encoding="utf-8")
    h.refs["nmap.xml"] = "hosts/203.0.113.10/phase1/nmap.xml"
    b.enrichment = {"CVE-2016-2183": {
        "nvd": {"cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "cwes": ["CWE-327"]},
        "epss": {"epss": 0.0123, "percentile": 0.85},
        "cisa_kev": {"vendor": "x", "product": "y", "date_added": "2024-01-01", "known_ransomware": "Unknown"},
        "exploitdb": {"exploit_count": 2, "metasploit_module": False},
    }}
    b.correlated_findings = [{"cve_id": "CVE-2016-2183", "host_ip": "203.0.113.10", "port": 443, "is_false_positive": False}]
    return b


def test_builder_synthetisch_threat_und_dns():
    facts = build_from_bundle(_bundle())
    assert facts.scan.scanner_egress == "198.51.100.7"
    assert facts.scan.tool_versions == [S.ToolVersion(name="gobuster", version=None), S.ToolVersion(name="nmap", version="7.93")]
    t = {x.cve_id: x for x in facts.threats}["CVE-2016-2183"]
    assert t.cvss_nvd.score == 7.5 and t.epss.percentile == 0.85 and t.kev.listed is True
    assert t.exploitdb.count == 2 and t.host_ip == "203.0.113.10" and t.port == 443
    assert t.cwes == ["CWE-327"]
    dns = facts.dns[0]
    assert dns.spf.all_qualifier == "-all" and dns.dmarc.p == "reject" and dns.dmarc.present is True
    assert dns.dmarc.rua == ["mailto:a@example.test"] and dns.dkim.present is True
    svc = {s.port: s for s in facts.services}
    assert svc[21].tls_required is True and svc[143].login_disabled is True and svc[587].tls_required is True
    assert svc[3306].family == "mariadb" and svc[3306].version_norm == "10.11.18"
    sw = {(s.family, s.version_norm): s for s in facts.software}
    assert sw[("mariadb", "10.11.18")].eol.status == "unknown"
    assert sw[("nginx", "1.24.0")].distro == "ubuntu" and sw[("nginx", "1.24.0")].eol.status == "unknown"
    assert sw[("postgresql", None)].hints == ["9.6.0 or later"]
    # ohne tool_runs: Coverage unbekannt, keine erfundenen Zeilen
    assert [c for c in facts.coverage if c.tool == "scan_results"][0].reason == "no_tool_runs"
    ids = [f.id for f in facts.all_facts()]
    assert len(ids) == len(set(ids))
    for f in facts.all_facts():
        assert f.source and f.mode in ("active", "passive") and 0.0 <= f.confidence <= 1.0


def test_builder_synthetisch_ipv6_coverage():
    b = _bundle()
    h6 = b.host("2001:db8::2")
    h6.nmap_xml = (FIXTURES / "nmap_ipv6_skipped.xml").read_text(encoding="utf-8")
    b.host_inventory["hosts"].append({"ip": "2001:db8::2", "fqdns": ["v6.example.test"], "vhosts": []})
    rows = [_row(toolName="nmap", hostIp="2001:db8::2", phase=1, status="ok", exitCode=0,
                 rawOutput="Starting Nmap 7.93 ( https://nmap.org )\n"),
            _row(toolName="nmap", hostIp="203.0.113.10", phase=1, status="ok", exitCode=0, rawOutput="Nmap scan report for 203.0.113.10\nHost is up")]
    from reporter.facts.sources import merge_tool_runs
    merge_tool_runs(b, rows, name="rows", sha256=None)
    facts = build_from_bundle(b)
    cov = {c.id: c for c in facts.coverage}
    v6 = cov["cov:1:nmap:[2001:db8::2]"]
    assert v6.status == "failed" and v6.reason == "target_invalid_ipv6" and v6.raw_status == "ok"
    host6 = [h for h in facts.hosts if h.ip == "2001:db8::2"][0]
    assert host6.family == 6 and host6.nmap_state == "skipped" and host6.ports_summary.open == 0
    assert cov["cov:1:nmap:203.0.113.10"].status == "ok"
