"""S1: facts.json fuer alle Golden-Orders (spec/01, spec/06 Abschnitt 3, negative.json).

Die Tars werden ueber ``tarfile`` im Speicher gelesen, deshalb laeuft dieser Test auch
unter Windows fuer die beiden Junkerwerk-Tars mit IPv6-Hostverzeichnissen. Die
``scan_results``-Zeilen kommen immer aus dem API-Snapshot (Coverage, testssl-Rohtext,
Header je VHost stehen nur dort).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from reporter.facts import schema as S
from reporter.facts.build import build_facts
from reporter.facts.golden import (
    GOLDEN, SNAPSHOT, build_golden_facts, build_snapshot_facts, facts_path, first_difference,
    golden_orders, tar_path, results_path,
)
from reporter.facts.serialize import dumps, load_json

JW_MULTI = "0bf16342-ed96-4b0e-a596-05aee3a62cb5"
JW_DE = "2572eebc-6135-40e6-b1d2-e9dfccc20ae6"
JW_HU = "a6df9d9d-eccd-49d1-8dd3-b00a5e005108"
SECURESS = "ae8d1d70-7925-4e3c-84de-3113f3e57b60"
CASTENOW_COVERAGE = "f77ccff2-fc7a-4488-a9ba-540a42a25056"
TRUNK = "45bb234c-d556-4a80-9c78-3ce221ea28a6"
KRAUSE = "fb13a98f-22c6-4d17-875c-eeeb14643beb"
HEUEL = "176db198-fa4a-4520-bf18-43cbc02a229d"

_CACHE: dict[str, S.Facts] = {}
_NEGATIVE = load_json(GOLDEN / "negative.json")
_TAR_ORDERS = {o["order_id"] for o in golden_orders()}


def _facts(order_id: str) -> S.Facts:
    """Golden-Facts aus Tar + Zeilen, sonst aus dem Snapshot (Orders ohne Tar)."""
    if order_id not in _CACHE:
        if order_id in _TAR_ORDERS:
            _CACHE[order_id] = build_golden_facts(order_id)
        else:
            _CACHE[order_id] = build_snapshot_facts(order_id)
    return _CACHE[order_id]


def _neg_orders(pattern: str) -> list[str]:
    return sorted({e["order"] for e in _NEGATIVE["entries"] if e["pattern"] == pattern})


def _cases():
    return [pytest.param(o["order_id"], id=o["order_id"][:8]) for o in golden_orders()]


def _service(f: S.Facts, ip: str, port: int) -> S.ServiceFact:
    for s in f.services:
        if s.host_ip == ip and s.port == port:
            return s
    raise AssertionError(f"kein Dienst {ip}:{port}")


# ------------------------------------------------------------------ Drift-Guard

@pytest.mark.parametrize("order_id", _cases())
def test_golden_facts_eingecheckt_und_aktuell(order_id):
    path = facts_path(order_id)
    assert path.exists(), f"{path.name} fehlt; neu bauen mit: python -m reporter.facts --golden"
    stored = load_json(path)
    current = _facts(order_id).to_dict()
    diff = first_difference(stored, current)
    assert not diff, (f"facts/{order_id[:8]} weicht vom Neubau ab: {diff}. "
                      "Wenn die Aenderung gewollt ist: python -m reporter.facts --golden")


@pytest.mark.parametrize("order_id", _cases())
def test_golden_facts_schema(order_id):
    f = _facts(order_id)
    data = f.to_dict()
    assert data["schema_version"] == S.FACTS_SCHEMA_VERSION
    again = S.Facts.from_dict(data)
    assert again.to_dict() == data
    ids = [x.id for x in f.all_facts()]
    assert len(ids) == len(set(ids))
    for x in f.all_facts():
        assert x.source and x.mode in ("active", "passive")
        assert 0.0 <= x.confidence <= 1.0
        assert x.observed_at is None or x.observed_at.endswith("Z")
    kinds = {i.kind for i in f.generator.inputs}
    assert {"tar", "tool_runs", "eol_feed"} <= kinds
    assert f.scan.started_at and f.scan.finished_at and f.scan.started_at <= f.scan.finished_at


@pytest.mark.parametrize("order_id", _cases())
def test_golden_facts_groesse(order_id):
    assert facts_path(order_id).stat().st_size < 1_000_000


def test_tar_only_build_konsistent():
    """Ohne Zeilen bleiben Coverage und observed_at duenner, die Entitaeten sind gleich."""
    full = _facts(JW_DE)
    only = build_facts(tar_path(JW_DE), orders_json=SNAPSHOT / "orders.json")
    assert {s.id for s in only.services} == {s.id for s in full.services}
    assert {h.id for h in only.hosts} == {h.id for h in full.hosts}
    assert {d.id for d in only.dns} == {d.id for d in full.dns}
    unknown = [c for c in only.coverage if c.tool == "scan_results"]
    assert unknown and unknown[0].status == "unknown" and unknown[0].reason == "no_tool_runs"
    cloud = [t for t in only.tls if t.fqdn == "cloud.junkerwerk.de"]
    assert cloud and cloud[0].json_filtered is True and cloud[0].protocols["TLS1.0"] is None
    assert any("severity-Filter" in w for w in only.warnings)


# ------------------------------------------------------------------ Negativ-Fixtures auf Faktenebene

def test_spf_vorhanden_bei_allen_neg_spf_orders():
    orders = _neg_orders("NEG-SPF-MISSING")
    # S6b-2: acht Auftraege; 57b3ac85 (lumbeck-wolter, seit S2b im Snapshot) traegt dasselbe Muster.
    assert len(orders) == 8
    for oid in orders:
        f = _facts(oid)
        assert f.dns, oid
        assert f.dns[0].spf is not None and f.dns[0].spf.raw.startswith("v=spf1"), oid


def test_mariadb_10x_nicht_mysql_55():
    for oid in _neg_orders("NEG-MARIADB-55"):
        f = _facts(oid)
        maria = [s for s in f.software if s.family == "mariadb"]
        assert maria, oid
        for s in maria:
            assert s.version_norm and s.version_norm.startswith("10.11."), (oid, s.version_raw)
            assert s.eol.status != "eol", (oid, s.version_norm)
            assert s.product == "MariaDB"
        assert not [s for s in f.software if s.family == "mysql" and (s.version_norm or "").startswith("5.5")], oid
    trunk = _facts(TRUNK)
    echt = [s for s in trunk.software if s.family == "mariadb"]
    assert echt and echt[0].version_norm == "5.5.68" and echt[0].eol.status == "eol"


@pytest.mark.parametrize("order_id", [JW_MULTI, JW_DE])
def test_exchange_se_bei_junkerwerk(order_id):
    f = _facts(order_id)
    ex = [s for s in f.software if s.family == "exchange" and s.host_ip == "217.243.248.28"]
    assert ex
    for s in ex:
        assert s.edition == "SE" and s.build == "15.2.2562" and s.version_norm == "SE"
        assert any("X-FEServer" in h and "EXCHANGE-SE" in h for h in s.hints)
        assert s.eol.status == "unknown"
    assert not [s for s in f.software if s.version_norm == "2016"]
    dec = [d for d in f.decisions if d.id == "dec:cms_profile:217.243.248.28"]
    assert dec and dec[0].payload.get("cms") == "Exchange" and "KI#2" in (dec[0].note or "")
    if order_id == JW_MULTI:
        # Lauf 1: KI#2 nannte "2016", der Build sagt SE. Nur Protokoll, kein Software-Fakt.
        assert dec[0].payload.get("cms_version") == "2016"


def test_ftp_tls_required():
    s = _service(_facts(SECURESS), "212.227.60.78", 21)
    assert s.tls_required is True and s.product == "ProFTPD"
    assert any("requires SSL" in e.excerpt for e in s.evidence)
    s2 = _service(_facts(JW_MULTI), "188.40.3.130", 21)
    assert s2.tls_required is True


def test_starttls_bei_110_und_143():
    for oid, ip in ((JW_MULTI, "188.40.3.130"), (JW_DE, "188.40.3.130"), (SECURESS, "212.227.60.78")):
        f = _facts(oid)
        assert _service(f, ip, 110).starttls is True, oid
        s143 = _service(f, ip, 143)
        assert s143.starttls is True, oid
    jw143 = _service(_facts(JW_MULTI), "188.40.3.130", 143)
    assert jw143.login_disabled is True and jw143.tls_required is True
    jw587 = _service(_facts(JW_MULTI), "188.40.3.130", 587)
    assert jw587.starttls is True and jw587.login_disabled is True and jw587.auth_mechanisms == []
    jw465 = _service(_facts(JW_MULTI), "188.40.3.130", 465)
    assert jw465.tunnel_ssl is True and "PLAIN" in jw465.auth_mechanisms


def test_eol_negativ_distro_pakete():
    for oid in _neg_orders("NEG-WEBSERVER-EOL"):
        f = _facts(oid)
        for s in f.software:
            if s.family == "nginx" and s.version_norm == "1.24.0":
                assert s.distro == "ubuntu" and s.eol.status == "unknown", (oid, s.id)
                assert s.eol.upstream_eol_date == "2024-04-23"
            if s.family == "apache" and s.version_norm == "2.4.41":
                assert s.eol.status == "unknown", (oid, s.id)
        assert any(s.family in ("nginx", "apache") for s in f.software), oid


def test_wordpress_theme_ist_kein_plugin():
    f = _facts(TRUNK)
    themes = [s for s in f.software if s.product == "BeTheme"]
    assert themes and all(s.kind == "theme" for s in themes)
    assert {s.version_norm for s in themes} >= {"27.2.11", "28.2.1"}
    assert not [s for s in f.software if s.product.isdigit()]
    for s in f.software:
        assert s.product and not s.product.strip().isdigit()


# ------------------------------------------------------------------ Coverage

def test_coverage_junkerwerk_multi():
    f = _facts(JW_MULTI)
    assert f.scan.domains == ["junkerwerk.de", "junkerwerk.hu"]
    cov = {c.id: c for c in f.coverage}
    v6 = cov["cov:1:nmap:[2a01:4f8:d0a:3124::2]"]
    assert v6.status == "failed" and v6.reason == "target_invalid_ipv6" and v6.raw_status == "ok"
    host = {h.ip: h for h in f.hosts}
    assert host["2a01:4f8:d0a:3124::2"].family == 6 and host["2a01:4f8:d0a:3124::2"].nmap_state == "skipped"
    hetzner = host["188.40.3.130"]
    assert hetzner.blocked.detected and hetzner.blocked.source == "derived"
    assert hetzner.blocked.reason == "web_unreachable_after_portscan"
    assert hetzner.ports_summary.open == 13
    web_188 = [c for c in f.coverage if c.host_ip == "188.40.3.130" and c.tool in ("header_check", "testssl", "httpx")]
    assert web_188 and all(c.status == "blocked" for c in web_188)
    zap_active = [c for c in f.coverage if c.tool == "zap_active" and c.host_ip == "217.243.248.28"]
    assert zap_active and zap_active[0].status == "failed" and "does_not_exist" in (zap_active[0].reason or "")
    ffuf = [c for c in f.coverage if c.tool == "ffuf_sensitive" and c.host_ip == "217.243.248.30"]
    assert ffuf and ffuf[0].status == "skipped" and (ffuf[0].reason or "").startswith("wordlist_missing")
    vt = [c for c in f.coverage if c.tool == "virustotal"]
    assert vt and vt[0].status == "skipped" and vt[0].reason == "no_api_key"
    gob = [c for c in f.coverage if c.tool == "gobuster_dns"]
    assert gob and gob[0].status == "failed" and gob[0].raw_status == "timeout"
    hu = [c for c in f.coverage if c.scope == "domain" and c.domain == "junkerwerk.hu"]
    assert hu and hu[0].status == "unknown" and hu[0].reason == "second_target_unlabeled"
    assert any("junkerwerk.hu" in w for w in f.warnings)
    ticket = host["217.243.248.27"]
    assert ticket.nmap_state == "up" and ticket.ports_summary.open == 0
    # S6b-3 (spec/10 R3): nmap lieferte fuer den Host keinen Hostbericht (--open).
    assert cov["cov:1:nmap:217.243.248.27"].reason == "no_response"


def test_coverage_castenow_luecken():
    f = _facts(CASTENOW_COVERAGE)
    assert len(f.hosts) == 9

    def hosts_ok(tool: str) -> int:
        return len({c.host_ip for c in f.coverage if c.tool == tool and c.status == "ok"})

    assert hosts_ok("nmap") == 9 and hosts_ok("testssl") == 9
    assert hosts_ok("feroxbuster") == 7
    assert hosts_ok("zap") == 6
    assert hosts_ok("wpscan") == 1
    assert hosts_ok("ffuf_param") == 1


# ------------------------------------------------------------------ TLS, Passiv, WAF, HTTP

def test_tls_protokolle_junkerwerk():
    f = _facts(JW_MULTI)
    tls = {t.fqdn: t for t in f.tls}
    cloud = tls["cloud.junkerwerk.de"]
    assert cloud.protocols["TLS1.0"] is True and cloud.protocols["TLS1.1"] is True
    assert cloud.fallback_scsv is False and cloud.grade == "B"
    owa = tls["outlook.junkerwerk.de"]
    assert owa.protocols["TLS1.0"] is False and owa.protocols["TLS1.1"] is False
    assert owa.protocols["TLS1.2"] is True and owa.protocols["TLS1.3"] is True
    assert owa.cert.mismatch is False and owa.cert.chain_ok is True and owa.cert.wildcard is True
    openotp = tls["openotp.junkerwerk.de"]
    assert "3des" in openotp.ciphers_weak
    assert {v.name: v.status for v in openotp.vulns}["SWEET32"] == "vulnerable"
    assert openotp.hsts.max_age == 86400
    assert openotp.cert.not_after == "2026-12-11T23:59:59Z" and openotp.cert.days_left == 102
    hu = _facts(JW_HU)
    mism = [t for t in hu.tls if t.fqdn == "openotp.junkerwerk.hu"]
    assert mism and mism[0].cert.mismatch is True and mism[0].cert.cn == "*.junkerwerk.de"


def test_passive_shodan_unbestaetigt():
    f = _facts(JW_MULTI)
    p = {(x.host_ip, x.port): x for x in f.passive if x.source == "shodan"}
    sonic = p[("217.243.248.28", 4433)]
    assert sonic.product == "SonicWall" and sonic.verified is False and sonic.mode == "passive"
    exim = p[("217.243.248.30", 25)]
    assert exim.product == "Exim smtpd" and exim.version == "4.96" and exim.verified is False
    assert p[("188.40.3.130", 3306)].verified is True
    exim_sw = [s for s in f.software if s.family == "exim"]
    assert not exim_sw, "Shodan-Versionen bleiben passiv und werden keine Software-Fakten"


def test_http_je_vhost_und_x_feserver():
    f = _facts(JW_MULTI)
    http = {h.fqdn: h for h in f.http}
    for vh in ("mail.junkerwerk.de", "outlook.junkerwerk.de", "autodiscover.junkerwerk.de"):
        assert http[vh].x_feserver == "EXCHANGE-SE" and http[vh].score == "0/7", vh
        assert http[vh].reachable is True and http[vh].login_form is True
    openotp = http["openotp.junkerwerk.de"]
    assert openotp.csp and openotp.csp.unsafe_inline and openotp.csp.unsafe_eval
    assert openotp.duplicate_headers == ["x-frame-options", "cache-control"] or set(openotp.duplicate_headers) == {"x-frame-options", "cache-control"}
    csrf = [a for a in openotp.alerts if a.plugin_id == "10202"]
    assert csrf and csrf[0].count >= 1 and csrf[0].url and "login_uid.php" in (csrf[0].url + "".join(csrf[0].urls_sample))
    www = http["www.junkerwerk.de"]
    assert www.reachable is False and www.status_code is None
    fq = {x.name: x for x in f.fqdns if x.host_ip == "188.40.3.130"}
    assert fq["nachhaltigkeit.junkerwerk.de"].http_status == 403


def test_waf_erkennung():
    heuel = _facts(HEUEL)
    detected = [x for x in heuel.fqdns if x.waf and x.waf.detected]
    assert detected and any("Cloudflare" in (x.waf.name or "") for x in detected)
    jw = _facts(JW_MULTI)
    mail = [x for x in jw.fqdns if x.name == "mail.junkerwerk.de"][0]
    assert mail.waf is not None and mail.waf.detected is False


def test_multi_target_drei_domains_snapshot():
    f = _facts("68cabf05-5ed2-4ba7-b28e-da3ba8af2b87")
    assert f.scan.domains == ["lumbeck-wolter.de", "castenow.de", "huendgen-entsorgung.de"]
    assert [t.domain for t in f.targets] == f.scan.domains
    extra = {c.domain for c in f.coverage if c.scope == "domain" and c.reason == "second_target_unlabeled"}
    assert extra == {"castenow.de", "huendgen-entsorgung.de"}
    assert len(f.dns) == 1 and f.dns[0].domain == "lumbeck-wolter.de"


# ------------------------------------------------------------------ Determinismus

def test_determinismus_zwei_prozesse(tmp_path):
    outs = []
    for seed in ("1", "4242"):
        out = tmp_path / f"facts-{seed}.json"
        env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONIOENCODING="utf-8")
        cmd = [sys.executable, "-m", "reporter.facts", str(tar_path(JW_MULTI)),
               "--tool-runs", str(results_path(JW_MULTI)), "--orders", str(SNAPSHOT / "orders.json"),
               "-o", str(out)]
        res = subprocess.run(cmd, cwd=str(Path(__file__).resolve().parents[1]), env=env,
                             capture_output=True, text=True, timeout=300)
        assert res.returncode == 0, res.stderr[-2000:]
        outs.append(out.read_bytes())
    assert outs[0] == outs[1]
    assert b"\r\n" not in outs[0]
    assert outs[0] == dumps(json.loads(outs[0].decode("utf-8"))).encode("utf-8")
