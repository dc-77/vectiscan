"""Engine: Statuslogik, Gruppen, Abdeckung, Positiv, Auffangregeln, Ignorierliste, Determinismus."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from reporter.catalog.catchall import run_catchalls
from reporter.catalog.engine import evaluate, load_catalog
from reporter.catalog.scope import FactsIndex, build_groups
from reporter.facts.serialize import dumps
from tests.catalog.conftest import get_catalog, make_facts, run_check

REPORT_WORKER = Path(__file__).resolve().parents[2]


def _one(results, key):
    hits = [r for r in results if r.group_key == key]
    assert hits, [r.group_key for r in results]
    return hits[0]


def test_absent_pass_braucht_abdeckung():
    facts = make_facts({"hosts": [{"ip": "10.0.0.1"}]})
    r = _one(run_check("db_exposed", facts), "10.0.0.1")
    assert r.status == "not_testable" and r.reason_code == "no_coverage_rows"
    facts_ok = make_facts({"hosts": [{"ip": "10.0.0.1"}]}, coverage_default="ok")
    r2 = _one(run_check("db_exposed", facts_ok), "10.0.0.1")
    assert r2.status == "pass" and r2.positive is True and r2.items_seen == 0


def test_coverage_code_wird_abgebildet():
    facts = make_facts({"hosts": [{"ip": "10.0.0.1"}],
                        "coverage": [{"scope": "host", "host_ip": "10.0.0.1", "tool": "nmap", "status": "skipped", "reason": "host_unreachable"}]})
    r = _one(run_check("db_exposed", facts), "10.0.0.1")
    assert r.status == "not_testable" and r.reason_code == "host_unreachable" and "erreichbar" in r.reason


def test_domain_ohne_dns_fakten_ist_not_testable():
    facts = make_facts({"dns": [], "coverage": [{"scope": "domain", "domain": "example.test", "tool": "dns_records", "status": "skipped", "reason": "not_in_package"}]})
    r = _one(run_check("dmarc_missing", facts), "example.test")
    assert r.status == "not_testable" and r.reason_code == "no_dns_facts"


def test_coverage_regel_not_in_package_ist_not_applicable(tmp_path):
    """Eine Gruppenregel mit reason_code coverage:<tool> uebernimmt Status und Grund der Abdeckung."""
    import shutil
    from reporter.catalog.engine import load_catalog as _load
    target = tmp_path / "catalog"
    shutil.copytree(REPORT_WORKER / "reporter" / "catalog", target, ignore=shutil.ignore_patterns("__pycache__"))
    for p in (target / "checks").glob("*.yaml"):
        if p.stem != "http_no_tls":
            p.unlink()
    text = (target / "checks" / "http_no_tls.yaml").read_text(encoding="utf-8")
    text = text.replace("not_testable_when: []",
                        'not_testable_when:\n  - when: coverage_status("whois") != "ok"\n    reason_code: "coverage:whois"\n    context: group')
    (target / "checks" / "http_no_tls.yaml").write_text(text, encoding="utf-8")
    cat = _load(target)
    facts = make_facts({"services": [{"host_ip": "10.0.0.1", "port": 80, "service": "http"}],
                        "coverage": [{"scope": "domain", "domain": "example.test", "tool": "whois", "status": "skipped", "reason": "not_in_package"},
                                     {"scope": "host", "host_ip": "10.0.0.1", "tool": "nmap", "status": "ok"}]})
    r = _one(run_check("http_no_tls", facts, cat), "10.0.0.1")
    assert r.status == "not_applicable" and r.reason_code == "not_in_package"
    facts_ok = make_facts({"services": [{"host_ip": "10.0.0.1", "port": 80, "service": "http"}]}, coverage_default="ok")
    assert _one(run_check("http_no_tls", facts_ok, cat), "10.0.0.1").status == "fail"


def test_zweite_domain_ohne_dns_ist_not_testable():
    facts = make_facts({"scan": {"domain": "a.test", "domains": ["a.test", "b.test"]},
                        "dns": [{"domain": "a.test", "dmarc": {"present": True, "p": "reject"}}],
                        "coverage": [{"scope": "domain", "domain": "b.test", "tool": "dns", "status": "unknown", "reason": "second_target_unlabeled"}]},
                       coverage_default="ok")
    res = run_check("dmarc_missing", facts)
    assert _one(res, "a.test").status == "pass"
    b = _one(res, "b.test")
    assert b.status == "not_testable" and b.reason_code == "second_target_unlabeled"


def test_item_not_testable_macht_gruppe_not_testable():
    facts = make_facts({"tls": [
        {"host_ip": "10.0.0.1", "fqdn": "a.example.test", "port": 443, "source": "testssl",
         "protocols": {"SSLv2": False, "SSLv3": False, "TLS1.0": False, "TLS1.1": False, "TLS1.2": True, "TLS1.3": True}},
        {"host_ip": "10.0.0.1", "fqdn": "a.example.test", "port": 8443, "source": "httpx",
         "protocols": {"SSLv2": None, "SSLv3": None, "TLS1.0": None, "TLS1.1": None, "TLS1.2": None, "TLS1.3": True}},
    ]}, coverage_default="ok")
    r = _one(run_check("tls_legacy_protocols", facts), "a.example.test@10.0.0.1")
    assert r.status == "not_testable" and r.reason_code == "tls_protocols_unknown"
    assert {m.key: m.status for m in r.members} == {"a.example.test:443@10.0.0.1": "pass", "a.example.test:8443@10.0.0.1": "not_testable"}


def test_fail_gewinnt_ueber_not_testable():
    facts = make_facts({"tls": [
        {"host_ip": "10.0.0.1", "fqdn": "a.example.test", "port": 443, "source": "testssl",
         "protocols": {"SSLv2": False, "SSLv3": False, "TLS1.0": True, "TLS1.1": False, "TLS1.2": True, "TLS1.3": True}},
        {"host_ip": "10.0.0.1", "fqdn": "a.example.test", "port": 8443, "source": "httpx",
         "protocols": {"SSLv2": None, "SSLv3": None, "TLS1.0": None, "TLS1.1": None, "TLS1.2": None, "TLS1.3": True}},
    ]}, coverage_default="ok")
    r = _one(run_check("tls_legacy_protocols", facts), "a.example.test@10.0.0.1")
    assert r.status == "fail" and r.affected == ["a.example.test:443 (TLS 1.0)"]
    # S6: Der Nachweis kommt aus dem getroffenen Teilobjekt, nicht aus der
    # Evidenzliste des Fakts. Ein Fixture ohne evidence traegt deshalb jetzt
    # trotzdem eine Zeile, und sie nennt genau das, was die Regel gesehen hat.
    assert len(r.evidence) == 1
    assert r.evidence[0].tool == "testssl"
    assert "TLS1.0" in r.evidence[0].excerpt


def test_evidence_wird_uebernommen():
    facts = make_facts({"services": [
        {"host_ip": "10.0.0.1", "port": 3306, "service": "mysql", "product": "MySQL",
         "evidence": [{"tool": "nmap", "ref": "hosts/10.0.0.1/phase1/nmap.xml", "excerpt": "3306/tcp open mysql MySQL 5.5.5-10.11.18-MariaDB"}]}
    ]}, coverage_default="ok")
    r = _one(run_check("db_exposed", facts), "10.0.0.1")
    assert r.status == "fail"
    assert r.evidence and r.evidence[0].tool == "nmap" and r.evidence[0].fact_id == "svc:10.0.0.1:3306/tcp"
    assert r.affected_fact_ids == ["svc:10.0.0.1:3306/tcp"]


def test_passiv_nur_treffer_verified_false():
    facts = make_facts({"passive": [{"host_ip": "10.0.0.1", "port": 4433, "product": "SonicWall", "verified": False, "confidence": 0.5}]},
                       coverage_default="ok")
    r = _one(run_check("admin_service_exposed_passive", facts), "10.0.0.1")
    assert r.status == "fail" and r.verified is False and r.source_mode == "passive"


def test_alias_fqdn_bildet_keine_gruppe():
    facts = make_facts({"fqdns": [
        {"name": "cloud.example.test", "host_ip": "10.0.0.1", "http_status": 200, "title": "IIS Windows Server",
         "aliases": [{"fqdn": "team.example.test", "status": 200, "reason": "body-hash-dup"}]},
        {"name": "team.example.test", "host_ip": "10.0.0.1"},
    ]}, coverage_default="ok")
    groups = build_groups(FactsIndex(facts), "fqdn", "fqdn")
    keys = [g.key for g in groups]
    assert "cloud.example.test@10.0.0.1" in keys and "team.example.test@10.0.0.1" not in keys
    g = groups[[k for k in keys].index("cloud.example.test@10.0.0.1")]
    assert g.fqdn_names == ["cloud.example.test", "team.example.test"]


def test_blockierter_host_liefert_blockadegrund():
    facts = make_facts({
        "hosts": [{"ip": "10.0.0.1", "blocked": {"detected": True, "reason": "web_unreachable_after_portscan", "source": "derived"}}],
        "http": [{"host_ip": "10.0.0.1", "fqdn": "www.example.test", "reachable": False, "security_headers": {}}],
    }, coverage_default="ok")
    r = _one(run_check("security_headers_incomplete", facts), "www.example.test@10.0.0.1")
    assert r.status == "not_testable" and r.reason_code == "web_unreachable_after_portscan"


def test_pass_silent_und_positiv_nur_bei_treffer():
    facts = make_facts({"software": [
        {"host_ip": "10.0.0.1", "product": "nginx", "family": "nginx", "kind": "webserver", "version_norm": None, "eol": {"status": "unknown"}},
    ], "services": [{"host_ip": "10.0.0.1", "port": 443, "service": "http"}]}, coverage_default="ok")
    r = _one(run_check("software_eol", facts), "10.0.0.1")
    assert r.status == "pass" and r.positive is False


def test_auffangregeln_und_ignorierliste(catalog):
    facts = make_facts({
        "services": [{"host_ip": "10.0.0.1", "port": 8001, "service": "vcom-tunnel"}, {"host_ip": "10.0.0.1", "port": 443, "service": "http"}],
        "http": [{"host_ip": "10.0.0.1", "fqdn": "www.example.test", "alerts": [
            {"plugin_id": "10109", "name": "Modern Web Application", "risk": "Informational"},
            {"plugin_id": "99999", "name": "Something Odd", "risk": "Low", "count": 3},
            {"plugin_id": "10202", "name": "Absence of Anti-CSRF Tokens", "risk": "Medium", "url": "https://www.example.test/x"},
        ]}],
        "passive": [{"host_ip": "10.0.0.1", "port": 18018, "verified": False, "confidence": 0.5},
                    {"host_ip": "10.0.0.2", "port": 2052, "verified": None, "confidence": 0.5}],
        "hosts": [{"ip": "10.0.0.2", "cdn_provider": "cloudflare"}],
    }, coverage_default="ok")
    out = evaluate(facts, catalog)
    kinds = {(u.kind, u.what): u for u in out.unprocessed}
    assert ("service_unknown_port", "8001/tcp vcom-tunnel") in kinds
    assert ("zap_alert_unmapped", "Something Odd (99999)") in kinds and kinds[("zap_alert_unmapped", "Something Odd (99999)")].count == 3
    assert ("passive_port_unverified", "10.0.0.1:18018") in kinds
    assert not any(u.what.startswith("10.0.0.2:2052") for u in out.unprocessed)
    assert any(i.kind == "passive_port" and i.what.startswith("10.0.0.2:2052") for i in out.ignored)
    assert any(i.kind == "zap_alert" and i.what.startswith("Modern Web Application") for i in out.ignored)
    assert not any(u.what.startswith("Absence of Anti-CSRF") for u in out.unprocessed)  # beansprucht durch csrf_token_missing


def test_ausgabe_ist_deterministisch_und_json_rund(catalog):
    facts = make_facts({"services": [{"host_ip": "10.0.0.1", "port": 3306, "service": "mysql", "product": "MySQL"}]}, coverage_default="ok")
    a = dumps(evaluate(facts, catalog).to_dict())
    b = dumps(evaluate(facts, catalog).to_dict())
    assert a == b
    data = json.loads(a)
    assert data["catalog_version"] and data["catalog_digest"] and data["checks"] and data["summary"]["checks"] == len(catalog.checks)
    assert all(r["status"] in ("pass", "fail", "not_applicable", "not_testable") for r in data["results"])


def test_cli_zwei_prozesse_gleiche_bytes(tmp_path):
    facts = make_facts({"services": [{"host_ip": "10.0.0.1", "port": 3306, "service": "mysql", "product": "MySQL"}]}, coverage_default="ok")
    src = tmp_path / "facts.json"
    src.write_text(dumps(facts.to_dict()), encoding="utf-8")
    outs = []
    for seed in ("1", "4242"):
        out = tmp_path / f"out-{seed}.json"
        env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONIOENCODING="utf-8")
        res = subprocess.run([sys.executable, "-m", "reporter.catalog", str(src), "-o", str(out)], cwd=str(REPORT_WORKER),
                             env=env, capture_output=True, text=True, timeout=120)
        assert res.returncode == 0, res.stderr[-2000:]
        outs.append(out.read_bytes())
    assert outs[0] == outs[1] and b"\r\n" not in outs[0]


def test_stdout_ist_utf8(tmp_path):
    facts = make_facts({"dns": [{"domain": "example.test", "dmarc": {"present": False}}]}, coverage_default="ok")
    src = tmp_path / "facts.json"
    src.write_text(dumps(facts.to_dict()), encoding="utf-8")
    res = subprocess.run([sys.executable, "-m", "reporter.catalog", str(src)], cwd=str(REPORT_WORKER),
                         env=dict(os.environ, PYTHONIOENCODING="cp1252"), capture_output=True, timeout=120)
    assert res.returncode == 0, res.stderr[-2000:].decode("utf-8", "replace")
    data = json.loads(res.stdout.decode("utf-8"))
    assert data["order_id"] == "fixture"
