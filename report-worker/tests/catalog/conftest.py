"""Test-Helfer fuer den Pruefkatalog (Session S2).

Fixtures sind Facts-Ausschnitte als JSON unter ``tests/catalog/fixtures/<id>_<art>.json``
mit ``art`` in ``pass``, ``fail``, ``nt`` (not_testable), ``na`` (not_applicable):

    {
      "facts": {"services": [{"host_ip": "10.0.0.1", "port": 3306, "service": "mysql", "product": "MySQL"}]},
      "coverage_default": "ok",
      "expect": {"status": "fail", "group_key": "10.0.0.1", "affected": ["10.0.0.1:3306 (MariaDB/MySQL)"]}
    }

``make_facts`` fuellt alles, was das Facts-Schema verlangt (scan, generator, id, source,
mode, confidence), legt fehlende Hosts, FQDNs und Targets an und erzeugt bei
``coverage_default: ok`` Abdeckungszeilen fuer alle Werkzeuge je Host und Domain. Das Schema
bleibt ``extra=forbid``: ein Tippfehler im Fixture ist ein Testfehler.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from reporter.catalog import tables as T
from reporter.catalog.engine import Catalog, evaluate, evaluate_check, load_catalog
from reporter.catalog.schema import CheckResult
from reporter.facts import schema as FS
from reporter.facts.serialize import ip_family, ip_token

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
REPORT_WORKER = HERE.parents[1]
GOLDEN = REPORT_WORKER / "tests" / "golden"

DEFAULT_DOMAIN = "example.test"
DEFAULT_TIME = "2026-09-01T10:00:00Z"
DEFAULT_END = "2026-09-01T11:00:00Z"

_ENTITY_MODE = {"passive": "passive"}


def _id_for(entity: str, item: dict[str, Any]) -> str:
    ip = ip_token(item.get("host_ip") or item.get("ip") or "")
    if entity == "hosts":
        return f"host:{ip}"
    if entity == "services":
        return f"svc:{ip}:{item.get('port')}/{item.get('proto', 'tcp')}"
    if entity == "fqdns":
        return f"fqdn:{item.get('name')}@{ip}"
    if entity == "http":
        return f"http:{item.get('fqdn') or ip}@{ip}"
    if entity == "tls":
        return f"tls:{item.get('fqdn') or ip}:{item.get('port', 443)}@{ip}"
    if entity == "dns":
        return f"dns:{item.get('domain')}"
    if entity == "software":
        return f"sw:{ip}:{item.get('fqdn') or '-'}:{item.get('family')}:{item.get('version_norm') or 'unknown'}"
    if entity == "passive":
        return f"passive:{item.get('source', 'shodan')}:{ip or item.get('domain') or '-'}:{item.get('port', '-')}"
    if entity == "coverage":
        return f"cov:{item.get('phase', '-')}:{item.get('tool')}:{item.get('fqdn') or ip or item.get('domain') or 'scan'}"
    if entity == "threats":
        return f"threat:{item.get('cve_id')}:{ip}:{item.get('port', '-')}"
    if entity == "targets":
        return f"target:{item.get('domain')}"
    if entity == "unprocessed":
        return f"unproc:{item.get('kind')}:{item.get('what')}"
    if entity == "decisions":
        return f"dec:{item.get('source', 'fixture')}:{ip or 'scan'}"
    return f"{entity}:{len(str(item))}"


_ENTITY_DEFAULTS: dict[str, dict[str, Any]] = {
    "hosts": {"reachable": True, "nmap_state": "up"},
    "services": {"proto": "tcp", "state": "open"},
    "fqdns": {"http_status": 200},
    "http": {"reachable": True, "status_code": 200},
    "tls": {"port": 443},
    "software": {"kind": "component"},
    "passive": {"source": "shodan"},
    "coverage": {"status": "ok"},
    "targets": {"targets_source": "fixture", "is_primary": True},
}


def make_facts(partial: dict[str, Any] | None = None, *, coverage_default: str | None = None,
               domain: str | None = None) -> FS.Facts:
    """Minimales, schemagueltiges Facts-Objekt aus einem Teil-Dict."""
    partial = dict(partial or {})
    domain = domain or partial.pop("domain", None) or (partial.get("dns") or [{}])[0].get("domain") or DEFAULT_DOMAIN
    scan = {
        "id": "scan:fixture", "source": "fixture", "mode": "active", "confidence": 1.0, "observed_at": DEFAULT_END,
        "order_id": "fixture", "package": "perimeter", "domain": domain, "domains": [domain],
        "started_at": DEFAULT_TIME, "finished_at": DEFAULT_END,
    }
    scan.update(partial.pop("scan", {}) or {})
    if not scan.get("domains"):
        scan["domains"] = [scan["domain"]]
    data: dict[str, Any] = {
        "schema_version": FS.FACTS_SCHEMA_VERSION,
        "generator": {"name": "fixture", "version": "0", "inputs": []},
        "scan": scan,
    }
    for entity in FS.Facts.ENTITY_FIELDS:
        items = partial.pop(entity, []) or []
        out = []
        for raw in items:
            item = dict(_ENTITY_DEFAULTS.get(entity, {}))
            item.update(raw)
            if entity == "hosts" and "family" not in item:
                item["family"] = ip_family(item["ip"])
            item.setdefault("id", _id_for(entity, item))
            item.setdefault("source", "fixture")
            item.setdefault("mode", _ENTITY_MODE.get(entity, "active"))
            item.setdefault("confidence", 1.0)
            out.append(item)
        data[entity] = out
    data["warnings"] = partial.pop("warnings", [])
    if partial:
        raise KeyError(f"unbekannte Fixture-Schluessel: {sorted(partial)}")

    # fehlende Hosts, FQDNs, Targets ergaenzen
    host_ips = {h["ip"] for h in data["hosts"]}
    referenced: list[str] = []
    for entity in ("services", "fqdns", "http", "tls", "software", "passive", "threats"):
        for item in data[entity]:
            ip = item.get("host_ip")
            if ip and ip not in host_ips and ip not in referenced:
                referenced.append(ip)
    for ip in referenced:
        data["hosts"].append({"id": f"host:{ip_token(ip)}", "source": "fixture", "mode": "active", "confidence": 1.0,
                             "ip": ip, "family": ip_family(ip), "reachable": True, "nmap_state": "up"})
        host_ips.add(ip)
    fq_keys = {(f["name"], f["host_ip"]) for f in data["fqdns"]}
    for entity in ("http", "tls"):
        for item in data[entity]:
            name, ip = item.get("fqdn"), item.get("host_ip")
            if name and ip and (name, ip) not in fq_keys:
                data["fqdns"].append({"id": f"fqdn:{name}@{ip_token(ip)}", "source": "fixture", "mode": "active",
                                      "confidence": 1.0, "name": name, "host_ip": ip, "http_status": 200})
                fq_keys.add((name, ip))
    for h in data["hosts"]:
        names = sorted({n for (n, ip) in fq_keys if ip == h["ip"]} | set(h.get("fqdns", [])))
        h["fqdns"] = names
    target_domains = {t["domain"] for t in data["targets"]}
    for i, dom in enumerate(scan["domains"]):
        if dom not in target_domains:
            data["targets"].append({"id": f"target:{dom}", "source": "fixture", "mode": "active", "confidence": 1.0,
                                    "domain": dom, "is_primary": i == 0, "targets_source": "fixture"})

    if coverage_default == "ok":
        present = {(c["tool"], c.get("host_ip"), c.get("domain")) for c in data["coverage"]}
        for h in data["hosts"]:
            for tool in T.HOST_TOOLS:
                if (tool, h["ip"], None) not in present:
                    data["coverage"].append({"id": f"cov:-:{tool}:{ip_token(h['ip'])}", "source": "fixture", "mode": "active",
                                             "confidence": 1.0, "scope": "host", "host_ip": h["ip"], "tool": tool,
                                             "status": "ok"})
        for dom in scan["domains"]:
            for tool in T.DOMAIN_TOOLS:
                if (tool, None, dom) not in present:
                    data["coverage"].append({"id": f"cov:-:{tool}:{dom}", "source": "fixture", "mode": "active",
                                             "confidence": 1.0, "scope": "domain", "domain": dom, "tool": tool,
                                             "status": "ok"})
    return FS.Facts.from_dict(data)


def load_fixture(name: str) -> dict[str, Any]:
    path = FIXTURES / (name if name.endswith(".json") else f"{name}.json")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def facts_from_fixture(data: dict[str, Any]) -> FS.Facts:
    return make_facts(data.get("facts", {}), coverage_default=data.get("coverage_default"), domain=data.get("domain"))


_CATALOG: dict[str, Catalog] = {}


def get_catalog() -> Catalog:
    if "default" not in _CATALOG:
        _CATALOG["default"] = load_catalog()
    return _CATALOG["default"]


@pytest.fixture(scope="session")
def catalog() -> Catalog:
    return get_catalog()


def run_check(check_id: str, facts: FS.Facts | dict[str, Any], cat: Catalog | None = None) -> list[CheckResult]:
    """Nur eine Pruefung auswerten (ohne Auffangregeln)."""
    cat = cat or get_catalog()
    if check_id not in cat.by_id:
        raise KeyError(f"Pruefung {check_id!r} nicht im Katalog")
    if isinstance(facts, dict):
        facts = FS.Facts.from_dict(facts)
    from reporter.catalog.scope import FactsIndex
    return evaluate_check(cat.by_id[check_id], FactsIndex(facts), set())


def pick_result(results: list[CheckResult], expect: dict[str, Any]) -> CheckResult:
    key = expect.get("group_key")
    if key is not None:
        hits = [r for r in results if r.group_key == key]
        assert hits, f"kein Ergebnis fuer group_key {key!r}; vorhanden: {[r.group_key for r in results]}"
        return hits[0]
    assert len(results) == 1, f"expect.group_key fehlt und es gibt {len(results)} Ergebnisse: {[r.group_key for r in results]}"
    return results[0]


def assert_expect(result: CheckResult, expect: dict[str, Any], where: str = "") -> None:
    assert result.status == expect["status"], f"{where}: status {result.status} != {expect['status']} ({result.reason_code}; {result.affected})"
    if "affected" in expect:
        assert result.affected == expect["affected"], f"{where}: affected {result.affected} != {expect['affected']}"
    if "affected_contains" in expect:
        for needle in expect["affected_contains"]:
            assert any(needle in a for a in result.affected), f"{where}: {needle!r} nicht in {result.affected}"
    if "positive" in expect:
        assert result.positive is expect["positive"], f"{where}: positive {result.positive} != {expect['positive']}"
    if "reason_code" in expect:
        assert result.reason_code == expect["reason_code"], f"{where}: reason_code {result.reason_code} != {expect['reason_code']}"
    if "notes" in expect:
        assert result.notes == expect["notes"], f"{where}: notes {result.notes} != {expect['notes']}"
    if "verified" in expect:
        assert result.verified is expect["verified"], f"{where}: verified {result.verified} != {expect['verified']}"
    if "source_mode" in expect:
        assert result.source_mode == expect["source_mode"], f"{where}: source_mode {result.source_mode}"
    if "members" in expect:
        got = {m.key: m.status for m in result.members}
        for k, v in expect["members"].items():
            assert got.get(k) == v, f"{where}: member {k} ist {got.get(k)}, erwartet {v}"
    if "evidence_min" in expect:
        assert len(result.evidence) >= expect["evidence_min"], f"{where}: nur {len(result.evidence)} Nachweise"
    if "results_count" in expect:
        pass  # wird von run_fixture geprueft


def run_fixture(check_id: str, kind: str, cat: Catalog | None = None) -> CheckResult:
    """Fixture <check_id>_<kind>.json laden, Pruefung auswerten, Erwartung pruefen, Ergebnis zurueckgeben."""
    data = load_fixture(f"{check_id}_{kind}")
    facts = facts_from_fixture(data)
    results = run_check(check_id, facts, cat)
    expect = data["expect"]
    if "results_count" in expect:
        assert len(results) == expect["results_count"], f"{check_id}_{kind}: {len(results)} Ergebnisse"
    result = pick_result(results, expect)
    assert_expect(result, expect, f"{check_id}_{kind}")
    if kind == "fail" and result.kind == "note":
        # kind note: ein Treffer ist ein Hinweis, nie ein fail
        assert result.status == "pass" and result.notes, f"{check_id}_fail: note ohne Hinweis"
    elif kind == "fail":
        assert result.status == "fail"
        assert result.affected, f"{check_id}_fail: Betroffenenliste leer"
        for label in result.affected:
            assert "{" not in label and "}" not in label and "?" not in label, f"{check_id}_fail: Platzhalter im Label {label!r}"
        assert result.texts.observation and "{" not in result.texts.observation, f"{check_id}_fail: observation nicht gerendert"
    return result


def fixture_kinds(check_id: str) -> list[str]:
    return sorted(p.stem[len(check_id) + 1:] for p in FIXTURES.glob(f"{check_id}_*.json")
                  if p.stem[len(check_id) + 1:] in ("pass", "fail", "nt", "na"))


def evaluate_all(facts: FS.Facts | dict[str, Any], cat: Catalog | None = None):
    return evaluate(facts, cat or get_catalog())
