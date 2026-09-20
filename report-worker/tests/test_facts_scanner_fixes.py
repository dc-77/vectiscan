"""Leser fuer die Tar-Ablage nach den Scanner-Fixes S2b (#10 und #12).

Der Scanner legt seit S2b je VHost eine eigene Header-/httpx-Datei ab und je
Domain eigene DNS-Dateien; domainweite scan_results-Zeilen tragen die Domain
als ``_domain``. Diese Tests pruefen beide Richtungen:

- neue Ablage wird vollstaendig gelesen und richtig zugeordnet,
- alte Ablage verhaelt sich unveraendert (der eigentliche Beweis dafuer ist
  tests/test_facts_golden.py, das ohne Neubau gruen bleiben muss).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporter.facts.build import build_facts, build_from_bundle
from reporter.facts.sources import load_from_dir

IP = "1.2.3.4"
PRIMARY = "www.example.de"
SECOND = "mail.example.de"
DOMAIN_A = "example.de"
DOMAIN_B = "example.hu"


def _headers(url: str, hsts: bool = True) -> dict:
    headers = {"server": "nginx/1.24.0", "content-type": "text/html"}
    if hsts:
        headers["strict-transport-security"] = "max-age=63072000"
    return {"url": url, "reachable": True, "score": "3/7", "headers": headers}


def _httpx_line(fqdn: str) -> dict:
    return {"input": fqdn, "host": IP, "status_code": 200, "webserver": "nginx/1.24.0",
            "tech": ["nginx:1.24.0"], "timestamp": "2026-09-19T10:00:00Z"}


def _scan_dir(tmp_path: Path, *, per_vhost: bool, domains: list[str] | None = None,
              extra_dns: bool = False) -> Path:
    """Minimales Scan-Verzeichnis, wahlweise in alter oder neuer Ablage."""
    root = tmp_path / "scan"
    phase0 = root / "phase0"
    phase0a = root / "phase0a"
    p2 = root / "hosts" / IP / "phase2"
    for d in (phase0, phase0a, p2, root / "hosts" / IP / "phase1"):
        d.mkdir(parents=True, exist_ok=True)

    meta = {"orderId": "order-1", "domain": DOMAIN_A, "package": "perimeter",
            "startedAt": "2026-09-19T09:00:00Z", "finishedAt": "2026-09-19T10:00:00Z"}
    if domains:
        meta["domains"] = domains
    (root / "meta.json").write_text(json.dumps(meta), encoding="utf-8")

    (phase0 / "host_inventory.json").write_text(json.dumps({
        "domain": DOMAIN_A,
        "hosts": [{"ip": IP, "fqdns": [PRIMARY, SECOND], "alive": True,
                   "vhosts": [{"fqdn": PRIMARY}, {"fqdn": SECOND}]}],
    }), encoding="utf-8")
    (phase0 / "dns_records.json").write_text(json.dumps({
        "spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject", "dkim": True,
        "dkim_selectors": ["s1"], "mx": ["mx.example.de"], "ns": ["ns1.example.de"],
    }), encoding="utf-8")

    # headers/httpx: alte Ablage (nur der letzte VHost) oder je VHost
    (p2 / "headers.json").write_text(json.dumps(_headers(f"https://{PRIMARY}/")),
                                     encoding="utf-8")
    (p2 / "httpx.json").write_text(json.dumps(_httpx_line(PRIMARY)) + "\n",
                                   encoding="utf-8")
    if per_vhost:
        for vh in (PRIMARY, SECOND):
            (p2 / f"headers_{vh}.json").write_text(
                json.dumps(_headers(f"https://{vh}/", hsts=(vh == PRIMARY))),
                encoding="utf-8")
            (p2 / f"httpx_{vh}.json").write_text(
                json.dumps(_httpx_line(vh)) + "\n", encoding="utf-8")

    if extra_dns:
        (phase0 / f"dns_records_{DOMAIN_B}.json").write_text(json.dumps({
            "_domain": DOMAIN_B, "spf": None, "dmarc": None, "dkim": False,
            "mx": ["mx.example.hu"], "ns": ["ns1.example.hu"],
        }), encoding="utf-8")
        (phase0a / f"dns_security_{DOMAIN_B}.json").write_text(json.dumps({
            "_domain": DOMAIN_B, "dnssec": {"dnssec_signed": False},
            "caa": {"has_caa": False},
        }), encoding="utf-8")
        (phase0a / f"whois_{DOMAIN_B}.json").write_text(json.dumps({
            "_domain": DOMAIN_B,
            "domain": {"registrar": "Beispiel Registrar", "expiration_date": "2027-01-01"},
        }), encoding="utf-8")
    return root


# --------------------------------------------------------- Issue #10 lesen

def test_vhost_dateien_werden_gelesen(tmp_path):
    bundle = load_from_dir(_scan_dir(tmp_path, per_vhost=True))
    host = bundle.hosts[IP]
    assert set(host.headers_by_vhost_tar) == {PRIMARY, SECOND}
    assert set(host.httpx_by_vhost_tar) == {PRIMARY, SECOND}
    assert host.headers_ref_by_vhost[SECOND].endswith(f"headers_{SECOND}.json")


def test_fqdn_kommt_aus_dem_inhalt_nicht_dem_dateinamen(tmp_path):
    """Der Slug kann gekuerzt oder gehasht sein; die url im Inhalt gilt."""
    root = _scan_dir(tmp_path, per_vhost=False)
    p2 = root / "hosts" / IP / "phase2"
    (p2 / "headers_gekuerzt-1a2b3c4d.json").write_text(
        json.dumps(_headers(f"https://{SECOND}/")), encoding="utf-8")

    bundle = load_from_dir(root)
    assert set(bundle.hosts[IP].headers_by_vhost_tar) == {SECOND}


def test_zwei_http_fakten_je_vhost(tmp_path):
    """Der Defekt: ohne die VHost-Dateien kannte facts.json nur einen VHost."""
    facts = build_facts(_scan_dir(tmp_path, per_vhost=True))
    by_fqdn = {f.fqdn: f for f in facts.http}
    assert {PRIMARY, SECOND} <= set(by_fqdn)
    assert by_fqdn[PRIMARY].hsts.present is True
    # Der zweite VHost hat kein HSTS — genau das war vorher unsichtbar.
    assert by_fqdn[SECOND].hsts.present is False
    assert by_fqdn[SECOND].status_code == 200


def test_evidenz_zeigt_auf_die_vhost_datei(tmp_path):
    facts = build_facts(_scan_dir(tmp_path, per_vhost=True))
    second = [f for f in facts.http if f.fqdn == SECOND][0]
    refs = [e.ref for e in second.evidence]
    assert any(r.endswith(f"headers_{SECOND}.json") for r in refs), refs


def test_alte_ablage_bleibt_wie_bisher(tmp_path):
    bundle = load_from_dir(_scan_dir(tmp_path, per_vhost=False))
    host = bundle.hosts[IP]
    assert host.headers_by_vhost_tar == {}
    assert host.httpx_by_vhost_tar == {}
    assert host.headers_json is not None
    facts = build_from_bundle(load_from_dir(_scan_dir(tmp_path, per_vhost=False)))
    # Nur der eine VHost aus headers.json, wie vor S2b.
    assert [f.fqdn for f in facts.http] == [PRIMARY]


# --------------------------------------------------------- Issue #12 lesen

def test_dns_fakt_je_domain(tmp_path):
    """Der Defekt: fuer die zweite Domain gab es weder SPF noch DMARC."""
    root = _scan_dir(tmp_path, per_vhost=False, domains=[DOMAIN_A, DOMAIN_B],
                     extra_dns=True)
    facts = build_facts(root)
    by_domain = {d.domain: d for d in facts.dns}
    assert set(by_domain) == {DOMAIN_A, DOMAIN_B}
    assert by_domain[DOMAIN_A].spf is not None
    assert by_domain[DOMAIN_B].spf is None
    assert by_domain[DOMAIN_B].mx == ["mx.example.hu"]
    assert by_domain[DOMAIN_B].dnssec.signed is False


def test_domain_etikett_ist_kein_fakt(tmp_path):
    """_domain ist Transportmittel und darf nicht in den Fakten auftauchen."""
    root = _scan_dir(tmp_path, per_vhost=False, domains=[DOMAIN_A, DOMAIN_B],
                     extra_dns=True)
    bundle = load_from_dir(root)
    assert "_domain" not in bundle.dns_records_by_domain[DOMAIN_B]
    assert "_domain" not in bundle.dns_security_by_domain[DOMAIN_B]


def test_whois_je_domain(tmp_path):
    root = _scan_dir(tmp_path, per_vhost=False, domains=[DOMAIN_A, DOMAIN_B],
                     extra_dns=True)
    facts = build_facts(root)
    zweite = [t for t in facts.targets if t.domain == DOMAIN_B][0]
    assert zweite.whois is not None
    assert zweite.whois.registrar == "Beispiel Registrar"


def test_meta_domains_macht_den_tar_multidomainfaehig(tmp_path):
    """Ohne orders.json sah ein reiner Tar-Bau nur die erste Domain."""
    ohne = load_from_dir(_scan_dir(tmp_path / "a", per_vhost=False))
    mit = load_from_dir(_scan_dir(tmp_path / "b", per_vhost=False,
                                  domains=[DOMAIN_A, DOMAIN_B]))
    assert ohne.targets == [DOMAIN_A]
    assert mit.targets == [DOMAIN_A, DOMAIN_B]


def test_kein_second_target_unlabeled_mehr_wenn_fakten_da_sind(tmp_path):
    root = _scan_dir(tmp_path, per_vhost=False, domains=[DOMAIN_A, DOMAIN_B],
                     extra_dns=True)
    runs = [
        {"toolName": "dns_records", "hostIp": None, "phase": 0, "status": "ok",
         "rawOutput": json.dumps({"_domain": DOMAIN_B, "spf": None})},
        {"toolName": "dns_records", "hostIp": None, "phase": 0, "status": "ok",
         "rawOutput": json.dumps({"_domain": DOMAIN_A, "spf": "v=spf1 -all"})},
    ]
    facts = build_facts(root, tool_runs=runs)
    gruende = {c.reason for c in facts.coverage}
    assert "second_target_unlabeled" not in gruende
    zweite = [c for c in facts.coverage if c.domain == DOMAIN_B]
    assert zweite and all(c.scope == "domain" for c in zweite)


def test_second_target_unlabeled_bleibt_fuer_altdaten(tmp_path):
    """Historische Tars (Junkerwerk) haben keine Etiketten; der Grund bleibt."""
    root = _scan_dir(tmp_path, per_vhost=False, domains=[DOMAIN_A, DOMAIN_B])
    runs = [{"toolName": "dns_records", "hostIp": None, "phase": 0, "status": "ok",
             "rawOutput": json.dumps({"spf": "v=spf1 -all"})}]
    facts = build_facts(root, tool_runs=runs)
    gruende = {c.reason for c in facts.coverage}
    assert "second_target_unlabeled" in gruende


def test_zeile_ohne_etikett_zaehlt_zum_primaerziel(tmp_path):
    root = _scan_dir(tmp_path, per_vhost=False)
    runs = [{"toolName": "whois", "hostIp": None, "phase": 0, "status": "ok",
             "rawOutput": json.dumps({"domain": {"registrar": "X"}})}]
    facts = build_facts(root, tool_runs=runs)
    whois_rows = [c for c in facts.coverage if c.tool == "whois"]
    assert whois_rows[0].scope == "scan"
    assert whois_rows[0].domain == DOMAIN_A


# ----------------------------------------------------- Issue #13 Abdeckung

def _zap_scan_dir(tmp_path: Path, alerts: list | None, spider_urls: int = 5) -> Path:
    root = _scan_dir(tmp_path, per_vhost=False)
    p2 = root / "hosts" / IP / "phase2"
    if alerts is not None:
        (p2 / "zap_alerts.json").write_text(json.dumps(alerts), encoding="utf-8")
    (p2 / "zap_spider_urls.json").write_text(
        json.dumps([f"https://{PRIMARY}/{i}" for i in range(spider_urls)]),
        encoding="utf-8")
    return root


def _zap_row(status: str = "ok") -> dict:
    return {"toolName": "zap", "hostIp": IP, "phase": 2, "status": status,
            "rawOutput": json.dumps({"active": 0, "passive": 0, "total_alerts": 0})}


def _coverage(facts, tool: str):
    return [c for c in facts.coverage if c.tool == tool]


def test_zap_ok_ohne_alerts_ist_empty(tmp_path):
    """Der Defekt: "ok" ohne Alerts las sich als "keine Befunde"."""
    facts = build_facts(_zap_scan_dir(tmp_path, alerts=[]),
                        tool_runs=[_zap_row()])
    zap = _coverage(facts, "zap")
    assert [c.status for c in zap] == ["empty"]
    assert zap[0].reason == "zap_no_alerts"
    # Der Rohstatus der Zeile bleibt sichtbar.
    assert zap[0].raw_status == "ok"


def test_zap_mit_alerts_bleibt_ok(tmp_path):
    alerts = [{"pluginId": "10038", "name": "CSP Header Not Set", "risk": "Medium",
               "url": f"https://{PRIMARY}/"}]
    facts = build_facts(_zap_scan_dir(tmp_path, alerts=alerts),
                        tool_runs=[_zap_row()])
    zap = _coverage(facts, "zap")
    assert [c.status for c in zap] == ["ok"]


def test_zap_ohne_alertdatei_bleibt_unveraendert(tmp_path):
    """Ohne belastbare Quelle fuer die Alertzahl wird nicht herabgestuft."""
    row = {"toolName": "zap", "hostIp": IP, "phase": 2, "status": "ok",
           "rawOutput": "irgendein Text ohne JSON"}
    facts = build_facts(_zap_scan_dir(tmp_path, alerts=None), tool_runs=[row])
    assert [c.status for c in _coverage(facts, "zap")] == ["ok"]


def test_zap_spider_wird_nicht_herabgestuft(tmp_path):
    """Der Spider zaehlt URLs, nicht Alerts."""
    row = {"toolName": "zap_spider", "hostIp": IP, "phase": 2, "status": "ok",
           "rawOutput": json.dumps({"urls_found": 5})}
    facts = build_facts(_zap_scan_dir(tmp_path, alerts=[]), tool_runs=[row])
    assert [c.status for c in _coverage(facts, "zap_spider")] == ["ok"]


def test_zap_active_wird_nicht_herabgestuft(tmp_path):
    """zap_active hat seine eigene Abdeckung und eigene Pruefungen."""
    row = {"toolName": "zap_active", "hostIp": IP, "phase": 2, "status": "ok",
           "rawOutput": json.dumps({"alerts": 0})}
    facts = build_facts(_zap_scan_dir(tmp_path, alerts=[]), tool_runs=[row])
    assert [c.status for c in _coverage(facts, "zap_active")] == ["ok"]


def test_grund_passt_zur_katalogtabelle():
    """Der Grund traegt genau den Code, den tables.COVERAGE_REASONS kennt."""
    from reporter.catalog.tables import COVERAGE_REASONS
    status, text = COVERAGE_REASONS["zap_no_alerts"]
    assert status == "not_testable"
    assert text


def test_etikett_faellt_auch_beim_primaerziel_weg(tmp_path):
    """Die Datei des Primaerziels traegt seit dem Nachweis-Scan ebenfalls
    `_domain`. Das ist Transportmittel und darf nicht als Fakt auftauchen."""
    root = _scan_dir(tmp_path, per_vhost=False)
    p = root / "phase0" / "dns_records.json"
    daten = json.loads(p.read_text(encoding="utf-8"))
    p.write_text(json.dumps({"_domain": DOMAIN_A, **daten}), encoding="utf-8")

    bundle = load_from_dir(root)
    assert "_domain" not in (bundle.dns_records or {})
    facts = build_facts(root)
    assert [d.domain for d in facts.dns] == [DOMAIN_A]
    assert facts.dns[0].spf is not None
