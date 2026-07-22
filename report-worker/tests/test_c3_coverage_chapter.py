"""C3 — Tests fuer das Abdeckungskapitel "Was wurde geprueft — und was nicht".

Deckt ab:
  - build_scan_coverage: 3-Zustands-Klassifikation, Grund-Prioritaet,
    Tool-Name-Filter/Normalisierung, host_ip IS NULL -> "scanweit",
    dreistufige Status-Lesung (status > exit_code > Strategie), Determinismus.
  - chunked_matrix_tables: Breiten-Garantie (<=170mm) und Chunk-Zerlegung.
  - Render-Smoke: generate_report_v2 mit und ohne scan_coverage (Degradation).
  - _augment_for_v2: verdrahtet scan_coverage + _host_inventory.
"""
from __future__ import annotations

import json
import os
import pathlib

import pytest
from reportlab.lib.units import mm

from reporter.coverage import (
    build_scan_coverage,
    STATE_BEFUND,
    STATE_CLEAN,
    STATE_NOT_TESTABLE,
    SCANWIDE_KEY,
)
from reporter.pdf.v2.flowables import chunked_matrix_tables
from reporter.pdf.v2 import generate_report_v2


# ====================================================================
# Test-Fixtures / Helper
# ====================================================================
def _base_inventory() -> dict:
    return {
        "domain": "example.com",
        "hosts": [
            {"ip": "10.0.0.1", "fqdns": ["example.com", "www.example.com"]},
            {"ip": "10.0.0.2", "fqdns": ["mail.example.com"]},
            {"ip": "10.0.0.3", "fqdns": ["skip.example.com"], "status": "skipped"},
        ],
        "skipped_hosts": [
            {"ip": "10.0.0.9", "fqdns": ["overflow.example.com"]},
        ],
    }


def _base_tool_runs() -> list[dict]:
    return [
        # .1 -> Befund (Finding) + erfolgreicher nmap-Lauf
        {"host_ip": "10.0.0.1", "phase": 1, "tool_name": "nmap",
         "exit_code": 0, "duration_ms": 100, "status": "ok", "skip_reason": None},
        # .2 -> unauffaellig: nmap ok, ffuf (Variante) ok, testssl (echter
        # Schwachstellenscan) ok, kein Finding. Ohne den testssl-Lauf waere der
        # Host nach BEFUND 5 "nicht_pruefbar" (nur Detektion/Discovery).
        {"host_ip": "10.0.0.2", "phase": 1, "tool_name": "nmap",
         "exit_code": 0, "duration_ms": 90, "status": "ok", "skip_reason": None},
        {"host_ip": "10.0.0.2", "phase": 2, "tool_name": "ffuf_sensitive",
         "exit_code": 0, "duration_ms": 90, "status": "ok", "skip_reason": None},
        {"host_ip": "10.0.0.2", "phase": 2, "tool_name": "testssl",
         "exit_code": 0, "duration_ms": 90, "status": "ok", "skip_reason": None},
        # .3 -> nicht_pruefbar: A7 ai_host_skip mit Grund + Strategie-Grund
        {"host_ip": "10.0.0.3", "phase": 0, "tool_name": "ai_host_skip",
         "exit_code": 0, "duration_ms": 0, "status": "skipped",
         "skip_reason": "A7-Grund: kein Web-Content"},
        # scanweite Discovery-Laeufe (host_ip = None)
        {"host_ip": None, "phase": 0, "tool_name": "subfinder",
         "exit_code": 0, "duration_ms": 500, "status": "ok", "skip_reason": None},
        {"host_ip": None, "phase": 0, "tool_name": "crtsh_retry2",
         "exit_code": 0, "duration_ms": 500, "status": "ok", "skip_reason": None},
        # Nicht-Tool-Zeilen, die herausgefiltert werden muessen
        {"host_ip": None, "phase": 4, "tool_name": "report_cost",
         "exit_code": 0, "duration_ms": 0, "status": "ok", "skip_reason": None},
        {"host_ip": None, "phase": 0, "tool_name": "ai_host_strategy",
         "exit_code": 0, "duration_ms": 0, "status": "ok", "skip_reason": None},
        {"host_ip": "10.0.0.1", "phase": 1, "tool_name": "webtech_debug",
         "exit_code": 0, "duration_ms": 0, "status": "ok", "skip_reason": None},
    ]


def _base_strategy() -> dict:
    return {
        "hosts": [
            {"ip": "10.0.0.1", "action": "scan", "reasoning": ""},
            {"ip": "10.0.0.2", "action": "scan", "reasoning": ""},
            {"ip": "10.0.0.3", "action": "skip",
             "reasoning": "Strategie-Grund (soll von A7 uebertrumpft werden)"},
        ],
        "strategy_notes": "Test",
    }


def _base_findings() -> list[dict]:
    return [{"id": "F1", "affected": "10.0.0.1:443", "title": "Test-Befund"}]


def _cov() -> dict:
    return build_scan_coverage(
        _base_inventory(), _base_tool_runs(), _base_strategy(),
        _base_findings(), [], "perimeter",
    )


def _host(cov: dict, ip: str) -> dict:
    for h in cov["hosts"]:
        if h["ip"] == ip:
            return h
    raise AssertionError(f"Host {ip} fehlt im coverage-Output")


# ====================================================================
# 1. Drei-Zustands-Klassifikation
# ====================================================================
class TestThreeStates:
    def test_host_with_finding_is_befund(self):
        cov = _cov()
        assert _host(cov, "10.0.0.1")["state"] == STATE_BEFUND
        assert _host(cov, "10.0.0.1")["finding_ids"] == ["F1"]
        assert _host(cov, "10.0.0.1")["finding_count"] == 1

    def test_host_with_successful_run_no_finding_is_clean(self):
        cov = _cov()
        assert _host(cov, "10.0.0.2")["state"] == STATE_CLEAN

    def test_skipped_host_is_not_testable(self):
        cov = _cov()
        assert _host(cov, "10.0.0.3")["state"] == STATE_NOT_TESTABLE

    def test_limit_skipped_host_is_not_testable(self):
        cov = _cov()
        assert _host(cov, "10.0.0.9")["state"] == STATE_NOT_TESTABLE

    def test_host_without_any_p12_run_is_not_testable(self):
        # Host, fuer den nur ein Phase-0-Lauf existiert -> kein erfolgreicher
        # Phase-1/2-Lauf -> nicht_pruefbar.
        inv = {"domain": "x.de", "hosts": [{"ip": "1.1.1.1", "fqdns": ["x.de"]}]}
        runs = [{"host_ip": "1.1.1.1", "phase": 0, "tool_name": "httpx",
                 "exit_code": 0, "duration_ms": 1, "status": "ok",
                 "skip_reason": None}]
        cov = build_scan_coverage(inv, runs, {}, [], [], "webcheck")
        assert cov["hosts"][0]["state"] == STATE_NOT_TESTABLE

    def test_detection_only_host_is_not_testable(self):
        # BEFUND 5: nur wafw00f (Detektion) erfolgreich, alle echten
        # Schwachstellen-Scans (testssl/nikto/zap) fehlgeschlagen -> der Host
        # darf NICHT als unauffaellig gelten, sondern nicht_pruefbar mit
        # klarer Begruendung.
        inv = {"domain": "x.de", "hosts": [{"ip": "3.3.3.3", "fqdns": ["x.de"]}]}
        runs = [
            {"host_ip": "3.3.3.3", "phase": 1, "tool_name": "wafw00f",
             "exit_code": 0, "duration_ms": 5, "status": "ok",
             "skip_reason": None},
            {"host_ip": "3.3.3.3", "phase": 2, "tool_name": "testssl",
             "exit_code": -2, "duration_ms": 5, "status": "failed",
             "skip_reason": None},
            {"host_ip": "3.3.3.3", "phase": 2, "tool_name": "nikto",
             "exit_code": -2, "duration_ms": 5, "status": "failed",
             "skip_reason": None},
            {"host_ip": "3.3.3.3", "phase": 2, "tool_name": "zap_active",
             "exit_code": -2, "duration_ms": 5, "status": "failed",
             "skip_reason": None},
        ]
        cov = build_scan_coverage(inv, runs, {}, [], [], "perimeter")
        h = cov["hosts"][0]
        assert h["state"] == STATE_NOT_TESTABLE
        assert h["reason"] == "Schwachstellenprüfung nicht abgeschlossen"

    def test_successful_vuln_scan_makes_host_clean(self):
        # Gegenprobe zu BEFUND 5: derselbe Host, aber testssl erfolgreich ->
        # unauffaellig.
        inv = {"domain": "x.de", "hosts": [{"ip": "3.3.3.4", "fqdns": ["x.de"]}]}
        runs = [
            {"host_ip": "3.3.3.4", "phase": 1, "tool_name": "wafw00f",
             "exit_code": 0, "duration_ms": 5, "status": "ok",
             "skip_reason": None},
            {"host_ip": "3.3.3.4", "phase": 2, "tool_name": "testssl",
             "exit_code": 0, "duration_ms": 5, "status": "ok",
             "skip_reason": None},
        ]
        cov = build_scan_coverage(inv, runs, {}, [], [], "perimeter")
        assert cov["hosts"][0]["state"] == STATE_CLEAN

    def test_failed_only_host_is_not_testable_with_reason(self):
        inv = {"domain": "x.de", "hosts": [{"ip": "2.2.2.2", "fqdns": ["x.de"]}]}
        runs = [{"host_ip": "2.2.2.2", "phase": 1, "tool_name": "nmap",
                 "exit_code": -2, "duration_ms": 1, "status": "failed",
                 "skip_reason": None}]
        cov = build_scan_coverage(inv, runs, {}, [], [], "webcheck")
        h = cov["hosts"][0]
        assert h["state"] == STATE_NOT_TESTABLE
        assert h["reason"] == "alle Tool-Läufe fehlgeschlagen"


# ====================================================================
# 2. Grund-Prioritaet
# ====================================================================
class TestReasonPriority:
    def test_a7_skip_reason_wins_over_strategy(self):
        cov = _cov()
        assert _host(cov, "10.0.0.3")["reason"] == "A7-Grund: kein Web-Content"

    def test_strategy_reason_when_no_a7(self):
        inv = {"domain": "x.de",
               "hosts": [{"ip": "3.3.3.3", "fqdns": ["x.de"], "status": "skipped"}]}
        strat = {"hosts": [{"ip": "3.3.3.3", "action": "skip",
                            "reasoning": "Nur Strategie"}]}
        cov = build_scan_coverage(inv, [], strat, [], [], "webcheck")
        assert cov["hosts"][0]["reason"] == "Nur Strategie"

    def test_redirect_dedup_reasoning_when_no_strategy(self):
        inv = {"domain": "x.de",
               "hosts": [{"ip": "4.4.4.4", "fqdns": ["x.de"],
                          "status": "skipped",
                          "_reasoning": "Redirects to y.de"}]}
        cov = build_scan_coverage(inv, [], {}, [], [], "webcheck")
        assert cov["hosts"][0]["reason"] == "Redirects to y.de"

    def test_limit_reason(self):
        cov = _cov()
        assert _host(cov, "10.0.0.9")["reason"] == "Host-Limit des Pakets erreicht"

    def test_alt_order_reason_when_nothing_logged(self):
        inv = {"domain": "x.de", "hosts": [{"ip": "5.5.5.5", "fqdns": ["x.de"]}]}
        cov = build_scan_coverage(inv, [], {}, [], [], "webcheck")
        assert cov["hosts"][0]["reason"] == "Grund nicht protokolliert"


# ====================================================================
# 3. Tool-Name-Filter + Normalisierung
# ====================================================================
class TestToolFilter:
    def test_non_tools_are_filtered_from_matrix(self):
        cov = _cov()
        tools = cov["matrix"]["tools"]
        for junk in ("report_cost", "ai_host_strategy", "ai_host_skip",
                     "webtech_debug"):
            assert junk not in tools

    def test_retry_suffix_normalized(self):
        cov = _cov()
        assert "crtsh" in cov["matrix"]["tools"]
        assert "crtsh_retry2" not in cov["matrix"]["tools"]

    def test_ffuf_variant_normalized(self):
        cov = _cov()
        assert "ffuf" in cov["matrix"]["tools"]
        assert "ffuf_sensitive" not in cov["matrix"]["tools"]

    def test_real_tools_present(self):
        cov = _cov()
        assert "nmap" in cov["matrix"]["tools"]
        assert "subfinder" in cov["matrix"]["tools"]


# ====================================================================
# 4. scanweit-Spalte (host_ip IS NULL)
# ====================================================================
class TestScanwideColumn:
    def test_scanwide_column_present(self):
        cov = _cov()
        assert SCANWIDE_KEY in cov["matrix"]["hosts"]
        assert cov["matrix"]["host_labels"][SCANWIDE_KEY] == "scanweit"

    def test_scanwide_cell_is_ok(self):
        cov = _cov()
        assert cov["matrix"]["cells"]["subfinder"][SCANWIDE_KEY] == "ok"

    def test_no_scanwide_when_all_host_bound(self):
        inv = {"domain": "x.de", "hosts": [{"ip": "6.6.6.6", "fqdns": ["x.de"]}]}
        runs = [{"host_ip": "6.6.6.6", "phase": 1, "tool_name": "nmap",
                 "exit_code": 0, "duration_ms": 1, "status": "ok",
                 "skip_reason": None}]
        cov = build_scan_coverage(inv, runs, {}, [], [], "webcheck")
        assert SCANWIDE_KEY not in cov["matrix"]["hosts"]


# ====================================================================
# 5. Dreistufige Status-Lesung (status > exit_code > Strategie)
# ====================================================================
class TestThreeStageStatus:
    def test_status_ok_wins_over_negative_exit_code(self):
        inv = {"domain": "x.de", "hosts": [{"ip": "7.7.7.7", "fqdns": ["x.de"]}]}
        # widerspruechlich: exit_code negativ, status aber "ok" -> ok gewinnt.
        # nuclei = echter Schwachstellenscan, damit der Host nach BEFUND 5
        # als unauffaellig gilt (nicht nur Detektion).
        runs = [{"host_ip": "7.7.7.7", "phase": 1, "tool_name": "nuclei",
                 "exit_code": -2, "duration_ms": 1, "status": "ok",
                 "skip_reason": None}]
        cov = build_scan_coverage(inv, runs, {}, [], [], "webcheck")
        assert cov["matrix"]["cells"]["nuclei"]["7.7.7.7"] == "ok"
        assert cov["hosts"][0]["state"] == STATE_CLEAN

    def test_exit_code_minus3_is_skip_when_status_null(self):
        inv = {"domain": "x.de", "hosts": [{"ip": "8.8.8.8", "fqdns": ["x.de"]}]}
        runs = [{"host_ip": "8.8.8.8", "phase": 2, "tool_name": "nuclei",
                 "exit_code": -3, "duration_ms": 0, "status": None,
                 "skip_reason": None}]
        cov = build_scan_coverage(inv, runs, {}, [], [], "webcheck")
        assert cov["matrix"]["cells"]["nuclei"]["8.8.8.8"] == "skip"

    def test_legacy_exit_code_zero_is_ok(self):
        inv = {"domain": "x.de", "hosts": [{"ip": "9.9.9.9", "fqdns": ["x.de"]}]}
        # nuclei = echter Schwachstellenscan -> Host darf unauffaellig sein.
        runs = [{"host_ip": "9.9.9.9", "phase": 1, "tool_name": "nuclei",
                 "exit_code": 0, "duration_ms": 1, "status": None,
                 "skip_reason": None}]
        cov = build_scan_coverage(inv, runs, {}, [], [], "webcheck")
        assert cov["matrix"]["cells"]["nuclei"]["9.9.9.9"] == "ok"
        assert cov["hosts"][0]["state"] == STATE_CLEAN

    def test_cell_merge_ok_wins_over_fail_and_skip(self):
        # derselbe Tool-Name mehrfach auf demselben Host (z.B. pro VHost):
        # ok > fail > skip.
        inv = {"domain": "x.de", "hosts": [{"ip": "1.2.3.4", "fqdns": ["x.de"]}]}
        runs = [
            {"host_ip": "1.2.3.4", "phase": 2, "tool_name": "zap",
             "exit_code": -2, "duration_ms": 0, "status": "failed",
             "skip_reason": None},
            {"host_ip": "1.2.3.4", "phase": 2, "tool_name": "zap",
             "exit_code": 0, "duration_ms": 0, "status": "ok",
             "skip_reason": None},
        ]
        cov = build_scan_coverage(inv, runs, {}, [], [], "perimeter")
        assert cov["matrix"]["cells"]["zap"]["1.2.3.4"] == "ok"


# ====================================================================
# 6. Totals
# ====================================================================
class TestTotals:
    def test_totals_counts(self):
        cov = _cov()
        t = cov["totals"]
        assert t["hosts_total"] == 4
        assert t["hosts_with_findings"] == 1
        assert t["hosts_clean"] == 1
        assert t["hosts_not_testable"] == 2
        # gefilterte echte Tool-Laeufe: nmap x2, ffuf, testssl, subfinder,
        # crtsh = 6
        assert t["tool_runs_total"] == 6
        assert t["tool_runs_failed"] == 0


# ====================================================================
# 7. Determinismus
# ====================================================================
class TestDeterminism:
    def test_two_runs_identical(self):
        a = build_scan_coverage(
            _base_inventory(), _base_tool_runs(), _base_strategy(),
            _base_findings(), [], "perimeter")
        b = build_scan_coverage(
            _base_inventory(), _base_tool_runs(), _base_strategy(),
            _base_findings(), [], "perimeter")
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)

    def test_host_order_is_by_ip(self):
        cov = _cov()
        ips = [h["ip"] for h in cov["hosts"]]
        assert ips == sorted(ips)


# ====================================================================
# 8. Degradation
# ====================================================================
class TestDegradation:
    def test_empty_inventory_returns_none(self):
        assert build_scan_coverage({}, [], {}, [], [], "webcheck") is None

    def test_garbage_input_never_raises(self):
        # bewusst kaputte Typen -> None statt Exception (Fail-open).
        assert build_scan_coverage(
            {"hosts": [123, None, "x"]}, ["junk"], {"hosts": [1]},
            ["nope"], None, None,
        ) is None


# ====================================================================
# 9. chunked_matrix_tables — Breiten-Garantie
# ====================================================================
class TestChunking:
    def test_15_hosts_split_into_chunks_within_width(self):
        cols = [f"10.0.0.{i}" for i in range(1, 16)]  # 15 Hosts
        labels = {c: c for c in cols}
        rows = ["nmap", "nuclei"]
        chunks = chunked_matrix_tables(
            "Tool", rows, {r: r for r in rows}, cols, labels,
            lambda r, c: "x", max_cols=6,
        )
        assert len(chunks) == 3  # 6 + 6 + 3
        for ch in chunks:
            assert sum(ch["col_widths"]) <= 170 * mm + 0.01
            # jede Datenzeile hat genau so viele Zellen wie Header-Spalten
            for row in ch["rows"]:
                assert len(row) == len(ch["header"])

    def test_empty_matrix_returns_no_chunks(self):
        assert chunked_matrix_tables("Tool", [], {}, [], {},
                                     lambda r, c: "x") == []


# ====================================================================
# 10. _augment_for_v2 — Verdrahtung
# ====================================================================
class TestAugmentWiring:
    def test_scan_coverage_and_host_inventory_set(self):
        from reporter.report_mapper import _augment_for_v2
        report_data: dict = {}
        claude_output = {"findings": _base_findings()}
        scan_meta = {
            "domain": "example.com",
            "startedAt": "2026-07-21T08:00:00",
            "completedAt": "2026-07-21T09:00:00",
            "package": "perimeter",
            "techProfiles": [],
            "toolRuns": _base_tool_runs(),
            "hostStrategy": _base_strategy(),
        }
        _augment_for_v2(report_data, claude_output, _base_inventory(),
                        "perimeter", scan_meta)
        assert report_data["scan_coverage"] is not None
        assert report_data["scan_coverage"]["totals"]["hosts_total"] == 4
        assert report_data["_host_inventory"]["domain"] == "example.com"


# ====================================================================
# 11. Render-Smoke (generate_report_v2)
# ====================================================================
FIXTURE_DIR = (
    pathlib.Path(__file__).parent.parent
    / "reporter" / "validation" / "tests" / "fixtures"
)
TRUNK_FX = FIXTURE_DIR / "replay_trunk_heuel_like.json"


def _build_report_data(with_coverage: bool) -> dict:
    """Volle v2-augmentierte report_data analog test_m5, plus toolRuns."""
    from reporter.report_mapper import _augment_for_v2

    co = json.loads(TRUNK_FX.read_text(encoding="utf-8"))
    domain = "trunk-immobilien.de"
    host_inventory = {
        "domain": domain,
        "hosts": [
            {"ip": "5.199.141.24", "fqdns": [domain, f"www.{domain}"]},
            {"ip": "45.157.234.103", "fqdns": [f"mail.{domain}"]},
        ],
    }
    scan_meta = {
        "domain": domain,
        "orderId": "test-c3",
        "startedAt": "2026-07-21T08:00:00",
        "completedAt": "2026-07-21T09:30:00",
        "package": "perimeter",
        "techProfiles": [],
        "toolRuns": [
            {"host_ip": "5.199.141.24", "phase": 1, "tool_name": "nmap",
             "exit_code": 0, "duration_ms": 100, "status": "ok",
             "skip_reason": None},
            {"host_ip": "45.157.234.103", "phase": 2, "tool_name": "testssl",
             "exit_code": -3, "duration_ms": 0, "status": "skipped",
             "skip_reason": "not_in_package"},
            {"host_ip": None, "phase": 0, "tool_name": "subfinder",
             "exit_code": 0, "duration_ms": 500, "status": "ok",
             "skip_reason": None},
        ] if with_coverage else [],
        "hostStrategy": {},
    }
    base = {
        "meta": {"title": f"C3 {domain}", "author": "VectiScan",
                 "classification_label": "VERTRAULICH"},
        "cover": {"cover_subtitle": "VECTISCAN",
                  "cover_title": f"Sicherheitsbewertung {domain}",
                  "package": "perimeter",
                  "cover_meta": [["Ziel:", domain], ["Paket:", "Perimeter"]]},
        "domain": domain,
        "toc": [("1", "Befunde", False)],
        "executive_summary": {"section_label": "1 ES", "subsections": [
            {"title": "Zusammenfassung", "paragraphs": ["Test."]}]},
        "scope": {"section_label": "2 Scope", "subsections": [
            {"title": "Pruefungsumfang", "paragraphs": [domain]}]},
        "findings": [
            {"id": f.get("id"), "external_id": f.get("id"),
             "policy_id": f.get("policy_id", ""),
             "title": f.get("title", ""), "severity": f.get("severity"),
             "cvss_score": f.get("cvss_score"),
             "affected": f.get("affected", ""),
             "description": f.get("description", ""),
             "evidence": str(f.get("evidence", "—")),
             "impact": f.get("impact", ""),
             "recommendation": f.get("recommendation", ""),
             "scale": f.get("scale", "cvss")}
            for f in co.get("findings", [])
        ],
        "recommendations": {"intro_paragraph": "x", "roadmap_table": None},
        "screenshots": [],
        "disclaimer": "Disclaimer",
    }
    _augment_for_v2(base, co, host_inventory, "perimeter", scan_meta)
    if not with_coverage:
        base["scan_coverage"] = None
    return base


class TestRenderSmoke:
    def test_render_with_coverage_builds(self, tmp_path):
        data = _build_report_data(with_coverage=True)
        assert data["scan_coverage"] is not None
        out = tmp_path / "c3_with.pdf"
        generate_report_v2(data, str(out))
        assert out.exists()
        assert out.stat().st_size > 9000

    def test_render_without_coverage_still_builds(self, tmp_path):
        # Degradation: scan_coverage None -> Kapitel wird uebersprungen, das
        # PDF baut trotzdem.
        data = _build_report_data(with_coverage=False)
        data["scan_coverage"] = None
        out = tmp_path / "c3_without.pdf"
        generate_report_v2(data, str(out))
        assert out.exists()
        assert out.stat().st_size > 9000
