"""A7-Vollstaendigkeitstest — jeder Tool-Lauf hinterlaesst genau eine Zeile.

Exit-Kriterium von Phase 1: ein Scan mit abgeschaltetem ZAP macht sichtbar,
dass ZAP nicht lief. Dieser Test ist der maschinelle Nachweis dafuer — und
zusaetzlich dafuer, dass Paket-Gating, KI-Skip und Host-Ausfall jeweils eine
begruendete `skipped`-Zeile erzeugen statt spurlos zu verschwinden.
"""

from unittest.mock import MagicMock, patch

import pytest


def _collect(calls: list[tuple]) -> object:
    """Sammel-Fake fuer record_tool_run(order_id, host, phase, tool, status, ...)."""
    def _fake(order_id, host_ip, phase, tool_name, status, **kw):
        calls.append({
            "order_id": order_id,
            "host_ip": host_ip,
            "phase": phase,
            "tool": tool_name,
            "status": status,
            "reason": kw.get("reason"),
        })
    return _fake


def _rows_for(calls: list[dict], tool: str) -> list[dict]:
    return [c for c in calls if c["tool"] == tool]


def _make_zap(health: bool = True) -> MagicMock:
    zap = MagicMock()
    zap.health_check.return_value = health
    zap.create_context.return_value = 1
    zap.start_spider.return_value = 1
    zap.spider_status.return_value = 100
    zap.spider_results.return_value = []
    zap.ajax_spider_status.return_value = "stopped"
    zap.start_active_scan.return_value = 1
    zap.active_scan_status.return_value = 100
    zap.get_alerts.return_value = []
    return zap


def _tech_profile(has_ssl: bool = False, has_web: bool = True) -> dict:
    return {
        "ip": "1.2.3.4",
        "fqdns": ["example.com"],
        "has_ssl": has_ssl,
        "has_web": has_web,
        "open_ports": [80],
    }


# ---------------------------------------------------------------------------
# Phase 2
# ---------------------------------------------------------------------------

class TestPhase2Coverage:

    def _run(self, tmp_path, config: dict, zap_health: bool = True,
             tech_profile: dict | None = None) -> list[dict]:
        from scanner.phase2 import run_phase2
        calls: list[dict] = []
        with patch("scanner.phase2.record_tool_run", side_effect=_collect(calls)), \
             patch("scanner.phase2._save_result"), \
             patch("scanner.phase2.publish_event"), \
             patch("scanner.phase2.publish_tool_output"), \
             patch("scanner.phase2.run_header_check", return_value={"score": "3/7"}), \
             patch("scanner.phase2.run_httpx", return_value={"status_code": 200}), \
             patch("scanner.phase2.run_testssl", return_value=[]), \
             patch("scanner.tools.zap_client.ZapClient",
                   return_value=_make_zap(zap_health)):
            run_phase2(
                "1.2.3.4", ["example.com"],
                tech_profile if tech_profile is not None else _tech_profile(),
                str(tmp_path / "scan"), "order-a7", MagicMock(), config,
            )
        return calls

    def test_gated_tools_each_get_one_skipped_row(self, tmp_path):
        """phase2_tools=['headers'] → jedes andere Tool meldet sich als skipped."""
        calls = self._run(tmp_path, {"phase2_tools": ["headers"]})

        expected_skips = {
            "testssl": "no_ssl",
            "httpx": "not_in_package",
            "zap_spider": "not_in_package",
            "zap_active": "not_in_package",
            "ffuf_param": "not_in_package",
            "ffuf_sensitive": "not_in_package",
            "feroxbuster": "not_in_package",
            "wpscan": "not_in_package",
            "zap": "no_zap_context",
        }
        for tool, reason in expected_skips.items():
            rows = _rows_for(calls, tool)
            assert len(rows) == 1, f"{tool}: erwartet genau 1 Zeile, bekam {rows}"
            assert rows[0]["status"] == "skipped", f"{tool}: {rows[0]}"
            assert rows[0]["reason"] == reason, f"{tool}: {rows[0]}"
            assert rows[0]["phase"] == 2

    def test_zap_daemon_unavailable_is_recorded(self, tmp_path):
        """Der wichtigste Einzelfall: ZAP-Daemon nicht erreichbar."""
        calls = self._run(
            tmp_path,
            {"phase2_tools": ["zap_spider", "zap_active", "headers"]},
            zap_health=False,
        )
        rows = _rows_for(calls, "zap_spider")
        assert len(rows) == 1
        assert rows[0]["status"] == "skipped"
        assert rows[0]["reason"] == "zap_daemon_unavailable"

    def test_no_web_host_skips_zap_with_reason_no_web(self, tmp_path):
        calls = self._run(
            tmp_path,
            {"phase2_tools": ["zap_spider", "headers"]},
            tech_profile=_tech_profile(has_web=False),
        )
        rows = _rows_for(calls, "zap_spider")
        assert len(rows) == 1
        assert rows[0]["reason"] == "no_web"

    def test_ai_skip_is_visible_as_reason(self, tmp_path):
        """KI-Skip war bisher nur im Log — jetzt steht er in scan_results."""
        from scanner.phase2 import run_phase2
        calls: list[dict] = []
        with patch("scanner.phase2.record_tool_run", side_effect=_collect(calls)), \
             patch("scanner.phase2._save_result"), \
             patch("scanner.phase2.publish_event"), \
             patch("scanner.phase2.publish_tool_output"), \
             patch("scanner.phase2.run_header_check", return_value={"score": "3/7"}), \
             patch("scanner.phase2.run_httpx", return_value={"status_code": 200}), \
             patch("scanner.tools.zap_client.ZapClient", return_value=_make_zap(True)):
            run_phase2(
                "1.2.3.4", ["example.com"], _tech_profile(),
                str(tmp_path / "scan"), "order-a7", MagicMock(),
                {"phase2_tools": ["ffuf", "feroxbuster", "headers"]},
                adaptive_config={"skip_tools": ["ffuf", "feroxbuster"]},
            )
        for tool in ("ffuf_param", "ffuf_sensitive", "feroxbuster"):
            rows = _rows_for(calls, tool)
            assert len(rows) == 1, f"{tool}: {rows}"
            assert rows[0]["reason"] == "ai_skip", f"{tool}: {rows[0]}"

    def test_no_duplicate_rows_per_tool(self, tmp_path):
        """Kein Tool darf im Gating-Pfad zwei Zeilen bekommen."""
        calls = self._run(tmp_path, {"phase2_tools": ["headers"]})
        seen: dict[str, int] = {}
        for c in calls:
            seen[c["tool"]] = seen.get(c["tool"], 0) + 1
        doppelte = {k: v for k, v in seen.items() if v > 1}
        assert not doppelte, f"Doppelte Zeilen: {doppelte}"


# ---------------------------------------------------------------------------
# Phase 1
# ---------------------------------------------------------------------------

class TestPhase1Coverage:

    def _run(self, tmp_path, config: dict) -> list[dict]:
        from scanner.phase1 import run_phase1
        calls: list[dict] = []
        with patch("scanner.phase1.record_tool_run", side_effect=_collect(calls)), \
             patch("scanner.phase1.publish_event"), \
             patch("scanner.phase1.run_nmap", return_value={"open_ports": [], "services": []}), \
             patch("scanner.phase1.build_tech_profile", return_value={"ip": "1.2.3.4"}):
            run_phase1("1.2.3.4", ["example.com"], str(tmp_path / "scan"),
                       "order-a7", MagicMock(), config)
        return calls

    def test_tlscompliance_reports_webtech_and_wafw00f_as_skipped(self, tmp_path):
        calls = self._run(tmp_path, {"phase1_tools": ["nmap"],
                                     "nmap_ports": "--top-ports 100"})
        for tool in ("webtech", "wafw00f"):
            rows = _rows_for(calls, tool)
            assert len(rows) == 1, f"{tool}: {rows}"
            assert rows[0]["status"] == "skipped"
            assert rows[0]["reason"] == "not_in_package"
            assert rows[0]["phase"] == 1

    def test_nmap_gated_writes_skipped_row(self, tmp_path):
        calls = self._run(tmp_path, {"phase1_tools": ["webtech"],
                                     "nmap_ports": "--top-ports 100"})
        rows = _rows_for(calls, "nmap")
        assert len(rows) == 1
        assert rows[0]["status"] == "skipped"
        assert rows[0]["reason"] == "not_in_package"


# ---------------------------------------------------------------------------
# Phase 0a — bis A7 komplett unsichtbar in scan_results
# ---------------------------------------------------------------------------

class TestPhase0aCoverage:

    def test_passive_tools_not_in_package_are_recorded(self, tmp_path):
        from scanner.phase0a import run_phase0a
        calls: list[dict] = []
        whois_client = MagicMock()
        whois_client.lookup.return_value = {"registrar": "Test"}
        with patch("scanner.phase0a.record_tool_run", side_effect=_collect(calls)), \
             patch("scanner.phase0a.publish_event"), \
             patch("scanner.phase0a.run_all_dns_security", return_value={}), \
             patch("scanner.phase0a.WhoisClient", return_value=whois_client):
            run_phase0a("example.com", [], str(tmp_path / "scan"), "order-a7",
                        {"phase0a_tools": ["whois"]})

        for tool in ("shodan", "abuseipdb", "securitytrails", "urlhaus",
                     "greynoise", "otx", "virustotal"):
            rows = _rows_for(calls, tool)
            assert len(rows) == 1, f"{tool}: {rows}"
            assert rows[0]["status"] == "skipped"
            assert rows[0]["reason"] == "not_in_package"

        whois_rows = _rows_for(calls, "whois")
        assert len(whois_rows) == 1
        assert whois_rows[0]["status"] == "ok"


# ---------------------------------------------------------------------------
# Soll-Tool-Ableitung fuer Host-Ausfaelle (worker.py)
# ---------------------------------------------------------------------------

class TestExpectedToolsForPhase:

    def test_phase1_uses_config_list_without_cms_fingerprint(self):
        from scanner.worker import expected_tools_for_phase
        tools = expected_tools_for_phase(
            {"phase1_tools": ["nmap", "webtech", "wafw00f", "cms_fingerprint"]}, 1)
        assert tools == ["nmap", "webtech", "wafw00f"]

    def test_phase2_config_names_are_translated(self):
        from scanner.worker import expected_tools_for_phase
        tools = expected_tools_for_phase(
            {"phase2_tools": ["headers", "ffuf", "testssl"]}, 2)
        assert tools == ["header_check", "ffuf_param", "ffuf_sensitive", "testssl"]

    def test_missing_config_falls_back(self):
        from scanner.worker import expected_tools_for_phase, PHASE2_FALLBACK_TOOLS
        assert expected_tools_for_phase({}, 2) == list(PHASE2_FALLBACK_TOOLS)
        assert expected_tools_for_phase(None, 2) == list(PHASE2_FALLBACK_TOOLS)

    def test_unknown_phase_is_empty(self):
        from scanner.worker import expected_tools_for_phase
        assert expected_tools_for_phase({"phase1_tools": ["nmap"]}, 3) == []


# ---------------------------------------------------------------------------
# AI-Meta-Zeilen: raw_output muss JSON-parsebar bleiben (Frontend-Vertrag)
# ---------------------------------------------------------------------------

class TestAiMetaRowsStayParseable:

    @pytest.mark.parametrize("tool_name", [
        "ai_host_strategy", "ai_phase2_config", "ai_host_skip",
        "phase3_correlation",
    ])
    def test_record_tool_run_does_not_invent_raw_output(self, tool_name):
        """Wird raw_output explizit gesetzt, darf record_tool_run es nicht
        durch 'SKIPPED: <grund>' ersetzen — orders.ts parst diese Zeilen."""
        from scanner.tools import record_tool_run
        seen: dict = {}
        with patch("scanner.tools._save_result",
                   side_effect=lambda **kw: seen.update(kw)):
            record_tool_run("order-a7", None, 0, tool_name, "skipped",
                            reason="skip_ai_decisions", raw_output="{}")
        assert seen["raw_output"] == "{}"
        assert seen["tool_name"] == tool_name
        assert seen["skip_reason"] == "skip_ai_decisions"
