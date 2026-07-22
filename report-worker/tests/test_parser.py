"""Unit tests for reporter.parser module."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from reporter.parser import (
    parse_nmap_xml,
    parse_nuclei_json,
    parse_testssl_json,
    parse_nikto_json,
    parse_headers_json,
    parse_gobuster_dir,
    compute_testssl_status,
    consolidate_findings,
    parse_scan_data,
    parse_wpscan,
    _project_host_tool_data,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# parse_nmap_xml
# ---------------------------------------------------------------------------


class TestParseNmapXml:
    def test_parses_open_ports(self) -> None:
        result = parse_nmap_xml(str(FIXTURES / "nmap_example.xml"))
        ports = result["open_ports"]
        assert len(ports) == 4  # 22, 80, 443, 3306 (8080 is closed)

    def test_port_details(self) -> None:
        result = parse_nmap_xml(str(FIXTURES / "nmap_example.xml"))
        ports = {p["port"]: p for p in result["open_ports"]}
        assert ports[80]["service"] == "http"
        assert ports[80]["product"] == "nginx"
        assert ports[3306]["service"] == "mysql"
        assert ports[3306]["product"] == "MariaDB"

    def test_summary_generated(self) -> None:
        result = parse_nmap_xml(str(FIXTURES / "nmap_example.xml"))
        assert "4 open ports" in result["summary"]

    def test_missing_file_returns_empty(self) -> None:
        result = parse_nmap_xml("/nonexistent/nmap.xml")
        assert result["open_ports"] == []

    def test_invalid_xml_returns_empty(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write("not valid xml <<<")
            f.flush()
            result = parse_nmap_xml(f.name)
        os.unlink(f.name)
        assert result["open_ports"] == []


# ---------------------------------------------------------------------------
# parse_nuclei_json
# ---------------------------------------------------------------------------


class TestParseNucleiJson:
    def test_parses_findings(self) -> None:
        findings = parse_nuclei_json(str(FIXTURES / "nuclei_example.json"))
        assert len(findings) == 3

    def test_sorted_by_severity(self) -> None:
        findings = parse_nuclei_json(str(FIXTURES / "nuclei_example.json"))
        severities = [f["severity"] for f in findings]
        assert severities[0] == "critical"
        assert severities[1] == "medium"
        assert severities[2] == "low"

    def test_fields_populated(self) -> None:
        findings = parse_nuclei_json(str(FIXTURES / "nuclei_example.json"))
        critical = findings[0]
        assert critical["template_id"] == "cve-2024-12345"
        assert critical["name"] == "Critical RCE in Example Service"

    def test_missing_file_returns_empty(self) -> None:
        assert parse_nuclei_json("/nonexistent/nuclei.json") == []


# ---------------------------------------------------------------------------
# parse_testssl_json
# ---------------------------------------------------------------------------


class TestParseTestsslJson:
    def test_filters_ok_and_info(self) -> None:
        data = [
            {"id": "tls1_2", "severity": "OK", "finding": "TLS 1.2 offered"},
            {"id": "tls1_0", "severity": "HIGH", "finding": "TLS 1.0 offered"},
            {"id": "cert_chain", "severity": "INFO", "finding": "Certificate chain"},
            {"id": "weak_cipher", "severity": "MEDIUM", "finding": "Weak cipher"},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            findings = parse_testssl_json(f.name)
        os.unlink(f.name)
        assert len(findings) == 2
        # Sorted by severity: HIGH before MEDIUM
        severities = [f["severity"] for f in findings]
        assert "HIGH" in severities
        assert "MEDIUM" in severities

    def test_missing_file_returns_empty(self) -> None:
        assert parse_testssl_json("/nonexistent/testssl.json") == []


# ---------------------------------------------------------------------------
# parse_nikto_json
# ---------------------------------------------------------------------------


class TestParseNiktoJson:
    def test_parses_vulnerabilities(self) -> None:
        data = {
            "vulnerabilities": [
                {"id": "000001", "msg": "Server leaks version info", "method": "GET", "url": "/"},
                {"id": "000002", "msg": "X-Frame-Options not set", "method": "GET", "url": "/"},
            ]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            result = parse_nikto_json(f.name)
        os.unlink(f.name)
        assert len(result) == 2
        assert result[0]["msg"] == "Server leaks version info"

    def test_missing_file_returns_empty(self) -> None:
        result = parse_nikto_json("/nonexistent/nikto.json")
        assert result == []


# ---------------------------------------------------------------------------
# parse_headers_json
# ---------------------------------------------------------------------------


class TestParseHeadersJson:
    def test_loads_headers(self) -> None:
        result = parse_headers_json(str(FIXTURES / "headers_example.json"))
        assert "score" in result
        assert "missing" in result
        assert "present" in result
        # Parser uses lowercase matching against security_headers keys
        # Present headers are detected, some may be missing
        assert isinstance(result["present"], list)
        assert isinstance(result["missing"], list)

    def test_missing_file_returns_defaults(self) -> None:
        result = parse_headers_json("/nonexistent/headers.json")
        assert result["score"] == "0/0"
        assert result["missing"] == []

    # -- A5 (Strang A): reachable:false / score:null --------------------------

    def test_reachable_false_yields_no_missing(self, tmp_path: Path) -> None:
        """Nicht-Antwort (reachable:false) darf NICHT als '0/7 fehlen' erscheinen."""
        p = tmp_path / "headers.json"
        p.write_text(json.dumps({
            "url": "https://vpn.example.com",
            "reachable": False,
            "score": None,
            "headers": {},
            "security_headers": {},
        }))
        result = parse_headers_json(str(p))
        assert result["reachable"] is False
        assert result["score"] is None
        # Kein Header darf als "fehlend" markiert werden -> kein Falsch-Finding.
        assert result["missing"] == []
        assert result["present"] == []

    def test_reachable_true_keeps_numeric_score(self, tmp_path: Path) -> None:
        """Echte Antwort: reachable:true + numerischer Score bleibt belastbar."""
        p = tmp_path / "headers.json"
        p.write_text(json.dumps({
            "url": "https://www.example.com",
            "reachable": True,
            "score": "3/7",
            "security_headers": {
                "x-frame-options": {"present": True, "value": "DENY"},
                "content-security-policy": {"present": True, "value": "default-src"},
                "x-content-type-options": {"present": True, "value": "nosniff"},
            },
        }))
        result = parse_headers_json(str(p))
        assert result["reachable"] is True
        assert result["score"] == "3/7"
        assert "x-frame-options" in result["present"]
        assert "strict-transport-security" in result["missing"]

    def test_missing_reachable_flag_is_legacy(self, tmp_path: Path) -> None:
        """Alt-Datensatz ohne reachable-Flag: numerischer Score wie bisher."""
        p = tmp_path / "headers.json"
        p.write_text(json.dumps({
            "url": "https://legacy.example.com",
            "security_headers": {
                "x-frame-options": {"present": True, "value": "DENY"},
            },
        }))
        result = parse_headers_json(str(p))
        # reachable ist None (Alt-Datensatz) -> Score wird normal berechnet.
        assert result["reachable"] is None
        assert result["score"] == "1/7"


class TestConsolidateHeadersReachable:
    """A5: consolidate_findings darf fuer reachable:false keine '0/7'-Zeile schreiben."""

    def test_no_score_line_for_unreachable_host(self) -> None:
        host_results = {
            "10.0.0.1": {
                "fqdns": ["vpn.example.com"],
                "headers": {
                    "url": "https://vpn.example.com",
                    "reachable": False,
                    "score": None,
                    "missing": [],
                    "present": [],
                },
            }
        }
        text = consolidate_findings(host_results, {})
        # Keine numerische Score-Zeile, kein "Missing:"-Block -> kein Falsch-Finding.
        assert "Score:" not in text
        assert "Missing:" not in text
        assert "0/7" not in text
        # Stattdessen expliziter Nicht-pruefbar-Hinweis.
        assert "keine HTTP-Antwort" in text

    def test_reachable_host_keeps_score_line(self) -> None:
        host_results = {
            "10.0.0.2": {
                "fqdns": ["www.example.com"],
                "headers": {
                    "url": "https://www.example.com",
                    "reachable": True,
                    "score": "2/7",
                    "present": ["x-frame-options", "x-content-type-options"],
                    "missing": ["content-security-policy"],
                },
            }
        }
        text = consolidate_findings(host_results, {})
        assert "Score: 2/7" in text
        assert "Missing:" in text


# ---------------------------------------------------------------------------
# parse_gobuster_dir
# ---------------------------------------------------------------------------


class TestParseGobusterDir:
    def test_parses_paths(self) -> None:
        content = "/admin                (Status: 200) [Size: 1234]\n/login                (Status: 200) [Size: 567]\n# comment line\n\n/api                  (Status: 301) [Size: 89]\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            paths = parse_gobuster_dir(f.name)
        os.unlink(f.name)
        assert paths == ["/admin", "/login", "/api"]

    def test_missing_file_returns_empty(self) -> None:
        assert parse_gobuster_dir("/nonexistent/gobuster.txt") == []


# ---------------------------------------------------------------------------
# compute_testssl_status (VEC-373 D4b: fail-loud)
# ---------------------------------------------------------------------------


class TestComputeTestsslStatus:
    _SSL_HOST = {"nmap": {"open_ports": [{"port": 443, "protocol": "tcp",
                                          "service": "https"}]}}
    _NO_SSL_HOST = {"nmap": {"open_ports": [{"port": 80, "protocol": "tcp",
                                             "service": "http"}]}}

    def test_valid_empty_json_is_ok(self, tmp_path: Path) -> None:
        # Sauberer Lauf ohne MEDIUM+ Findings → [] → "ok" (kein False-Positive).
        p = tmp_path / "testssl.json"
        p.write_text("[]")
        assert compute_testssl_status(str(p), self._SSL_HOST) == "ok"

    def test_valid_findings_json_is_ok(self, tmp_path: Path) -> None:
        p = tmp_path / "testssl.json"
        p.write_text(json.dumps([{"id": "x", "severity": "HIGH", "finding": "y"}]))
        assert compute_testssl_status(str(p), self._SSL_HOST) == "ok"

    def test_missing_file_with_ssl_is_failed(self, tmp_path: Path) -> None:
        assert compute_testssl_status(
            str(tmp_path / "nope.json"), self._SSL_HOST
        ) == "failed"

    def test_usage_banner_file_with_ssl_is_failed(self, tmp_path: Path) -> None:
        # testssl-Usage-Banner statt JSON (3.3dev-Bug) → kein gueltiges JSON.
        p = tmp_path / "testssl.json"
        p.write_text('"testssl.sh [options] <URI>"    or    "testssl.sh <options>"')
        assert compute_testssl_status(str(p), self._SSL_HOST) == "failed"

    def test_missing_file_without_ssl_is_skipped(self, tmp_path: Path) -> None:
        assert compute_testssl_status(
            str(tmp_path / "nope.json"), self._NO_SSL_HOST
        ) == "skipped"

    def test_https_headers_url_implies_ssl_expected(self, tmp_path: Path) -> None:
        host = {"nmap": {"open_ports": []},
                "headers": {"url": "https://example.com"}}
        assert compute_testssl_status(str(tmp_path / "nope.json"), host) == "failed"


class TestTestsslFailLoudPrompt:
    """VEC-373 D4b: bei testssl-Failure muss der Claude-Prompt explizit
    sagen, dass TLS/HSTS NICHT geprueft wurde (statt den Block still
    wegzulassen) — sonst halluziniert die KI 'HSTS max-age=0'."""

    def test_failed_status_emits_loud_warning(self) -> None:
        host_results = {
            "1.2.3.4": {
                "fqdns": ["example.com"],
                "nmap": {"open_ports": [{"port": 443, "protocol": "tcp",
                                         "service": "https"}], "summary": "1 open"},
                "testssl": [],
                "testssl_status": "failed",
                "headers": {"missing": [], "present": [], "score": "0/0"},
            }
        }
        out = consolidate_findings(host_results, {})
        assert "TOOL-FEHLER" in out
        assert "NICHT geprueft" in out
        assert "HSTS" in out

    def test_skipped_status_stays_silent(self) -> None:
        host_results = {
            "1.2.3.4": {
                "fqdns": ["example.com"],
                "nmap": {"open_ports": [], "summary": "no ports"},
                "testssl": [],
                "testssl_status": "skipped",
                "headers": {"missing": [], "present": [], "score": "0/0"},
            }
        }
        out = consolidate_findings(host_results, {})
        assert "TOOL-FEHLER" not in out


# ---------------------------------------------------------------------------
# consolidate_findings
# ---------------------------------------------------------------------------


class TestConsolidateFindings:
    def test_includes_host_label(self) -> None:
        host_results = {
            "1.2.3.4": {
                "fqdns": ["example.com"],
                "nmap": {"open_ports": [], "summary": "No open ports", "os_detection": ""},
                "nuclei": [],
                "testssl": [],
                "nikto": [],
                "headers": {"missing": [], "present": [], "score": "0/0"},
                "gobuster_dir": [],
            }
        }
        result = consolidate_findings(host_results, {})
        assert "1.2.3.4" in result
        assert "example.com" in result

    def test_includes_dns_records(self) -> None:
        dns = {"spf": "v=spf1 include:example.com -all", "zone_transfer": False}
        result = consolidate_findings({}, dns)
        assert "SPF" in result
        assert "Zone Transfer" in result


# ---------------------------------------------------------------------------
# parse_scan_data (integration)
# ---------------------------------------------------------------------------


class TestParseScanData:
    def test_returns_dict_with_expected_keys(self, tmp_path: Path) -> None:
        # Build minimal scan directory structure
        phase0 = tmp_path / "phase0"
        phase0.mkdir()
        inventory = {
            "domain": "beispiel.de",
            "hosts": [{"ip": "1.2.3.4", "fqdns": ["beispiel.de"]}],
        }
        (phase0 / "host_inventory.json").write_text(json.dumps(inventory))

        hosts_dir = tmp_path / "hosts" / "1.2.3.4"
        (hosts_dir / "phase1").mkdir(parents=True)
        (hosts_dir / "phase2").mkdir(parents=True)

        # Write minimal nmap XML
        (hosts_dir / "phase1" / "nmap.xml").write_text(
            '<?xml version="1.0"?><nmaprun></nmaprun>'
        )

        result = parse_scan_data(str(tmp_path))
        assert "host_inventory" in result
        assert "tech_profiles" in result
        assert "consolidated_findings" in result
        assert result["host_inventory"]["domain"] == "beispiel.de"

    def test_missing_inventory_returns_default(self, tmp_path: Path) -> None:
        result = parse_scan_data(str(tmp_path))
        assert result["host_inventory"]["domain"] == "unknown"


# ---------------------------------------------------------------------------
# ADDITIVE Exportfelder (Phase 1 / Fundament):
# wp_version_status, host_strategy, host_tool_data
# ---------------------------------------------------------------------------


def _nmap_xml_with_ports() -> str:
    """Minimales nmap-XML mit einem offenen Port inkl. Produkt und Version."""
    return (
        '<?xml version="1.0"?><nmaprun><host><ports>'
        '<port protocol="tcp" portid="443"><state state="open"/>'
        '<service name="https" product="nginx" version="1.24.0"/>'
        "</port></ports></host></nmaprun>"
    )


def _build_scan_dir(tmp_path: Path, *, with_strategy: bool = False) -> Path:
    """Baut ein minimales Scan-Verzeichnis mit genau einem Host auf."""
    phase0 = tmp_path / "phase0"
    phase0.mkdir()
    inventory = {
        "domain": "beispiel.de",
        "hosts": [{"ip": "1.2.3.4", "fqdns": ["beispiel.de"]}],
    }
    (phase0 / "host_inventory.json").write_text(json.dumps(inventory))

    if with_strategy:
        strategy = {
            "hosts": [
                {
                    "ip": "1.2.3.4",
                    "action": "skip",
                    "reasoning": "Reiner Redirect-Host ohne eigenen Inhalt",
                    "priority": 3,
                }
            ],
            "strategy_notes": "Nur ein Host relevant",
        }
        (phase0 / "host_strategy.json").write_text(
            json.dumps(strategy, ensure_ascii=False), encoding="utf-8"
        )

    host_dir = tmp_path / "hosts" / "1.2.3.4"
    (host_dir / "phase1").mkdir(parents=True)
    (host_dir / "phase2").mkdir(parents=True)
    (host_dir / "phase1" / "nmap.xml").write_text(_nmap_xml_with_ports())
    (host_dir / "phase2" / "wpscan.json").write_text(
        json.dumps(
            {
                "version": {"number": "6.7.1", "status": "latest"},
                "plugins": {},
                "themes": {},
            }
        )
    )
    # Rohtext-Tool, das NICHT in host_tool_data auftauchen darf
    (host_dir / "phase2" / "nuclei.json").write_text(
        json.dumps({"info": {"name": "x", "severity": "low"}}) + "\n"
    )
    return tmp_path


class TestParseWpscanVersionStatus:
    def test_status_latest_is_exported(self) -> None:
        result = parse_wpscan({"version": {"number": "6.7.1", "status": "latest"}})
        assert result["wp_version_status"] == "latest"
        # Bestehender Consumer-Vertrag bleibt unveraendert
        assert result["wp_version_vulnerable"] is False

    def test_status_insecure_keeps_boolean(self) -> None:
        result = parse_wpscan({"version": {"number": "5.0.0", "status": "insecure"}})
        assert result["wp_version_status"] == "insecure"
        assert result["wp_version_vulnerable"] is True

    def test_missing_status_is_empty_string(self) -> None:
        result = parse_wpscan({"version": {"number": "6.7.1"}})
        assert result["wp_version_status"] == ""
        assert result["wp_version_vulnerable"] is False

    def test_non_dict_version_does_not_crash(self) -> None:
        result = parse_wpscan({"version": "6.7.1"})
        assert result["wp_version_status"] == ""
        assert result["wp_version_vulnerable"] is False

    def test_consolidate_findings_shows_status(self) -> None:
        text = consolidate_findings(
            {
                "1.2.3.4": {
                    "fqdns": ["beispiel.de"],
                    "wpscan": {
                        "wordpress_version": "6.7.1",
                        "wp_version_status": "latest",
                        "plugins_found": 0,
                    },
                }
            },
            {},
        )
        assert "WordPress Version: 6.7.1 (Status laut wpscan: latest)" in text

    def test_consolidate_findings_without_status_unchanged(self) -> None:
        text = consolidate_findings(
            {
                "1.2.3.4": {
                    "fqdns": ["beispiel.de"],
                    "wpscan": {"wordpress_version": "6.7.1", "plugins_found": 0},
                }
            },
            {},
        )
        assert "WordPress Version: 6.7.1" in text
        assert "Status laut wpscan" not in text


class TestParseScanDataHostStrategy:
    def test_host_strategy_is_returned(self, tmp_path: Path) -> None:
        _build_scan_dir(tmp_path, with_strategy=True)
        result = parse_scan_data(str(tmp_path))
        assert result["host_strategy"]["hosts"][0]["action"] == "skip"
        assert "Redirect-Host" in result["host_strategy"]["hosts"][0]["reasoning"]

    def test_missing_host_strategy_defaults_to_empty_dict(self, tmp_path: Path) -> None:
        _build_scan_dir(tmp_path, with_strategy=False)
        result = parse_scan_data(str(tmp_path))
        assert result["host_strategy"] == {}

    def test_broken_host_strategy_defaults_to_empty_dict(self, tmp_path: Path) -> None:
        _build_scan_dir(tmp_path, with_strategy=False)
        (tmp_path / "phase0" / "host_strategy.json").write_text("{ kaputt")
        result = parse_scan_data(str(tmp_path))
        assert result["host_strategy"] == {}

    def test_non_dict_host_strategy_defaults_to_empty_dict(self, tmp_path: Path) -> None:
        _build_scan_dir(tmp_path, with_strategy=False)
        (tmp_path / "phase0" / "host_strategy.json").write_text('["a"]')
        result = parse_scan_data(str(tmp_path))
        assert result["host_strategy"] == {}


class TestParseScanDataHostToolData:
    def test_contains_nmap_ports_with_product_and_version(self, tmp_path: Path) -> None:
        _build_scan_dir(tmp_path)
        result = parse_scan_data(str(tmp_path))
        entry = result["host_tool_data"]["1.2.3.4"]
        port = entry["nmap"]["open_ports"][0]
        assert port["port"] == 443
        assert port["product"] == "nginx"
        assert port["version"] == "1.24.0"
        assert "os_detection" in entry["nmap"]

    def test_contains_wpscan_version_status(self, tmp_path: Path) -> None:
        _build_scan_dir(tmp_path)
        result = parse_scan_data(str(tmp_path))
        wpscan = result["host_tool_data"]["1.2.3.4"]["wpscan"]
        assert wpscan["wp_version"] == "6.7.1"
        assert wpscan["wp_version_status"] == "latest"

    def test_no_raw_text_fields_are_exported(self, tmp_path: Path) -> None:
        _build_scan_dir(tmp_path)
        result = parse_scan_data(str(tmp_path))
        entry = result["host_tool_data"]["1.2.3.4"]
        assert set(entry.keys()) <= {"nmap", "wpscan"}
        for verboten in (
            "nuclei",
            "nikto",
            "testssl",
            "testssl_raw",
            "headers",
            "gobuster_dir",
            "katana",
            "zap",
            "screenshots",
        ):
            assert verboten not in entry
        assert set(entry["nmap"].keys()) == {"open_ports", "os_detection"}

    def test_projection_survives_garbage(self) -> None:
        projected = _project_host_tool_data(
            {"1.2.3.4": None, "5.6.7.8": {"nmap": "kaputt"}, "9.9.9.9": {}}
        )
        assert projected == {}


class TestParseScanDataContract:
    """Vertragstest: alle bisherigen Return-Keys bleiben erhalten."""

    def test_all_expected_keys_present(self, tmp_path: Path) -> None:
        _build_scan_dir(tmp_path, with_strategy=True)
        result = parse_scan_data(str(tmp_path))
        for key in (
            "host_inventory",
            "tech_profiles",
            "consolidated_findings",
            "host_screenshots",
            "host_screenshots_per_vhost",
            "testssl_raw_by_host",
            "headers_by_host",
            "meta",
            "host_strategy",
            "host_tool_data",
        ):
            assert key in result, f"Return-Key {key} fehlt"
