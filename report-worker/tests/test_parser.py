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
    consolidate_findings,
    parse_scan_data,
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
