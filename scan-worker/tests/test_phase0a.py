"""Tests for Phase 0a — Passive Intelligence."""

import json
from unittest.mock import patch, MagicMock

import pytest

from scanner.passive.base_client import PassiveClient
from scanner.passive.shodan_client import ShodanClient
from scanner.passive.abuseipdb_client import AbuseIPDBClient
from scanner.passive.securitytrails_client import SecurityTrailsClient
from scanner.passive.whois_client import WhoisClient
from scanner.phase0a import run_phase0a, build_passive_intel_for_ai


class TestBaseClient:
    def test_available_without_key(self):
        client = PassiveClient(api_key=None)
        assert not client.available

    def test_available_with_key(self):
        client = PassiveClient(api_key="test-key")
        assert client.available


class TestShodanClient:
    @patch.dict("os.environ", {"SHODAN_API_KEY": ""})
    def test_not_available_without_key(self):
        client = ShodanClient()
        assert not client.available
        assert client.lookup_domain("example.com") is None
        assert client.lookup_host("1.2.3.4") is None

    @patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"})
    @patch("scanner.passive.base_client.PassiveClient._get")
    def test_lookup_host(self, mock_get):
        mock_get.return_value = {
            "ports": [80, 443, 22],
            "os": "Linux",
            "tags": [],
            "last_update": "2026-03-10",
            "hostnames": ["example.com"],
            "data": [
                {"port": 443, "product": "nginx", "version": "1.24.0",
                 "data": "HTTP/1.1", "_shodan": {"module": "https"}},
            ],
        }
        client = ShodanClient()
        result = client.lookup_host("1.2.3.4")
        assert result is not None
        assert result["ports"] == [80, 443, 22]
        assert len(result["services"]) == 1
        assert result["services"][0]["product"] == "nginx"


class TestAbuseIPDBClient:
    @patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test-key"})
    @patch("scanner.passive.base_client.PassiveClient._get")
    def test_check_ip(self, mock_get):
        mock_get.return_value = {
            "data": {
                "abuseConfidenceScore": 15,
                "totalReports": 3,
                "numDistinctUsers": 2,
                "lastReportedAt": "2026-02-28",
                "isWhitelisted": False,
                "countryCode": "DE",
                "usageType": "Data Center",
                "isp": "Hetzner",
                "domain": "hetzner.com",
                "isTor": False,
            }
        }
        client = AbuseIPDBClient()
        result = client.check_ip("88.99.35.112")
        assert result is not None
        assert result["abuseConfidenceScore"] == 15
        assert result["isp"] == "Hetzner"


class TestSecurityTrailsClient:
    @patch.dict("os.environ", {"SECURITYTRAILS_API_KEY": ""})
    def test_not_available_without_key(self):
        client = SecurityTrailsClient()
        assert not client.available
        assert client.lookup_domain("example.com") is None
        assert client.get_subdomains("example.com") == []


class TestWhoisClient:
    def test_always_available(self):
        client = WhoisClient()
        assert client.available

    @patch("subprocess.run")
    def test_lookup_parses_fields(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "Domain Name: EXAMPLE.COM\n"
                "Registrar: United Domains AG\n"
                "Creation Date: 2010-05-15\n"
                "Registry Expiry Date: 2027-05-15\n"
                "Name Server: ns1.example.com\n"
                "Name Server: ns2.example.com\n"
                "DNSSEC: signedDelegation\n"
            ),
        )
        client = WhoisClient()
        result = client.lookup("example.com")
        assert result is not None
        assert result["registrar"] == "United Domains AG"
        assert result["dnssec"] == "signedDelegation"
        assert len(result["name_servers"]) == 2


class TestBuildPassiveIntelForAI:
    def test_extracts_shodan_data(self):
        phase0a = {
            "shodan_hosts": {
                "1.2.3.4": {
                    "ports": [80, 443, 22],
                    "services": [
                        {"port": 443, "product": "nginx", "version": "1.24.0"},
                        {"port": 22, "product": "OpenSSH", "version": "7.9"},
                    ],
                }
            },
            "abuseipdb": {
                "1.2.3.4": {"abuseConfidenceScore": 15, "isTor": False}
            },
            "whois": {"dnssec": "signedDelegation", "expiration_date": "2027-05-15"},
            "dns_security": {"dnssec": {"dnssec_signed": True}},
        }
        intel = build_passive_intel_for_ai(phase0a, "1.2.3.4")
        assert intel["shodan_ports"] == [80, 443, 22]
        assert "443" in intel["shodan_services"]
        assert intel["abuseipdb_score"] == 15
        assert intel["dnssec_signed"] is True

    def test_empty_for_unknown_ip(self):
        intel = build_passive_intel_for_ai({}, "9.9.9.9")
        assert intel == {}


class TestRunPhase0a:
    @patch("scanner.phase0a.run_all_dns_security")
    @patch("scanner.phase0a.WhoisClient")
    def test_webcheck_only_whois_and_dns(self, mock_whois_cls, mock_dns, tmp_path):
        mock_whois = MagicMock()
        mock_whois.lookup.return_value = {"domain": "example.com", "registrar": "Test"}
        mock_whois_cls.return_value = mock_whois
        mock_dns.return_value = {"dnssec": {"dnssec_signed": False}}

        config = {
            "phase0a_tools": ["whois"],
            "package": "webcheck",
        }
        result = run_phase0a("example.com", [], str(tmp_path), "test-id", config)

        assert "whois" in result
        assert "dns_security" in result
        mock_whois.lookup.assert_called_once_with("example.com")
