"""Tests for AlienVault OTX passive intelligence client (F-P0A-003)."""

from unittest.mock import patch

import pytest

from scanner.passive.otx_client import OTXClient


class TestOTXClient:
    def test_available_without_key(self):
        client = OTXClient()
        assert client.available is True

    @patch("scanner.passive.base_client.PassiveClient._get")
    def test_lookup_domain_with_pulses(self, mock_get):
        mock_get.return_value = {
            "pulse_info": {
                "count": 3,
                "pulses": [
                    {"name": "Phishing Campaign A", "id": "p1",
                     "tags": ["phishing", "malware"], "modified": "2026-04-01"},
                    {"name": "Botnet B", "id": "p2", "tags": ["botnet"]},
                ],
            },
            "validation": [{"name": "alexa"}],
            "type": "domain",
            "alexa": "5000",
            "whois": "https://whois.example",
        }
        client = OTXClient()
        result = client.lookup_domain("evil.example.com")
        assert result is not None
        assert result["pulse_count"] == 3
        assert len(result["pulses"]) == 2
        assert result["pulses"][0]["name"] == "Phishing Campaign A"
        assert "phishing" in result["pulses"][0]["tags"]

    @patch("scanner.passive.base_client.PassiveClient._get")
    def test_lookup_domain_no_pulses(self, mock_get):
        mock_get.return_value = {"pulse_info": {"count": 0, "pulses": []}}
        client = OTXClient()
        result = client.lookup_domain("clean.example.com")
        assert result is not None
        assert result["pulse_count"] == 0
        assert result["pulses"] == []

    @patch("scanner.passive.base_client.PassiveClient._get")
    def test_lookup_ip(self, mock_get):
        mock_get.return_value = {
            "pulse_info": {"count": 1},
            "asn": "AS13335",
            "country_name": "United States",
            "reputation": 0,
        }
        client = OTXClient()
        result = client.lookup_ip("1.1.1.1")
        assert result is not None
        assert result["pulse_count"] == 1
        assert result["asn"] == "AS13335"

    def test_empty_inputs(self):
        client = OTXClient()
        assert client.lookup_domain("") is None
        assert client.lookup_ip("   ") is None

    @patch.dict("os.environ", {"OTX_API_KEY": "secret"})
    @patch("scanner.passive.base_client.PassiveClient._get")
    def test_api_key_passed_when_set(self, mock_get):
        mock_get.return_value = {"pulse_info": {"count": 0, "pulses": []}}
        client = OTXClient()
        client.lookup_domain("example.com")
        _args, kwargs = mock_get.call_args
        headers = kwargs.get("headers") or {}
        assert headers.get("X-OTX-API-KEY") == "secret"
