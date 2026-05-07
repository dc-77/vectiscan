"""Tests for VirusTotal v3 passive intelligence client (F-P0A-003)."""

import os
from unittest.mock import patch

import pytest

from scanner.passive.virustotal_client import VirusTotalClient


class TestVirusTotalClient:
    def test_unavailable_without_key(self):
        # Wipe inherited key to be deterministic
        with patch.dict("os.environ", {}, clear=False):
            os.environ.pop("VIRUSTOTAL_API_KEY", None)
            client = VirusTotalClient()
            assert client.available is False
            assert client.lookup_domain("example.com") is None

    @patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"})
    @patch("scanner.passive.base_client.PassiveClient._get")
    def test_lookup_domain_clean(self, mock_get):
        mock_get.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 80, "malicious": 0, "suspicious": 0,
                        "undetected": 5, "timeout": 0,
                    },
                    "categories": {"engine_a": "search engines"},
                    "reputation": 100,
                    "last_analysis_date": 1700000000,
                }
            }
        }
        client = VirusTotalClient()
        result = client.lookup_domain("google.com")
        assert result is not None
        assert result["malicious"] == 0
        assert result["harmless"] == 80
        assert result["total_engines"] == 85
        assert result["reputation"] == 100
        assert result["categories"]["engine_a"] == "search engines"

    @patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"})
    @patch("scanner.passive.base_client.PassiveClient._get")
    def test_lookup_domain_malicious(self, mock_get):
        mock_get.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 50, "malicious": 12,
                        "suspicious": 3, "undetected": 20, "timeout": 0,
                    },
                    "categories": {"engine_x": "malware"},
                    "reputation": -45,
                }
            }
        }
        client = VirusTotalClient()
        result = client.lookup_domain("evil.example.com")
        assert result is not None
        assert result["malicious"] == 12
        assert result["suspicious"] == 3
        assert result["reputation"] == -45

    @patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"})
    @patch("scanner.passive.base_client.PassiveClient._get")
    def test_lookup_domain_handles_empty_attributes(self, mock_get):
        mock_get.return_value = {"data": {"attributes": {}}}
        client = VirusTotalClient()
        result = client.lookup_domain("unknown.example.com")
        assert result is not None
        assert result["malicious"] == 0
        assert result["total_engines"] == 0

    @patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"})
    def test_empty_domain_returns_none(self):
        client = VirusTotalClient()
        assert client.lookup_domain("") is None
        assert client.lookup_domain("   ") is None

    @patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"})
    @patch("scanner.passive.base_client.PassiveClient._get")
    def test_api_key_in_header(self, mock_get):
        mock_get.return_value = {"data": {"attributes": {}}}
        client = VirusTotalClient()
        client.lookup_domain("example.com")
        _args, kwargs = mock_get.call_args
        headers = kwargs.get("headers") or {}
        assert headers.get("x-apikey") == "test-key"
