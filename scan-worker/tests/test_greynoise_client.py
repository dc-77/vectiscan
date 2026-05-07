"""Tests for GreyNoise Community passive intelligence client (F-P0A-003)."""

from unittest.mock import patch

import pytest

from scanner.passive.greynoise_client import GreyNoiseClient


class TestGreyNoiseClient:
    def test_available_without_key(self):
        # GreyNoise Community endpoint works key-less.
        client = GreyNoiseClient()
        assert client.available is True

    @patch("scanner.passive.base_client.PassiveClient._get")
    def test_lookup_ip_classification_malicious(self, mock_get):
        mock_get.return_value = {
            "ip": "1.2.3.4",
            "noise": True,
            "riot": False,
            "classification": "malicious",
            "name": "Mirai",
            "link": "https://viz.greynoise.io/ip/1.2.3.4",
            "last_seen": "2026-04-01",
            "message": "Success",
        }
        client = GreyNoiseClient()
        result = client.lookup_ip("1.2.3.4")
        assert result is not None
        assert result["classification"] == "malicious"
        assert result["noise"] is True
        assert result["name"] == "Mirai"

    @patch("scanner.passive.base_client.PassiveClient._get")
    def test_lookup_ip_benign_riot(self, mock_get):
        mock_get.return_value = {
            "ip": "8.8.8.8",
            "noise": False,
            "riot": True,
            "classification": "benign",
            "name": "Google Public DNS",
        }
        client = GreyNoiseClient()
        result = client.lookup_ip("8.8.8.8")
        assert result is not None
        assert result["riot"] is True
        assert result["classification"] == "benign"

    @patch("scanner.passive.base_client.PassiveClient._get")
    def test_lookup_ip_returns_none_on_404(self, mock_get):
        # _get returns None for any HTTP 4xx — we propagate.
        mock_get.return_value = None
        client = GreyNoiseClient()
        assert client.lookup_ip("192.0.2.1") is None

    def test_lookup_empty_ip_returns_none(self):
        client = GreyNoiseClient()
        assert client.lookup_ip("") is None
        assert client.lookup_ip("   ") is None

    @patch.dict("os.environ", {"GREYNOISE_API_KEY": "premium-key"})
    @patch("scanner.passive.base_client.PassiveClient._get")
    def test_premium_key_passed_in_header(self, mock_get):
        mock_get.return_value = {
            "ip": "1.2.3.4", "noise": False, "riot": False,
            "classification": "unknown",
        }
        client = GreyNoiseClient()
        client.lookup_ip("1.2.3.4")
        _args, kwargs = mock_get.call_args
        headers = kwargs.get("headers") or {}
        assert headers.get("key") == "premium-key"
