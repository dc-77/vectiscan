"""Tests for URLhaus passive intelligence client (F-P0A-003)."""

from unittest.mock import patch

import pytest

from scanner.passive.urlhaus_client import URLhausClient


class TestURLhausClient:
    def test_always_available_without_key(self):
        with patch.dict("os.environ", {}, clear=False):
            # Wipe the key explicitly to be safe
            import os
            os.environ.pop("URLHAUS_API_KEY", None)
            client = URLhausClient()
            assert client.available is True

    @patch("scanner.passive.base_client.PassiveClient._post")
    def test_lookup_host_no_results(self, mock_post):
        mock_post.return_value = {"query_status": "no_results"}
        client = URLhausClient()
        result = client.lookup_host("safe.example.com")
        assert result is not None
        assert result["query_status"] == "no_results"
        assert client.is_compromised(result) is False

    @patch("scanner.passive.base_client.PassiveClient._post")
    def test_lookup_host_compromised(self, mock_post):
        mock_post.return_value = {
            "query_status": "ok",
            "urls": [
                {"url": "http://bad.example.com/payload.exe", "url_status": "online"},
                {"url": "http://bad.example.com/c2", "url_status": "online"},
            ],
            "blacklists": {"spamhaus_dbl": "listed"},
        }
        client = URLhausClient()
        result = client.lookup_host("bad.example.com")
        assert result is not None
        assert result["query_status"] == "ok"
        assert len(result["urls"]) == 2
        assert client.is_compromised(result) is True

    @patch("scanner.passive.base_client.PassiveClient._post")
    def test_lookup_empty_host_returns_none(self, mock_post):
        client = URLhausClient()
        assert client.lookup_host("") is None
        assert client.lookup_host("   ") is None
        mock_post.assert_not_called()

    @patch.dict("os.environ", {"URLHAUS_API_KEY": "test-key"})
    @patch("scanner.passive.base_client.PassiveClient._post")
    def test_lookup_sends_auth_header_when_key_set(self, mock_post):
        mock_post.return_value = {"query_status": "no_results"}
        client = URLhausClient()
        client.lookup_host("example.com")
        # Inspect kwargs the client passed in
        _args, kwargs = mock_post.call_args
        headers = kwargs.get("headers") or {}
        assert headers.get("Auth-Key") == "test-key"

    def test_is_compromised_handles_invalid_input(self):
        client = URLhausClient()
        assert client.is_compromised(None) is False
        assert client.is_compromised({}) is False
        assert client.is_compromised({"query_status": "ok", "urls": []}) is False
        assert client.is_compromised({"query_status": "ok"}) is False
        assert client.is_compromised(
            {"query_status": "ok", "urls": [{"url": "x"}]}
        ) is True
