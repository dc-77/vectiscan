"""Tests fuer CT-Robustheit (PR-CT-Robustheit, 2026-05-02).

- crt.sh 3-Stufen-Self-Retry
- certspotter-Fallback
"""

from __future__ import annotations

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from scanner import phase0
from scanner.passive.certspotter_client import CertSpotterClient


# -----------------------------------------------------------------------------
# certspotter
# -----------------------------------------------------------------------------

def test_certspotter_parses_subdomains():
    client = CertSpotterClient()
    fake_response = [
        {"dns_names": ["heuel.com", "*.heuel.com", "mail.heuel.com"]},
        {"dns_names": ["www.heuel.com", "owa.heuel.com"]},
        {"dns_names": ["other.com", "completely-different.example"]},
    ]
    with patch.object(client, "_get", return_value=fake_response):
        subs = client.get_subdomains("heuel.com")
    assert subs == ["heuel.com", "mail.heuel.com", "owa.heuel.com", "www.heuel.com"]


def test_certspotter_handles_none_response():
    client = CertSpotterClient()
    with patch.object(client, "_get", return_value=None):
        assert client.get_subdomains("x.com") == []


def test_certspotter_handles_empty_response():
    client = CertSpotterClient()
    with patch.object(client, "_get", return_value=[]):
        assert client.get_subdomains("x.com") == []


def test_certspotter_strips_wildcards_and_dedupes():
    client = CertSpotterClient()
    fake = [
        {"dns_names": ["*.x.com", "x.com", "*.x.com", "www.x.com", "WWW.X.COM"]},
    ]
    with patch.object(client, "_get", return_value=fake):
        subs = client.get_subdomains("x.com")
    assert subs == ["www.x.com", "x.com"]


def test_certspotter_uses_api_key_when_set(monkeypatch):
    monkeypatch.setenv("CERTSPOTTER_API_KEY", "test-token")
    client = CertSpotterClient()
    captured: dict = {}

    def fake_get(url, params=None, headers=None):
        captured["headers"] = headers or {}
        return []

    with patch.object(client, "_get", side_effect=fake_get):
        client.get_subdomains("x.com")
    assert captured["headers"].get("Authorization") == "Bearer test-token"


# -----------------------------------------------------------------------------
# crt.sh self-retry
# -----------------------------------------------------------------------------

def test_crtsh_retry_succeeds_on_second_attempt(tmp_path, monkeypatch):
    """Erster Versuch liefert leeren Response, zweiter Versuch klappt."""
    scan_dir = str(tmp_path)
    os.makedirs(os.path.join(scan_dir, "phase0"), exist_ok=True)

    call_count = {"n": 0}

    def fake_run_tool(cmd=None, timeout=None, output_path=None,
                      order_id=None, phase=None, tool_name=None, **kw):
        call_count["n"] += 1
        # Simuliere: 1. Versuch leer, 2. Versuch sinnvoll
        if call_count["n"] == 1:
            with open(output_path, "w") as f:
                f.write("")  # leer
        else:
            with open(output_path, "w") as f:
                json.dump([
                    {"name_value": "a.heuel.com\nb.heuel.com"},
                    {"name_value": "*.heuel.com"},
                ], f)
        return 0, 100

    monkeypatch.setattr(phase0, "run_tool", fake_run_tool)
    monkeypatch.setattr(phase0.time, "sleep", lambda s: None)  # kein echter Sleep

    subs = phase0.run_crtsh("heuel.com", scan_dir, "test-order")
    assert subs == ["a.heuel.com", "b.heuel.com", "heuel.com"]
    assert call_count["n"] == 2  # erster Versuch + Retry


def test_crtsh_retry_returns_empty_after_3_failures(tmp_path, monkeypatch):
    """Drei Versuche, alle leer → leere Liste."""
    scan_dir = str(tmp_path)
    os.makedirs(os.path.join(scan_dir, "phase0"), exist_ok=True)

    call_count = {"n": 0}

    def fake_run_tool(cmd=None, timeout=None, output_path=None, **kw):
        call_count["n"] += 1
        with open(output_path, "w") as f:
            f.write("")  # immer leer
        return 0, 100

    monkeypatch.setattr(phase0, "run_tool", fake_run_tool)
    monkeypatch.setattr(phase0.time, "sleep", lambda s: None)

    subs = phase0.run_crtsh("nope.com", scan_dir, "test-order")
    assert subs == []
    assert call_count["n"] == 3  # alle drei Stufen ausgeschoepft


def test_crtsh_retry_succeeds_first_try(tmp_path, monkeypatch):
    """Erster Versuch klappt → kein Retry."""
    scan_dir = str(tmp_path)
    os.makedirs(os.path.join(scan_dir, "phase0"), exist_ok=True)

    call_count = {"n": 0}

    def fake_run_tool(cmd=None, timeout=None, output_path=None, **kw):
        call_count["n"] += 1
        with open(output_path, "w") as f:
            json.dump([{"name_value": "x.heuel.com"}], f)
        return 0, 50

    monkeypatch.setattr(phase0, "run_tool", fake_run_tool)
    monkeypatch.setattr(phase0.time, "sleep", lambda s: None)

    subs = phase0.run_crtsh("heuel.com", scan_dir, "test-order")
    assert subs == ["x.heuel.com"]
    assert call_count["n"] == 1


def test_securitytrails_skipped_when_no_api_key(tmp_path, monkeypatch):
    """Ohne SECURITYTRAILS_API_KEY → leere Liste, kein Throw."""
    monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)
    scan_dir = str(tmp_path)
    os.makedirs(os.path.join(scan_dir, "phase0"), exist_ok=True)

    subs = phase0.run_securitytrails_subdomains("x.com", scan_dir, "test-order")
    assert subs == []


def test_securitytrails_returns_subdomains_with_key(tmp_path, monkeypatch):
    """Mit Key → SecurityTrailsClient.get_subdomains wird genutzt."""
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "test-key")
    scan_dir = str(tmp_path)
    os.makedirs(os.path.join(scan_dir, "phase0"), exist_ok=True)

    from scanner.passive import securitytrails_client as st_module

    fake_client = MagicMock()
    fake_client.available = True
    fake_client.get_subdomains.return_value = ["a.x.com", "b.x.com"]
    monkeypatch.setattr(st_module, "SecurityTrailsClient", lambda: fake_client)

    subs = phase0.run_securitytrails_subdomains("x.com", scan_dir, "test-order")
    assert subs == ["a.x.com", "b.x.com"]


def test_crtsh_retry_handles_zero_entries(tmp_path, monkeypatch):
    """JSON parsbar aber leere Liste → Retry."""
    scan_dir = str(tmp_path)
    os.makedirs(os.path.join(scan_dir, "phase0"), exist_ok=True)

    call_count = {"n": 0}

    def fake_run_tool(cmd=None, timeout=None, output_path=None, **kw):
        call_count["n"] += 1
        if call_count["n"] < 3:
            with open(output_path, "w") as f:
                json.dump([], f)  # leere Liste
        else:
            with open(output_path, "w") as f:
                json.dump([{"name_value": "rescued.heuel.com"}], f)
        return 0, 30

    monkeypatch.setattr(phase0, "run_tool", fake_run_tool)
    monkeypatch.setattr(phase0.time, "sleep", lambda s: None)

    subs = phase0.run_crtsh("heuel.com", scan_dir, "test-order")
    assert subs == ["rescued.heuel.com"]
    assert call_count["n"] == 3
