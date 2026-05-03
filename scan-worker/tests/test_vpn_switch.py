"""Tests fuer VpnSwitch (PR-VPN, 2026-05-03)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from scanner.vpn_switch import VpnSwitch, get_switch, cleanup_switch


def test_unavailable_when_env_missing(monkeypatch):
    monkeypatch.delenv("VPN_ENABLED", raising=False)
    sw = VpnSwitch("ord-1", "auto_on_block")
    assert not sw.is_available()
    assert not sw.is_active()
    assert sw.current_proxy_url() is None


def test_unavailable_when_strategy_never(monkeypatch):
    monkeypatch.setenv("VPN_ENABLED", "true")
    monkeypatch.setenv("VPN_GATEWAY_URL", "http://vpn-gw:8080")
    monkeypatch.setenv("VPN_PROXY_URL", "http://vpn-gw:3128")
    sw = VpnSwitch("ord-1", "never")
    assert not sw.is_available()


def test_available_when_all_set(monkeypatch):
    monkeypatch.setenv("VPN_ENABLED", "true")
    monkeypatch.setenv("VPN_GATEWAY_URL", "http://vpn-gw:8080")
    monkeypatch.setenv("VPN_PROXY_URL", "http://vpn-gw:3128")
    sw = VpnSwitch("ord-1", "auto_on_block")
    assert sw.is_available()


def test_should_activate_auto_on_real_block(monkeypatch):
    monkeypatch.setenv("VPN_ENABLED", "true")
    monkeypatch.setenv("VPN_GATEWAY_URL", "http://vpn-gw:8080")
    monkeypatch.setenv("VPN_PROXY_URL", "http://vpn-gw:3128")
    sw = VpnSwitch("ord-1", "auto_on_block")
    assert sw.should_activate("x.com", "429_burst(3)")
    assert not sw.should_activate("x.com", "no_data")
    assert not sw.should_activate("x.com", "below_threshold")


def test_should_activate_always_strategy(monkeypatch):
    monkeypatch.setenv("VPN_ENABLED", "true")
    monkeypatch.setenv("VPN_GATEWAY_URL", "http://vpn-gw:8080")
    monkeypatch.setenv("VPN_PROXY_URL", "http://vpn-gw:3128")
    sw = VpnSwitch("ord-1", "always")
    # Auch bei "no_data" — strategy=always
    assert sw.should_activate("x.com", "no_data")


def test_enable_no_op_when_unavailable(monkeypatch):
    monkeypatch.delenv("VPN_ENABLED", raising=False)
    sw = VpnSwitch("ord-1", "auto_on_block")
    assert sw.enable("test") is False
    assert not sw.is_active()


def test_enable_calls_gateway_and_sets_active(monkeypatch):
    monkeypatch.setenv("VPN_ENABLED", "true")
    monkeypatch.setenv("VPN_GATEWAY_URL", "http://vpn-gw:8080")
    monkeypatch.setenv("VPN_PROXY_URL", "http://vpn-gw:3128")

    sw = VpnSwitch("ord-1", "auto_on_block")

    class FakeResp:
        status_code = 200
        text = "ok"
        def json(self):
            return {"connected": True}

    with patch("requests.post", return_value=FakeResp()) as mock_post:
        ok = sw.enable(reason="test", host="x.com")

    assert ok
    assert sw.is_active()
    assert sw.current_proxy_url() == "http://vpn-gw:3128"
    mock_post.assert_called_once()


def test_enable_handles_gateway_error_gracefully(monkeypatch):
    monkeypatch.setenv("VPN_ENABLED", "true")
    monkeypatch.setenv("VPN_GATEWAY_URL", "http://vpn-gw:8080")
    monkeypatch.setenv("VPN_PROXY_URL", "http://vpn-gw:3128")
    sw = VpnSwitch("ord-1", "auto_on_block")
    with patch("requests.post", side_effect=Exception("connection refused")):
        ok = sw.enable("test")
    assert not ok
    assert not sw.is_active()


def test_rotate_picks_next_location(monkeypatch):
    monkeypatch.setenv("VPN_ENABLED", "true")
    monkeypatch.setenv("VPN_GATEWAY_URL", "http://vpn-gw:8080")
    monkeypatch.setenv("VPN_PROXY_URL", "http://vpn-gw:3128")
    sw = VpnSwitch("ord-1", "auto_on_block")

    class FakeResp:
        status_code = 200
        def json(self): return {"connected": True}

    with patch("requests.post", return_value=FakeResp()):
        sw.enable("first")
        first_loc = sw.get_activations()[-1]["location"]
        sw.rotate()
        second_loc = sw.get_activations()[-1]["location"]
    assert first_loc != second_loc


def test_audit_trail_collected(monkeypatch):
    monkeypatch.setenv("VPN_ENABLED", "true")
    monkeypatch.setenv("VPN_GATEWAY_URL", "http://vpn-gw:8080")
    monkeypatch.setenv("VPN_PROXY_URL", "http://vpn-gw:3128")
    sw = VpnSwitch("ord-1", "auto_on_block")
    class FakeResp:
        status_code = 200
        def json(self): return {"connected": True}
    with patch("requests.post", return_value=FakeResp()):
        sw.enable("first", host="a.com")
        sw.enable("second", host="b.com")
    activations = sw.get_activations()
    assert len(activations) == 2
    assert activations[0]["host"] == "a.com"
    assert activations[1]["host"] == "b.com"


def test_get_switch_returns_singleton_per_order():
    sw1 = get_switch("ord-A")
    sw2 = get_switch("ord-A")
    assert sw1 is sw2
    sw3 = get_switch("ord-B")
    assert sw3 is not sw1
    cleanup_switch("ord-A")
    cleanup_switch("ord-B")


def test_cleanup_disables_and_returns_audit(monkeypatch):
    monkeypatch.setenv("VPN_ENABLED", "true")
    monkeypatch.setenv("VPN_GATEWAY_URL", "http://vpn-gw:8080")
    monkeypatch.setenv("VPN_PROXY_URL", "http://vpn-gw:3128")
    class FakeResp:
        status_code = 200
        def json(self): return {"connected": True}
    sw = get_switch("ord-cleanup")
    with patch("requests.post", return_value=FakeResp()):
        sw.enable("test", host="x.com")
    audit = cleanup_switch("ord-cleanup")
    assert audit is not None
    assert len(audit) == 1
