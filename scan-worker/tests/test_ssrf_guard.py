"""Tests fuer scanner.common.ssrf_guard (VEC-196).

Gespiegelt an api/src/__tests__/ssrf_guard.test.ts: gleiche Block-/Allow-Vektoren
fuer IPv4/IPv6, fail-closed bei unparsebaren Eingaben, Resolve-and-Pin-Semantik
und Adapter-Verhalten (URL-Rewrite auf gepinnte IP, Block interner Ziele).
"""

import pytest
from requests.adapters import HTTPAdapter
from requests.models import Response

from scanner.common import dns_utils, ssrf_guard
from scanner.common.ssrf_guard import SsrfBlockedError, is_blocked_address


BLOCKED_V4 = [
    "127.0.0.1",            # loopback
    "127.99.1.2",
    "10.0.0.1",             # RFC1918
    "10.255.255.255",
    "172.16.0.1",           # RFC1918
    "172.31.255.254",
    "192.168.1.1",          # RFC1918
    "169.254.169.254",      # Cloud-Metadata (AWS/GCP/Azure)
    "169.254.0.1",          # link-local
    "100.64.0.1",           # CGNAT
    "0.0.0.0",              # "this network"
    "192.0.0.1",            # IETF protocol assignments
    "198.18.0.1",           # benchmark
    "224.0.0.1",            # multicast
    "240.0.0.1",            # reserved
    "255.255.255.255",      # broadcast
]

ALLOWED_V4 = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "172.32.0.1",
              "100.63.255.255", "11.0.0.1"]

BLOCKED_V6 = [
    "::1",                       # loopback
    "::",                        # unspecified
    "fe80::1",                   # link-local
    "fc00::1",                   # ULA
    "fd12:3456::1",              # ULA
    "ff02::1",                   # multicast
    "::ffff:127.0.0.1",          # IPv4-mapped loopback
    "::ffff:169.254.169.254",    # IPv4-mapped metadata
    "64:ff9b::a9fe:a9fe",        # NAT64 -> 169.254.169.254
]

ALLOWED_V6 = ["2606:4700:4700::1111", "2001:4860:4860::8888", "::ffff:8.8.8.8"]


@pytest.mark.parametrize("ip", BLOCKED_V4)
def test_blocks_internal_v4(ip):
    assert is_blocked_address(ip) is True


@pytest.mark.parametrize("ip", ALLOWED_V4)
def test_allows_public_v4(ip):
    assert is_blocked_address(ip) is False


@pytest.mark.parametrize("ip", BLOCKED_V6)
def test_blocks_internal_v6(ip):
    assert is_blocked_address(ip) is True


@pytest.mark.parametrize("ip", ALLOWED_V6)
def test_allows_public_v6(ip):
    assert is_blocked_address(ip) is False


@pytest.mark.parametrize("bad", ["not-an-ip", "", "999.999.999.999", "  ", "1.2.3"])
def test_unparsable_is_fail_closed(bad):
    assert is_blocked_address(bad) is True


def test_filter_public_drops_internal_keeps_order():
    ips = ["10.0.0.1", "93.184.216.34", "127.0.0.1", "8.8.8.8"]
    assert ssrf_guard.filter_public(ips) == ["93.184.216.34", "8.8.8.8"]


# --- Resolve-and-Pin ---------------------------------------------------------

def test_resolve_and_pin_picks_first_public(monkeypatch):
    monkeypatch.setattr(ssrf_guard, "_resolve_host",
                        lambda host, timeout: ["10.0.0.5", "93.184.216.34"])
    assert ssrf_guard.resolve_and_pin("evil.example.com") == "93.184.216.34"


def test_resolve_and_pin_blocks_when_all_internal(monkeypatch):
    monkeypatch.setattr(ssrf_guard, "_resolve_host",
                        lambda host, timeout: ["10.0.0.5", "169.254.169.254"])
    with pytest.raises(SsrfBlockedError):
        ssrf_guard.resolve_and_pin("rebind.example.com")


def test_resolve_and_pin_blocks_internal_literal():
    with pytest.raises(SsrfBlockedError):
        ssrf_guard.resolve_and_pin("169.254.169.254")


def test_resolve_and_pin_passes_public_literal_without_resolution(monkeypatch):
    def _boom(host, timeout):  # darf bei IP-Literal nicht aufgerufen werden
        raise AssertionError("literal darf nicht aufgeloest werden")
    monkeypatch.setattr(ssrf_guard, "_resolve_host", _boom)
    assert ssrf_guard.resolve_and_pin("93.184.216.34") == "93.184.216.34"


def test_resolve_and_pin_raises_on_nxdomain(monkeypatch):
    monkeypatch.setattr(ssrf_guard, "_resolve_host", lambda host, timeout: [])
    with pytest.raises(SsrfBlockedError):
        ssrf_guard.resolve_and_pin("nx.example.com")


# --- Adapter / safe_get ------------------------------------------------------

def test_adapter_rewrites_url_to_pinned_ip_and_keeps_host(monkeypatch):
    captured = {}

    def fake_super_send(self, request, **kwargs):
        captured["url"] = request.url
        captured["host"] = request.headers.get("Host")
        resp = Response()
        resp.status_code = 200
        resp._content = b""
        resp.url = request.url
        resp.request = request
        return resp

    monkeypatch.setattr(HTTPAdapter, "send", fake_super_send)
    monkeypatch.setattr(ssrf_guard, "_resolve_host",
                        lambda host, timeout: ["93.184.216.34"])

    session = ssrf_guard.guarded_session()
    session.get("http://example.com/path?q=1")

    assert captured["url"] == "http://93.184.216.34/path?q=1"
    assert captured["host"] == "example.com"


def test_safe_get_blocks_internal_resolution(monkeypatch):
    monkeypatch.setattr(ssrf_guard, "_resolve_host",
                        lambda host, timeout: ["10.0.0.5"])
    with pytest.raises(SsrfBlockedError):
        ssrf_guard.safe_get("http://evil.example.com/")


def test_safe_get_blocks_internal_literal_without_network():
    # 127.0.0.1-Literal wird vor jedem Connect-Versuch geblockt.
    with pytest.raises(SsrfBlockedError):
        ssrf_guard.safe_get("http://127.0.0.1:9/")


# --- dns_utils public_only-Filter -------------------------------------------

class _FakeAnswer:
    def __init__(self, text):
        self._text = text

    def to_text(self):
        return self._text


class _FakeResolver:
    def resolve(self, fqdn, rtype):
        return [_FakeAnswer("10.0.0.1"), _FakeAnswer("93.184.216.34")]


def _patch_resolver(monkeypatch):
    monkeypatch.setattr(dns_utils, "_HAS_DNSPYTHON", True)
    monkeypatch.setattr(dns_utils, "_resolver", lambda timeout=5.0: _FakeResolver())


def test_resolve_a_default_keeps_internal(monkeypatch):
    _patch_resolver(monkeypatch)
    assert dns_utils.resolve_a("x.example.com") == ["10.0.0.1", "93.184.216.34"]


def test_resolve_a_public_only_filters_internal(monkeypatch):
    _patch_resolver(monkeypatch)
    assert dns_utils.resolve_a("x.example.com", public_only=True) == ["93.184.216.34"]
