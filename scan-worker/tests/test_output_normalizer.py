"""Tests fuer scanner.output_normalizer (PR-ABC, 2026-05-02)."""
from __future__ import annotations

import json

import pytest

from scanner.output_normalizer import (
    normalize,
    normalize_dnsx,
    normalize_httpx,
    normalize_wafw00f,
)


# -----------------------------------------------------------------------------
# httpx
# -----------------------------------------------------------------------------

def test_normalize_httpx_strips_timestamp_and_time():
    raw = (
        '{"host":"217.72.203.132","timestamp":"2026-05-01T20:54:58.879Z",'
        '"time":"191.475269ms","status_code":200}'
    )
    out = normalize_httpx(raw)
    assert 'timestamp' not in out
    assert '"time"' not in out
    assert '"status_code":200' in out
    assert '"host":"217.72.203.132"' in out


def test_normalize_httpx_two_runs_same_payload_same_bytes():
    """Zwei Laeufe mit identischem Server-Verhalten aber unterschiedlichen
    Latencies und Wall-Clock-Timestamps muessen byte-identisch werden."""
    r1 = (
        '{"host":"x","timestamp":"2026-05-01T20:54:58.879Z","time":"191.475269ms","sc":200}'
    )
    r2 = (
        '{"host":"x","timestamp":"2026-05-01T21:17:05.920Z","time":"181.55308ms","sc":200}'
    )
    assert normalize_httpx(r1) == normalize_httpx(r2)


def test_normalize_httpx_handles_empty_and_none():
    assert normalize_httpx(None) is None
    assert normalize_httpx('') == ''


def test_normalize_httpx_keeps_non_json_lines():
    raw = 'plaintext line\n{"host":"x","time":"5ms"}'
    out = normalize_httpx(raw)
    assert 'plaintext line' in out
    assert '"time"' not in out


# -----------------------------------------------------------------------------
# wafw00f
# -----------------------------------------------------------------------------

def test_normalize_wafw00f_strips_ascii_banner():
    raw = (
        '                              ______\n'
        '                             /      \\\n'
        '                            (  Wo0o!  )\n'
        '                             \\______/ )\n'
        '\n'
        '[*] Checking https://example.com\n'
        '[+] Generic Detection results:\n'
        '[-] No WAF detected by the generic detection\n'
        '[~] Number of requests: 7\n'
    )
    out = normalize_wafw00f(raw)
    assert '______' not in out
    assert 'Wo0o' not in out
    assert '[*] Checking https://example.com' in out
    assert '[+] Generic Detection results' in out
    assert '[-] No WAF detected' in out
    # Number-of-requests-Counter ist volatil → muss weg
    assert 'Number of requests' not in out


def test_normalize_wafw00f_strips_ansi_codes():
    raw = (
        '\x1b[1;33m[~] Banner Text\x1b[0m\n'
        '[*] Checking https://x\n'
        '[-] No WAF detected\n'
    )
    out = normalize_wafw00f(raw)
    assert '\x1b' not in out
    assert '[*] Checking https://x' in out


def test_normalize_wafw00f_two_banner_variants_same_detection():
    """Variante A: W00f-Banner; Variante B: Wave-Banner — gleiche Detection."""
    a = (
        '   ___\n'
        '  / W00f \\\n'
        '\n'
        '[*] Checking https://heuel.com:8443\n'
        '[+] Generic Detection results:\n'
        '[-] No WAF detected by the generic detection\n'
    )
    b = (
        '~~~~~ wave ~~~~~\n'
        '\n'
        '[*] Checking https://heuel.com:8443\n'
        '[+] Generic Detection results:\n'
        '[-] No WAF detected by the generic detection\n'
    )
    assert normalize_wafw00f(a) == normalize_wafw00f(b)


# -----------------------------------------------------------------------------
# dnsx
# -----------------------------------------------------------------------------

def test_normalize_dnsx_sorts_ip_lists_per_line():
    raw = '{"host":"x.com","a":["3.3.3.3","1.1.1.1","2.2.2.2"]}'
    out = normalize_dnsx(raw)
    obj = json.loads(out)
    assert obj['a'] == ['1.1.1.1', '2.2.2.2', '3.3.3.3']


def test_normalize_dnsx_sorts_lines_by_host():
    raw = (
        '{"host":"zeta.x","a":["1.1.1.1"]}\n'
        '{"host":"alpha.x","a":["2.2.2.2"]}\n'
    )
    out = normalize_dnsx(raw)
    lines = out.splitlines()
    assert json.loads(lines[0])['host'] == 'alpha.x'
    assert json.loads(lines[1])['host'] == 'zeta.x'


def test_normalize_dnsx_two_resolver_orderings_identical():
    """Cloudflare-IPv6-Resolver liefern in unterschiedlicher Reihenfolge."""
    r1 = (
        '{"host":"x.com","aaaa":["2606:4700:10::6816:b06","2606:4700:10::6816:a06"]}'
    )
    r2 = (
        '{"host":"x.com","aaaa":["2606:4700:10::6816:a06","2606:4700:10::6816:b06"]}'
    )
    assert normalize_dnsx(r1) == normalize_dnsx(r2)


def test_normalize_dnsx_keeps_invalid_lines():
    raw = 'not-json\n{"host":"x.com","a":["1.1.1.1"]}'
    out = normalize_dnsx(raw)
    assert 'not-json' in out


# -----------------------------------------------------------------------------
# Dispatcher
# -----------------------------------------------------------------------------

def test_normalize_unknown_tool_passthrough():
    raw = 'arbitrary nmap output\n   timestamp: ...'
    assert normalize('nmap', raw) == raw


def test_normalize_known_tools_call_through():
    httpx_raw = '{"host":"x","time":"5ms","status_code":200}'
    assert 'time' not in normalize('httpx', httpx_raw)


def test_normalize_handles_none_safely():
    assert normalize('httpx', None) is None
    assert normalize('wafw00f', None) is None
    assert normalize('dnsx', None) is None
    assert normalize('whatever', None) is None
