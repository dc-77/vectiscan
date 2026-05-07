"""Tests fuer output_normalizer (F-XS-001 — testssl/ffuf/katana/feroxbuster).

Spec: docs/scan-flow/Scan-Optimierung.md, Finding F-XS-001.
"""

from __future__ import annotations

import json

from scanner.output_normalizer import (
    normalize,
    normalize_feroxbuster,
    normalize_ffuf,
    normalize_katana,
    normalize_testssl,
)


# -----------------------------------------------------------------------------
# testssl
# -----------------------------------------------------------------------------

def test_normalize_testssl_strips_runtime_and_invocation():
    raw = json.dumps({
        "Invocation": "testssl.sh --jsonfile-pretty out.json https://x",
        "at": "2026-05-07 13:14:15 +0000",
        "startTime": "1715091255",
        "finishedTime": "1715091300",
        "runtime": "45.0",
        "version": "3.1rc1",
        "openssl": "OpenSSL 1.1.1n",
        "service": "HTTP",
        "scanResult": [
            {"id": "cipher_TLS_AES_256", "cipher_name": "TLS_AES_256_GCM_SHA384",
             "finding": "offered"},
            {"id": "cipher_TLS_AES_128", "cipher_name": "TLS_AES_128_GCM_SHA256",
             "finding": "offered"},
        ],
    })
    out = normalize_testssl(raw)
    parsed = json.loads(out)

    # Run-Metadata weg
    for k in ("Invocation", "at", "startTime", "finishedTime", "runtime",
              "version", "openssl", "service"):
        assert k not in parsed, f"{k} sollte entfernt sein"

    # Findings noch da, sortiert nach cipher_name → AES_128 vor AES_256
    assert "scanResult" in parsed
    assert len(parsed["scanResult"]) == 2
    assert parsed["scanResult"][0]["cipher_name"] == "TLS_AES_128_GCM_SHA256"
    # Per-Finding-id wurde gestrippt
    assert "id" not in parsed["scanResult"][0]


def test_normalize_testssl_two_runs_byte_identical():
    """Zwei Laeufe mit identischem Server-Verhalten (gleiche Cipher), aber
    unterschiedlichen Run-Times und shuffled Findings → byte-identisch."""
    r1 = json.dumps({
        "Invocation": "testssl.sh --jsonfile-pretty out.json https://x",
        "at": "2026-05-01 10:00:00",
        "startTime": "1714557600",
        "runtime": "30.0",
        "scanResult": [
            {"id": "cipher_A", "cipher_name": "TLS_A", "finding": "offered"},
            {"id": "cipher_B", "cipher_name": "TLS_B", "finding": "offered"},
        ],
    })
    r2 = json.dumps({
        "Invocation": "testssl.sh --jsonfile-pretty other.json https://x",
        "at": "2026-05-07 13:14:15",
        "startTime": "1715091255",
        "runtime": "45.5",
        "scanResult": [
            {"id": "cipher_X", "cipher_name": "TLS_B", "finding": "offered"},
            {"id": "cipher_Y", "cipher_name": "TLS_A", "finding": "offered"},
        ],
    })
    assert normalize_testssl(r1) == normalize_testssl(r2)


def test_normalize_testssl_top_level_array():
    """testssl liefert manchmal direkt ein Array auf Top-Level."""
    raw = json.dumps([
        {"id": "B", "cipher_name": "B", "finding": "offered"},
        {"id": "A", "cipher_name": "A", "finding": "offered"},
    ])
    out = normalize_testssl(raw)
    parsed = json.loads(out)
    assert isinstance(parsed, list)
    assert parsed[0]["cipher_name"] == "A"
    assert "id" not in parsed[0]


# -----------------------------------------------------------------------------
# ffuf
# -----------------------------------------------------------------------------

def test_normalize_ffuf_sorts_results_by_url():
    raw = json.dumps({
        "commandline": "ffuf -u https://x/FUZZ -w wl",
        "time": "2026-05-07T13:14:15Z",
        "config": {
            "commandline": "ffuf -u ...",
            "outputfile": "/tmp/ffuf-1234.json",
            "proxyurl": "http://10.0.0.1:8080",
            "threads": 40,
        },
        "results": [
            {"url": "https://x/zeta", "status": 200, "time": "10ms",
             "host": "203.0.113.5"},
            {"url": "https://x/alpha", "status": 200, "time": "20ms",
             "host": "203.0.113.6"},
        ],
    })
    out = normalize_ffuf(raw)
    parsed = json.loads(out)

    # Top-Level-Time/Commandline weg
    assert "time" not in parsed
    assert "commandline" not in parsed

    # Config: commandline/outputfile/proxyurl weg, threads bleibt
    assert "commandline" not in parsed["config"]
    assert "outputfile" not in parsed["config"]
    assert "proxyurl" not in parsed["config"]
    assert parsed["config"]["threads"] == 40

    # Results sortiert nach url, time/host weg
    assert parsed["results"][0]["url"] == "https://x/alpha"
    assert parsed["results"][1]["url"] == "https://x/zeta"
    for r in parsed["results"]:
        assert "time" not in r
        assert "host" not in r


def test_normalize_ffuf_two_runs_byte_identical():
    """Zwei Laeufe: gleiche Findings, andere proxyurl/host/time."""
    r1 = json.dumps({
        "commandline": "ffuf -u x", "time": "2026-05-01",
        "config": {"proxyurl": "http://a:8080", "threads": 40},
        "results": [
            {"url": "https://x/a", "status": 200, "host": "1.1.1.1", "time": "5ms"},
        ],
    })
    r2 = json.dumps({
        "commandline": "ffuf -u y", "time": "2026-05-07",
        "config": {"proxyurl": "http://b:8080", "threads": 40},
        "results": [
            {"url": "https://x/a", "status": 200, "host": "2.2.2.2", "time": "30ms"},
        ],
    })
    assert normalize_ffuf(r1) == normalize_ffuf(r2)


# -----------------------------------------------------------------------------
# katana
# -----------------------------------------------------------------------------

def test_normalize_katana_strips_timestamps_jsonl():
    raw = "\n".join([
        json.dumps({"timestamp": "2026-05-07T13:14:15Z",
                    "endpoint": "https://x/zeta"}),
        json.dumps({"timestamp": "2026-05-07T13:14:16Z",
                    "endpoint": "https://x/alpha"}),
        json.dumps({"timestamp": "2026-05-07T13:14:17Z",
                    "endpoint": "https://x/middle"}),
    ])
    out = normalize_katana(raw)

    assert "timestamp" not in out
    lines = out.splitlines()
    assert len(lines) == 3
    # Sortiert nach endpoint
    assert json.loads(lines[0])["endpoint"] == "https://x/alpha"
    assert json.loads(lines[1])["endpoint"] == "https://x/middle"
    assert json.loads(lines[2])["endpoint"] == "https://x/zeta"


def test_normalize_katana_two_runs_byte_identical():
    r1 = "\n".join([
        json.dumps({"timestamp": "2026-05-01", "endpoint": "https://x/a"}),
        json.dumps({"timestamp": "2026-05-01", "endpoint": "https://x/b"}),
    ])
    r2 = "\n".join([
        json.dumps({"timestamp": "9999-12-31", "endpoint": "https://x/b"}),
        json.dumps({"timestamp": "1111-01-01", "endpoint": "https://x/a"}),
    ])
    assert normalize_katana(r1) == normalize_katana(r2)


def test_normalize_katana_keeps_invalid_lines():
    raw = "not-json\n" + json.dumps({"timestamp": "x", "endpoint": "https://x/a"})
    out = normalize_katana(raw)
    assert "not-json" in out
    assert "timestamp" not in out


def test_normalize_katana_strips_request_response_timestamps_and_cookies():
    raw = json.dumps({
        "timestamp": "2026-05-07T13:14:15Z",
        "endpoint": "https://x/a",
        "request": {
            "timestamp": "...",
            "headers": {"User-Agent": "katana/1.0", "Cookie": "session=abc",
                        "authorization": "Bearer xyz"},
        },
        "response": {"timestamp": "...", "status": 200},
    })
    out = normalize_katana(raw)
    parsed = json.loads(out)
    assert "timestamp" not in parsed
    assert "timestamp" not in parsed["request"]
    assert "timestamp" not in parsed["response"]
    assert "Cookie" not in parsed["request"]["headers"]
    assert "authorization" not in parsed["request"]["headers"]
    # User-Agent darf bleiben
    assert parsed["request"]["headers"].get("User-Agent") == "katana/1.0"


# -----------------------------------------------------------------------------
# feroxbuster
# -----------------------------------------------------------------------------

def test_normalize_feroxbuster_strips_timestamp_and_response_time():
    raw = "\n".join([
        json.dumps({"timestamp": "2026-05-07T13:14:15Z",
                    "url": "https://x/zeta",
                    "status": 200, "content_length": 1234,
                    "response_time": 0.123, "wildcard": False}),
        json.dumps({"timestamp": "2026-05-07T13:14:16Z",
                    "url": "https://x/alpha",
                    "status": 200, "content_length": 5678,
                    "response_time": 0.234, "wildcard": True}),
    ])
    out = normalize_feroxbuster(raw)

    assert "timestamp" not in out
    assert "response_time" not in out
    assert "wildcard" not in out

    lines = out.splitlines()
    assert len(lines) == 2
    # Sortiert nach url
    assert json.loads(lines[0])["url"] == "https://x/alpha"
    assert json.loads(lines[1])["url"] == "https://x/zeta"


def test_normalize_feroxbuster_two_runs_byte_identical():
    r1 = "\n".join([
        json.dumps({"timestamp": "2026-05-01", "url": "https://x/a",
                    "status": 200, "response_time": 0.1, "wildcard": False}),
        json.dumps({"timestamp": "2026-05-01", "url": "https://x/b",
                    "status": 404, "response_time": 0.2, "wildcard": True}),
    ])
    r2 = "\n".join([
        json.dumps({"timestamp": "9999-12-31", "url": "https://x/b",
                    "status": 404, "response_time": 0.99, "wildcard": False}),
        json.dumps({"timestamp": "1111-01-01", "url": "https://x/a",
                    "status": 200, "response_time": 9.9, "wildcard": True}),
    ])
    assert normalize_feroxbuster(r1) == normalize_feroxbuster(r2)


# -----------------------------------------------------------------------------
# Dispatcher / Aliase / Fehlerrobustheit
# -----------------------------------------------------------------------------

def test_normalize_returns_input_for_unknown_tool():
    raw = "raw output of an unknown tool"
    assert normalize("doesnotexist", raw) == raw


def test_normalize_handles_invalid_json_gracefully():
    """Kaputter JSON-Input fuer testssl/ffuf darf nicht crashen."""
    bad = "{not-json"
    assert normalize_testssl(bad) == bad
    assert normalize_ffuf(bad) == bad
    # JSONL-Tools tolerieren kaputte Zeilen sowieso
    assert "broken" in normalize_katana("broken\n")
    assert "broken" in normalize_feroxbuster("broken\n")


def test_normalize_dispatcher_aliases_resolve():
    """testssl.sh, ffuf_sensitive werden auf die gleichen Funktionen geroutet."""
    payload = json.dumps([{"id": "x", "cipher_name": "A", "finding": "offered"}])
    assert normalize("testssl", payload) == normalize("testssl.sh", payload)

    ffuf_payload = json.dumps({"results": [{"url": "https://x/a", "status": 200}]})
    assert normalize("ffuf", ffuf_payload) == normalize("ffuf_sensitive", ffuf_payload)


def test_normalize_handles_none_safely():
    assert normalize_testssl(None) is None
    assert normalize_ffuf(None) is None
    assert normalize_katana(None) is None
    assert normalize_feroxbuster(None) is None
