"""Tests fuer output_normalizer (B1 — nmap/zap/nuclei/nikto/wpscan)."""

import json

from scanner.output_normalizer import (
    normalize_nmap, normalize_zap, normalize_nuclei,
    normalize_nikto, normalize_wpscan,
)


def test_zap_alerts_order_independent():
    a = json.dumps([
        {"pluginId": "10020", "url": "https://x.com/a", "name": "X-Frame", "riskcode": 2, "alertId": "42"},
        {"pluginId": "10038", "url": "https://x.com/b", "name": "CSP", "riskcode": 1, "alertId": "17"},
    ])
    b = json.dumps([
        {"pluginId": "10038", "url": "https://x.com/b", "name": "CSP", "riskcode": 1, "alertId": "999"},
        {"pluginId": "10020", "url": "https://x.com/a", "name": "X-Frame", "riskcode": 2, "alertId": "1"},
    ])
    assert normalize_zap(a) == normalize_zap(b)


def test_zap_strips_volatile_ids():
    raw = json.dumps([{"pluginId": "1", "url": "x", "alertId": "abc",
                       "messageId": "def", "sourceid": "z"}])
    out = normalize_zap(raw)
    assert "alertId" not in out
    assert "messageId" not in out
    assert "sourceid" not in out


def test_nuclei_jsonl_sorted_and_no_timestamp():
    n1 = "\n".join([
        json.dumps({"template-id": "tech-detect", "matched-at": "https://x.com",
                    "timestamp": "2026-01-01"}),
        json.dumps({"template-id": "cve-2024-1", "matched-at": "https://x.com",
                    "timestamp": "2026-02-02"}),
    ])
    n2 = "\n".join([
        json.dumps({"template-id": "cve-2024-1", "matched-at": "https://x.com",
                    "timestamp": "9999-12-31"}),
        json.dumps({"template-id": "tech-detect", "matched-at": "https://x.com",
                    "timestamp": "1111-11-11"}),
    ])
    assert normalize_nuclei(n1) == normalize_nuclei(n2)
    assert "timestamp" not in normalize_nuclei(n1)


def test_nikto_json_sorted():
    nk1 = json.dumps({"host": "x.com", "scanstart": "2026-01-01",
                       "vulnerabilities": [{"id": "OSVDB-3268", "url": "/test/"},
                                            {"id": "OSVDB-3092", "url": "/admin/"}]})
    nk2 = json.dumps({"host": "x.com", "scanstart": "9999-99-99",
                       "vulnerabilities": [{"id": "OSVDB-3092", "url": "/admin/"},
                                            {"id": "OSVDB-3268", "url": "/test/"}]})
    assert normalize_nikto(nk1) == normalize_nikto(nk2)
    out = normalize_nikto(nk1)
    assert "scanstart" not in out


def test_nikto_plaintext_fallback():
    """Plain-Text nikto-Output: Findings werden sortiert, Timestamps weg."""
    raw1 = "+ Start Time: 2026-01-01\n+ /admin/: Found\n+ /test/: Found\n+ End Time: ..."
    raw2 = "+ Start Time: 9999-99-99\n+ /test/: Found\n+ /admin/: Found\n+ End Time: ..."
    out1 = normalize_nikto(raw1)
    out2 = normalize_nikto(raw2)
    assert out1 == out2


def test_wpscan_strips_runtime_and_sorts():
    w1 = json.dumps({"start_time": "2026-01-01", "elapsed": 5,
                      "plugins": {"a": {"version": "1.0"}, "b": {"version": "2.0"}}})
    w2 = json.dumps({"start_time": "9999-99-99", "elapsed": 99,
                      "plugins": {"b": {"version": "2.0"}, "a": {"version": "1.0"}}})
    assert normalize_wpscan(w1) == normalize_wpscan(w2)
    out = normalize_wpscan(w1)
    assert "start_time" not in out
    assert "elapsed" not in out


def test_nmap_strips_timestamps():
    nm1 = '<nmaprun start="123" startstr="2026-01-01" elapsed="4.2">\n<host><port>80</port></host>\nNmap done: 1 host scanned in 4.23 seconds'
    nm2 = '<nmaprun start="888" startstr="9999-12-31" elapsed="9.9">\n<host><port>80</port></host>\nNmap done: 1 host scanned in 9.91 seconds'
    assert normalize_nmap(nm1) == normalize_nmap(nm2)


def test_normalizer_passthrough_for_unknown_tool():
    from scanner.output_normalizer import normalize
    assert normalize("unknown_tool", "raw output") == "raw output"


def test_normalizer_handles_empty_input():
    assert normalize_zap("") == ""
    assert normalize_nuclei("") == ""
    assert normalize_nikto(None) is None
