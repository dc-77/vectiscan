"""Tests for F-PRE-002 — DNS-Resolution parallel via ThreadPoolExecutor.

Audit-Eintrag: docs/scan-flow/Scan-Optimierung.md Sektion 3.1.3.
"""

from __future__ import annotations

import time
from unittest.mock import patch

from scanner.common import dns_utils


def test_resolve_all_returns_deterministic_keys():
    """resolve_all liefert immer die gleichen 5 Keys in stabiler Reihenfolge."""
    with patch.object(dns_utils, "resolve_a", return_value=["1.1.1.1"]), \
         patch.object(dns_utils, "resolve_aaaa", return_value=[]), \
         patch.object(dns_utils, "resolve_cname", return_value=None), \
         patch.object(dns_utils, "resolve_mx", return_value=["mx.example.com"]), \
         patch.object(dns_utils, "resolve_ns", return_value=["ns1.example.com"]):
        result = dns_utils.resolve_all("example.com")

    assert list(result.keys()) == ["a", "aaaa", "cname", "mx", "ns"]
    assert result["a"] == ["1.1.1.1"]
    assert result["aaaa"] == []
    assert result["cname"] is None
    assert result["mx"] == ["mx.example.com"]
    assert result["ns"] == ["ns1.example.com"]


def test_resolve_all_runs_record_types_in_parallel():
    """5 simulierte 0.2s-Calls duerfen nicht 1.0s+ brauchen (sequenziell wuerde)."""
    sleep_time = 0.2

    def slow_resolver(_fqdn, _timeout=5.0):
        time.sleep(sleep_time)
        return []

    with patch.object(dns_utils, "resolve_a", side_effect=slow_resolver), \
         patch.object(dns_utils, "resolve_aaaa", side_effect=slow_resolver), \
         patch.object(dns_utils, "resolve_cname", side_effect=lambda *a, **k: (slow_resolver(*a, **k), None)[1]), \
         patch.object(dns_utils, "resolve_mx", side_effect=slow_resolver), \
         patch.object(dns_utils, "resolve_ns", side_effect=slow_resolver):
        start = time.monotonic()
        dns_utils.resolve_all("example.com")
        duration = time.monotonic() - start

    # Sequentiell waeren das 5 * 0.2 = 1.0s. Parallel ~0.2-0.4s.
    # Wir lassen einen grosszuegigen Puffer, um nicht flaky zu sein.
    assert duration < 0.7, f"resolve_all dauerte {duration:.3f}s — vermutlich nicht parallel"
