"""Tests for parallel execution patterns used across the scan pipeline.

Verifies that ThreadPoolExecutor patterns handle timeouts, errors,
and result collection correctly.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from unittest.mock import MagicMock, patch
import time

import pytest


class TestThreadPoolBasics:
    """Verify ThreadPoolExecutor patterns work as expected."""

    def test_parallel_tasks_complete(self):
        """Multiple tasks should all complete and return results."""
        def task(n):
            return n * 2

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {pool.submit(task, i): i for i in range(5)}
            results = {}
            for future in as_completed(futures):
                idx = futures[future]
                results[idx] = future.result()

        assert results == {0: 0, 1: 2, 2: 4, 3: 6, 4: 8}

    def test_partial_failure_handled(self):
        """If one task fails, others should still complete."""
        def task(n):
            if n == 2:
                raise ValueError("task 2 failed")
            return n * 2

        results = {}
        errors = {}
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {pool.submit(task, i): i for i in range(5)}
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    results[idx] = future.result()
                except ValueError as e:
                    errors[idx] = str(e)

        assert len(results) == 4  # 0, 1, 3, 4
        assert 2 in errors
        assert errors[2] == "task 2 failed"

    def test_timeout_handling(self):
        """Timeout on individual future should not block others."""
        def fast_task():
            return "fast"

        def slow_task():
            time.sleep(10)
            return "slow"

        with ThreadPoolExecutor(max_workers=2) as pool:
            fast = pool.submit(fast_task)
            slow = pool.submit(slow_task)

            assert fast.result(timeout=2) == "fast"

            with pytest.raises(TimeoutError):
                slow.result(timeout=0.1)

    def test_result_order_preserved(self):
        """Results should be assignable to correct indices regardless of completion order."""
        def task(n):
            # Task 0 is slowest, task 4 is fastest
            time.sleep(0.01 * (5 - n))
            return n

        results = [None] * 5
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(task, i): i for i in range(5)}
            for future in as_completed(futures):
                idx = futures[future]
                results[idx] = future.result()

        assert results == [0, 1, 2, 3, 4]


class TestPhase3EnrichmentPattern:
    """Test the parallel enrichment pattern from phase3.py."""

    def test_all_enrichment_apis_called(self):
        """All 4 enrichment APIs should be called in parallel."""
        call_log = []

        def mock_nvd():
            call_log.append("nvd")
            return {"CVE-2021-1234": {"score": 9.8}}

        def mock_epss():
            call_log.append("epss")
            return {"CVE-2021-1234": {"epss": 0.95}}

        def mock_kev():
            call_log.append("kev")
            return {}

        def mock_edb():
            call_log.append("edb")
            return {}

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [
                pool.submit(mock_nvd),
                pool.submit(mock_epss),
                pool.submit(mock_kev),
                pool.submit(mock_edb),
            ]
            results = [f.result(timeout=5) for f in futures]

        assert len(call_log) == 4
        assert "nvd" in call_log
        assert "epss" in call_log

    def test_one_api_failure_doesnt_break_others(self):
        """If NVD fails, EPSS/KEV/ExploitDB should still return data."""
        def failing_nvd():
            raise ConnectionError("NVD API down")

        def ok_epss():
            return {"CVE-2021-1234": {"epss": 0.5}}

        with ThreadPoolExecutor(max_workers=4) as pool:
            nvd = pool.submit(failing_nvd)
            epss = pool.submit(ok_epss)

            nvd_result = {}
            try:
                nvd_result = nvd.result(timeout=5)
            except ConnectionError:
                pass

            epss_result = epss.result(timeout=5)

        assert nvd_result == {}
        assert "CVE-2021-1234" in epss_result


class TestPhase0aPattern:
    """Test the parallel passive intel pattern from phase0a.py."""

    def test_tools_run_concurrently(self):
        """Tools should run concurrently, not sequentially."""
        start_times = {}

        def mock_tool(name):
            start_times[name] = time.monotonic()
            time.sleep(0.05)
            return name, {"data": True}

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {
                pool.submit(mock_tool, "whois"): "whois",
                pool.submit(mock_tool, "shodan"): "shodan",
                pool.submit(mock_tool, "abuseipdb"): "abuseipdb",
            }
            for future in as_completed(futures):
                future.result()

        # All should have started within 20ms of each other (concurrent)
        times = list(start_times.values())
        assert max(times) - min(times) < 0.05  # Started nearly simultaneously


class TestPhase0bPattern:
    """Test the parallel DNS discovery pattern from phase0.py."""

    def test_subdomain_results_merged(self):
        """Subdomains from multiple tools should be merged."""
        def crtsh():
            return ["sub1.example.com", "sub2.example.com"]

        def subfinder():
            return ["sub2.example.com", "sub3.example.com"]

        def amass():
            return ["sub4.example.com"]

        all_subdomains = set()
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(crtsh), pool.submit(subfinder), pool.submit(amass)]
            for future in as_completed(futures):
                subs = future.result()
                all_subdomains.update(subs)

        assert len(all_subdomains) == 4  # Deduped
        assert "sub2.example.com" in all_subdomains


class TestMultiHostPattern:
    """Test the parallel host scanning pattern from worker.py."""

    def test_host_results_preserve_order(self):
        """Results should be assigned to correct host indices."""
        def scan_host(idx, ip):
            time.sleep(0.01 * (5 - idx))  # Varying completion order
            return idx, {"ip": ip, "tools_run": ["nmap"]}

        results = [None] * 5
        ips = ["1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4", "1.2.3.5"]

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {pool.submit(scan_host, i, ip): i for i, ip in enumerate(ips)}
            for future in as_completed(futures):
                idx, result = future.result()
                results[idx] = result

        for i, ip in enumerate(ips):
            assert results[i]["ip"] == ip

    def test_failed_host_doesnt_block_others(self):
        """One host failure should not prevent other hosts from completing."""
        def scan_host(idx, ip):
            if idx == 2:
                raise RuntimeError(f"Host {ip} unreachable")
            return idx, {"ip": ip, "ok": True}

        results = [None] * 4
        ips = ["1.0.0.1", "1.0.0.2", "1.0.0.3", "1.0.0.4"]

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {pool.submit(scan_host, i, ip): i for i, ip in enumerate(ips)}
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    _, result = future.result()
                    results[idx] = result
                except RuntimeError:
                    results[idx] = {"ip": ips[idx], "skipped": True}

        assert results[0]["ok"] is True
        assert results[2]["skipped"] is True
        assert results[3]["ok"] is True

    def test_max_parallel_respected(self):
        """Should not exceed max_workers limit."""
        active = []
        max_active = [0]

        def scan_host(idx):
            import threading
            active.append(threading.current_thread().name)
            current = len(set(active))
            if current > max_active[0]:
                max_active[0] = current
            time.sleep(0.02)
            return idx, {}

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(scan_host, i) for i in range(5)]
            for f in as_completed(futures):
                f.result()

        # ThreadPoolExecutor with max_workers=2 should use at most 2 threads
        assert max_active[0] <= 2
