"""ZAP daemon REST API client with context-based session isolation.

Communicates with OWASP ZAP running as a daemon container on port 8090.
Each scan gets its own ZAP context (named ctx-{order_id[:8]}-{ip}) so that
multiple scan-worker replicas can share one ZAP instance without interference.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Callable, Optional

import requests
import structlog

log = structlog.get_logger()

ZAP_BASE_URL = os.environ.get("ZAP_BASE_URL", "http://zap:8090")
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 30

# Thread-local pool assignment: worker.py leases a zap_id for the duration
# of a host scan and stores it here. ZapClient() (no args) reads it as
# fallback so every existing call site picks up the right daemon without
# signature changes.
_thread_local = threading.local()


def set_thread_zap_id(zap_id: str | None) -> None:
    """Set the ZAP daemon for the current thread. ``None`` clears it."""
    _thread_local.zap_id = zap_id


def get_thread_zap_id() -> str | None:
    return getattr(_thread_local, "zap_id", None)


class ZapError(Exception):
    """Raised when a ZAP API call fails or times out."""


class ZapClient:
    """ZAP daemon REST API client with context-based session isolation."""

    def __init__(
        self,
        base_url: str | None = None,
        zap_id: str | None = None,
    ):
        """Connect to a ZAP daemon.

        Precedence: explicit ``base_url`` > explicit ``zap_id`` > thread-local
        ``zap_id`` (set by the pool-leased worker task) > env ``ZAP_BASE_URL``
        (legacy single-daemon fallback).
        """
        effective_zap_id = zap_id or get_thread_zap_id()
        if base_url:
            resolved = base_url
        elif effective_zap_id:
            resolved = f"http://{effective_zap_id}:8090"
        else:
            resolved = ZAP_BASE_URL
        self.base_url = resolved.rstrip("/")
        self.zap_id = effective_zap_id
        self.session = requests.Session()
        self.session.headers["Accept"] = "application/json"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET request to ZAP API. Returns parsed JSON response."""
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.get(
                url, params=params or {},
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )
            resp.raise_for_status()
            return resp.json()
        except requests.ConnectionError as e:
            raise ZapError(f"ZAP unreachable at {self.base_url}: {e}") from e
        except requests.Timeout as e:
            raise ZapError(f"ZAP request timed out: {path}") from e
        except requests.HTTPError as e:
            raise ZapError(f"ZAP API error {resp.status_code}: {resp.text[:200]}") from e
        except ValueError as e:
            raise ZapError(f"ZAP returned invalid JSON: {path}") from e

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health_check(self) -> bool:
        """Check if ZAP daemon is responsive. Returns True/False, never raises."""
        try:
            data = self._get("/JSON/core/view/version/")
            version = data.get("version", "unknown")
            log.info("zap_health_ok", version=version)
            return True
        except ZapError:
            log.warning("zap_health_failed", base_url=self.base_url)
            return False

    def get_version(self) -> str:
        """Return ZAP version string."""
        data = self._get("/JSON/core/view/version/")
        return data.get("version", "unknown")

    # ------------------------------------------------------------------
    # Context Management
    # ------------------------------------------------------------------

    def create_context(self, context_name: str) -> int:
        """Create a new ZAP context. Returns the context ID."""
        data = self._get("/JSON/context/action/newContext/", {"contextName": context_name})
        context_id = int(data.get("contextId", 0))
        log.info("zap_context_created", name=context_name, id=context_id)
        return context_id

    def include_in_context(self, context_name: str, regex: str) -> None:
        """Add a URL regex pattern to the context scope."""
        self._get("/JSON/context/action/includeInContext/", {
            "contextName": context_name,
            "regex": regex,
        })

    def remove_context(self, context_name: str) -> None:
        """Remove a context and all its data."""
        try:
            self._get("/JSON/context/action/removeContext/", {"contextName": context_name})
            log.info("zap_context_removed", name=context_name)
        except ZapError as e:
            log.warning("zap_context_remove_failed", name=context_name, error=str(e))

    def get_context_list(self) -> list[str]:
        """List all context names that currently exist on the ZAP daemon."""
        data = self._get("/JSON/context/view/contextList/")
        raw = data.get("contextList", [])
        # ZAP historically returns the list as a JSON-encoded string with brackets;
        # modern builds return a proper list. Normalize both shapes.
        if isinstance(raw, str):
            stripped = raw.strip().lstrip("[").rstrip("]")
            if not stripped:
                return []
            return [p.strip().strip('"').strip("'") for p in stripped.split(",") if p.strip()]
        return [str(entry) for entry in raw]

    def delete_context(self, context_name: str) -> None:
        """Alias for ``remove_context`` used by the pool-cleanup path."""
        self.remove_context(context_name)

    def cleanup_stale_contexts(self, active_context_names: set[str]) -> int:
        """Remove all ``ctx-*`` contexts that are not in ``active_context_names``.

        Called at the start of every pool lease so a worker never inherits
        contexts from a previous (crashed) lease on the same ZAP daemon.
        Non-``ctx-`` contexts (default, manually created) are left alone.
        """
        deleted = 0
        try:
            contexts = self.get_context_list()
        except ZapError as e:
            log.warning("zap_context_list_failed", error=str(e))
            return 0
        for ctx_name in contexts:
            if not ctx_name.startswith("ctx-"):
                continue
            if ctx_name in active_context_names:
                continue
            self.delete_context(ctx_name)
            deleted += 1
        if deleted:
            log.info("zap_cleanup_performed", zap_id=self.zap_id, stale_contexts_deleted=deleted)
        return deleted

    # ------------------------------------------------------------------
    # Traditional Spider
    # ------------------------------------------------------------------

    def start_spider(
        self,
        url: str,
        context_name: str | None = None,
        max_depth: int = 5,
    ) -> int:
        """Start the traditional spider. Returns scan ID."""
        params: dict[str, Any] = {"url": url, "maxChildren": 0, "recurse": "true"}
        if context_name:
            params["contextName"] = context_name
        data = self._get("/JSON/spider/action/scan/", params)
        scan_id = int(data.get("scan", 0))
        log.info("zap_spider_started", url=url, scan_id=scan_id, max_depth=max_depth)

        # Set max depth
        self._get("/JSON/spider/action/setOptionMaxDepth/", {"Integer": str(max_depth)})
        return scan_id

    def spider_status(self, scan_id: int) -> int:
        """Get spider progress (0-100)."""
        data = self._get("/JSON/spider/view/status/", {"scanId": str(scan_id)})
        return int(data.get("status", 0))

    def spider_results(self, scan_id: int) -> list[str]:
        """Get list of URLs discovered by the spider."""
        data = self._get("/JSON/spider/view/results/", {"scanId": str(scan_id)})
        return data.get("results", [])

    # ------------------------------------------------------------------
    # AJAX Spider
    # ------------------------------------------------------------------

    def start_ajax_spider(self, url: str, context_name: str | None = None) -> None:
        """Start the AJAX spider (headless browser crawl)."""
        params: dict[str, Any] = {"url": url}
        if context_name:
            params["contextName"] = context_name
        self._get("/JSON/ajaxSpider/action/scan/", params)
        log.info("zap_ajax_spider_started", url=url)

    def ajax_spider_status(self) -> str:
        """Get AJAX spider status: 'running' or 'stopped'."""
        data = self._get("/JSON/ajaxSpider/view/status/")
        return data.get("status", "stopped")

    def stop_ajax_spider(self) -> None:
        """Stop the AJAX spider."""
        self._get("/JSON/ajaxSpider/action/stop/")
        log.info("zap_ajax_spider_stopped")

    # ------------------------------------------------------------------
    # Passive Scanner
    # ------------------------------------------------------------------

    def wait_for_passive_scan(self, timeout: int = 30) -> bool:
        """Wait for ZAP passive scanner queue to drain.

        The passive scanner runs automatically on all traffic (spider, active scan).
        After spider/active scan completes, there may still be items queued.
        Call this before collecting alerts to ensure passive findings are included.
        """
        return self.poll_until_complete(
            lambda: int(self._get("/JSON/pscan/view/recordsToScan/").get("recordsToScan", "0")),
            timeout=timeout, interval=3, stop_value=0,
            tool_name="zap_passive_wait",
        )

    # ------------------------------------------------------------------
    # Active Scan
    # ------------------------------------------------------------------

    def start_active_scan(
        self,
        url: str,
        context_id: int | None = None,
        scan_policy: str | None = None,
    ) -> int:
        """Start active scan. Returns scan ID."""
        params: dict[str, Any] = {"url": url, "recurse": "true"}
        if context_id is not None:
            params["contextId"] = str(context_id)
        if scan_policy:
            params["scanPolicyName"] = scan_policy
        data = self._get("/JSON/ascan/action/scan/", params)
        scan_id = int(data.get("scan", 0))
        log.info("zap_active_scan_started", url=url, scan_id=scan_id, policy=scan_policy)
        return scan_id

    def active_scan_status(self, scan_id: int) -> int:
        """Get active scan progress (0-100)."""
        data = self._get("/JSON/ascan/view/status/", {"scanId": str(scan_id)})
        return int(data.get("status", 0))

    def stop_active_scan(self, scan_id: int) -> None:
        """Stop an active scan."""
        self._get("/JSON/ascan/action/stop/", {"scanId": str(scan_id)})
        log.info("zap_active_scan_stopped", scan_id=scan_id)

    # ------------------------------------------------------------------
    # Scan Policy & Rate Config
    # ------------------------------------------------------------------

    # Active scan category → ZAP scanner IDs (groups)
    # See: https://www.zaproxy.org/docs/alerts/
    CATEGORY_SCANNER_IDS: dict[str, list[int]] = {
        "sqli": [40018, 40019, 40020, 40021, 40022, 40024],
        "xss": [40012, 40014, 40016, 40017],
        "lfi": [6, 40009],        # Path Traversal + SSRF overlap
        "rfi": [7],               # Remote File Inclusion
        "ssrf": [40046],          # Server Side Request Forgery
        "cmdi": [90020],          # Remote OS Command Injection
        "xxe": [90023],           # XML External Entity
        "crlf": [40003],          # CRLF Injection
        "pathtraversal": [6],     # Path Traversal
        "headerinjection": [40003, 10054],
        "defaultlogin": [10010],  # Default credentials
    }

    # Forbidden categories — NEVER enable these
    FORBIDDEN_SCANNERS: set[int] = {
        # DoS scanners
        40032,  # .htaccess as source
        # Buffer overflow
        30001, 30002,
        # Fuzzer categories — too noisy, too slow
        40033, 40034,
    }

    def create_scan_policy(
        self,
        name: str,
        categories: list[str],
        policy_type: str = "standard",
    ) -> None:
        """Create a custom active scan policy.

        policy_type: "waf-safe"|"standard"|"aggressive"
        categories: list of category names from CATEGORY_SCANNER_IDS
        """
        # Create base policy
        self._get("/JSON/ascan/action/addScanPolicy/", {"scanPolicyName": name})

        # Disable all scanners first
        self._get("/JSON/ascan/action/disableAllScanners/", {"scanPolicyName": name})

        # Enable only requested categories
        enabled_ids: set[int] = set()
        for cat in categories:
            ids = self.CATEGORY_SCANNER_IDS.get(cat, [])
            enabled_ids.update(ids)

        # Remove forbidden scanners
        enabled_ids -= self.FORBIDDEN_SCANNERS

        if enabled_ids:
            ids_str = ",".join(str(i) for i in sorted(enabled_ids))
            self._get("/JSON/ascan/action/enableScanners/", {
                "ids": ids_str,
                "scanPolicyName": name,
            })

        # Set strength based on policy type
        strength_map = {"waf-safe": "LOW", "standard": "MEDIUM", "aggressive": "HIGH"}
        strength = strength_map.get(policy_type, "MEDIUM")
        threshold_map = {"waf-safe": "HIGH", "standard": "MEDIUM", "aggressive": "LOW"}
        threshold = threshold_map.get(policy_type, "MEDIUM")

        # Set attack strength and alert threshold for all enabled scanners
        for scanner_id in enabled_ids:
            try:
                self._get("/JSON/ascan/action/setScannerAttackStrength/", {
                    "id": str(scanner_id),
                    "attackStrength": strength,
                    "scanPolicyName": name,
                })
                self._get("/JSON/ascan/action/setScannerAlertThreshold/", {
                    "id": str(scanner_id),
                    "alertThreshold": threshold,
                    "scanPolicyName": name,
                })
            except ZapError:
                pass  # Some scanners don't support strength/threshold

        log.info("zap_scan_policy_created", name=name, policy_type=policy_type,
                 categories=categories, enabled_scanners=len(enabled_ids))

    def remove_scan_policy(self, name: str) -> None:
        """Remove a scan policy."""
        try:
            self._get("/JSON/ascan/action/removeScanPolicy/", {"scanPolicyName": name})
        except ZapError:
            pass

    def configure_rate_limit(
        self,
        req_per_sec: int = 80,
        threads: int = 5,
        delay_ms: int = 0,
    ) -> None:
        """Configure ZAP rate limiting for WAF-safe scanning."""
        try:
            # Spider thread count
            self._get("/JSON/spider/action/setOptionThreadCount/", {
                "Integer": str(threads),
            })
            # Spider delay
            if delay_ms > 0:
                self._get("/JSON/spider/action/setOptionPostForm/", {
                    "Boolean": "false",  # Disable form posting when throttled
                })
            # Active scan threads per host
            self._get("/JSON/ascan/action/setOptionThreadPerHost/", {
                "Integer": str(threads),
            })
            # Active scan delay in ms
            self._get("/JSON/ascan/action/setOptionDelayInMs/", {
                "Integer": str(delay_ms),
            })
            log.info("zap_rate_configured", req_per_sec=req_per_sec,
                     threads=threads, delay_ms=delay_ms)
        except ZapError as e:
            log.warning("zap_rate_config_failed", error=str(e))

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def get_alerts(
        self,
        base_url: str = "",
        context_name: str = "",
        start: int = 0,
        count: int = 5000,
    ) -> list[dict[str, Any]]:
        """Get all alerts, optionally filtered by base URL.

        Returns list of alert dicts from ZAP.
        """
        params: dict[str, Any] = {"start": str(start), "count": str(count)}
        if base_url:
            params["baseurl"] = base_url
        data = self._get("/JSON/alert/view/alerts/", params)
        alerts = data.get("alerts", [])
        log.info("zap_alerts_retrieved", count=len(alerts), base_url=base_url[:60] if base_url else "all")
        return alerts

    # ------------------------------------------------------------------
    # Generic Polling
    # ------------------------------------------------------------------

    def poll_until_complete(
        self,
        status_fn: Callable[[], int | str],
        timeout: int = 300,
        interval: int = 5,
        stop_value: int | str = 100,
        order_id: str = "",
        tool_name: str = "",
    ) -> bool:
        """Poll a status function until it returns stop_value or timeout.

        Returns True if completed, False if timed out.
        On timeout, does NOT raise — caller handles partial results.
        """
        start = time.monotonic()
        last_status: int | str = 0

        while True:
            elapsed = time.monotonic() - start
            if elapsed >= timeout:
                log.warning("zap_poll_timeout", tool=tool_name, timeout=timeout,
                            last_status=last_status)
                return False

            try:
                status = status_fn()
                last_status = status
            except ZapError as e:
                log.warning("zap_poll_error", tool=tool_name, error=str(e))
                return False

            if status == stop_value:
                log.info("zap_poll_complete", tool=tool_name,
                         elapsed_s=round(elapsed, 1))
                return True

            time.sleep(interval)
