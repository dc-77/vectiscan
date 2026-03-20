"""MITRE CWE REST API client with Redis caching.

Validates CWE existence and fetches metadata (name, description,
likelihood of exploit) from the official MITRE database.
Graceful degradation: network errors never crash the pipeline.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Optional

import redis
import requests
import structlog

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# Redis cache helpers (same pattern as threat_intel.py)
# ---------------------------------------------------------------------------

def _get_redis() -> redis.Redis:
    return redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379"))


def _cache_get(key: str) -> Optional[dict[str, Any]]:
    try:
        r = _get_redis()
        raw = r.get(key)
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    return None


def _cache_set(key: str, value: Any, ttl: int = 86400) -> None:
    try:
        r = _get_redis()
        r.set(key, json.dumps(value, default=str), ex=ttl)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# CWE API Client
# ---------------------------------------------------------------------------

class CWEAPIClient:
    """MITRE CWE REST API client.

    Free, no auth required. Uses /cwe/weakness/{ids} for batch lookups.
    """

    BASE_URL = "https://cwe-api.mitre.org/api/v1"

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "VectiScan/2.0"})
        self._last_request = 0.0
        self._min_interval = 0.15  # ~7 req/s conservative

    def _rate_limit(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()

    def lookup_batch(self, cwe_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Fetch multiple CWEs, falling back to individual lookups.

        The MITRE API returns 404 if ANY ID in a batch is invalid,
        so we try batch first, then fall back to per-ID lookups on 404.

        Args:
            cwe_ids: e.g. ["CWE-79", "CWE-200"]

        Returns:
            {cwe_id: {exists, name, description, likelihood}} per CWE.
        """
        if not cwe_ids:
            return {}

        results: dict[str, dict[str, Any]] = {}
        uncached: list[str] = []

        # 1. Check cache first
        for cwe_id in cwe_ids:
            num = cwe_id.replace("CWE-", "")
            cached = _cache_get(f"cwe:{num}")
            if cached is not None:
                results[cwe_id] = cached
            else:
                uncached.append(cwe_id)

        if not uncached:
            return results

        # 2. Try batch call first (works when all IDs are valid)
        if len(uncached) > 1:
            numeric_csv = ",".join(c.replace("CWE-", "") for c in uncached)
            batch_result = self._fetch_weaknesses(numeric_csv)
            if batch_result is not None:
                # Batch succeeded — all IDs are valid
                self._process_response(batch_result, uncached, results)
                return results
            # Batch returned 404 — at least one ID invalid, do individual lookups

        # 3. Individual lookups (single ID or fallback from failed batch)
        for cwe_id in uncached:
            if cwe_id in results:
                continue
            num = cwe_id.replace("CWE-", "")
            single_result = self._fetch_weaknesses(num)
            if single_result is not None:
                self._process_response(single_result, [cwe_id], results)
            else:
                # 404 or error — this specific CWE does not exist
                not_found: dict[str, Any] = {"exists": False}
                results[cwe_id] = not_found
                _cache_set(f"cwe:{num}", not_found)
                log.info("cwe_not_found_in_mitre", cwe=cwe_id)

        return results

    def _fetch_weaknesses(self, numeric_ids: str) -> dict[str, Any] | None:
        """GET /cwe/weakness/{ids}. Returns parsed JSON or None on error."""
        self._rate_limit()
        try:
            resp = self.session.get(
                f"{self.BASE_URL}/cwe/weakness/{numeric_ids}",
                timeout=10,
            )
            if resp.status_code == 429:
                log.warning("cwe_api_rate_limited")
                return None
            if resp.status_code != 200:
                return None
            return resp.json()
        except requests.RequestException as e:
            log.warning("cwe_api_request_error", error=str(e))
        except Exception as e:
            log.warning("cwe_api_parse_error", error=str(e))
        return None

    def _process_response(
        self,
        data: dict[str, Any],
        requested: list[str],
        results: dict[str, dict[str, Any]],
    ) -> None:
        """Parse API response and update results + cache."""
        returned_ids: set[str] = set()
        for w in data.get("Weaknesses", []):
            cwe_num = str(w.get("ID", ""))
            cwe_id = f"CWE-{cwe_num}"
            parsed = {
                "exists": True,
                "name": w.get("Name", ""),
                "description": (w.get("Description", "") or "")[:300],
                "likelihood": w.get("LikelihoodOfExploit", ""),
            }
            results[cwe_id] = parsed
            returned_ids.add(cwe_id)
            _cache_set(f"cwe:{cwe_num}", parsed)
