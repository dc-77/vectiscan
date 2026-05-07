"""VirusTotal v3 API client — domain reputation.

Endpoint `/api/v3/domains/<domain>` returns the AV-engine voting summary
(`last_analysis_stats`), categorisation, popularity ranks, etc. Requires an
API key (free tier: 4 req/min, 500 req/day). If `VIRUSTOTAL_API_KEY` is not
set the client logs and returns None gracefully.
"""

import os
from typing import Any

import structlog

from scanner.passive.base_client import PassiveClient

log = structlog.get_logger()


class VirusTotalClient(PassiveClient):
    """Query VirusTotal v3 for domain / IP reputation."""

    name = "virustotal"
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        api_key = os.environ.get("VIRUSTOTAL_API_KEY")
        super().__init__(api_key=api_key, timeout=15)

    @property
    def available(self) -> bool:
        """VT requires an API key — strict gate."""
        return bool(self.api_key)

    def _vt_get(self, path: str) -> dict[str, Any] | None:
        if not self.available:
            log.warning("virustotal_skipped", reason="no_api_key")
            return None
        return self._get(
            f"{self.BASE_URL}{path}",
            headers={"x-apikey": self.api_key, "Accept": "application/json"},
        )

    def lookup_domain(self, domain: str) -> dict[str, Any] | None:
        """Fetch VT v3 `domains/<domain>` summary.

        Returns:
            Compact dict: domain, malicious, suspicious, harmless, undetected,
            timeout, total_engines, reputation, categories, last_analysis_date.
            None on transport / parse errors / missing key.
        """
        if not domain or not domain.strip():
            return None

        raw = self._vt_get(f"/domains/{domain.strip()}")
        if not raw:
            return None

        attrs = (raw.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        categories = attrs.get("categories") or {}
        total = sum(int(v or 0) for v in stats.values()) if stats else 0

        result = {
            "domain": domain,
            "malicious": int(stats.get("malicious", 0) or 0),
            "suspicious": int(stats.get("suspicious", 0) or 0),
            "harmless": int(stats.get("harmless", 0) or 0),
            "undetected": int(stats.get("undetected", 0) or 0),
            "timeout": int(stats.get("timeout", 0) or 0),
            "total_engines": total,
            "reputation": attrs.get("reputation"),
            "categories": dict(categories) if isinstance(categories, dict) else {},
            "last_analysis_date": attrs.get("last_analysis_date"),
        }
        log.info(
            "virustotal_domain_lookup",
            domain=domain,
            malicious=result["malicious"],
            suspicious=result["suspicious"],
            total_engines=total,
        )
        return result
