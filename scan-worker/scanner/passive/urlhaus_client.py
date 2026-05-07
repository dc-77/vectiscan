"""URLhaus (abuse.ch) client — host/domain compromise + malware-distribution detection.

URLhaus is a project by abuse.ch tracking malware-distribution URLs. The /v1/host/
endpoint accepts a host (domain or IP) via form-encoded POST and returns any
URLs known to host malicious content for that host.

Auth: An `Auth-Key` header is OPTIONAL. abuse.ch recommends signing up for a
free API key (sets higher rate-limits) but the API works key-less. We honor an
`URLHAUS_API_KEY` ENV but the client is `available` regardless.
"""

import os
from typing import Any

import structlog

from scanner.passive.base_client import PassiveClient

log = structlog.get_logger()


class URLhausClient(PassiveClient):
    """Query URLhaus for known malware-distribution URLs on a host."""

    name = "urlhaus"
    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self):
        api_key = os.environ.get("URLHAUS_API_KEY")
        super().__init__(api_key=api_key, timeout=10)

    @property
    def available(self) -> bool:
        """URLhaus is open — always available; key only affects rate-limits."""
        return True

    def lookup_host(self, host: str) -> dict[str, Any] | None:
        """Look up a host (domain or IP) at URLhaus.

        Returns:
            Parsed response dict with at least:
              - query_status: "ok" | "no_results" | "invalid_host" | ...
              - urls: list of URL entries (only if query_status == "ok")
              - blacklists: dict of blacklist hits (Spamhaus DBL, SURBL, ...)
              - firstseen, urlhaus_reference, ...
            None on transport / parse errors.
        """
        if not host or not host.strip():
            return None

        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        data = self._post(
            f"{self.BASE_URL}/host/",
            data={"host": host.strip()},
            headers=headers,
        )
        if not data:
            return None

        status = (data.get("query_status") or "").lower()
        urls = data.get("urls") or []
        log.info(
            "urlhaus_host_lookup",
            host=host,
            status=status,
            url_count=len(urls) if isinstance(urls, list) else 0,
        )
        return data

    def is_compromised(self, response: dict[str, Any] | None) -> bool:
        """True iff URLhaus returned an `ok` query with at least one URL entry."""
        if not response or not isinstance(response, dict):
            return False
        if (response.get("query_status") or "").lower() != "ok":
            return False
        urls = response.get("urls")
        return isinstance(urls, list) and len(urls) > 0
