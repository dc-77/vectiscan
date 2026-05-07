"""GreyNoise Community API client — Internet background-noise IP classification.

GreyNoise classifies IPs that scan the entire Internet (background noise),
benign infrastructure (RIOT — Rule It Out), or known malicious actors. The
Community endpoint (`/v3/community/<ip>`) is keyless but rate-limited; if a
`GREYNOISE_API_KEY` is set we send it for higher quotas.
"""

import os
from typing import Any

import structlog

from scanner.passive.base_client import PassiveClient

log = structlog.get_logger()


class GreyNoiseClient(PassiveClient):
    """Query GreyNoise Community API for IP classification."""

    name = "greynoise"
    BASE_URL = "https://api.greynoise.io/v3/community"

    def __init__(self):
        api_key = os.environ.get("GREYNOISE_API_KEY")
        super().__init__(api_key=api_key, timeout=10)

    @property
    def available(self) -> bool:
        """Community endpoint works without a key — always available."""
        return True

    def lookup_ip(self, ip: str) -> dict[str, Any] | None:
        """Look up an IPv4 / IPv6 at GreyNoise Community.

        Returns:
            Dict with keys: ip, noise (bool), riot (bool), classification
            (`benign`|`malicious`|`unknown`), name, link, last_seen, message.
            None on transport / parse errors.
        """
        if not ip or not ip.strip():
            return None

        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["key"] = self.api_key

        data = self._get(f"{self.BASE_URL}/{ip.strip()}", headers=headers)
        if not data:
            return None

        # Community endpoint returns 404 for IPs it has never seen — _get
        # returns None for >=400, so any data here is a real hit.
        result = {
            "ip": data.get("ip", ip),
            "noise": bool(data.get("noise", False)),
            "riot": bool(data.get("riot", False)),
            "classification": data.get("classification") or "unknown",
            "name": data.get("name"),
            "link": data.get("link"),
            "last_seen": data.get("last_seen"),
            "message": data.get("message"),
        }
        log.info(
            "greynoise_ip_lookup",
            ip=ip,
            classification=result["classification"],
            noise=result["noise"],
            riot=result["riot"],
        )
        return result
