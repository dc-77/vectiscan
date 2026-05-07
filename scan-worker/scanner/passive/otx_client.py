"""AlienVault OTX (Open Threat Exchange) client — domain reputation.

OTX exposes a free, key-less indicator API. We hit `general` for a quick
reputation summary (pulse counts, ASN, country, validation hints). An
`OTX_API_KEY` ENV is honored when present (sets X-OTX-API-KEY header) for
higher rate-limits, but the API works without it.
"""

import os
from typing import Any

import structlog

from scanner.passive.base_client import PassiveClient

log = structlog.get_logger()


class OTXClient(PassiveClient):
    """Query AlienVault OTX for domain / IP indicator data."""

    name = "otx"
    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self):
        api_key = os.environ.get("OTX_API_KEY")
        super().__init__(api_key=api_key, timeout=10)

    @property
    def available(self) -> bool:
        """OTX free tier works without a key — always available."""
        return True

    def _otx_get(self, path: str) -> dict[str, Any] | None:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key
        return self._get(f"{self.BASE_URL}{path}", headers=headers)

    def lookup_domain(self, domain: str) -> dict[str, Any] | None:
        """Fetch OTX `general` indicator data for a domain.

        Returns:
            Dict with keys: domain, pulse_count, pulses (list of pulse-summary
            dicts, capped at 5), validation, type, alexa_rank, whois.
            None on transport / parse errors.
        """
        if not domain or not domain.strip():
            return None

        data = self._otx_get(f"/domain/{domain.strip()}/general")
        if not data:
            return None

        pulse_info = data.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        pulse_count = pulse_info.get("count", len(pulses) if isinstance(pulses, list) else 0)

        # Keep payload compact for downstream AI / report use.
        compact_pulses = []
        if isinstance(pulses, list):
            for p in pulses[:5]:
                compact_pulses.append({
                    "name": p.get("name"),
                    "id": p.get("id"),
                    "tags": p.get("tags", [])[:8],
                    "modified": p.get("modified"),
                })

        result = {
            "domain": domain,
            "pulse_count": pulse_count,
            "pulses": compact_pulses,
            "validation": data.get("validation", []),
            "type": data.get("type"),
            "alexa_rank": data.get("alexa") or data.get("alexa_rank"),
            "whois": data.get("whois"),
        }
        log.info("otx_domain_lookup", domain=domain, pulse_count=pulse_count)
        return result

    def lookup_ip(self, ip: str) -> dict[str, Any] | None:
        """Fetch OTX `general` indicator data for an IPv4."""
        if not ip or not ip.strip():
            return None

        data = self._otx_get(f"/IPv4/{ip.strip()}/general")
        if not data:
            return None

        pulse_info = data.get("pulse_info") or {}
        pulse_count = pulse_info.get("count", 0)
        result = {
            "ip": ip,
            "pulse_count": pulse_count,
            "asn": data.get("asn"),
            "country_name": data.get("country_name"),
            "reputation": data.get("reputation"),
        }
        log.info("otx_ip_lookup", ip=ip, pulse_count=pulse_count)
        return result
