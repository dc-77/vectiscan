"""SecurityTrails API client — historical DNS intelligence."""

import os
from typing import Any

import structlog

from scanner.passive.base_client import PassiveClient

log = structlog.get_logger()


class SecurityTrailsClient(PassiveClient):
    """Query SecurityTrails for domain details, subdomains, and DNS history."""

    name = "securitytrails"
    BASE_URL = "https://api.securitytrails.com/v1"

    def __init__(self):
        api_key = os.environ.get("SECURITYTRAILS_API_KEY")
        super().__init__(api_key=api_key, timeout=10)

    def _st_get(self, path: str) -> dict[str, Any] | None:
        """SecurityTrails GET with API key header."""
        return self._get(
            f"{self.BASE_URL}{path}",
            headers={"apikey": self.api_key, "Accept": "application/json"},
        )

    def lookup_domain(self, domain: str) -> dict[str, Any] | None:
        """Fetch current DNS records for a domain."""
        if not self.available:
            return None

        data = self._st_get(f"/domain/{domain}")
        if not data:
            return None

        current = data.get("current_dns", {})
        result = {
            "domain": domain,
            "alexa_rank": data.get("alexa_rank"),
            "hostname": data.get("hostname"),
            "a_records": [r.get("ip") for r in current.get("a", {}).get("values", [])],
            "mx_records": [r.get("hostname") for r in current.get("mx", {}).get("values", [])],
            "ns_records": [r.get("nameserver") for r in current.get("ns", {}).get("values", [])],
            "txt_records": [r.get("value") for r in current.get("txt", {}).get("values", [])],
        }

        log.info("securitytrails_domain", domain=domain,
                 a_records=len(result["a_records"]))
        return result

    def get_subdomains(self, domain: str) -> list[str]:
        """Fetch known subdomains for a domain."""
        if not self.available:
            return []

        data = self._st_get(f"/domain/{domain}/subdomains")
        if not data:
            return []

        subs = data.get("subdomains", [])
        log.info("securitytrails_subdomains", domain=domain, count=len(subs))
        return [f"{s}.{domain}" for s in subs]

    def get_dns_history(self, domain: str, record_type: str = "a") -> list[dict[str, Any]]:
        """Fetch DNS history (IP changes over time)."""
        if not self.available:
            return []

        data = self._st_get(f"/history/{domain}/dns/{record_type}")
        if not data:
            return []

        records = data.get("records", [])
        history = []
        for r in records[:20]:  # Limit to 20 most recent
            history.append({
                "first_seen": r.get("first_seen"),
                "last_seen": r.get("last_seen"),
                "values": [v.get("ip", v.get("ip_count", "")) for v in r.get("values", [])],
                "type": record_type,
            })

        log.info("securitytrails_history", domain=domain,
                 type=record_type, entries=len(history))
        return history
