"""AbuseIPDB API client — IP reputation and abuse history."""

import os
from typing import Any

import structlog

from scanner.passive.base_client import PassiveClient

log = structlog.get_logger()


class AbuseIPDBClient(PassiveClient):
    """Query AbuseIPDB for IP reputation scores and abuse reports."""

    name = "abuseipdb"
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self):
        api_key = os.environ.get("ABUSEIPDB_API_KEY")
        super().__init__(api_key=api_key, timeout=10)

    def check_ip(self, ip: str, max_age_days: int = 90) -> dict[str, Any] | None:
        """Check IP reputation. Returns abuse confidence score (0-100)."""
        if not self.available:
            return None

        data = self._get(
            f"{self.BASE_URL}/check",
            params={
                "ipAddress": ip,
                "maxAgeInDays": str(max_age_days),
                "verbose": "true",
            },
            headers={
                "Key": self.api_key,
                "Accept": "application/json",
            },
        )
        if not data or "data" not in data:
            return None

        d = data["data"]
        result = {
            "ip": ip,
            "abuseConfidenceScore": d.get("abuseConfidenceScore", 0),
            "totalReports": d.get("totalReports", 0),
            "numDistinctUsers": d.get("numDistinctUsers", 0),
            "lastReportedAt": d.get("lastReportedAt"),
            "isWhitelisted": d.get("isWhitelisted", False),
            "countryCode": d.get("countryCode"),
            "usageType": d.get("usageType"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "isTor": d.get("isTor", False),
        }

        log.info("abuseipdb_check", ip=ip,
                 score=result["abuseConfidenceScore"],
                 reports=result["totalReports"])
        return result
