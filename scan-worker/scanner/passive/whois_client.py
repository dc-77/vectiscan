"""WHOIS client — domain registrar data, expiry, DNSSEC status."""

import json
import subprocess
from typing import Any

import structlog

from scanner.passive.base_client import PassiveClient

log = structlog.get_logger()


class WhoisClient(PassiveClient):
    """Query WHOIS for domain registration details."""

    name = "whois"

    def __init__(self):
        super().__init__(api_key="n/a", timeout=30)

    @property
    def available(self) -> bool:
        return True  # WHOIS is always available (public protocol)

    def lookup(self, domain: str) -> dict[str, Any] | None:
        """Run whois query and parse key fields."""
        try:
            proc = subprocess.run(
                ["whois", domain],
                capture_output=True, text=True, timeout=30,
            )
            raw = proc.stdout
            if not raw or proc.returncode != 0:
                log.warning("whois_failed", domain=domain,
                            returncode=proc.returncode)
                return None

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            log.warning("whois_error", domain=domain, error=str(e))
            return None

        result: dict[str, Any] = {
            "domain": domain,
            "raw_length": len(raw),
        }

        # Parse key fields from raw output
        for line in raw.splitlines():
            line_lower = line.lower().strip()
            parts = line.split(":", 1)
            if len(parts) != 2:
                continue
            key = parts[0].strip().lower()
            value = parts[1].strip()

            if not value:
                continue

            if key in ("registrar", "registrar name"):
                result["registrar"] = value
            elif key in ("creation date", "created"):
                result["creation_date"] = value
            elif key in ("registry expiry date", "expiry date", "paid-till"):
                result["expiration_date"] = value
            elif key in ("name server", "nserver"):
                result.setdefault("name_servers", []).append(value.lower().rstrip("."))
            elif key == "dnssec":
                result["dnssec"] = value
            elif key in ("registrant country", "country"):
                result.setdefault("registrant_country", value)

        log.info("whois_lookup", domain=domain,
                 registrar=result.get("registrar", "unknown"),
                 dnssec=result.get("dnssec", "unknown"))
        return result
