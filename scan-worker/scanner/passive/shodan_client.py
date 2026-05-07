"""Shodan API client — passive port/service intelligence."""

import os
from typing import Any

import requests
import structlog

from scanner.passive.base_client import PassiveClient

log = structlog.get_logger()


class ShodanClient(PassiveClient):
    """Query Shodan for known open ports, services, and banners.

    Uses two endpoints:
    1. /dns/domain/{domain} — discover subdomains and IPs
    2. /shodan/host/{ip} — open ports, services, versions per IP
    """

    name = "shodan"
    BASE_URL = "https://api.shodan.io"

    def __init__(self):
        api_key = os.environ.get("SHODAN_API_KEY")
        super().__init__(api_key=api_key, timeout=10)

    def lookup_domain(self, domain: str) -> dict[str, Any] | None:
        """Fetch DNS records and subdomains for a domain."""
        if not self.available:
            return None

        data = self._get(
            f"{self.BASE_URL}/dns/domain/{domain}",
            params={"key": self.api_key},
        )
        if not data:
            return None

        log.info("shodan_domain_lookup", domain=domain,
                 subdomains=len(data.get("subdomains", [])))
        return {
            "domain": domain,
            "subdomains": data.get("subdomains", []),
            "records": data.get("data", []),
        }

    def request_scan(self, ips: list[str]) -> str | None:
        """Trigger Shodan on-demand scan for IPs (F-P0A-006).

        POST /shodan/scan with form-encoded `ips=<csv>` — returns the
        scan_id when accepted. Used as Pre-Warm before a scheduled
        Subscription-Re-Scan or for opt-in One-Off-Orders, so Phase 0a
        sees fresh Shodan-Daten 24-48h spaeter.

        Args:
            ips: List of IPv4 addresses (max 50, caller-capped). Empty
                 list returns None without API contact.

        Returns:
            scan_id string on success, None on failure or no API key.

        Failure-Mode: returns None on any HTTP error. Callers should
        treat this as best-effort fire-and-forget — Phase 0a degrades
        gracefully to the existing cached Shodan-Daten.
        """
        if not self.available:
            log.info("shodan_request_scan_skipped", reason="no_api_key")
            return None
        if not ips:
            log.info("shodan_request_scan_skipped", reason="no_ips")
            return None

        # Cap defensiv (caller sollte bereits gecappt haben).
        capped = list(ips)[:50]
        ip_csv = ",".join(capped)

        try:
            resp = self.session.post(
                f"{self.BASE_URL}/shodan/scan",
                params={"key": self.api_key},
                data={"ips": ip_csv},
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            log.warning("shodan_request_scan_error", error=str(e), ip_count=len(capped))
            return None

        if resp.status_code >= 400:
            log.warning("shodan_request_scan_http_error",
                        status=resp.status_code, ip_count=len(capped))
            return None

        try:
            data = resp.json()
        except ValueError:
            log.warning("shodan_request_scan_json_decode_error")
            return None

        scan_id = data.get("id")
        if scan_id:
            log.info("shodan_request_scan_submitted",
                     scan_id=scan_id, ip_count=len(capped),
                     credits_left=data.get("credits_left"))
            return str(scan_id)

        log.warning("shodan_request_scan_no_id", response=data)
        return None

    def lookup_host(self, ip: str) -> dict[str, Any] | None:
        """Fetch open ports, services, and banners for an IP."""
        if not self.available:
            return None

        data = self._get(
            f"{self.BASE_URL}/shodan/host/{ip}",
            params={"key": self.api_key},
        )
        if not data:
            return None

        services = []
        for item in data.get("data", []):
            services.append({
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
                "banner": (item.get("data", "") or "")[:200],
                "module": item.get("_shodan", {}).get("module", ""),
            })

        result = {
            "ip": ip,
            "ports": data.get("ports", []),
            "os": data.get("os"),
            "tags": data.get("tags", []),
            "last_update": data.get("last_update"),
            "hostnames": data.get("hostnames", []),
            "services": services,
        }

        log.info("shodan_host_lookup", ip=ip, ports=len(result["ports"]),
                 services=len(services))
        return result
