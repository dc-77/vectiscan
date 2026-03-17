"""Shodan API client — passive port/service intelligence."""

import os
from typing import Any

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
