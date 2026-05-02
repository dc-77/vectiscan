"""SSLMate certspotter API — alternativer Cert-Transparency-Provider.

Wird als Fallback fuer crt.sh genutzt: crt.sh ist notorisch instabil
(HTTP 502/timeout, Tagesform-abhaengig). certspotter ist seit Jahren
zuverlaessig und liefert dieselbe Klasse von Daten (Subdomains aus
SSL-Zertifikaten in CT-Logs).

Endpoint: https://api.certspotter.com/v1/issuances?domain=<d>&include_subdomains=true&expand=dns_names
- Ohne API-Key: 100 req/h pro IP — fuer unseren Scan-Worker (1 Call pro
  Order) reicht das mit ~10x Headroom.
- Mit API-Key (`CERTSPOTTER_API_KEY` ENV): 2500 req/h.

Returns: list[str] — alle gefundenen Subdomains der Domain (lowercase,
ohne Wildcards `*.`-Prefix, dedupliziert + sortiert).
"""

from __future__ import annotations

import os
from typing import Any

from scanner.passive.base_client import PassiveClient


class CertSpotterClient(PassiveClient):
    name = "certspotter"
    BASE_URL = "https://api.certspotter.com/v1/issuances"

    def __init__(self) -> None:
        super().__init__(api_key=os.environ.get("CERTSPOTTER_API_KEY"))

    def get_subdomains(self, domain: str) -> list[str]:
        """Hole alle Subdomains aus CT-Issuances fuer `domain`.

        Bei Fehler: leere Liste (PassiveClient garantiert "kein Throw").
        """
        params: dict[str, Any] = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        }
        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        data = self._get(self.BASE_URL, params=params, headers=headers)
        if not data or not isinstance(data, list):
            return []

        domain_l = domain.lower()
        seen: set[str] = set()
        for issuance in data:
            for name in issuance.get("dns_names", []) or []:
                n = (name or "").strip().lower().lstrip("*.")
                if n and (n == domain_l or n.endswith("." + domain_l)):
                    seen.add(n)
        return sorted(seen)


__all__ = ["CertSpotterClient"]
