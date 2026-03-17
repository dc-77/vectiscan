"""Base class for external API clients with rate-limiting, retries, and caching."""

import os
import time
from typing import Any

import requests
import structlog

log = structlog.get_logger()

# Default timeouts
DEFAULT_TIMEOUT = 10  # seconds per request
DEFAULT_RETRIES = 2


class PassiveClient:
    """Base class for passive intelligence API clients.

    Provides:
    - Configurable timeouts and retries
    - Structured logging
    - Graceful degradation (returns None on failure, never raises)
    """

    name: str = "base"

    def __init__(self, api_key: str | None = None, timeout: int = DEFAULT_TIMEOUT):
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "VectiScan/2.0"})

    def _get(self, url: str, params: dict | None = None,
             headers: dict | None = None) -> dict[str, Any] | None:
        """HTTP GET with retries and error handling. Returns JSON or None."""
        for attempt in range(DEFAULT_RETRIES + 1):
            try:
                resp = self.session.get(
                    url, params=params, headers=headers,
                    timeout=self.timeout,
                )
                if resp.status_code == 429:
                    wait = min(2 ** attempt * 2, 30)
                    log.warning(f"{self.name}_rate_limited", wait=wait, attempt=attempt)
                    time.sleep(wait)
                    continue

                if resp.status_code >= 400:
                    log.warning(f"{self.name}_http_error",
                                status=resp.status_code, url=url)
                    return None

                return resp.json()

            except requests.Timeout:
                log.warning(f"{self.name}_timeout", url=url, attempt=attempt)
            except requests.RequestException as e:
                log.warning(f"{self.name}_request_error", error=str(e), attempt=attempt)
            except ValueError:
                log.warning(f"{self.name}_json_decode_error", url=url)
                return None

        return None

    @property
    def available(self) -> bool:
        """Whether this client has a valid API key configured."""
        return bool(self.api_key)
