"""Gemeinsame Fixtures fuer die ZAP-Integrationstests (S0b).

Die Tests laufen nur mit ``ZAP_IT=1`` und gegen die Umgebung aus
``docker-compose.zap-it.yml``. Ohne die Variable ueberspringt pytest sie,
damit ``pytest`` in der CI-Pipeline ohne Docker gruen bleibt
(.gitlab-ci.yml ruft pytest ohne Marker-Filter auf).
"""

from __future__ import annotations

import os

import pytest

# Vorgabe sind die Containernamen: die Tests laufen im Compose-Netz
# (Dienst "runner"), nicht auf dem Host. ZAP bedient seine API nur, wenn der
# Host-Header zum eigenen Listener passt, und vom Host aus stimmt der Port
# nicht ueberein (18090 gegen 8090) -- ZAP antwortet dann mit 502.
ZAP_A_URL = os.environ.get("ZAP_IT_A_URL", "http://zap-a:8090")
ZAP_B_URL = os.environ.get("ZAP_IT_B_URL", "http://zap-b:8090")
REDIS_URL = os.environ.get("ZAP_IT_REDIS_URL", "redis://redis:6379")
TARGET_URL = os.environ.get("ZAP_IT_TARGET_URL", "http://target:8080")

pytestmark = pytest.mark.integration


def _enabled() -> bool:
    return os.environ.get("ZAP_IT", "").lower() in ("1", "true", "yes")


requires_zap_it = pytest.mark.skipif(
    not _enabled(),
    reason="ZAP-Integrationstest: ZAP_IT=1 setzen und docker-compose.zap-it.yml starten",
)


@pytest.fixture(scope="session")
def zap_a():
    from scanner.tools.zap_client import ZapClient
    client = ZapClient(base_url=ZAP_A_URL)
    if not client.health_check():
        pytest.skip(f"ZAP-Instanz A nicht erreichbar: {ZAP_A_URL}")
    return client


@pytest.fixture(scope="session")
def zap_b():
    from scanner.tools.zap_client import ZapClient
    client = ZapClient(base_url=ZAP_B_URL)
    if not client.health_check():
        pytest.skip(f"ZAP-Instanz B nicht erreichbar: {ZAP_B_URL}")
    return client
