"""S0b: Reproduktion des Produktionsfehlers, mit echtem ZAP-Pool.

Aufruf im Compose-Netz (siehe docker-compose.zap-it.yml; vom Host aus
antwortet ZAP mit 502, weil der Host-Header nicht zum Listener passt):

    docker compose -f scan-worker/tests/integration/docker-compose.zap-it.yml \\
      run --rm runner sh -c "pip install --quiet requests redis structlog && \\
      python -m tests.integration.repro_zap_active"

Das Skript fuehrt drei Laeufe und schreibt ein Protokoll auf stdout:

1. ``pool-lease``   Lease ueber zap_pool.acquire_zap, danach alle vier
                    Schritte ueber die geleaste Instanz. So soll es sein.
2. ``split``        Kontext und Policy auf der geleasten Instanz, Active Scan
                    auf der anderen. Das ist der Produktionsfehler.
3. ``ids``          Welche Scanner-IDs aus CATEGORY_SCANNER_IDS dieses Image
                    nicht kennt.

Es wird ausschliesslich das eigene Testziel gescannt.
"""

from __future__ import annotations

import json
import os
import sys
import uuid

import redis

from scanner import zap_pool
from scanner.tools.zap_client import ZapClient, ZapError
from scanner.tools.zap_mapper import ZapAlertMapper

ZAP_A_URL = os.environ.get("ZAP_IT_A_URL", "http://zap-a:8090")
ZAP_B_URL = os.environ.get("ZAP_IT_B_URL", "http://zap-b:8090")
REDIS_URL = os.environ.get("ZAP_IT_REDIS_URL", "redis://redis:6379")
TARGET_URL = os.environ.get("ZAP_IT_TARGET_URL", "http://target:8080")
CATEGORIES = ["sqli", "xss", "lfi", "cmdi"]

URL_BY_MEMBER = {"zap-a": ZAP_A_URL, "zap-b": ZAP_B_URL}


def _client(member: str) -> ZapClient:
    return ZapClient(base_url=URL_BY_MEMBER[member])


def _other(member: str) -> str:
    return "zap-b" if member == "zap-a" else "zap-a"


def _spider(zap: ZapClient, context_name: str) -> list[str]:
    scan_id = zap.start_spider(TARGET_URL, context_name=context_name, max_depth=5)
    zap.poll_until_complete(
        lambda: zap.spider_status(scan_id),
        timeout=180, interval=3, stop_value=100, tool_name="zap_spider",
    )
    return zap.spider_results(scan_id)


def run_split(leased: str) -> dict:
    """Kontext und Policy auf A, Active Scan auf B. Erwartet: Fehler."""
    order_id = uuid.uuid4().hex
    ctx = zap_pool.build_context_name(order_id, "10.9.9.1")
    policy = zap_pool.build_policy_name(order_id, "10.9.9.1")
    owner, stranger = _client(leased), _client(_other(leased))
    out: dict = {"lauf": "split", "kontext_auf": leased, "scan_auf": _other(leased)}
    try:
        context_id = owner.create_context(ctx)
        owner.include_in_context(ctx, ".*target.*")
        out["spider_urls"] = len(_spider(owner, ctx))
        owner.create_scan_policy(policy, CATEGORIES, "standard")
        stranger.start_active_scan(TARGET_URL, context_id=context_id, scan_policy=policy)
        out["ergebnis"] = "kein Fehler (unerwartet)"
    except ZapError as e:
        out["ergebnis"] = "ZapError"
        out["endpoint"] = e.endpoint
        out["zap_code"] = e.zap_code
        out["http_status"] = e.http_status
        out["text"] = str(e)
    finally:
        owner.remove_scan_policy(policy)
        owner.remove_context(ctx)
    return out


def run_affine(leased: str) -> dict:
    """Alle vier Schritte auf der geleasten Instanz. Erwartet: Alerts."""
    order_id = uuid.uuid4().hex
    ctx = zap_pool.build_context_name(order_id, "10.9.9.2")
    policy = zap_pool.build_policy_name(order_id, "10.9.9.2")
    zap = _client(leased)
    out: dict = {"lauf": "pool-lease", "instanz": leased, "base_url": zap.base_url}
    try:
        context_id = zap.create_context(ctx)
        zap.include_in_context(ctx, ".*target.*")
        out["spider_urls"] = len(_spider(zap, ctx))
        enabled = zap.create_scan_policy(policy, CATEGORIES, "aggressive")
        out["enabled_scanners"] = sorted(enabled)
        out["dropped_scanners"] = zap.last_dropped_scanner_ids
        scan_id = zap.start_active_scan(TARGET_URL, context_id=context_id,
                                        scan_policy=policy)
        out["completed"] = zap.poll_until_complete(
            lambda: zap.active_scan_status(scan_id),
            timeout=600, interval=5, stop_value=100, tool_name="zap_active",
        )
        zap.wait_for_passive_scan(timeout=60)
        alerts = zap.get_alerts(base_url=TARGET_URL)
        findings = ZapAlertMapper().map_alerts(alerts, "10.9.9.2", "target")
        out["alerts"] = len(alerts)
        out["active_alerts"] = sum(1 for f in findings if f.get("tool") == "zap_active")
        out["alert_namen"] = sorted({str(a.get("name")) for a in alerts})
        out["ergebnis"] = "ok"
    except ZapError as e:
        out["ergebnis"] = "ZapError"
        out["endpoint"] = e.endpoint
        out["zap_code"] = e.zap_code
        out["text"] = str(e)
    finally:
        zap.remove_scan_policy(policy)
        zap.remove_context(ctx)
    return out


def run_id_check(leased: str) -> dict:
    zap = _client(leased)
    installed = zap.get_installed_scanner_ids()
    missing = {}
    for category, ids in ZapClient.CATEGORY_SCANNER_IDS.items():
        gap = sorted(set(ids) - ZapClient.FORBIDDEN_SCANNERS - installed)
        if gap:
            missing[category] = gap
    return {
        "lauf": "ids",
        "zap_version": zap.get_version(),
        "installierte_regeln": len(installed),
        "fehlende_ids_je_kategorie": missing or "keine",
    }


def main() -> int:
    client = redis.from_url(REDIS_URL)
    zap_pool.init_zap_pool(client, ["zap-a", "zap-b"])
    lease = zap_pool.acquire_zap(client, uuid.uuid4().hex, "10.9.9.1", "repro", timeout_s=30)
    if lease is None:
        print("kein Lease bekommen", file=sys.stderr)
        return 1
    leased, lease_value = lease
    try:
        for result in (run_id_check(leased), run_split(leased), run_affine(leased)):
            print(json.dumps(result, ensure_ascii=False, indent=2))
    finally:
        zap_pool.release_zap(client, leased, lease_value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
