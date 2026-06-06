"""Precheck-Worker-Entrypoint.

Konsumiert `precheck-pending` Redis-Queue, fuehrt Pre-Check pro Target aus
und schaltet die Order/Subscription auf `pending_target_review`, sobald
alle Targets des Owners fertig sind.

Payload-Format:
  {"orderId": "...", "targetIds": ["uuid", ...]}
  oder
  {"subscriptionId": "...", "targetIds": ["uuid", ...]}
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from typing import Any

import redis
import structlog

from scanner.progress import publish_event
from scanner.precheck import runner, writer

log = structlog.get_logger()


def _enqueue_scan(order_id: str, package: str, client: "redis.Redis | None") -> None:
    """Scan-Job in die `scan-pending`-Liste schieben (spiegelt scanQueue.add).

    Re-nutzt die bestehende Worker-Redis-Verbindung, faellt aber auf eine eigene
    zurueck, falls keine uebergeben wurde (z.B. in Unit-Tests).
    """
    payload = json.dumps({"orderId": order_id, "package": package})
    cl = client or redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379"))
    cl.rpush("scan-pending", payload)


def _handle_job(job: dict[str, Any], client: "redis.Redis | None" = None) -> None:
    order_id = job.get("orderId")
    sub_id = job.get("subscriptionId")
    target_ids = job.get("targetIds") or []
    owner_id = order_id or sub_id

    if not target_ids or not owner_id:
        log.warning("precheck_job_invalid", job=job)
        return

    log.info("precheck_job_start", owner=owner_id, targets=len(target_ids))

    if order_id:
        writer.set_order_status(order_id, "precheck_running")

    summaries = []
    for tid in target_ids:
        target = writer.load_target(tid)
        if target is None:
            log.warning("precheck_target_missing", target_id=tid)
            continue
        summary = runner.run_target(target)
        summaries.append({"targetId": tid, **summary})

    if order_id:
        live_count = writer.update_live_hosts_count(order_id)
        remaining = writer.count_pending_targets(order_id=order_id, subscription_id=None)
        if remaining == 0:
            writer.set_order_status(order_id, "pending_target_review")
            publish_event(order_id, {
                "type": "precheck_complete",
                "orderId": order_id,
                "summary": {
                    "targets": len(summaries),
                    "live_hosts": live_count,
                    "details": summaries,
                },
            })
            # VEC-172: Verifizierte WebCheck-Free-Orders ueberspringen das
            # Admin-Gate — die Scan-Autorisierung ist via Domain-Kontrolle
            # kryptografisch bewiesen. Komplettmediation/deny-by-default in
            # writer.try_auto_approve_webcheck_order: NUR webcheck + verifizierter
            # Lead + 1 Target werden freigegeben, alles andere bleibt im Gate.
            if writer.try_auto_approve_webcheck_order(order_id):
                _enqueue_scan(order_id, "webcheck", client)
                publish_event(order_id, {
                    "type": "status",
                    "orderId": order_id,
                    "status": "queued",
                })
                log.info("webcheck_auto_approved", order=order_id)
    else:
        remaining = writer.count_pending_targets(order_id=None, subscription_id=sub_id)
        if remaining == 0:
            # Subscription-flow: publish to sub channel (frontend subscribes by id)
            publish_event(sub_id, {
                "type": "precheck_complete",
                "subscriptionId": sub_id,
                "summary": {"targets": len(summaries), "details": summaries},
            })


def wait_for_jobs(client: redis.Redis) -> None:
    log.info("precheck_worker_listening", queue="precheck-pending")
    while True:
        try:
            result = client.blpop(["precheck-pending"], timeout=5)
            if result is None:
                continue
            _, job_data = result
            job = json.loads(job_data.decode() if isinstance(job_data, bytes) else job_data)
            try:
                _handle_job(job, client)
            except Exception as exc:
                log.error("precheck_job_failed", error=str(exc))
        except redis.ConnectionError:
            log.warning("precheck_redis_lost_retrying_5s")
            time.sleep(5)


def main() -> None:
    log.info("precheck_worker_started")
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    client = redis.from_url(redis_url)

    def shutdown(signum, frame):
        log.info("precheck_worker_shutdown", signal=signum)
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    wait_for_jobs(client)


if __name__ == "__main__":
    main()
