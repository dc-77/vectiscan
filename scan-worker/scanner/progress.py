"""Progress tracking — Redis (fast polling) + PostgreSQL (persistent)."""

import json
import os
from datetime import datetime, timezone
from typing import Optional

import psycopg2
import redis
import structlog

log = structlog.get_logger()


def _get_redis() -> redis.Redis:
    return redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379"))


def _get_db():
    return psycopg2.connect(
        os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan"),
        connect_timeout=10,
        options="-c statement_timeout=30000",
    )


def update_progress(
    order_id: str,
    phase: str,
    tool: str,
    host: Optional[str] = None,
    hosts_completed: int = 0,
    hosts_total: int = 0,
    tool_output: Optional[str] = None,
) -> None:
    """Update scan progress in Redis and PostgreSQL.

    Args:
        order_id: UUID of the order
        phase: Current phase name (dns_recon, scan_phase1, scan_phase2)
        tool: Current tool name
        host: Current host IP (if applicable)
        hosts_completed: Number of hosts fully scanned
        hosts_total: Total number of hosts to scan
        tool_output: Brief summary of the last completed tool's output
    """
    # Determine status from phase
    status = phase  # dns_recon, scan_phase1, scan_phase2

    progress_data = {
        "orderId": order_id,
        "status": status,
        "currentPhase": phase,
        "currentTool": tool,
        "currentHost": host,
        "hostsCompleted": hosts_completed,
        "hostsTotal": hosts_total,
        "updatedAt": datetime.now(timezone.utc).isoformat(),
    }

    if tool_output is not None:
        progress_data["toolOutput"] = tool_output

    # Redis — fast polling (SET with 1h expiry) + Pub/Sub for WebSocket
    try:
        r = _get_redis()
        payload = json.dumps(progress_data)
        r.set(f"order:progress:{order_id}", payload, ex=3600)
        r.publish(f"scan:events:{order_id}", json.dumps({
            "type": "progress",
            **progress_data,
        }))
    except Exception as e:
        log.error("redis_progress_failed", order_id=order_id, error=str(e))

    # PostgreSQL — persistent
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE orders
                   SET status = %s,
                       current_phase = %s,
                       current_tool = %s,
                       current_host = %s,
                       hosts_completed = %s,
                       hosts_total = %s,
                       updated_at = NOW()
                   WHERE id = %s""",
                (status, phase, tool, host, hosts_completed, hosts_total, order_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("db_progress_failed", order_id=order_id, error=str(e))

    log.debug("progress_updated", order_id=order_id, phase=phase, tool=tool, host=host)


def set_scan_started(order_id: str) -> None:
    """Mark scan as started with timestamp."""
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE orders SET scan_started_at = NOW(), status = 'dns_recon', updated_at = NOW() WHERE id = %s""",
                (order_id,),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("set_started_failed", order_id=order_id, error=str(e))


def set_scan_complete(order_id: str) -> None:
    """Mark scan as complete with timestamp."""
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE orders SET status = 'scan_complete', finished_at = NOW(), updated_at = NOW() WHERE id = %s""",
                (order_id,),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("set_complete_failed", order_id=order_id, error=str(e))

    # Update Redis too + publish event
    try:
        r = _get_redis()
        progress = r.get(f"order:progress:{order_id}")
        if progress:
            data = json.loads(progress)
            data["status"] = "scan_complete"
            data["updatedAt"] = datetime.now(timezone.utc).isoformat()
            r.set(f"order:progress:{order_id}", json.dumps(data), ex=3600)
        r.publish(f"scan:events:{order_id}", json.dumps({
            "type": "status",
            "orderId": order_id,
            "status": "scan_complete",
            "updatedAt": datetime.now(timezone.utc).isoformat(),
        }))
    except Exception as e:
        log.error("redis_complete_failed", order_id=order_id, error=str(e))


def set_scan_failed(order_id: str, error_message: str) -> None:
    """Mark scan as failed with error message."""
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE orders SET status = 'failed', error_message = %s, finished_at = NOW(), updated_at = NOW() WHERE id = %s""",
                (error_message, order_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("set_failed_failed", order_id=order_id, error=str(e))

    # Update Redis too + publish event
    try:
        r = _get_redis()
        data = {
            "orderId": order_id,
            "status": "failed",
            "error": error_message,
            "updatedAt": datetime.now(timezone.utc).isoformat(),
        }
        r.set(f"order:progress:{order_id}", json.dumps(data), ex=3600)
        r.publish(f"scan:events:{order_id}", json.dumps({
            "type": "error",
            **data,
        }))
    except Exception as e:
        log.error("redis_failed_failed", order_id=order_id, error=str(e))


def set_discovered_hosts(order_id: str, host_inventory: dict) -> None:
    """Store discovered hosts in the orders table."""
    hosts = host_inventory.get("hosts", [])
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE orders
                   SET discovered_hosts = %s, hosts_total = %s, updated_at = NOW()
                   WHERE id = %s""",
                (json.dumps(host_inventory), len(hosts), order_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("set_hosts_failed", order_id=order_id, error=str(e))

    # Publish hosts discovered event
    try:
        r = _get_redis()
        r.publish(f"scan:events:{order_id}", json.dumps({
            "type": "hosts_discovered",
            "orderId": order_id,
            "hostsTotal": len(hosts),
            "hosts": hosts,
            "updatedAt": datetime.now(timezone.utc).isoformat(),
        }))
    except Exception as e:
        log.error("redis_hosts_publish_failed", order_id=order_id, error=str(e))


def publish_tool_output(
    order_id: str,
    tool: str,
    host: str,
    summary: str,
) -> None:
    """Publish a tool completion summary via Redis pub/sub and update progress key.

    This is called after each tool completes to provide a brief output summary
    that the frontend can display in the terminal view.
    """
    try:
        r = _get_redis()
        # Update the stored progress data with the latest tool output
        progress_raw = r.get(f"order:progress:{order_id}")
        if progress_raw:
            data = json.loads(progress_raw)
            data["toolOutput"] = summary
            data["lastCompletedTool"] = tool
            data["updatedAt"] = datetime.now(timezone.utc).isoformat()
            r.set(f"order:progress:{order_id}", json.dumps(data), ex=3600)

        # Also publish for WebSocket consumers
        r.publish(f"scan:events:{order_id}", json.dumps({
            "type": "tool_output",
            "orderId": order_id,
            "tool": tool,
            "host": host,
            "summary": summary,
            "updatedAt": datetime.now(timezone.utc).isoformat(),
        }))
    except Exception as e:
        log.error("tool_output_publish_failed", order_id=order_id, tool=tool, error=str(e))
