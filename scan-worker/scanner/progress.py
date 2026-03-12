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
    return psycopg2.connect(os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan"))


def update_progress(
    scan_id: str,
    phase: str,
    tool: str,
    host: Optional[str] = None,
    hosts_completed: int = 0,
    hosts_total: int = 0,
) -> None:
    """Update scan progress in Redis and PostgreSQL.

    Args:
        scan_id: UUID of the scan
        phase: Current phase name (dns_recon, scan_phase1, scan_phase2)
        tool: Current tool name
        host: Current host IP (if applicable)
        hosts_completed: Number of hosts fully scanned
        hosts_total: Total number of hosts to scan
    """
    # Determine status from phase
    status = phase  # dns_recon, scan_phase1, scan_phase2

    progress_data = {
        "scanId": scan_id,
        "status": status,
        "currentPhase": phase,
        "currentTool": tool,
        "currentHost": host,
        "hostsCompleted": hosts_completed,
        "hostsTotal": hosts_total,
        "updatedAt": datetime.now(timezone.utc).isoformat(),
    }

    # Redis — fast polling (SET with 1h expiry)
    try:
        r = _get_redis()
        r.set(f"scan:progress:{scan_id}", json.dumps(progress_data), ex=3600)
    except Exception as e:
        log.error("redis_progress_failed", scan_id=scan_id, error=str(e))

    # PostgreSQL — persistent
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE scans
                   SET status = %s,
                       current_phase = %s,
                       current_tool = %s,
                       current_host = %s,
                       hosts_completed = %s,
                       hosts_total = %s,
                       updated_at = NOW()
                   WHERE id = %s""",
                (status, phase, tool, host, hosts_completed, hosts_total, scan_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("db_progress_failed", scan_id=scan_id, error=str(e))

    log.debug("progress_updated", scan_id=scan_id, phase=phase, tool=tool, host=host)


def set_scan_started(scan_id: str) -> None:
    """Mark scan as started with timestamp."""
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE scans SET started_at = NOW(), status = 'dns_recon', updated_at = NOW() WHERE id = %s""",
                (scan_id,),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("set_started_failed", scan_id=scan_id, error=str(e))


def set_scan_complete(scan_id: str) -> None:
    """Mark scan as complete with timestamp."""
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE scans SET status = 'scan_complete', finished_at = NOW(), updated_at = NOW() WHERE id = %s""",
                (scan_id,),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("set_complete_failed", scan_id=scan_id, error=str(e))

    # Update Redis too
    try:
        r = _get_redis()
        progress = r.get(f"scan:progress:{scan_id}")
        if progress:
            data = json.loads(progress)
            data["status"] = "scan_complete"
            data["updatedAt"] = datetime.now(timezone.utc).isoformat()
            r.set(f"scan:progress:{scan_id}", json.dumps(data), ex=3600)
    except Exception as e:
        log.error("redis_complete_failed", scan_id=scan_id, error=str(e))


def set_scan_failed(scan_id: str, error_message: str) -> None:
    """Mark scan as failed with error message."""
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE scans SET status = 'failed', error_message = %s, finished_at = NOW(), updated_at = NOW() WHERE id = %s""",
                (error_message, scan_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("set_failed_failed", scan_id=scan_id, error=str(e))

    # Update Redis too
    try:
        r = _get_redis()
        data = {
            "scanId": scan_id,
            "status": "failed",
            "error": error_message,
            "updatedAt": datetime.now(timezone.utc).isoformat(),
        }
        r.set(f"scan:progress:{scan_id}", json.dumps(data), ex=3600)
    except Exception as e:
        log.error("redis_failed_failed", scan_id=scan_id, error=str(e))


def set_discovered_hosts(scan_id: str, host_inventory: dict) -> None:
    """Store discovered hosts in the scans table."""
    hosts = host_inventory.get("hosts", [])
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE scans
                   SET discovered_hosts = %s, hosts_total = %s, updated_at = NOW()
                   WHERE id = %s""",
                (json.dumps(host_inventory), len(hosts), scan_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("set_hosts_failed", scan_id=scan_id, error=str(e))
