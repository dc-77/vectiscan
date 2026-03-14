"""Tool-Runner — subprocess wrapper with timeout and logging."""

import json
import os
import subprocess
import time
from typing import Optional

import psycopg2
import structlog

log = structlog.get_logger()


def get_db_connection():
    """Get PostgreSQL connection from DATABASE_URL env var."""
    return psycopg2.connect(os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan"))


def run_tool(
    cmd: list[str],
    timeout: int,
    output_path: Optional[str] = None,
    order_id: Optional[str] = None,
    host_ip: Optional[str] = None,
    phase: int = 0,
    tool_name: str = "",
) -> tuple[int, int]:
    """
    Run an external tool as subprocess with timeout.

    Args:
        cmd: Command and arguments as list
        timeout: Timeout in seconds
        output_path: Optional path where tool writes its output
        order_id: Order UUID for DB logging
        host_ip: Host IP for DB logging
        phase: Scan phase (0, 1, 2)
        tool_name: Name of the tool

    Returns:
        Tuple of (exit_code, duration_ms)
    """
    log.info("tool_start", tool=tool_name, cmd=" ".join(cmd), timeout=timeout)
    start = time.monotonic()

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        exit_code = result.returncode

        log.info(
            "tool_complete",
            tool=tool_name,
            exit_code=exit_code,
            duration_ms=duration_ms,
        )

        if result.stderr:
            log.debug("tool_stderr", tool=tool_name, stderr=result.stderr[:500])

        # Save result to scan_results table
        if order_id:
            _save_result(
                order_id=order_id,
                host_ip=host_ip,
                phase=phase,
                tool_name=tool_name,
                raw_output=result.stdout[:50000] if result.stdout else None,
                exit_code=exit_code,
                duration_ms=duration_ms,
            )

        return exit_code, duration_ms

    except subprocess.TimeoutExpired:
        duration_ms = int((time.monotonic() - start) * 1000)
        log.warning("tool_timeout", tool=tool_name, timeout=timeout)

        if order_id:
            _save_result(
                order_id=order_id,
                host_ip=host_ip,
                phase=phase,
                tool_name=tool_name,
                raw_output=f"TIMEOUT after {timeout}s",
                exit_code=-1,
                duration_ms=duration_ms,
            )

        return -1, duration_ms

    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        log.error("tool_error", tool=tool_name, error=str(e))

        if order_id:
            _save_result(
                order_id=order_id,
                host_ip=host_ip,
                phase=phase,
                tool_name=tool_name,
                raw_output=f"ERROR: {e}",
                exit_code=-2,
                duration_ms=duration_ms,
            )

        return -2, duration_ms


def _save_result(
    order_id: str,
    host_ip: Optional[str],
    phase: int,
    tool_name: str,
    raw_output: Optional[str],
    exit_code: int,
    duration_ms: int,
) -> None:
    """Save tool result to scan_results table."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO scan_results (order_id, host_ip, phase, tool_name, raw_output, exit_code, duration_ms)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (order_id, host_ip, phase, tool_name, raw_output, exit_code, duration_ms),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("save_result_failed", tool=tool_name, error=str(e))
