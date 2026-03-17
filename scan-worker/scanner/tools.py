"""Tool-Runner — subprocess wrapper with timeout and process-group kill."""

import json
import os
import signal
import subprocess
import time
from typing import Optional

import psycopg2
import structlog

log = structlog.get_logger()


def get_db_connection():
    """Get PostgreSQL connection from DATABASE_URL env var."""
    return psycopg2.connect(
        os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan"),
        connect_timeout=10,
        options="-c statement_timeout=30000",
    )


def _kill_process_group(proc: subprocess.Popen) -> None:
    """Kill the entire process group so child processes don't linger."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        # Process already exited or we lack permission — try direct kill
        try:
            proc.kill()
        except ProcessLookupError:
            pass


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

    Uses start_new_session=True so that on timeout the entire process group
    (including child processes spawned by the tool) can be killed cleanly.

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

    proc: Optional[subprocess.Popen] = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        duration_ms = int((time.monotonic() - start) * 1000)
        exit_code = proc.returncode

        log.info(
            "tool_complete",
            tool=tool_name,
            exit_code=exit_code,
            duration_ms=duration_ms,
        )

        if stderr:
            log.debug("tool_stderr", tool=tool_name, stderr=stderr[:500])

        # Determine raw output: prefer stdout, fall back to output file
        # Append stderr on failure so error details are visible in scan results
        raw = stdout
        if stderr and exit_code != 0:
            # Always include stderr when tool exits non-zero (even exit 1)
            # Some tools use exit 1 for errors (nikto), others for "findings found" (nuclei)
            raw = f"{raw}\n--- STDERR ---\n{stderr}" if raw else stderr
        if not raw and output_path:
            try:
                if os.path.isfile(output_path):
                    with open(output_path, "r", errors="replace") as f:
                        raw = f.read()
            except Exception:
                pass

        # Save result to scan_results table
        if order_id:
            _save_result(
                order_id=order_id,
                host_ip=host_ip,
                phase=phase,
                tool_name=tool_name,
                raw_output=raw[:50000] if raw else None,
                exit_code=exit_code,
                duration_ms=duration_ms,
            )

        return exit_code, duration_ms

    except subprocess.TimeoutExpired:
        duration_ms = int((time.monotonic() - start) * 1000)
        log.warning("tool_timeout", tool=tool_name, timeout=timeout)

        # Kill entire process group — prevents orphaned child processes
        if proc is not None:
            _kill_process_group(proc)
            # Drain remaining pipe data to avoid zombies
            try:
                proc.communicate(timeout=5)
            except (subprocess.TimeoutExpired, Exception):
                proc.kill()

        # On timeout, try to read partial output from file (tools like nuclei write incrementally)
        raw = f"TIMEOUT after {timeout}s"
        if output_path:
            try:
                if os.path.isfile(output_path):
                    with open(output_path, "r", errors="replace") as f:
                        content = f.read()
                    if content:
                        raw = f"TIMEOUT after {timeout}s\n--- PARTIAL OUTPUT ({len(content)} chars) ---\n{content}"
                        log.info("tool_timeout_partial_output", tool=tool_name, chars=len(content))
            except Exception:
                pass

        if order_id:
            _save_result(
                order_id=order_id,
                host_ip=host_ip,
                phase=phase,
                tool_name=tool_name,
                raw_output=raw[:50000],
                exit_code=-1,
                duration_ms=duration_ms,
            )

        return -1, duration_ms

    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        log.error("tool_error", tool=tool_name, error=str(e))

        # Clean up process if it was started
        if proc is not None:
            _kill_process_group(proc)
            try:
                proc.communicate(timeout=5)
            except Exception:
                pass

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
