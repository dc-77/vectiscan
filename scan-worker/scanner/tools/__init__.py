"""Tool-Runner — subprocess wrapper with timeout and process-group kill.

Also serves as package init for scanner.tools submodules (zap_client, zap_mapper).
"""

import json
import os
import signal
import subprocess
import time
from typing import Optional

import structlog

log = structlog.get_logger()


def get_db_connection():
    """Get PostgreSQL connection from DATABASE_URL env var."""
    import psycopg2
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


def _build_env_with_vpn(order_id: Optional[str]) -> Optional[dict]:
    """ENV-Dict mit HTTPS_PROXY/HTTP_PROXY wenn VPN aktiv ist (PR-VPN, 2026-05-03).

    Returns None wenn keine VPN-Variablen gesetzt werden muessen — der
    subprocess erbt dann das Process-ENV unmodifiziert.
    """
    if not order_id:
        return None
    try:
        from scanner.vpn_switch import get_switch
        sw = get_switch(order_id)
        proxy = sw.current_proxy_url()
        if not proxy:
            return None
        env = dict(os.environ)
        env["HTTPS_PROXY"] = proxy
        env["HTTP_PROXY"] = proxy
        env["https_proxy"] = proxy
        env["http_proxy"] = proxy
        env["NO_PROXY"] = "localhost,127.0.0.1,::1"
        return env
    except Exception:
        return None


def _record_response_for_block_detection(
    order_id: Optional[str], host_ip: Optional[str],
    raw_output: Optional[str], exit_code: int, is_timeout: bool,
) -> None:
    """Sammle Response-Metriken fuer den BlockDetector.

    Heuristik: extrahiere HTTP-Status aus raw_output (curl/httpx haben den
    Code im JSON; ZAP/wpscan/nuclei strukturiert anders). Wenn nicht
    parsbar: Status 0, body_size = len(raw_output).
    """
    if not order_id or not host_ip:
        return
    try:
        from scanner.vpn_switch import get_switch
        # WICHTIG: get_switch nicht initialisieren wenn VPN nicht verfuegbar
        sw = get_switch(order_id)
        if not sw.is_available():
            return
        # Heuristisches Status-Extraction
        status = 0
        body_excerpt = (raw_output or "")[:500]
        body_size = len(raw_output or "")
        if raw_output:
            # Schnelle JSON-Status-Extraktion
            for marker in ('"status_code":', '"status":'):
                idx = raw_output.find(marker)
                if idx != -1:
                    chunk = raw_output[idx + len(marker):idx + len(marker) + 8].strip(' ,"')
                    try:
                        status = int(chunk.split(',')[0].split('"')[0])
                        break
                    except (ValueError, IndexError):
                        pass

        from scanner.waf_block_detector import BlockDetector
        # BlockDetector ist per-Order-Singleton im VpnSwitch-Modul
        det = _get_or_create_detector(order_id)
        det.report_response(host_ip, status, body_size, body_excerpt, is_timeout=is_timeout)
    except Exception:
        pass


# Per-Order BlockDetector-Singleton
_detectors: dict = {}


def _get_or_create_detector(order_id: str):
    from scanner.waf_block_detector import BlockDetector
    if order_id not in _detectors:
        _detectors[order_id] = BlockDetector()
    return _detectors[order_id]


def _check_block_and_maybe_activate_vpn(
    order_id: Optional[str], host_ip: Optional[str], tool_name: str,
) -> bool:
    """Prueft Block-Status. Wenn geblockt + VPN moeglich: activate.

    Returns True wenn VPN wegen dieser Pruefung neu aktiviert wurde
    (Caller kann dann Tool-Retry triggern).
    """
    if not order_id or not host_ip:
        return False
    try:
        from scanner.vpn_switch import get_switch
        sw = get_switch(order_id)
        if not sw.is_available():
            return False
        det = _get_or_create_detector(order_id)
        blocked, reason = det.is_blocked(host_ip)
        if not blocked:
            return False
        if not sw.should_activate(host_ip, reason):
            return False
        if sw.is_active():
            # VPN war schon an, Block trotzdem → Location rotieren
            log.warning("vpn_already_active_but_still_blocked",
                        host=host_ip, reason=reason, tool=tool_name)
            ok = sw.rotate(host=host_ip)
            if ok:
                det.reset_host(host_ip)
            return ok
        # Erstaktivierung
        log.warning("vpn_activating_due_to_block",
                    host=host_ip, reason=reason, tool=tool_name)
        ok = sw.enable(reason=reason, host=host_ip)
        if ok:
            det.reset_host(host_ip)
        return ok
    except Exception as e:
        log.warning("vpn_check_failed", error=str(e))
        return False


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

    PR-VPN (2026-05-03): wenn VpnSwitch fuer diese order_id aktiv ist,
    werden HTTPS_PROXY/HTTP_PROXY in die subprocess-ENV injiziert. Bei
    Block-Detection (BlockDetector signalisiert "blocked") wird automatisch
    1x Retry mit aktiviertem VPN durchgefuehrt — sofern VPN verfuegbar
    UND Subscription-Strategy != 'never'.

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
    return _run_tool_with_optional_vpn(
        cmd, timeout, output_path, order_id, host_ip, phase, tool_name,
        retry_with_vpn=True,
    )


def _run_tool_with_optional_vpn(
    cmd: list[str], timeout: int, output_path: Optional[str],
    order_id: Optional[str], host_ip: Optional[str],
    phase: int, tool_name: str,
    retry_with_vpn: bool,
) -> tuple[int, int]:
    """Internal: wraps subprocess + Block-Detection + optional VPN-Retry."""
    env = _build_env_with_vpn(order_id)
    log.info("tool_start", tool=tool_name, cmd=" ".join(cmd), timeout=timeout,
             via_vpn=bool(env))
    start = time.monotonic()

    proc: Optional[subprocess.Popen] = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
            env=env,
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
            # Some tools use exit 1 for "findings found" or warnings
            raw = f"{raw}\n--- STDERR ---\n{stderr}" if raw else stderr
        if not raw and output_path:
            try:
                if os.path.isfile(output_path):
                    with open(output_path, "r", errors="replace") as f:
                        raw = f.read()
            except Exception:
                pass

        # PR-VPN Block-Detection: Response an Detector melden
        _record_response_for_block_detection(
            order_id, host_ip, raw, exit_code, is_timeout=False,
        )
        # Wenn dieser Run KEIN VPN-Retry war und der Detector jetzt sagt
        # "blocked" → VPN aktivieren und Tool 1x retry ohne weitere Retries.
        if retry_with_vpn and not env:
            vpn_just_activated = _check_block_and_maybe_activate_vpn(
                order_id, host_ip, tool_name,
            )
            if vpn_just_activated:
                log.info("tool_retry_with_vpn", tool=tool_name, host=host_ip)
                return _run_tool_with_optional_vpn(
                    cmd, timeout, output_path, order_id, host_ip,
                    phase, tool_name, retry_with_vpn=False,
                )

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

        # On timeout, try to read partial output from file (some tools write incrementally)
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

        # PR-VPN: Timeout zaehlt als Block-Signal
        _record_response_for_block_detection(
            order_id, host_ip, raw, -1, is_timeout=True,
        )
        if retry_with_vpn and not env:
            vpn_just_activated = _check_block_and_maybe_activate_vpn(
                order_id, host_ip, tool_name,
            )
            if vpn_just_activated:
                log.info("tool_retry_with_vpn_after_timeout", tool=tool_name, host=host_ip)
                return _run_tool_with_optional_vpn(
                    cmd, timeout, output_path, order_id, host_ip,
                    phase, tool_name, retry_with_vpn=False,
                )

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
    """Save tool result to scan_results table.

    PR-ABC (2026-05-02): raw_output durchlaeuft erst output_normalizer.normalize()
    fuer bekannte Tools (httpx, wafw00f, dnsx). Strippt Timestamps,
    Latencies, ASCII-Banner, Resolver-Reihenfolge — damit identische
    Server-Antworten zu identischen Bytes fuehren und der KI-Cache greifen
    kann (siehe TIEFENANALYSE-RUN-DRIFT-2026-05-02.md).
    """
    try:
        from scanner.output_normalizer import normalize
        raw_output = normalize(tool_name, raw_output)
    except Exception:
        # Bei Normalisierungs-Fehler nicht crashen — Original speichern
        pass
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
