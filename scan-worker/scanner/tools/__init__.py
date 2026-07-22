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
                # A7: der Erst-Versuch bekommt seine eigene Zeile, sonst
                # verschwindet der geblockte Lauf spurlos aus scan_results.
                record_tool_run(
                    order_id, host_ip, phase, tool_name, "blocked",
                    reason="waf_block_retry_via_vpn",
                    duration_ms=duration_ms,
                    raw_output=raw[:50000] if raw else None,
                )
                return _run_tool_with_optional_vpn(
                    cmd, timeout, output_path, order_id, host_ip,
                    phase, tool_name, retry_with_vpn=False,
                )

        # Save result to scan_results table
        if order_id:
            record_tool_run(
                order_id, host_ip, phase, tool_name,
                classify_exit(tool_name, exit_code),
                exit_code=exit_code,
                duration_ms=duration_ms,
                raw_output=raw[:50000] if raw else None,
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
                # A7: Erst-Versuch protokollieren, bevor der Retry uebernimmt
                record_tool_run(
                    order_id, host_ip, phase, tool_name, "blocked",
                    reason="waf_block_timeout_retry_via_vpn",
                    duration_ms=duration_ms,
                    raw_output=raw[:50000],
                )
                return _run_tool_with_optional_vpn(
                    cmd, timeout, output_path, order_id, host_ip,
                    phase, tool_name, retry_with_vpn=False,
                )

        if order_id:
            record_tool_run(
                order_id, host_ip, phase, tool_name, "timeout",
                reason=f"timeout_after_{timeout}s",
                exit_code=-1,
                duration_ms=duration_ms,
                raw_output=raw[:50000],
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
            record_tool_run(
                order_id, host_ip, phase, tool_name, "failed",
                reason=str(e)[:150],
                exit_code=-2,
                duration_ms=duration_ms,
                raw_output=f"ERROR: {e}",
            )

        return -2, duration_ms


# ============================================================
# A7 (Jul 2026): Lauf-Status pro Tool
# ============================================================
# Bis A7 war die Bewertung "welcher Exit-Code heisst Erfolg" an jeder
# Call-Site einzeln hinterlegt (phase0.py:213, phase1.py:338, phase2.py:124
# usw.). Diese Tabelle ist ab jetzt die SSoT dafuer. Die bestehenden
# Call-Sites bleiben vorerst unveraendert — sie werden schrittweise
# hierher umgezogen.
DEFAULT_OK_EXIT_CODES: tuple[int, ...] = (0,)

TOOL_OK_EXIT_CODES: dict[str, tuple[int, ...]] = {
    "testssl": (0, 1),          # 1 = Findings vorhanden
    "wpscan": (0, 4, 5),        # 4 = kein WordPress, 5 = WAF-Block
    "ffuf": (0, 1),
    "feroxbuster": (0, 1),
    "gobuster_dir": (0,),
    "gobuster_dns": (0,),
    "httpx": (0,),
    "nmap": (0,),
    "wafw00f": (0,),
    "crtsh": (0,),
    "subfinder": (0,),
    "dnsx": (0,),
}

# Gueltige Werte fuer scan_results.status (Migration 044).
TOOL_RUN_STATUSES: frozenset = frozenset(
    {"ok", "failed", "skipped", "timeout", "blocked"}
)

# Sentinel-Exit-Codes. -3 fuer skipped/blocked ist bewusst negativ: die
# Live-Feed-Queries (api/src/routes/ws.ts, orders.ts) filtern mit
# "AND exit_code >= 0" und halten damit ausgelassene Tools automatisch aus
# dem Terminal-Stream heraus.
EXIT_CODE_TIMEOUT: int = -1
EXIT_CODE_ERROR: int = -2
EXIT_CODE_SKIPPED: int = -3

_STATUS_TO_EXIT_CODE: dict[str, int] = {
    "ok": 0,
    "failed": EXIT_CODE_ERROR,
    "timeout": EXIT_CODE_TIMEOUT,
    "skipped": EXIT_CODE_SKIPPED,
    "blocked": EXIT_CODE_SKIPPED,
}

# tool_name ist VARCHAR(50) (003_mvp_schema.sql:61)
_TOOL_NAME_MAX_LEN: int = 50
# skip_reason ist VARCHAR(160) (044_scan_results_run_status.sql)
_SKIP_REASON_MAX_LEN: int = 160


def _normalize_tool_name(tool_name: str) -> str:
    """Varianten-Namen auf den Basis-Tool-Namen zurueckfuehren.

    Beispiele: 'crtsh_retry2' -> 'crtsh', 'ffuf_sensitive' -> 'ffuf'.
    Exakter Treffer gewinnt immer (sonst wuerde 'gobuster_dns' faelschlich
    auf 'gobuster_dir' gemappt).
    """
    if not tool_name:
        return ""
    if tool_name in TOOL_OK_EXIT_CODES:
        return tool_name
    candidates = [k for k in TOOL_OK_EXIT_CODES if tool_name.startswith(k)]
    if not candidates:
        return tool_name
    return max(candidates, key=len)


def classify_exit(tool_name: str, exit_code: Optional[int]) -> str:
    """Exit-Code in einen A7-Status uebersetzen.

    Nie werfend — im Zweifel 'failed', damit ein Klassifizierungsfehler
    keinen Scan kippt.
    """
    try:
        if exit_code is None:
            return "failed"
        if exit_code == EXIT_CODE_TIMEOUT:
            return "timeout"
        if exit_code == EXIT_CODE_ERROR:
            return "failed"
        if exit_code == EXIT_CODE_SKIPPED:
            return "skipped"
        ok_codes = TOOL_OK_EXIT_CODES.get(
            _normalize_tool_name(tool_name), DEFAULT_OK_EXIT_CODES
        )
        return "ok" if exit_code in ok_codes else "failed"
    except Exception as e:  # pragma: no cover — reiner Sicherheitsnetz-Pfad
        log.warning("classify_exit_failed", tool=tool_name, error=str(e))
        return "failed"


def record_tool_run(
    order_id: Optional[str],
    host_ip: Optional[str],
    phase: int,
    tool_name: str,
    status: str,
    *,
    reason: Optional[str] = None,
    exit_code: Optional[int] = None,
    duration_ms: int = 0,
    raw_output: Optional[str] = None,
) -> None:
    """Genau eine Ergebniszeile fuer einen Tool-Lauf schreiben (A7).

    Zentrale Einstiegsstelle fuer alle Zustaende — auch fuer die, bei denen
    ein Tool gar nicht lief ('skipped', 'blocked'). Ohne order_id gibt es
    keine FK-faehige Zeile, dann passiert nichts.

    Wirft NIEMALS: ein Fehler in der Protokollierung darf einen Scan nicht
    kippen (Muster wie _save_result unten).
    """
    try:
        if not order_id:
            return

        clean_status = (status or "").strip().lower()
        if clean_status not in TOOL_RUN_STATUSES:
            log.warning(
                "record_tool_run_unknown_status",
                tool=tool_name,
                status=status,
            )
            clean_status = "failed"

        if exit_code is None:
            exit_code = _STATUS_TO_EXIT_CODE.get(clean_status, EXIT_CODE_ERROR)

        clean_reason = reason[:_SKIP_REASON_MAX_LEN] if reason else None

        if raw_output is None and clean_reason:
            # Damit ToolTrace im Frontend etwas anzuzeigen hat
            raw_output = f"{clean_status.upper()}: {clean_reason}"

        clean_tool = (tool_name or "unknown")[:_TOOL_NAME_MAX_LEN]

        # WICHTIG: _save_result ueber den Modul-Global aufrufen (kein
        # from-Import-Alias), damit @patch("scanner.tools._save_result")
        # in tests/test_tools.py weiterhin greift.
        _save_result(
            order_id=order_id,
            host_ip=host_ip,
            phase=phase,
            tool_name=clean_tool,
            raw_output=raw_output,
            exit_code=exit_code,
            duration_ms=duration_ms,
            status=clean_status,
            skip_reason=clean_reason,
        )
    except Exception as e:
        log.error("record_tool_run_failed", tool=tool_name, error=str(e))


# Rolling-Deploy-Schalter: None = noch unbekannt, True = Migration 044 ist da,
# False = alter API-Stand ohne status/skip_reason, wir fahren den Legacy-INSERT.
_HAS_RUN_STATUS_COLUMNS: Optional[bool] = None

_INSERT_WITH_STATUS = """INSERT INTO scan_results (order_id, host_ip, phase, tool_name, raw_output, exit_code, duration_ms, status, skip_reason)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""

_INSERT_LEGACY = """INSERT INTO scan_results (order_id, host_ip, phase, tool_name, raw_output, exit_code, duration_ms)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)"""


def _save_result(
    order_id: str,
    host_ip: Optional[str],
    phase: int,
    tool_name: str,
    raw_output: Optional[str],
    exit_code: int,
    duration_ms: int,
    *,
    status: Optional[str] = None,
    skip_reason: Optional[str] = None,
) -> None:
    """Save tool result to scan_results table.

    PR-ABC (2026-05-02): raw_output durchlaeuft erst output_normalizer.normalize()
    fuer bekannte Tools (httpx, wafw00f, dnsx). Strippt Timestamps,
    Latencies, ASCII-Banner, Resolver-Reihenfolge — damit identische
    Server-Antworten zu identischen Bytes fuehren und der KI-Cache greifen
    kann (siehe TIEFENANALYSE-RUN-DRIFT-2026-05-02.md).

    A7 (Jul 2026): status/skip_reason sind keyword-only und optional. Fehlen
    die Spalten in der DB (alter API-Container waehrend Rolling-Deploy,
    SQLSTATE 42703), faellt der INSERT einmalig auf die 7-Spalten-Variante
    zurueck und merkt sich das modul-global — ohne diesen Fallback gingen
    ALLE Tool-Zeilen still verloren, weil Fehler hier geschluckt werden.
    """
    global _HAS_RUN_STATUS_COLUMNS
    try:
        from scanner.output_normalizer import normalize
        raw_output = normalize(tool_name, raw_output)
    except Exception:
        # Bei Normalisierungs-Fehler nicht crashen — Original speichern
        pass
    legacy_params = (order_id, host_ip, phase, tool_name, raw_output, exit_code, duration_ms)
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            if _HAS_RUN_STATUS_COLUMNS is False:
                cur.execute(_INSERT_LEGACY, legacy_params)
            else:
                try:
                    cur.execute(_INSERT_WITH_STATUS, legacy_params + (status, skip_reason))
                    _HAS_RUN_STATUS_COLUMNS = True
                except Exception as col_err:
                    if not _is_undefined_column(col_err):
                        raise
                    # Migration 044 noch nicht angewendet — ab jetzt Legacy
                    _HAS_RUN_STATUS_COLUMNS = False
                    log.warning(
                        "save_result_status_columns_missing",
                        tool=tool_name,
                        detail="Migration 044 fehlt, INSERT faellt auf 7 Spalten zurueck",
                    )
                    conn.rollback()
                    with conn.cursor() as retry_cur:
                        retry_cur.execute(_INSERT_LEGACY, legacy_params)
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("save_result_failed", tool=tool_name, error=str(e))


def _is_undefined_column(err: Exception) -> bool:
    """True wenn der Fehler ein psycopg2 UndefinedColumn (SQLSTATE 42703) ist.

    Bewusst ueber den pgcode-String statt ueber den Exception-Typ, damit die
    Pruefung auch ohne installiertes psycopg2 (Unit-Tests) funktioniert.
    """
    try:
        return getattr(err, "pgcode", None) == "42703"
    except Exception:  # pragma: no cover
        return False
