"""BullMQ Consumer — Orchestriert die Report-Generierung."""

from __future__ import annotations

import json
import os
import shutil
import signal
import sys
import tarfile
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2
import psycopg2.extras
import redis
import structlog
from minio import Minio

from reporter.claude_client import call_claude
from reporter.deterministic_pipeline import apply_deterministic_pipeline
from reporter.generate_report import generate_report
from reporter.parser import parse_scan_data
from reporter.qa_check import run_qa_checks
from reporter.report_mapper import map_to_report_data

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# Configuration (all via environment variables)
# ---------------------------------------------------------------------------

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan")
MINIO_ENDPOINT = f"{os.environ.get('MINIO_ENDPOINT', 'minio')}:{os.environ.get('MINIO_PORT', '9000')}"
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "minioadmin")
MINIO_SECURE = os.environ.get("MINIO_SECURE", "false").lower() == "true"

QUEUE_NAME = "report-pending"
RAWDATA_BUCKET = "scan-rawdata"
REPORTS_BUCKET = "scan-reports"
DEBUG_BUCKET = "scan-debug"
BLPOP_TIMEOUT = 5  # seconds


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def _get_db_connection() -> psycopg2.extensions.connection:
    """Create a new database connection."""
    return psycopg2.connect(DATABASE_URL)


def _apply_finding_overrides(
    findings_data: dict,
    conn: Any,
    order_id: str,
) -> dict[str, list[dict]]:
    """Apply admin-set finding_overrides (Migration 029) to findings_data.

    Liest aus `finding_overrides` (order_id, finding_id, field_name, new_value)
    und ueberschreibt die entsprechenden Felder im Finding-dict. Sonderfaelle:

    - field='_ignored' (boolean): markiert das Finding als
      `_admin_ignored_warnings = True`. Kein Feld-Override, nur informativ
      fuer die UI — alle warnings dazu werden als "akzeptiert" angezeigt.
    - field in {'cvss_score'}: numerisch gecastet.

    Returns dict {finding_id -> list[applied_overrides]} fuer Logging/Audit.
    Defensive: Wenn die Tabelle nicht existiert (Migration 029 fehlt),
    returned {} und logged eine Warnung — Worker laeuft weiter.
    """
    applied: dict[str, list[dict]] = {}
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT finding_id, field_name, new_value
                  FROM finding_overrides
                 WHERE order_id = %s
                """,
                (order_id,),
            )
            rows = cur.fetchall()
    except Exception as exc:
        msg = str(exc)
        if "finding_overrides" in msg and "does not exist" in msg.lower():
            log.warning("finding_overrides_table_missing",
                        order_id=order_id,
                        hint="Run Migration 029 (api initDb auto-applies on next API start)")
        else:
            log.warning("finding_overrides_load_failed",
                        order_id=order_id, error=msg)
        try:
            conn.rollback()
        except Exception:
            pass
        return applied

    if not rows:
        return applied

    # Index findings nach id fuer O(1)-Lookup
    findings_list = findings_data.get("findings", []) or []
    by_id: dict[str, dict] = {}
    for f in findings_list:
        fid = f.get("id") or f.get("external_id")
        if fid:
            by_id[str(fid)] = f

    for fid, field, new_value in rows:
        target = by_id.get(str(fid))
        if target is None:
            # Override fuer ein Finding das nicht (mehr) im Output ist —
            # nur loggen, nicht failen (Re-Render kann legit weniger
            # Findings haben als der vorherige Run).
            log.info("finding_override_skipped_no_finding",
                     order_id=order_id, finding_id=fid, field=field)
            continue

        # new_value ist JSONB → psycopg2 liefert das schon als dict
        if not isinstance(new_value, dict) or "value" not in new_value:
            log.warning("finding_override_invalid_payload",
                        order_id=order_id, finding_id=fid, field=field)
            continue
        value = new_value["value"]

        if field == "_ignored":
            target["_admin_ignored_warnings"] = bool(value)
        elif field == "cvss_score":
            try:
                target["cvss_score"] = float(value)
            except (TypeError, ValueError):
                log.warning("finding_override_cvss_not_numeric",
                            order_id=order_id, finding_id=fid, value=value)
                continue
        else:
            target[field] = value

        applied.setdefault(str(fid), []).append({"field": field, "value": value})

    if applied:
        log.info("finding_overrides_applied",
                 order_id=order_id,
                 count=sum(len(v) for v in applied.values()),
                 finding_count=len(applied))
    return applied


def _load_tool_runs(conn: Any, order_id: str) -> list[dict]:
    """Laedt die Tool-Lauf-Zeilen (scan_results) fuer C3-Abdeckungskapitel.

    Autoritative Quelle fuer "welches Tool lief auf welchem Host mit welchem
    Ergebnis" ist die Tabelle ``scan_results`` — der report-worker liest sie
    bisher nie (er schreibt nur die ``report_cost``-Zeile). Ein SELECT auf die
    ohnehin offene Connection (worker.py:629) ist neue Query, keine neue
    Infrastruktur.

    ZWINGEND OHNE ``raw_output``: die Spalte ist TEXT und traegt pro Zeile
    potenziell MB an nuclei/testssl-Rohtext. Der Container hat 1 GB RAM-Limit
    (docker-compose.yml) — ein ``SELECT *`` wuerde ihn kippen.

    ``status``/``skip_reason`` (A7, Migration 044) werden mitselektiert: sie
    sind die autoritative Skip-Begruendung. Auf Alt-DBs ohne Migration 044
    faellt der SELECT auf die Legacy-Spalten zurueck (status/skip_reason=None).

    Vollstaendig defensiv (Muster wie ``_apply_finding_overrides``): jeder
    Fehler -> log.warning + conn.rollback() + Rueckgabe ``[]``. Ein DB-Problem
    darf den Report niemals kippen — das Kapitel wird dann uebersprungen.
    """
    select_with_status = """
        SELECT host_ip, phase, tool_name, exit_code, duration_ms,
               status, skip_reason
          FROM scan_results
         WHERE order_id = %s
         ORDER BY phase, tool_name, host_ip
    """
    select_legacy = """
        SELECT host_ip, phase, tool_name, exit_code, duration_ms
          FROM scan_results
         WHERE order_id = %s
         ORDER BY phase, tool_name, host_ip
    """
    try:
        with conn.cursor() as cur:
            cur.execute(select_with_status, (order_id,))
            rows = cur.fetchall()
        return [
            {
                "host_ip": r[0],
                "phase": r[1],
                "tool_name": r[2],
                "exit_code": r[3],
                "duration_ms": r[4],
                "status": r[5],
                "skip_reason": r[6],
            }
            for r in rows
        ]
    except Exception as exc:
        # Wahrscheinlichster Fall: Migration 044 fehlt (status/skip_reason
        # noch nicht vorhanden) -> Legacy-SELECT ohne die zwei Spalten.
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            with conn.cursor() as cur:
                cur.execute(select_legacy, (order_id,))
                rows = cur.fetchall()
            log.info("tool_runs_loaded_legacy", order_id=order_id,
                     hint="scan_results ohne status/skip_reason (Migration 044?)")
            return [
                {
                    "host_ip": r[0],
                    "phase": r[1],
                    "tool_name": r[2],
                    "exit_code": r[3],
                    "duration_ms": r[4],
                    "status": None,
                    "skip_reason": None,
                }
                for r in rows
            ]
        except Exception as exc2:
            log.warning("tool_runs_load_failed",
                        order_id=order_id, error=str(exc2),
                        first_error=str(exc))
            try:
                conn.rollback()
            except Exception:
                pass
            return []


def _build_findings_data(claude_output: dict, package: str, report_data: dict | None = None) -> dict:
    """Build a JSON-serializable findings_data dict from Claude output."""
    findings = claude_output.get("findings", [])
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    severity_rank = {s: i for i, s in enumerate(severity_order)}
    counts: dict[str, int] = {s: 0 for s in severity_order}
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        if sev in counts:
            counts[sev] += 1

    # Sort findings by severity (CRITICAL first), then by CVSS score descending
    def _cvss(f: dict) -> float:
        try:
            return float(f.get("cvss_score") or 0)
        except (ValueError, TypeError):
            return 0.0

    sorted_findings = sorted(
        findings,
        key=lambda f: (
            severity_rank.get((f.get("severity") or "INFO").upper(), 5),
            -_cvss(f),
        ),
    )

    data: dict = {
        "overall_risk": claude_output.get("overall_risk"),
        "overall_description": claude_output.get("overall_description"),
        "severity_counts": counts,
        "findings": sorted_findings,
        "positive_findings": claude_output.get("positive_findings", []),
        "recommendations": claude_output.get("recommendations") or claude_output.get("top_recommendations", []),
        "package": package,
    }

    # Juli 2026 — Dashboard-Umlaute: findings_data ist die Quelle der Dashboard-
    # Befundansicht und lief (anders als das PDF via report_mapper._safe) bisher
    # NICHT durch die Mojibake-Reparatur. Falls KI-Ausgabe im Container zu Doppel-
    # Encoding (Ã¤) mutiert, wird das hier fuer die Dashboard-Textfelder
    # deterministisch repariert (No-op bei sauberem Text / ASCII-Umschrift).
    from reporter.report_mapper import _demojibake
    for _f in data["findings"]:
        if isinstance(_f, dict):
            for _k in ("title", "description", "impact", "recommendation",
                       "evidence", "affected"):
                if isinstance(_f.get(_k), str):
                    _f[_k] = _demojibake(_f[_k])
    for _pf in data["positive_findings"]:
        if isinstance(_pf, dict):
            for _k in ("title", "description", "recommendation"):
                if isinstance(_pf.get(_k), str):
                    _pf[_k] = _demojibake(_pf[_k])
    if isinstance(data.get("overall_description"), str):
        data["overall_description"] = _demojibake(data["overall_description"])

    # NIS2: attach compliance summary if available
    # Compliance / NIS2: attach compliance summary if available
    if package in ("nis2", "compliance") and report_data and report_data.get("nis2"):
        data["nis2_compliance_summary"] = report_data["nis2"].get("compliance_summary")

    # C1 (Phase 1): CVE-/Claims-Guard-Statistik als Audit-Feld nach
    # reports.findings_data (JSONB) durchreichen. Nur setzen, wenn vorhanden —
    # so bleiben Fixtures/Reports ohne Pipeline-Lauf byte-identisch. Der
    # findings_data-Trigger (Migration 018) liest nur findings_data->'findings',
    # Zusatz-Keys sind unschaedlich.
    cve_guard_stats = claude_output.get("cve_guard_stats")
    if cve_guard_stats is not None:
        data["cve_guard_stats"] = cve_guard_stats
    claims_guard_stats = claude_output.get("claims_guard_stats")
    if claims_guard_stats is not None:
        data["claims_guard_stats"] = claims_guard_stats

    return data


def _normalize_excluded_ids(raw: object) -> list[str]:
    """Finding-IDs aus dem excludedFindings-Payload ziehen.

    Akzeptiert beide Formen, die im Umlauf sind:
      * ``["VS-2026-004", ...]``                      (Legacy / direkte Jobs)
      * ``[{"finding_id": "VS-2026-004", "reason": …}]`` (API, orders.ts:1643/1753)
    """
    if not isinstance(raw, list):
        return []
    ids: list[str] = []
    for item in raw:
        if isinstance(item, str):
            candidate: object = item
        elif isinstance(item, dict):
            candidate = (
                item.get("finding_id")
                or item.get("findingId")
                or item.get("id")
            )
        else:
            candidate = None
        if candidate:
            ids.append(str(candidate))
    return ids


def _create_report_record(
    conn: psycopg2.extensions.connection,
    order_id: str,
    minio_path: str,
    file_size_bytes: int,
    findings_data: dict | None = None,
    version: int = 1,
    excluded_findings: list | None = None,
    policy_version: str | None = None,
    policy_id_distinct: list[str] | None = None,
    tech_profiles: list[dict] | None = None,
    additional_findings: list[dict] | None = None,
    validation_warnings: dict | None = None,
) -> tuple[str, str]:
    """Insert a row into the reports table and return (report_id, download_token).

    policy_version + policy_id_distinct werden in den Audit-Spalten der
    Migration 016 abgelegt. severity_counts wird automatisch via
    BEFORE-INSERT-Trigger aus findings_data abgeleitet.

    Migration 027 (Mai 2026): tech_profiles + additional_findings — Quelle fuer
    Per-Host-Tech-Tabelle und "alle Befunde anzeigen"-Drilldown.

    Migration 028 (M1, Q2/2026): validation_warnings — Output der
    ValidationGate (Phase A). Im WARN-Mode dokumentiert, im STRICT-Mode
    landet hier nichts, weil der Build vor dem Insert abbricht.
    """
    download_token = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(days=30)

    # Migration 028 (validation_warnings) ist zeitweise nicht in allen Umgebungen
    # verfuegbar — siehe Pipeline 2455-Issue. Detect column presence at runtime
    # und passe INSERT entsprechend an. Sobald Migration 028 ueberall durch ist,
    # kann der Fallback-Pfad entfernt werden.
    with conn.cursor() as cur:
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.columns
                WHERE table_name = 'reports' AND column_name = 'validation_warnings'
            )
        """)
        has_validation_warnings_col = cur.fetchone()[0]

    with conn.cursor() as cur:
        if has_validation_warnings_col:
            cur.execute(
                """
                INSERT INTO reports (
                    order_id, minio_bucket, minio_path, file_size_bytes,
                    download_token, expires_at, findings_data, version,
                    excluded_findings, policy_version, policy_id_distinct,
                    tech_profiles, additional_findings, validation_warnings
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    order_id, REPORTS_BUCKET, minio_path, file_size_bytes,
                    download_token, expires_at,
                    json.dumps(findings_data) if findings_data else None,
                    version,
                    json.dumps(excluded_findings) if excluded_findings else None,
                    policy_version,
                    policy_id_distinct,  # psycopg2 maps Python list → TEXT[]
                    json.dumps(tech_profiles) if tech_profiles else None,
                    json.dumps(additional_findings) if additional_findings else None,
                    json.dumps(validation_warnings) if validation_warnings else None,
                ),
            )
        else:
            log.warning(
                "validation_warnings_column_missing_skipping",
                order_id=order_id,
                hint="Run Migration 028 (api initDb auto-applies on next API start)",
            )
            cur.execute(
                """
                INSERT INTO reports (
                    order_id, minio_bucket, minio_path, file_size_bytes,
                    download_token, expires_at, findings_data, version,
                    excluded_findings, policy_version, policy_id_distinct,
                    tech_profiles, additional_findings
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    order_id, REPORTS_BUCKET, minio_path, file_size_bytes,
                    download_token, expires_at,
                    json.dumps(findings_data) if findings_data else None,
                    version,
                    json.dumps(excluded_findings) if excluded_findings else None,
                    policy_version,
                    policy_id_distinct,
                    json.dumps(tech_profiles) if tech_profiles else None,
                    json.dumps(additional_findings) if additional_findings else None,
                ),
            )
        report_id = cur.fetchone()[0]
    conn.commit()
    return str(report_id), download_token


def _update_order_status(
    conn: psycopg2.extensions.connection,
    order_id: str,
    status: str,
    error_message: str | None = None,
) -> None:
    """Update the order status (and optionally the error_message).

    Sets scan_finished_at for terminal statuses (report_complete, failed).
    """
    is_terminal = status in ("report_complete", "failed")
    with conn.cursor() as cur:
        if error_message is not None:
            cur.execute(
                f"""
                UPDATE orders
                   SET status = %s, error_message = %s,
                       {'scan_finished_at = NOW(),' if is_terminal else ''}
                       updated_at = NOW()
                 WHERE id = %s
                """,
                (status, error_message, order_id),
            )
        else:
            cur.execute(
                f"""
                UPDATE orders
                   SET status = %s,
                       {'scan_finished_at = NOW(),' if is_terminal else ''}
                       updated_at = NOW()
                 WHERE id = %s
                """,
                (status, order_id),
            )
    conn.commit()

    # Publish status event via Redis Pub/Sub for WebSocket
    try:
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        r = redis.from_url(redis_url)
        event: dict = {
            "type": "status",
            "orderId": order_id,
            "status": status,
        }
        if error_message:
            event["error"] = error_message
        r.publish(f"scan:events:{order_id}", json.dumps(event))
    except Exception as e:
        log.error("redis_publish_failed", order_id=order_id, error=str(e))


# ---------------------------------------------------------------------------
# MinIO helpers
# ---------------------------------------------------------------------------

def _get_minio_client() -> Minio:
    """Create a MinIO client."""
    return Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=MINIO_SECURE,
    )


def _download_rawdata(minio_client: Minio, raw_data_path: str, dest: Path) -> Path:
    """Download the tar.gz from MinIO and return the local file path."""
    local_tar = dest / "rawdata.tar.gz"
    minio_client.fget_object(RAWDATA_BUCKET, raw_data_path, str(local_tar))
    log.info("rawdata_downloaded", path=raw_data_path, size=local_tar.stat().st_size)
    return local_tar




def _upload_claude_debug(minio_client: Minio, order_id: str, debug_data: dict, work_dir: Path) -> None:
    """Upload Claude prompt+response debug data to MinIO (best-effort)."""
    try:
        if not minio_client.bucket_exists(DEBUG_BUCKET):
            minio_client.make_bucket(DEBUG_BUCKET)
        debug_path = work_dir / "claude-debug.json"
        debug_path.write_text(json.dumps(debug_data, indent=2, default=str, ensure_ascii=False), encoding="utf-8")
        minio_client.fput_object(
            DEBUG_BUCKET,
            f"{order_id}-claude.json",
            str(debug_path),
            content_type="application/json",
        )
        log.info("claude_debug_uploaded", order_id=order_id, bucket=DEBUG_BUCKET)
    except Exception as e:
        log.warning("claude_debug_upload_failed", order_id=order_id, error=str(e))


class TruncatedPdfError(RuntimeError):
    """Das erzeugte PDF ist unvollstaendig — nicht ausliefern."""


# Konservative Untergrenze: der kleinste echte Report in Prod liegt bei ~68 KB
# (WebCheck), ein Perimeter-Report bei 100 KB bis 2,8 MB. Alles unter 20 KB kann
# kein vollstaendiger Report sein.
_MIN_PDF_BYTES = 20 * 1024


def _assert_pdf_intact(local_path: Path) -> int:
    """Strukturelle Mindestpruefung des PDFs. Gibt die Dateigroesse zurueck.

    VEC-486: Bis hierher konnte ein unvollstaendiges PDF ungeprueft in MinIO
    landen, in die DB eingetragen und per E-Mail verschickt werden — es gab
    nirgends im Repo eine Pruefung des Datei-ENDES (bestehende Tests pruefen nur
    `%PDF` am Anfang oder `st_size > N`). Ein PDF ohne `startxref`/`%%EOF` ist
    fuer jeden Reader unlesbar.
    """
    size = local_path.stat().st_size
    if size < _MIN_PDF_BYTES:
        raise TruncatedPdfError(
            f"PDF zu klein: {size} Bytes (< {_MIN_PDF_BYTES}) — {local_path.name}",
        )

    with local_path.open("rb") as fh:
        if fh.read(5) != b"%PDF-":
            raise TruncatedPdfError(f"Kein PDF-Header in {local_path.name}")
        fh.seek(max(0, size - 2048))
        tail = fh.read()

    if b"startxref" not in tail:
        raise TruncatedPdfError(f"startxref fehlt im PDF-Ende — {local_path.name}")
    if not tail.rstrip().endswith(b"%%EOF"):
        raise TruncatedPdfError(f"%%EOF fehlt am PDF-Ende — {local_path.name}")
    return size


def _upload_report(minio_client: Minio, local_path: Path, minio_path: str) -> int:
    """Upload the PDF to MinIO and return the size MinIO actually stored."""
    # Ensure the bucket exists
    if not minio_client.bucket_exists(REPORTS_BUCKET):
        minio_client.make_bucket(REPORTS_BUCKET)

    file_size = _assert_pdf_intact(local_path)
    minio_client.fput_object(
        REPORTS_BUCKET,
        minio_path,
        str(local_path),
        content_type="application/pdf",
    )

    # Die Groesse, die in reports.file_size_bytes landet, muss die des
    # gespeicherten Objekts sein — nicht die der lokalen Datei.
    try:
        stored_size = minio_client.stat_object(REPORTS_BUCKET, minio_path).size
        if stored_size != file_size:
            log.warning("upload_size_mismatch", path=minio_path,
                        local_size=file_size, stored_size=stored_size)
        file_size = stored_size
    except Exception as e:  # stat ist best-effort, der Upload selbst hat geklappt
        log.warning("stat_after_upload_failed", path=minio_path, error=str(e))

    log.info("report_uploaded", bucket=REPORTS_BUCKET, path=minio_path, size=file_size)
    return file_size


# ---------------------------------------------------------------------------
# Post-QA risk recalculation
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_RANK_TO_RISK = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "LOW"}


def _recalculate_overall_risk(claude_output: dict) -> None:
    """Recalculate overall_risk from actual finding severities after QA.

    If QA downgrades findings (e.g. HIGH→MEDIUM), the overall_risk must
    reflect the actual maximum severity, not Claude's original assessment.
    Modifies claude_output in-place.
    """
    findings = claude_output.get("findings", [])
    if not findings:
        return

    original_risk = claude_output.get("overall_risk", "MEDIUM")
    original_rank = _SEVERITY_RANK.get(original_risk.upper(), 2)

    # Find the actual maximum severity across all findings
    max_rank = 0
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        rank = _SEVERITY_RANK.get(sev, 0)
        if rank > max_rank:
            max_rank = rank

    actual_risk = _RANK_TO_RISK[max_rank]

    if max_rank < original_rank:
        log.info(
            "overall_risk_recalculated",
            original=original_risk,
            actual=actual_risk,
            reason="QA corrections lowered max severity",
        )
        claude_output["overall_risk"] = actual_risk

        # Adjust overall_description to reflect the corrected risk level
        old_desc = claude_output.get("overall_description", "")
        if old_desc:
            # Replace risk level keywords in the description text
            import re
            risk_replacements = {
                "kritisch": {"HIGH": "erhöht", "MEDIUM": "moderat", "LOW": "gering"},
                "hohes Risiko": {"MEDIUM": "moderates Risiko", "LOW": "geringes Risiko"},
                "hohem Risiko": {"MEDIUM": "moderatem Risiko", "LOW": "geringem Risiko"},
                "erheblich": {"LOW": "begrenzt"},
                "signifikant": {"MEDIUM": "moderat", "LOW": "begrenzt"},
            }
            new_desc = old_desc
            for keyword, replacements in risk_replacements.items():
                if actual_risk in replacements and keyword.lower() in new_desc.lower():
                    new_desc = re.sub(
                        re.escape(keyword), replacements[actual_risk],
                        new_desc, count=1, flags=re.IGNORECASE,
                    )
            if new_desc != old_desc:
                claude_output["overall_description"] = new_desc
                log.info("overall_description_adjusted",
                         original_risk=original_risk, new_risk=actual_risk)


# ---------------------------------------------------------------------------
# Job processing
# ---------------------------------------------------------------------------

def process_job(job_data: dict) -> None:
    """Process a single report-generation job end-to-end.

    Expected *job_data* keys:
      - orderId            (str, UUID)
      - rawDataPath       (str, e.g. "<orderId>.tar.gz")
      - hostInventory     (dict, Phase-0 host inventory)
      - techProfiles      (list[dict], per-host technology profiles)

    PR-Posture (2026-05-03): Wenn `subscriptionId` statt `orderId` gesetzt
    ist, wird kein scan-report sondern ein Subscription-Status-Report
    erzeugt (siehe reporter/status_report_generator.py).
    """
    # Subscription-Status-Report-Job (PR-Posture)
    if job_data.get("subscriptionId") and not job_data.get("orderId"):
        try:
            from reporter.status_report_generator import process_status_report_job
            report_id = process_status_report_job(job_data)
            log.info("subscription_status_report_done",
                     subscription_id=job_data["subscriptionId"], report_id=report_id)
        except Exception as e:
            log.exception("subscription_status_report_failed",
                          subscription_id=job_data.get("subscriptionId"), error=str(e))
        return

    order_id: str = job_data.get("orderId", job_data.get("scanId", ""))
    raw_data_path: str = job_data.get("rawDataPath", f"{order_id}.tar.gz")
    host_inventory: dict = job_data.get("hostInventory", {})
    tech_profiles: list[dict] = job_data.get("techProfiles", [])
    package: str = job_data.get("package", "perimeter")
    # VEC-486: Die API stellt Ausschluesse als Objekte ein
    # ([{finding_id, reason}, ...] — api/src/routes/orders.ts:1643 und :1753),
    # der Filter in Schritt 5b vergleicht aber gegen Finding-IDs. Ohne
    # Normalisierung lief `f["id"] not in excluded` gegen eine Liste von Dicts
    # und traf nie: Admin-Ausschluesse blieben wirkungslos, der Report ging
    # trotzdem als report_complete raus. `excluded_raw` behaelt die Begruendungen
    # fuer die Audit-Spalte reports.excluded_findings.
    excluded_raw: list = job_data.get(
        "excludedFindings", job_data.get("excluded_findings", []),
    ) or []
    excluded: list[str] = _normalize_excluded_ids(excluded_raw)
    if excluded_raw and not excluded:
        log.warning(
            "excluded_findings_unparsable",
            order_id=job_data.get("orderId", job_data.get("scanId", "")),
            raw_sample=str(excluded_raw[:3]),
        )
    is_approved: bool = job_data.get("approved", False)

    work_dir = Path(tempfile.mkdtemp(prefix=f"report-{order_id}-"))
    log.info("job_started", order_id=order_id, package=package, work_dir=str(work_dir))

    conn: psycopg2.extensions.connection | None = None
    claude_debug: dict = {}

    try:
        # -- Clients ----------------------------------------------------------
        minio_client = _get_minio_client()
        conn = _get_db_connection()

        # -- 1. Download raw data from MinIO ----------------------------------
        tar_path = _download_rawdata(minio_client, raw_data_path, work_dir)

        # -- 2. Extract tar.gz ------------------------------------------------
        extract_dir = work_dir / "scan-data"
        extract_dir.mkdir()
        with tarfile.open(tar_path, "r:gz") as tar:
            tar.extractall(path=extract_dir)  # noqa: S202
        log.info("rawdata_extracted", dest=str(extract_dir))

        # -- 3. Parse scan data -----------------------------------------------
        # tar.gz has {orderId}/ as root, so extracted structure is:
        # extract_dir/{orderId}/meta.json, hosts/, phase0/, etc.
        # Resolve to the actual scan data directory inside the extraction.
        scan_data_dir = extract_dir
        subdirs = [d for d in extract_dir.iterdir() if d.is_dir()]
        if len(subdirs) == 1 and (subdirs[0] / "hosts").is_dir():
            scan_data_dir = subdirs[0]
            log.info("scan_data_resolved", subdir=subdirs[0].name)
        elif (extract_dir / "hosts").is_dir():
            scan_data_dir = extract_dir  # Flat extraction (no nesting)
        else:
            log.warning("scan_data_dir_ambiguous", subdirs=[d.name for d in subdirs])

        parsed = parse_scan_data(str(scan_data_dir))
        parsed_inventory = parsed["host_inventory"]
        parsed_profiles = parsed["tech_profiles"]
        consolidated_findings = parsed["consolidated_findings"]
        # F-PH1-003: bevorzugt per-VHost-Schema falls verfuegbar (parser.py
        # populiert beides parallel). _build_screenshot_data im report_mapper
        # versteht beide Schemata.
        host_screenshots = parsed.get("host_screenshots_per_vhost") or parsed.get("host_screenshots", {})
        log.info("scan_data_parsed", hosts=len(parsed_inventory.get("hosts", [])))

        # Use parsed inventory/profiles, fall back to job payload
        effective_inventory = parsed_inventory if parsed_inventory.get("hosts") else host_inventory
        effective_profiles = parsed_profiles if parsed_profiles else tech_profiles
        domain = effective_inventory.get("domain", "unknown")

        # Stichtag fuer KI-Freitext + EOL-Detektor: bevorzugt das echte
        # Scan-Startdatum aus den Scan-Metadaten (parser meta.startedAt),
        # Fallback heute. So rechnen KI UND deterministischer eol_detector gegen
        # dasselbe, korrekte Datum — auch beim Regenerate eines alten Reports.
        _started_at = str((parsed.get("meta", {}) or {}).get("startedAt") or "")
        scan_date_iso = _started_at[:10] or datetime.now().date().isoformat()

        # -- 4. Call Claude API for analysis ----------------------------------
        if package == "tlscompliance":
            # TLS-Compliance: build TR summary as findings text for Haiku
            from reporter.tr03116_checker import check_tr03116_compliance
            testssl_raw = parsed.get("testssl_raw_by_host", {})
            headers_raw = parsed.get("headers_by_host", {})
            tr_summary_lines = ["BSI TR-03116-4 TLS-Compliance-Prüfung\n"]
            for ip, raw in testssl_raw.items():
                header_data = headers_raw.get(ip)
                result = check_tr03116_compliance(raw, header_data, ip)
                tr_summary_lines.append(f"Host: {result['host']} — {result['overall_status']} ({result['score']})")
                for sec_id, sec in result.get("sections", {}).items():
                    for c in sec.get("checks", []):
                        if c["status"] in ("FAIL", "WARN"):
                            tr_summary_lines.append(f"  [{c['status']}] {c['check_id']} {c['title']}: {c['detail']}")
            consolidated_findings = "\n".join(tr_summary_lines) if len(tr_summary_lines) > 1 else "Keine TLS-Daten vorhanden."

            claude_output = call_claude(
                domain=domain,
                host_inventory=effective_inventory,
                tech_profiles=effective_profiles,
                consolidated_findings=consolidated_findings,
                package=package,
                debug_info=claude_debug,
                order_id=order_id,
                scan_date=scan_date_iso,
            )
            log.info("claude_analysis_complete", overall_risk=claude_output.get("overall_risk"))
            # No QA needed for tlscompliance (no CVSS findings)

            # C1 (Phase 1): tlscompliance umgeht apply_deterministic_pipeline
            # komplett — der Prompt (SYSTEM_PROMPT_TLSCOMPLIANCE) erlaubt aber
            # explizit CVE-Nennungen. Damit hier weder CVE- noch Claims-Guard
            # eine Luecke im Nachweis ist, laeuft der Guard separat (2 Zeilen).
            # tlscompliance ist NICHT im Kundenkatalog (VEC-284), daher genuegt
            # dieser schlanke Aufruf statt der vollen Pipeline. Fail-open.
            try:
                from reporter.claims_guard import apply_claims_guard
                from reporter.claims_inventory import build_evidence_inventory
                _tls_ctx = {
                    "tech_profiles": effective_profiles,
                    "host_inventory": effective_inventory,
                    "host_tool_data": parsed.get("host_tool_data"),
                    "enrichment": job_data.get("enrichment") or {},
                }
                _tls_inv = build_evidence_inventory(
                    _tls_ctx, host_tool_data=_tls_ctx["host_tool_data"])
                _tls_stats = apply_claims_guard(
                    claude_output, inventory=_tls_inv,
                    enrichment=_tls_ctx["enrichment"],
                )
                claude_output["claims_guard_stats"] = _tls_stats
                claude_output["cve_guard_stats"] = {
                    "removed_count": _tls_stats["removed_count"],
                    "distinct_removed": _tls_stats["distinct_removed"],
                    "allowlist_size": _tls_stats["allowlist_size"],
                }
            except Exception as _tls_guard_err:
                log.warning("tlscompliance_claims_guard_failed",
                            error=str(_tls_guard_err))
        else:
            claude_output = call_claude(
                domain=domain,
                host_inventory=effective_inventory,
                tech_profiles=effective_profiles,
                consolidated_findings=consolidated_findings,
                package=package,
                debug_info=claude_debug,
                order_id=order_id,
                scan_date=scan_date_iso,
            )
            log.info("claude_analysis_complete", overall_risk=claude_output.get("overall_risk"))

            # Extract cost info
            claude_cost = claude_output.pop("_cost", None)
            if claude_cost:
                claude_debug["cost"] = claude_cost
                # Save cost as separate scan_result for aggregation
                try:
                    cost_conn = _get_db_connection()
                    with cost_conn.cursor() as cur:
                        cur.execute(
                            """INSERT INTO scan_results (order_id, host_ip, phase, tool_name, raw_output, exit_code, duration_ms)
                               VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                            (order_id, None, 4, "report_cost", json.dumps(claude_cost), 0, 0),
                        )
                    cost_conn.commit()
                    cost_conn.close()
                except Exception as e:
                    log.warning("report_cost_save_failed", error=str(e))

            # -- 4b. Report QA — programmatic checks (OHNE severity-cap) ----
            # F-RPT-005: severity_evidence-Cap NACH der Determinismus-Pipeline
            # anwenden, nur auf SP-FALLBACK-Findings — severity_policy
            # ueberschreibt sonst eh ~95% der Findings (mit policy_id).
            enrichment = job_data.get("enrichment")
            qa_report = run_qa_checks(
                claude_output,
                package=package,
                enrichment=enrichment,
                apply_severity_cap=False,
            )
            log.info("qa_complete",
                     quality_score=qa_report.get("quality_score"),
                     auto_fixes=qa_report.get("auto_fixes_applied", 0),
                     manual_review=qa_report.get("manual_review_needed", False))

            # -- 4c. Deterministische Pipeline (Q2/2026 Determinismus) ---------
            # Severity-Policy + Top-N-Selection ueberschreiben die Claude-
            # Vorschlaege deterministisch. Spec: docs/deterministic/.
            scan_context = {
                "dns_records": effective_inventory.get("dns_findings") or {},
                "tech_profiles": effective_profiles,
                "enrichment": enrichment or {},
                "host_inventory": effective_inventory,
                "scan_date": scan_date_iso,  # -> detect_eol_findings (date-korrekt)
            }
            apply_deterministic_pipeline(
                claude_output,
                package=package,
                domain=domain,
                scan_context=scan_context,
            )

            # -- 4d. Severity-Cap nur fuer SP-FALLBACK-Findings (F-RPT-005) ---
            # severity_policy hat fuer alle policy_id-Findings die Severity
            # bereits final gesetzt. Nur bei SP-FALLBACK (kein Match in den
            # ~63 Regeln) hat KI-Severity ueberlebt — hier macht der
            # evidence-basierte Cap weiterhin Sinn.
            fallback_findings = [
                f for f in claude_output.get("findings", [])
                if (f.get("policy_id") or "") == "SP-FALLBACK"
            ]
            if fallback_findings:
                from reporter.qa_check import (
                    _apply_auto_fixes,
                    _check_severity_evidence,
                )
                cap_issues = _check_severity_evidence(fallback_findings)
                cap_fixes = _apply_auto_fixes(
                    {"findings": fallback_findings}, cap_issues,
                )
                if cap_fixes:
                    log.info(
                        "severity_cap_applied_to_fallback",
                        count=cap_fixes,
                        total_fallback=len(fallback_findings),
                    )
                # Audit-Flag: jedes betroffene Finding bekommt _qa_cap_applied
                capped_ids = {
                    i["finding_id"] for i in cap_issues
                    if i.get("auto_fix") and i.get("check") == "severity_evidence"
                }
                for f in claude_output.get("findings", []):
                    if f.get("id") in capped_ids:
                        f["_qa_cap_applied"] = True

            # -- 4e. Recalculate overall_risk after QA + Policy corrections ---
            _recalculate_overall_risk(claude_output)

        # -- 5. Map Claude output to report_data ------------------------------
        parsed_meta = parsed.get("meta", {})
        scan_meta = {
            "domain": domain,
            "orderId": order_id,
            "startedAt": parsed_meta.get("startedAt", datetime.now().isoformat()),
            "completedAt": parsed_meta.get("finishedAt", datetime.now().isoformat()),
            "package": package,
            "toolVersions": parsed_meta.get("toolVersions", []),
            # Migration 027 (Mai 2026): tech_profiles fuer Per-Host-Tech-Tabelle im PDF.
            "techProfiles": effective_profiles or [],
            # C3 (Phase 1): Datenkanal fuer das Abdeckungskapitel. scan_meta ist
            # der einzige Weg, den map_to_report_data/_augment_for_v2 ohne
            # Signaturaenderung bereits durchreichen. toolRuns = autoritative
            # scan_results-Zeilen (ohne raw_output); hostStrategy = KI-#1-Entscheid
            # (Skip-Gruende). Beide fail-open ([]/{}), nie den Report kippend.
            "toolRuns": _load_tool_runs(conn, order_id),
            "hostStrategy": parsed.get("host_strategy") or {},
        }
        report_data = map_to_report_data(
            claude_output=claude_output,
            scan_meta=scan_meta,
            host_inventory=effective_inventory,
            package=package,
            host_screenshots=host_screenshots,
            testssl_raw_by_host=parsed.get("testssl_raw_by_host"),
            headers_by_host=parsed.get("headers_by_host"),
        )
        log.info("report_data_mapped")

        # -- 5b. Filter excluded findings -------------------------------------
        if excluded:
            log.info("filtering_excluded_findings", count=len(excluded), ids=excluded)
            report_data["findings"] = [f for f in report_data.get("findings", [])
                                        if f.get("id") not in excluded]
            # Also filter claude_output so _build_findings_data reflects exclusions
            claude_output["findings"] = [f for f in claude_output.get("findings", [])
                                          if f.get("id") not in excluded]
            # Recalculate severity counts
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in report_data["findings"]:
                sev = f.get("severity", "INFO").upper()
                if sev in severity_counts:
                    severity_counts[sev] += 1
            report_data["severity_counts"] = severity_counts

        # -- 5c. Determine PDF version number ---------------------------------
        # VEC-486: JEDER Lauf bekommt eine eigene Version und damit einen eigenen
        # MinIO-Key. Frueher wurde nur bei gesetzten Exclusions hochgezaehlt
        # (`if excluded:`), und weil Approve/Regenerate mit `excludedFindings: []`
        # einstellen (orders.ts:1766 / :2004), lief der zweite Durchlauf mit
        # version=1 und ueberschrieb `{order_id}.pdf`. Die bereits per E-Mail
        # ausgelieferte reports-Zeile behielt ihre alte, kleinere
        # file_size_bytes -> der Download brach stumm mittendrin ab.
        version_fallback = False
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COALESCE(MAX(version), 0) FROM reports WHERE order_id = %s",
                    (order_id,),
                )
                version = cur.fetchone()[0] + 1
        except Exception:
            version = 2
            version_fallback = True
            log.warning("version_query_failed", order_id=order_id, fallback_version=version)

        if version == 1:
            minio_pdf_path = f"{order_id}.pdf"
        elif version_fallback:
            # Ohne verlaessliche MAX(version) darf der Key nicht geraten werden —
            # ein kollisionsfreier Name ist wichtiger als eine huebsche Nummer.
            minio_pdf_path = f"{order_id}_v{version}_{uuid.uuid4().hex[:8]}.pdf"
        else:
            minio_pdf_path = f"{order_id}_v{version}.pdf"

        # -- 5d. Validation-Gate (M1) ----------------------------------------
        # Phase A aus docs/report-erstellung/01_Fehleranalyse_und_Korrekturplan.md.
        # Validiert findings_data + report_data BEVOR PDF/Upload — bei STRICT-
        # Failure sparen wir uns die teure PDF-Generation und den MinIO-Upload.
        from reporter.validation.gate import (
            ValidationFailedError,
            ValidationGate,
            ValidationLevel,
        )
        findings_data_for_validation = _build_findings_data(
            claude_output, package, report_data,
        )
        # Migration 029 (Mai 2026): Admin-Overrides auf einzelne Findings
        # (cvss_score, severity, title, _ignored) — werden VOR der Gate
        # appliziert, damit korrigierte Werte direkt validiert werden.
        overrides_applied = _apply_finding_overrides(
            findings_data_for_validation, conn, order_id,
        )
        if overrides_applied:
            report_data["_finding_overrides_applied"] = overrides_applied

        gate = ValidationGate.from_env()
        gate_result = gate.run(
            findings_data_for_validation,
            report_data=report_data,
            context={
                "package": package,
                "order_id": order_id,
                "domain": domain,
                # M1: raw tech_profiles fuer consistency/tech_table/eol checks
                # (im report_data sind die Tech-Daten nur als Paragraph-
                # Objekte unter scope.subsections[*].host_tech_blocks vorhanden,
                # nicht direkt validierbar).
                "tech_profiles": effective_profiles or [],
            },
        )
        # Persist validation_warnings unabhaengig vom Level (auch
        # passed=True wird dokumentiert — checks_run/skipped sind Audit).
        validation_warnings_payload = gate_result.to_json()
        report_data["_validation_warnings"] = validation_warnings_payload
        if not gate_result.passed:
            log.warning(
                "validation_gate_failed",
                order_id=order_id,
                level=gate.level.value,
                error_count=len(gate_result.errors),
                warning_count=len(gate_result.warnings),
            )
            if gate.level == ValidationLevel.STRICT:
                # In STRICT: Order auf failed setzen, kein PDF/Upload, kein
                # report-record. Tech-Lead diagnostiziert via Logs +
                # orders.error_message.
                _update_order_status(
                    conn, order_id, "failed",
                    error_message=(
                        f"Validation-Gate STRICT: "
                        f"{len(gate_result.errors)} Defekte"
                    ),
                )
                log.error(
                    "validation_gate_strict_block",
                    order_id=order_id,
                    result=validation_warnings_payload,
                )
                raise ValidationFailedError(gate_result)

        # -- 6. Generate PDF --------------------------------------------------
        # M3: V2-Renderer ueber ENV-Flag aktivierbar. Default bleibt
        # Legacy v1 -- Big-Bang-Cutover erst in M6.
        pdf_path = work_dir / f"{order_id}.pdf"
        layout = os.environ.get("VECTISCAN_REPORT_LAYOUT", "v1").lower()
        if layout == "v2":
            from reporter.pdf.v2 import generate_report_v2
            generate_report_v2(report_data, str(pdf_path))
            log.info(
                "pdf_generated_v2",
                path=str(pdf_path),
                size=pdf_path.stat().st_size,
            )
        else:
            generate_report(report_data, str(pdf_path))
            log.info(
                "pdf_generated",
                path=str(pdf_path),
                size=pdf_path.stat().st_size,
            )

        # -- 7. Upload PDF to MinIO -------------------------------------------
        file_size = _upload_report(minio_client, pdf_path, minio_pdf_path)

        # -- 8. Build findings_data and create report record in DB ---------------
        findings_data = _build_findings_data(claude_output, package, report_data)
        # Audit-Felder aus deterministischer Pipeline
        policy_version = claude_output.get("policy_version")
        policy_ids_raw = claude_output.get("policy_id_distinct") or []
        policy_id_distinct = [pid for pid in policy_ids_raw if pid] or None
        # Migration 027: tech_profiles (1:1 aus Phase 1, mit pre-computed tech_rows
        # via tech_table_builder als Single Source of Truth — Frontend nutzt diese
        # statt eigener Klassifikation) + additional_findings (Voll-Body).
        from reporter.tech_table_builder import build_tech_table_for_host
        enriched_profiles: list[dict] | None = None
        if effective_profiles:
            enriched_profiles = []
            for p in effective_profiles:
                tech_rows = build_tech_table_for_host(p)
                enriched_profiles.append({**p, "tech_rows": tech_rows})
        additional_findings = claude_output.get("additional_findings_summary") or None
        report_id, download_token = _create_report_record(
            conn, order_id, minio_pdf_path, file_size, findings_data,
            # Audit-Spalte behaelt den Roh-Payload inkl. Begruendungen.
            version=version, excluded_findings=excluded_raw if excluded_raw else None,
            policy_version=policy_version,
            policy_id_distinct=policy_id_distinct,
            tech_profiles=enriched_profiles,
            additional_findings=additional_findings,
            validation_warnings=validation_warnings_payload,
        )
        log.info("report_record_created", report_id=report_id,
                 download_token=download_token, version=version,
                 policy_version=policy_version,
                 policy_id_count=len(policy_id_distinct or []),
                 tech_profile_count=len(enriched_profiles or []),
                 additional_finding_count=len(additional_findings or []))

        # -- 8b. Mark previous versions as superseded --------------------------
        # VEC-486: ALLE aelteren Zeilen der Order abloesen, nicht nur `version - 1`.
        # Durch den frueheren Versionierungs-Bug existieren Orders mit mehreren
        # version=1-Zeilen (Prod: bis zu neun), die sonst dauerhaft als "aktuell"
        # gelten — u.a. fuer den Join in api/src/lib/ws-manager.ts:71.
        if version > 1:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE reports SET superseded_by = %s
                        WHERE order_id = %s AND id <> %s AND superseded_by IS NULL
                        """,
                        (report_id, order_id, report_id),
                    )
                    superseded_count = cur.rowcount
                conn.commit()
                log.info("previous_versions_superseded", order_id=order_id,
                         count=superseded_count, new_version=version)
            except Exception as e:
                log.warning("supersede_failed", error=str(e))

        # -- 8c. Subscription-Posture-Aggregation (PR-Posture, 2026-05-03) ----
        # Akkumuliert Findings ueber alle Scans der Subscription in
        # consolidated_findings + tracked Lifecycle (open/resolved/regressed).
        # Best-effort: bei Fehlern wird der Report trotzdem ausgeliefert.
        # WICHTIG (2026-05-03 Fix): bei SQL-Exception im Aggregator landen
        # wir in einem aborted-transaction-State; conn.rollback() ist
        # noetig damit `_update_order_status` (naechster Step) nicht mit
        # InFailedSqlTransaction crasht und der Order in report_generating
        # haengen bleibt.
        try:
            from reporter.posture_aggregator import aggregate_into_posture
            posture = aggregate_into_posture(conn, order_id, findings_data)
            if posture:
                log.info(
                    "posture_aggregation_done",
                    order_id=order_id,
                    score=posture.posture_score,
                    new=posture.new_findings,
                    resolved=posture.resolved_findings,
                    regressed=posture.regressed_findings,
                    trend=posture.trend_direction,
                )
        except Exception as e:
            log.warning("posture_aggregation_failed", order_id=order_id, error=str(e))
            try:
                conn.rollback()
            except Exception:
                # conn moeglicherweise schon im broken state — neue holen
                try:
                    conn.close()
                except Exception:
                    pass
                conn = _get_db_connection()

        # -- 9. Update order status -----------------------------------------------
        # If admin approved (approved flag) or regeneration → report_complete.
        # First run after scan (no approval) → pending_review for admin to review.
        final_status = "report_complete" if (is_approved or bool(excluded)) else "pending_review"
        _update_order_status(conn, order_id, final_status)
        log.info("job_completed", order_id=order_id, package=package, status=final_status)

    except Exception as e:
        # Validation-Gate-STRICT-Failure: Order ist bereits auf failed gesetzt
        # mit kuratierter error_message. Nicht ueberschreiben — nur loggen +
        # weiter mit finally-Cleanup.
        from reporter.validation.gate import ValidationFailedError
        if isinstance(e, ValidationFailedError):
            log.warning("job_blocked_by_validation_gate", order_id=order_id,
                        error_count=len(e.result.errors))
        else:
            log.exception("job_failed", order_id=order_id)
            # Best-effort: mark the order as failed in the database
            try:
                if conn is None:
                    conn = _get_db_connection()
                import traceback
                err_msg = traceback.format_exc()[-500:]  # keep last 500 chars
                _update_order_status(conn, order_id, "failed", error_message=err_msg)
            except Exception:
                log.exception("failed_to_update_order_status", order_id=order_id)
    finally:
        # -- Upload Claude debug data (both success and failure) ---------------
        if claude_debug:
            try:
                mc = _get_minio_client()
                _upload_claude_debug(mc, order_id, claude_debug, work_dir)
            except Exception:
                log.warning("claude_debug_upload_skipped", order_id=order_id)

        # -- 10. Clean up /tmp ------------------------------------------------
        try:
            shutil.rmtree(work_dir, ignore_errors=True)
            log.info("work_dir_cleaned", path=str(work_dir))
        except Exception:
            log.warning("cleanup_failed", path=str(work_dir))
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Queue consumer loop
# ---------------------------------------------------------------------------

def wait_for_jobs(redis_client: redis.Redis) -> None:
    """Block and wait for report jobs on the Redis queue."""
    log.info("waiting_for_jobs", queue=QUEUE_NAME)
    while True:
        try:
            result = redis_client.blpop(QUEUE_NAME, timeout=BLPOP_TIMEOUT)
            if result is None:
                continue

            _, raw_data = result
            try:
                job_data = json.loads(raw_data)
            except json.JSONDecodeError:
                log.error("invalid_job_data", data=raw_data.decode(errors="replace"))
                continue

            log.info("job_received", order_id=job_data.get("orderId", job_data.get("scanId")))
            process_job(job_data)

        except redis.ConnectionError:
            log.warning("redis_connection_lost", retry_in_seconds=5)
            time.sleep(5)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Entry point for the report worker."""
    log.info("report_worker_started")

    redis_client = redis.from_url(REDIS_URL)

    def shutdown(signum: int, frame: object) -> None:
        log.info("report_worker_shutdown", signal=signum)
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    wait_for_jobs(redis_client)


if __name__ == "__main__":
    main()
