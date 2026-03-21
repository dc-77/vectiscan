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


def _build_findings_data(claude_output: dict, package: str, report_data: dict | None = None) -> dict:
    """Build a JSON-serializable findings_data dict from Claude output."""
    findings = claude_output.get("findings", [])
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts: dict[str, int] = {s: 0 for s in severity_order}
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        if sev in counts:
            counts[sev] += 1

    data: dict = {
        "overall_risk": claude_output.get("overall_risk"),
        "overall_description": claude_output.get("overall_description"),
        "severity_counts": counts,
        "findings": findings,
        "positive_findings": claude_output.get("positive_findings", []),
        "recommendations": claude_output.get("recommendations") or claude_output.get("top_recommendations", []),
        "package": package,
    }

    # NIS2: attach compliance summary if available
    # Compliance / NIS2: attach compliance summary if available
    if package in ("nis2", "compliance") and report_data and report_data.get("nis2"):
        data["nis2_compliance_summary"] = report_data["nis2"].get("compliance_summary")

    return data


def _create_report_record(
    conn: psycopg2.extensions.connection,
    order_id: str,
    minio_path: str,
    file_size_bytes: int,
    findings_data: dict | None = None,
    version: int = 1,
    excluded_findings: list[str] | None = None,
) -> tuple[str, str]:
    """Insert a row into the reports table and return (report_id, download_token)."""
    download_token = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(days=30)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO reports (order_id, minio_bucket, minio_path, file_size_bytes,
                                 download_token, expires_at, findings_data, version, excluded_findings)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (order_id, REPORTS_BUCKET, minio_path, file_size_bytes, download_token, expires_at,
             json.dumps(findings_data) if findings_data else None,
             version, json.dumps(excluded_findings) if excluded_findings else None),
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


def _upload_report(minio_client: Minio, local_path: Path, minio_path: str) -> int:
    """Upload the PDF to MinIO and return file size in bytes."""
    # Ensure the bucket exists
    if not minio_client.bucket_exists(REPORTS_BUCKET):
        minio_client.make_bucket(REPORTS_BUCKET)

    file_size = local_path.stat().st_size
    minio_client.fput_object(
        REPORTS_BUCKET,
        minio_path,
        str(local_path),
        content_type="application/pdf",
    )
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
    """
    order_id: str = job_data.get("orderId", job_data.get("scanId", ""))
    raw_data_path: str = job_data["rawDataPath"]
    host_inventory: dict = job_data["hostInventory"]
    tech_profiles: list[dict] = job_data["techProfiles"]
    package: str = job_data.get("package", "perimeter")
    excluded: list[str] = job_data.get("excluded_findings", [])

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
        host_screenshots = parsed.get("host_screenshots", {})
        log.info("scan_data_parsed", hosts=len(parsed_inventory.get("hosts", [])))

        # Use parsed inventory/profiles, fall back to job payload
        effective_inventory = parsed_inventory if parsed_inventory.get("hosts") else host_inventory
        effective_profiles = parsed_profiles if parsed_profiles else tech_profiles
        domain = effective_inventory.get("domain", "unknown")

        # -- 4. Call Claude API for analysis ----------------------------------
        claude_output = call_claude(
            domain=domain,
            host_inventory=effective_inventory,
            tech_profiles=effective_profiles,
            consolidated_findings=consolidated_findings,
            package=package,
            debug_info=claude_debug,
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

        # -- 4b. Report QA — programmatic checks + Haiku plausibility ---------
        enrichment = job_data.get("enrichment")
        qa_report = run_qa_checks(claude_output, package=package, enrichment=enrichment)
        log.info("qa_complete",
                 quality_score=qa_report.get("quality_score"),
                 auto_fixes=qa_report.get("auto_fixes_applied", 0),
                 manual_review=qa_report.get("manual_review_needed", False))

        # -- 4c. Recalculate overall_risk after QA corrections -----------------
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
        }
        report_data = map_to_report_data(
            claude_output=claude_output,
            scan_meta=scan_meta,
            host_inventory=effective_inventory,
            package=package,
            host_screenshots=host_screenshots,
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
        version = 1
        if excluded:
            # This is a regeneration — find current max version
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT COALESCE(MAX(version), 0) FROM reports WHERE order_id = %s", (order_id,))
                    current_max = cur.fetchone()[0]
                    version = current_max + 1
            except Exception:
                version = 2  # Fallback if query fails
                log.warning("version_query_failed", order_id=order_id, fallback_version=version)

        minio_pdf_path = f"{order_id}_v{version}.pdf" if version > 1 else f"{order_id}.pdf"

        # -- 6. Generate PDF --------------------------------------------------
        pdf_path = work_dir / f"{order_id}.pdf"
        generate_report(report_data, str(pdf_path))
        log.info("pdf_generated", path=str(pdf_path), size=pdf_path.stat().st_size)

        # -- 7. Upload PDF to MinIO -------------------------------------------
        file_size = _upload_report(minio_client, pdf_path, minio_pdf_path)

        # -- 8. Build findings_data and create report record in DB ---------------
        findings_data = _build_findings_data(claude_output, package, report_data)
        report_id, download_token = _create_report_record(
            conn, order_id, minio_pdf_path, file_size, findings_data,
            version=version, excluded_findings=excluded if excluded else None,
        )
        log.info("report_record_created", report_id=report_id, download_token=download_token, version=version)

        # -- 8b. Mark previous version as superseded --------------------------
        if version > 1:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE reports SET superseded_by = %s
                        WHERE order_id = %s AND version = %s
                        """,
                        (report_id, order_id, version - 1),
                    )
                conn.commit()
                log.info("previous_version_superseded", order_id=order_id, old_version=version - 1)
            except Exception as e:
                log.warning("supersede_failed", error=str(e))

        # -- 9. Update order status to report_complete -------------------------
        _update_order_status(conn, order_id, "report_complete")
        log.info("job_completed", order_id=order_id, package=package)

    except Exception:
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
