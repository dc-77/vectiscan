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
) -> tuple[str, str]:
    """Insert a row into the reports table and return (report_id, download_token)."""
    download_token = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(days=30)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO reports (order_id, minio_bucket, minio_path, file_size_bytes, download_token, expires_at, findings_data)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (order_id, REPORTS_BUCKET, minio_path, file_size_bytes, download_token, expires_at,
             json.dumps(findings_data) if findings_data else None),
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
    """Update the order status (and optionally the error_message)."""
    with conn.cursor() as cur:
        if error_message is not None:
            cur.execute(
                """
                UPDATE orders
                   SET status = %s, error_message = %s, updated_at = NOW()
                 WHERE id = %s
                """,
                (status, error_message, order_id),
            )
        else:
            cur.execute(
                """
                UPDATE orders
                   SET status = %s, updated_at = NOW()
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

    work_dir = Path(tempfile.mkdtemp(prefix=f"report-{order_id}-"))
    log.info("job_started", order_id=order_id, package=package, work_dir=str(work_dir))

    conn: psycopg2.extensions.connection | None = None

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
        parsed = parse_scan_data(str(extract_dir))
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
        )
        log.info("claude_analysis_complete", overall_risk=claude_output.get("overall_risk"))

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

        # -- 6. Generate PDF --------------------------------------------------
        pdf_path = work_dir / f"{order_id}.pdf"
        generate_report(report_data, str(pdf_path))
        log.info("pdf_generated", path=str(pdf_path), size=pdf_path.stat().st_size)

        # -- 7. Upload PDF to MinIO -------------------------------------------
        minio_pdf_path = f"{order_id}.pdf"
        file_size = _upload_report(minio_client, pdf_path, minio_pdf_path)

        # -- 8. Build findings_data and create report record in DB ---------------
        findings_data = _build_findings_data(claude_output, package, report_data)
        report_id, download_token = _create_report_record(conn, order_id, minio_pdf_path, file_size, findings_data)
        log.info("report_record_created", report_id=report_id, download_token=download_token)

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
