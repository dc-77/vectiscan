"""Upload scan results to MinIO and enqueue report generation."""

import json
import os
import tarfile
from pathlib import Path

import redis
import structlog
from minio import Minio

log = structlog.get_logger()


def get_minio_client() -> Minio:
    """Create MinIO client from environment variables."""
    return Minio(
        f"{os.environ.get('MINIO_ENDPOINT', 'minio')}:{os.environ.get('MINIO_PORT', '9000')}",
        access_key=os.environ.get("MINIO_ACCESS_KEY", "minioadmin"),
        secret_key=os.environ.get("MINIO_SECRET_KEY", "minioadmin"),
        secure=os.environ.get("MINIO_SECURE", "false").lower() == "true",
    )


def pack_results(scan_dir: str, order_id: str) -> str:
    """Pack scan results directory into a tar.gz archive.

    Returns path to the created archive.
    """
    archive_path = f"/tmp/{order_id}.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(scan_dir, arcname=order_id)

    log.info("results_packed", order_id=order_id, archive=archive_path)
    return archive_path


def upload_screenshots(scan_dir: str, order_id: str) -> dict[str, str]:
    """Sammle alle screenshot_<fqdn>.png aus /tmp/scan-<id>/hosts/*/phase*/
    und lade sie nach MinIO unter `screenshots/<orderId>/<fqdn>.png`.

    Returns: dict {fqdn -> minio_object_key}. Leeres dict bei Fehlern oder
    wenn keine Screenshots gefunden wurden — der Scan laeuft trotzdem.
    """
    from pathlib import Path
    import re
    out: dict[str, str] = {}
    try:
        client = get_minio_client()
        bucket = "scan-screenshots"
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
        # Suche alle screenshot_*.png unter <scan_dir>/hosts/*/phase*/
        scan_root = Path(scan_dir)
        for png in scan_root.glob("hosts/*/phase*/screenshot_*.png"):
            try:
                # Filename: screenshot_<fqdn-with-underscores>.png — wieder zurueckmappen
                # ist nicht eindeutig; daher nutzen wir einfach den Stem als Key
                # und mappen nach FQDN ueber das Filename-Pattern (siehe redirect_probe.py:89:
                # safe_fqdn = fqdn.replace(".", "_").replace("/", "")[:50]).
                safe = png.stem.replace("screenshot_", "")
                # Heuristisch: Underscores zurueck zu Punkten — funktioniert fuer
                # normale FQDNs (kein User-Input-Underscore in Realdomains)
                fqdn_guess = safe.replace("_", ".")
                obj_key = f"{order_id}/{safe}.png"
                client.fput_object(bucket, obj_key, str(png), content_type="image/png")
                out[fqdn_guess] = obj_key
            except Exception as e:
                log.warning("screenshot_upload_failed", path=str(png), error=str(e))
        log.info("screenshots_uploaded", order_id=order_id, count=len(out))
    except Exception as e:
        log.warning("screenshots_upload_skipped", error=str(e))
    return out


def upload_to_minio(archive_path: str, order_id: str) -> str:
    """Upload tar.gz to MinIO scan-rawdata bucket.

    Returns the MinIO object path.
    """
    client = get_minio_client()
    bucket = "scan-rawdata"

    # Ensure bucket exists
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket)

    object_name = f"{order_id}.tar.gz"
    client.fput_object(bucket, object_name, archive_path)

    minio_path = object_name
    log.info("uploaded_to_minio", order_id=order_id, path=minio_path)

    # Clean up local archive
    os.remove(archive_path)

    return minio_path


def enqueue_report_job(
    order_id: str,
    minio_path: str,
    host_inventory: dict,
    tech_profiles: list[dict],
    package: str = "perimeter",
    phase3_result: dict | None = None,
) -> None:
    """Push a job to the report-pending queue in Redis."""
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    r = redis.from_url(redis_url)

    job_payload: dict = {
        "orderId": order_id,
        "rawDataPath": minio_path,
        "hostInventory": host_inventory,
        "techProfiles": tech_profiles,
        "package": package,
    }

    # Include Phase 3 enrichment data for the report worker
    if phase3_result:
        job_payload["enrichment"] = phase3_result.get("enrichment", {})
        job_payload["correlatedFindings"] = phase3_result.get("correlated_findings", [])
        job_payload["businessImpactScore"] = phase3_result.get("business_impact_score", 0.0)
        job_payload["phase3Summary"] = phase3_result.get("phase3_summary", {})

    job_data = json.dumps(job_payload, default=str)

    r.rpush("report-pending", job_data)
    log.info("report_job_enqueued", order_id=order_id, package=package,
             has_phase3=bool(phase3_result))
