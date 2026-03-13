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
        os.environ.get("MINIO_ENDPOINT", "minio:9000"),
        access_key=os.environ.get("MINIO_ACCESS_KEY", "minioadmin"),
        secret_key=os.environ.get("MINIO_SECRET_KEY", "minioadmin"),
        secure=os.environ.get("MINIO_SECURE", "false").lower() == "true",
    )


def pack_results(scan_dir: str, scan_id: str) -> str:
    """Pack scan results directory into a tar.gz archive.

    Returns path to the created archive.
    """
    archive_path = f"/tmp/{scan_id}.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(scan_dir, arcname=scan_id)

    log.info("results_packed", scan_id=scan_id, archive=archive_path)
    return archive_path


def upload_to_minio(archive_path: str, scan_id: str) -> str:
    """Upload tar.gz to MinIO scan-rawdata bucket.

    Returns the MinIO object path.
    """
    client = get_minio_client()
    bucket = "scan-rawdata"

    # Ensure bucket exists
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket)

    object_name = f"{scan_id}.tar.gz"
    client.fput_object(bucket, object_name, archive_path)

    minio_path = f"{bucket}/{object_name}"
    log.info("uploaded_to_minio", scan_id=scan_id, path=minio_path)

    # Clean up local archive
    os.remove(archive_path)

    return minio_path


def enqueue_report_job(
    scan_id: str,
    minio_path: str,
    host_inventory: dict,
    tech_profiles: list[dict],
) -> None:
    """Push a job to the report:pending queue in Redis."""
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    r = redis.from_url(redis_url)

    job_data = json.dumps({
        "scanId": scan_id,
        "rawDataPath": minio_path,
        "hostInventory": host_inventory,
        "techProfiles": tech_profiles,
    })

    r.rpush("report:pending", job_data)
    log.info("report_job_enqueued", scan_id=scan_id)
