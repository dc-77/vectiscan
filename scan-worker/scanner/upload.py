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
) -> None:
    """Push a job to the report-pending queue in Redis."""
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    r = redis.from_url(redis_url)

    job_data = json.dumps({
        "orderId": order_id,
        "rawDataPath": minio_path,
        "hostInventory": host_inventory,
        "techProfiles": tech_profiles,
        "package": package,
    })

    r.rpush("report-pending", job_data)
    log.info("report_job_enqueued", order_id=order_id, package=package)
