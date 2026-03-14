"""BullMQ Consumer — Orchestrates the three scan phases."""

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any

import redis
import structlog

from scanner.packages import get_config
from scanner.phase0 import run_phase0
from scanner.phase1 import run_phase1
from scanner.phase2 import run_phase2
from scanner.progress import (
    set_discovered_hosts,
    set_scan_complete,
    set_scan_failed,
    set_scan_started,
    update_progress,
)
from scanner.upload import enqueue_report_job, pack_results, upload_to_minio

log = structlog.get_logger()


# Tool version commands — each returns (tool_name, version_string)
_VERSION_COMMANDS: list[tuple[str, list[str]]] = [
    ("nmap", ["nmap", "--version"]),
    ("nuclei", ["nuclei", "-version"]),
    ("subfinder", ["subfinder", "-version"]),
    ("amass", ["amass", "-version"]),
    ("gobuster", ["gobuster", "version"]),
    ("dnsx", ["dnsx", "-version"]),
    ("gowitness", ["gowitness", "version"]),
    ("testssl.sh", ["/opt/testssl.sh/testssl.sh", "--version"]),
    ("nikto", ["perl", "/opt/nikto/program/nikto.pl", "-Version"]),
    ("wafw00f", ["wafw00f", "--version"]),
]


def _collect_tool_versions() -> list[str]:
    """Collect installed tool versions at scan start.

    Returns a list of strings like ["nmap 7.94", "nuclei 3.7.1", ...].
    """
    versions: list[str] = []
    for tool_name, cmd in _VERSION_COMMANDS:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
            )
            output = (result.stdout + result.stderr).strip()
            # Extract version number from first line
            first_line = output.split("\n")[0].strip()
            # Try to find a version pattern (digits.digits...)
            import re
            match = re.search(r"(\d+\.\d+[\.\d]*)", first_line)
            if match:
                versions.append(f"{tool_name} {match.group(1)}")
            else:
                versions.append(f"{tool_name} (installed)")
        except Exception:
            versions.append(f"{tool_name} (not found)")
    return versions


def _process_job(scan_id: str, domain: str, package: str = "professional") -> None:
    """Run the full three-phase scan pipeline for a single job."""
    scan_dir = f"/tmp/scan-{scan_id}"
    os.makedirs(scan_dir, exist_ok=True)

    config = get_config(package)

    start = time.monotonic()

    # Package-specific timeout labels
    _PACKAGE_LABELS = {"basic": "Basic (~10 Min.)", "professional": "Professional (~45 Min.)", "nis2": "NIS2 (~45 Min.)"}
    _package_label = _PACKAGE_LABELS.get(package, package)
    _timeout_minutes = config["total_timeout"] // 60

    def _check_timeout() -> None:
        elapsed = time.monotonic() - start
        if elapsed >= config["total_timeout"]:
            raise TimeoutError(
                f"Scan-Timeout: Das {_package_label}-Paket hat das Zeitlimit "
                f"von {_timeout_minutes} Minuten überschritten."
            )

    # Collect tool versions before scanning
    tool_versions = _collect_tool_versions()
    log.info("tool_versions_collected", count=len(tool_versions))

    # Write meta.json
    meta = {
        "scanId": scan_id,
        "domain": domain,
        "package": package,
        "startedAt": datetime.now(timezone.utc).isoformat(),
        "toolVersions": tool_versions,
    }
    with open(f"{scan_dir}/meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    log.info("scan_start", scan_id=scan_id, domain=domain)
    set_scan_started(scan_id)

    # ── Phase 0: DNS Reconnaissance ─────────────────────────
    update_progress(scan_id, "dns_recon", "starting")
    host_inventory = run_phase0(domain, scan_dir, scan_id, config)
    set_discovered_hosts(scan_id, host_inventory)

    hosts = host_inventory.get("hosts", [])
    hosts_total = len(hosts)
    log.info("phase0_done", scan_id=scan_id, hosts_found=hosts_total)

    if hosts_total == 0:
        log.warning("no_hosts_found", scan_id=scan_id, domain=domain)
        # Still complete — report worker handles empty inventory
        _finalize(scan_id, scan_dir, host_inventory, [], package)
        return

    _check_timeout()

    # ── Phase 1 + 2: Per-Host scanning (sequential) ────────
    tech_profiles: list[dict[str, Any]] = []

    for idx, host in enumerate(hosts):
        ip = host["ip"]
        fqdns = host["fqdns"]

        _check_timeout()

        # Phase 1: Technology detection
        def p1_callback(sid: str, tool: str, status: str) -> None:
            update_progress(sid, "scan_phase1", tool, host=ip,
                            hosts_completed=idx, hosts_total=hosts_total)

        update_progress(scan_id, "scan_phase1", "starting", host=ip,
                        hosts_completed=idx, hosts_total=hosts_total)
        tech_profile = run_phase1(ip, fqdns, scan_dir, scan_id, p1_callback, config)
        tech_profiles.append(tech_profile)

        _check_timeout()

        # Phase 2: Deep scan
        def p2_callback(sid: str, tool: str, status: str) -> None:
            update_progress(sid, "scan_phase2", tool, host=ip,
                            hosts_completed=idx, hosts_total=hosts_total)

        update_progress(scan_id, "scan_phase2", "starting", host=ip,
                        hosts_completed=idx, hosts_total=hosts_total)
        run_phase2(ip, fqdns, tech_profile, scan_dir, scan_id, p2_callback, config)

        log.info("host_complete", scan_id=scan_id, ip=ip, idx=idx + 1, total=hosts_total)

    # ── Finalize ────────────────────────────────────────────
    _finalize(scan_id, scan_dir, host_inventory, tech_profiles, package)


def _finalize(
    scan_id: str,
    scan_dir: str,
    host_inventory: dict[str, Any],
    tech_profiles: list[dict[str, Any]],
    package: str = "professional",
) -> None:
    """Pack results, upload to MinIO, enqueue report job."""
    hosts_total = len(host_inventory.get("hosts", []))

    update_progress(scan_id, "scan_complete", "uploading",
                    hosts_completed=hosts_total, hosts_total=hosts_total)

    # Update meta.json with finish timestamp
    meta_path = f"{scan_dir}/meta.json"
    try:
        with open(meta_path) as f:
            meta = json.load(f)
        meta["finishedAt"] = datetime.now(timezone.utc).isoformat()
        meta["hostsScanned"] = hosts_total
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)
    except Exception as e:
        log.error("meta_update_failed", error=str(e))

    # Pack and upload
    archive_path = pack_results(scan_dir, scan_id)
    minio_path = upload_to_minio(archive_path, scan_id)

    # Enqueue report generation
    enqueue_report_job(scan_id, minio_path, host_inventory, tech_profiles, package)

    # Mark scan as complete
    set_scan_complete(scan_id)

    # Cleanup scan directory
    try:
        shutil.rmtree(scan_dir)
        log.info("scan_dir_cleaned", scan_dir=scan_dir)
    except Exception as e:
        log.warning("scan_dir_cleanup_failed", error=str(e))

    log.info("scan_complete", scan_id=scan_id)


def wait_for_jobs(redis_client: redis.Redis) -> None:
    """Block and wait for scan jobs on the Redis queue."""
    log.info("waiting_for_jobs", queue="scan-pending")
    while True:
        try:
            result = redis_client.blpop("scan-pending", timeout=5)
            if result is None:
                continue

            _, job_data = result
            job = json.loads(job_data.decode())
            scan_id = job["scanId"]
            domain = job["targetDomain"]
            package = job.get("package", "professional")

            log.info("job_received", scan_id=scan_id, domain=domain)

            try:
                _process_job(scan_id, domain, package)
            except TimeoutError as e:
                log.error("scan_timeout", scan_id=scan_id, error=str(e))
                set_scan_failed(scan_id, str(e))
                scan_dir = f"/tmp/scan-{scan_id}"
                if os.path.exists(scan_dir):
                    shutil.rmtree(scan_dir, ignore_errors=True)
            except Exception as e:
                log.error("scan_failed", scan_id=scan_id, error=str(e))
                set_scan_failed(scan_id, str(e))
                scan_dir = f"/tmp/scan-{scan_id}"
                if os.path.exists(scan_dir):
                    shutil.rmtree(scan_dir, ignore_errors=True)

        except redis.ConnectionError:
            log.warning("redis_connection_lost, retrying in 5s")
            time.sleep(5)


def main() -> None:
    """Entry point for the scan worker."""
    log.info("scan_worker_started")

    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    redis_client = redis.from_url(redis_url)

    def shutdown(signum: int, frame: object) -> None:
        log.info("scan_worker_shutdown", signal=signum)
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    wait_for_jobs(redis_client)


if __name__ == "__main__":
    main()
