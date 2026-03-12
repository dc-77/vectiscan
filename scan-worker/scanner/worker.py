"""BullMQ Consumer — Orchestriert die Scan-Phasen."""

import signal
import sys
import time

import redis
import structlog

log = structlog.get_logger()


def wait_for_jobs(redis_client: redis.Redis) -> None:
    """Block and wait for scan jobs on the Redis queue."""
    log.info("waiting_for_jobs", queue="scan:pending")
    while True:
        try:
            result = redis_client.blpop("scan:pending", timeout=5)
            if result:
                _, job_data = result
                log.info("job_received", data=job_data.decode())
        except redis.ConnectionError:
            log.warning("redis_connection_lost, retrying in 5s")
            time.sleep(5)


def main() -> None:
    """Entry point for the scan worker."""
    log.info("scan_worker_started")

    redis_url = "redis://localhost:6379"
    redis_client = redis.from_url(redis_url)

    def shutdown(signum: int, frame: object) -> None:
        log.info("scan_worker_shutdown", signal=signum)
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    wait_for_jobs(redis_client)


if __name__ == "__main__":
    main()
