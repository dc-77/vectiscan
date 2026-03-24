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

import socket as _socket

import psycopg2

from scanner.packages import get_config
from scanner.phase0 import run_phase0
from scanner.phase1 import run_phase1
from scanner.phase2 import run_phase2
from scanner.phase3 import run_phase3
from scanner.progress import (
    publish_event,
    set_discovered_hosts,
    set_scan_complete,
    set_scan_failed,
    set_scan_started,
    update_progress,
)
from scanner.upload import enqueue_report_job, pack_results, upload_to_minio
from scanner.ai_strategy import plan_host_strategy, plan_phase2_config, plan_tech_analysis

log = structlog.get_logger()

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan")


class ScanCancelled(Exception):
    """Raised when the order has been cancelled by the user."""
    pass


def _is_cancelled(order_id: str) -> bool:
    """Check if the order has been cancelled in the database."""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM orders WHERE id = %s", (order_id,))
            row = cur.fetchone()
        conn.close()
        return row is not None and row[0] == "cancelled"
    except Exception:
        return False


def _save_passive_intel_summary(order_id: str, phase0a_results: dict[str, Any]) -> None:
    """Persist passive intel summary to orders.passive_intel_summary."""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE orders SET passive_intel_summary = %s WHERE id = %s",
                (json.dumps(phase0a_results, default=str), order_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("passive_intel_save_failed", order_id=order_id, error=str(e))


def _save_phase3_data(order_id: str, phase3_result: dict[str, Any]) -> None:
    """Persist Phase 3 correlation data and business impact score to orders table."""
    try:
        correlation_data = json.dumps(
            phase3_result.get("correlated_findings", []),
            default=str, ensure_ascii=False,
        )
        impact_score = phase3_result.get("business_impact_score", 0.0)

        conn = psycopg2.connect(DATABASE_URL)
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE orders
                   SET correlation_data = %s,
                       business_impact_score = %s
                   WHERE id = %s""",
                (correlation_data, impact_score, order_id),
            )
        conn.commit()
        conn.close()
        log.info("phase3_data_saved", order_id=order_id, impact_score=impact_score)
    except Exception as e:
        log.warning("phase3_data_save_failed", order_id=order_id, error=str(e))


def _is_host_reachable(ip: str, timeout: int = 5) -> bool:
    """Quick TCP connect check on port 80 and 443. Returns True if either responds."""
    for port in (443, 80):
        try:
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.close()
            return True
        except (OSError, _socket.timeout):
            pass
    return False


# Tool version commands — each returns (tool_name, version_string)
_VERSION_COMMANDS: list[tuple[str, list[str]]] = [
    ("nmap", ["nmap", "--version"]),
    ("subfinder", ["subfinder", "-version"]),
    ("amass", ["amass", "-version"]),
    ("gobuster", ["gobuster", "version"]),
    ("dnsx", ["dnsx", "-version"]),
    ("testssl.sh", ["/opt/testssl.sh/testssl.sh", "--version"]),
    ("wafw00f", ["wafw00f", "--version"]),
    ("httpx", ["httpx", "-version"]),
    ("wpscan", ["wpscan", "--version"]),
    ("ffuf", ["ffuf", "-V"]),
    ("feroxbuster", ["feroxbuster", "--version"]),
    ("searchsploit", ["searchsploit", "--help"]),
]


def _collect_tool_versions() -> list[str]:
    """Collect installed tool versions at scan start.

    Returns a list of strings like ["nmap 7.94", "subfinder 2.6.7", ...].
    """
    versions: list[str] = []
    for tool_name, cmd in _VERSION_COMMANDS:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
                start_new_session=True,
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


def _process_job(order_id: str, domain: str, package: str = "perimeter") -> None:
    """Run the full three-phase scan pipeline for a single job."""
    scan_dir = f"/tmp/scan-{order_id}"
    os.makedirs(scan_dir, exist_ok=True)

    config = get_config(package)
    config["domain"] = domain  # Pass domain to Phase 2 for base-domain protection

    start = time.monotonic()

    # Package-specific timeout labels
    _PACKAGE_LABELS = {
        "webcheck": "WebCheck (~15–20 Min.)", "perimeter": "PerimeterScan (~60–90 Min.)",
        "compliance": "ComplianceScan (~65–95 Min.)", "supplychain": "SupplyChain (~65–95 Min.)",
        "insurance": "InsuranceReport (~65–95 Min.)",
        # Legacy
        "basic": "WebCheck (~15–20 Min.)", "professional": "PerimeterScan (~60–90 Min.)", "nis2": "ComplianceScan (~65–95 Min.)",
    }
    _package_label = _PACKAGE_LABELS.get(package, package)
    _timeout_minutes = config["total_timeout"] // 60

    def _check_timeout() -> None:
        elapsed = time.monotonic() - start
        if elapsed >= config["total_timeout"]:
            raise TimeoutError(
                f"Scan-Timeout: Das {_package_label}-Paket hat das Zeitlimit "
                f"von {_timeout_minutes} Minuten überschritten."
            )
        if _is_cancelled(order_id):
            raise ScanCancelled(f"Scan {order_id} wurde vom Benutzer abgebrochen.")

    # Collect tool versions before scanning
    tool_versions = _collect_tool_versions()
    log.info("tool_versions_collected", count=len(tool_versions))

    # Write meta.json
    meta = {
        "orderId": order_id,
        "domain": domain,
        "package": package,
        "startedAt": datetime.now(timezone.utc).isoformat(),
        "toolVersions": tool_versions,
    }
    with open(f"{scan_dir}/meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    log.info("scan_start", order_id=order_id, domain=domain)
    set_scan_started(order_id)

    # ── Phase 0a: Passive Intelligence (no contact to target) ──
    from scanner.phase0a import run_phase0a, build_passive_intel_for_ai

    phase0a_tools = config.get("phase0a_tools", [])
    phase0a_results: dict[str, Any] = {}
    if phase0a_tools:
        update_progress(order_id, "passive_intel", "starting")

        def p0a_callback(oid: str, tool: str, status: str) -> None:
            update_progress(oid, "passive_intel", tool)
            _check_timeout()

        # Phase 0a runs before active discovery — no IPs known yet
        phase0a_results = run_phase0a(
            domain, [], scan_dir, order_id, config,
            progress_callback=p0a_callback,
        )

        # Persist passive intel summary to DB
        _save_passive_intel_summary(order_id, phase0a_results)

        _check_timeout()

    # ── Phase 0b: DNS Reconnaissance (active discovery) ────
    update_progress(order_id, "dns_recon", "starting")
    host_inventory = run_phase0(domain, scan_dir, order_id, config)
    set_discovered_hosts(order_id, host_inventory)

    hosts = host_inventory.get("hosts", [])
    log.info("phase0b_done", order_id=order_id, hosts_found=len(hosts))

    # Re-run Shodan/AbuseIPDB with discovered IPs (if Phase 0a is enabled)
    if phase0a_tools and hosts:
        discovered_ips = [h["ip"] for h in hosts]
        ip_enrichment = run_phase0a(
            domain, discovered_ips, scan_dir, order_id,
            {**config, "phase0a_tools": [t for t in phase0a_tools if t in ("shodan", "abuseipdb")]},
        )
        # Merge IP-specific results into phase0a_results
        for key in ("shodan_hosts", "abuseipdb"):
            if key in ip_enrichment:
                phase0a_results.setdefault(key, {}).update(ip_enrichment[key])

    if len(hosts) == 0:
        log.warning("no_hosts_found", order_id=order_id, domain=domain)
        _finalize(order_id, scan_dir, host_inventory, [], package)
        return

    _check_timeout()

    # ── Redirect dedup: skip hosts whose web_probe redirects to another host ──
    from urllib.parse import urlparse
    fqdn_to_ip: dict[str, str] = {}
    for h in hosts:
        for fqdn in h.get("fqdns", []):
            fqdn_to_ip[fqdn.lower()] = h["ip"]

    for h in hosts:
        wp = h.get("web_probe") or {}
        final_url = wp.get("final_url", "")
        if not final_url:
            continue
        final_fqdn = (urlparse(final_url).hostname or "").lower()
        if not final_fqdn or final_fqdn in [f.lower() for f in h.get("fqdns", [])]:
            continue  # redirects to itself — normal
        target_ip = fqdn_to_ip.get(final_fqdn)
        if target_ip and target_ip != h["ip"]:
            h["status"] = "skipped"
            h["_reasoning"] = f"Redirects to {final_fqdn} (host {target_ip})"
            log.info("host_redirect_dedup", ip=h["ip"],
                     fqdns=h.get("fqdns"), redirect_to=final_fqdn, target_ip=target_ip)

    # Update host inventory after dedup
    host_inventory["hosts"] = hosts
    set_discovered_hosts(order_id, host_inventory)

    # ── AI Host Strategy: prioritize and filter hosts ─────
    # Enrich host inventory with passive intel for better AI decisions
    enriched_inventory = {**host_inventory}
    if phase0a_results:
        enriched_hosts = []
        for h in hosts:
            enriched = {**h}
            enriched["passive_intel"] = build_passive_intel_for_ai(phase0a_results, h["ip"])
            enriched_hosts.append(enriched)
        enriched_inventory["hosts"] = enriched_hosts
        enriched_inventory["dns_security"] = phase0a_results.get("dns_security", {})
        enriched_inventory["whois"] = phase0a_results.get("whois", {})

    strategy = plan_host_strategy(enriched_inventory, domain, package, order_id=order_id)

    # Save strategy to scan results and disk
    strategy_json = json.dumps(strategy, indent=2, ensure_ascii=False)
    strategy_path = os.path.join(scan_dir, "phase0", "host_strategy.json")
    try:
        with open(strategy_path, "w") as f:
            f.write(strategy_json)
    except Exception:
        pass

    from scanner.tools import _save_result
    _save_result(order_id=order_id, host_ip=None, phase=0,
                 tool_name="ai_host_strategy", raw_output=strategy_json,
                 exit_code=0, duration_ms=0)

    # Build scan list from strategy
    ip_to_host = {h["ip"]: h for h in hosts}
    scan_hosts: list[dict[str, Any]] = []
    for sh in sorted(strategy.get("hosts", []), key=lambda h: h.get("priority") or 999):
        if sh.get("action") == "scan" and sh["ip"] in ip_to_host:
            entry = ip_to_host[sh["ip"]]
            entry["_reasoning"] = sh.get("reasoning", "")
            scan_hosts.append(entry)
        elif sh.get("action") == "skip":
            _save_result(order_id=order_id, host_ip=sh["ip"], phase=0,
                         tool_name="ai_host_skip", raw_output=f"SKIP: {sh.get('reasoning', 'Kein Grund angegeben')}",
                         exit_code=0, duration_ms=0)
            log.info("host_skipped_by_ai", ip=sh["ip"], reasoning=sh.get("reasoning"))

    # Fallback if strategy returned nothing scannable
    if not scan_hosts:
        scan_hosts = hosts

    hosts_total = len(scan_hosts)
    log.info("ai_strategy_applied", scan=hosts_total,
             skip=len(hosts) - hosts_total,
             notes=strategy.get("strategy_notes", ""))

    # Publish AI strategy event for frontend visualization
    publish_event(order_id, {"type": "ai_strategy", "strategy": strategy})

    # Save ALL hosts (including skipped) with status markers for frontend
    skip_ips = {sh["ip"] for sh in strategy.get("hosts", []) if sh.get("action") == "skip"}
    all_hosts_with_status = []
    for h in hosts:
        entry = {**h}
        if h["ip"] in skip_ips:
            entry["status"] = "skipped"
        all_hosts_with_status.append(entry)
    set_discovered_hosts(order_id, {**host_inventory, "hosts": all_hosts_with_status})

    # ── Phase 1: Tech Detection (parallel, max 3 hosts) ─────
    from concurrent.futures import ThreadPoolExecutor, as_completed

    tech_profiles: list[dict[str, Any] | None] = [None] * len(scan_hosts)

    def _run_phase1_host(idx: int, host: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        ip = host["ip"]
        fqdns = list(host["fqdns"])

        # If web_probe found a working FQDN, put it first for Phase 1/2
        web_fqdn = host.get("web_probe", {}).get("web_fqdn")
        if web_fqdn and web_fqdn in fqdns and fqdns[0] != web_fqdn:
            fqdns = [web_fqdn] + [f for f in fqdns if f != web_fqdn]

        _check_timeout()

        if not _is_host_reachable(ip):
            log.warning("host_unreachable", ip=ip, fqdns=fqdns, order_id=order_id)
            return idx, {"ip": ip, "fqdns": fqdns, "skipped": True, "reason": "unreachable"}

        def p1_callback(oid: str, tool: str, status: str, _ip: str = ip) -> None:
            update_progress(oid, "scan_phase1", tool, host=_ip,
                            hosts_completed=0, hosts_total=hosts_total)
            _check_timeout()

        tech_profile = run_phase1(ip, fqdns, scan_dir, order_id, p1_callback, config)

        # Carry web_probe data from Phase 0 into tech_profile
        web_probe = host.get("web_probe", {})
        tech_profile["has_web"] = web_probe.get("has_web", True)
        tech_profile["web_fqdn"] = web_probe.get("web_fqdn")

        return idx, tech_profile

    max_parallel = min(3, len(scan_hosts))
    with ThreadPoolExecutor(max_workers=max_parallel, thread_name_prefix="phase1") as pool:
        futures = {
            pool.submit(_run_phase1_host, idx, host): idx
            for idx, host in enumerate(scan_hosts)
        }
        completed_count = 0
        for future in as_completed(futures):
            try:
                idx, profile = future.result()
                tech_profiles[idx] = profile
            except Exception as e:
                idx = futures[future]
                tech_profiles[idx] = {"ip": scan_hosts[idx]["ip"], "skipped": True, "reason": str(e)}
                log.error("phase1_host_failed", ip=scan_hosts[idx]["ip"], error=str(e))
            completed_count += 1
            update_progress(order_id, "scan_phase1", "host_done",
                            hosts_completed=completed_count, hosts_total=hosts_total)

    # Replace None entries with skip markers (shouldn't happen, but defensive)
    tech_profiles = [p if p is not None else {"skipped": True, "reason": "unknown"}
                     for p in tech_profiles]

    log.info("phase1_complete", order_id=order_id, profiles=len(tech_profiles))

    # ── Redirect Data + AI Tech Analysis ────────────────────
    # Extract redirect data from Phase 1 tech profiles (already collected via Playwright)
    _check_timeout()
    try:
        from scanner.tools.redirect_probe import probe_cms_paths, _is_playwright_available
        combined_redirect: dict[str, Any] = {"redirects": {}, "cms_probes": {}}

        # Reuse redirect data already gathered during Phase 1 (no second Playwright run)
        for profile in tech_profiles:
            if profile.get("redirect_data"):
                combined_redirect["redirects"].update(profile["redirect_data"])

        redirect_count = len(combined_redirect["redirects"])
        if redirect_count > 0:
            update_progress(order_id, "scan_phase1", "redirect_probe")
            publish_event(order_id, {"type": "tool_output", "tool": "redirect_probe",
                                     "summary": f"{redirect_count} FQDNs probed (from Phase 1)"})

            # Run CMS path probes separately (lightweight HTTP checks)
            if _is_playwright_available():
                all_fqdns = []
                for host, prof in zip(scan_hosts, tech_profiles):
                    if not prof.get("skipped"):
                        all_fqdns.extend(host.get("fqdns", [])[:3])
                all_fqdns = list(set(all_fqdns))
                cms_probe_data = probe_cms_paths(all_fqdns)
                combined_redirect["cms_probes"] = cms_probe_data

            # AI Tech Analysis — correct CMS detection
            update_progress(order_id, "scan_phase1", "ai_tech_analysis")
            tech_corrections = plan_tech_analysis(tech_profiles, combined_redirect, order_id=order_id)

            # Apply corrections to tech_profiles
            if tech_corrections.get("hosts"):
                for profile in tech_profiles:
                    ip = profile.get("ip", "")
                    correction = tech_corrections["hosts"].get(ip)
                    if correction:
                        old_cms = profile.get("cms")
                        new_cms = correction.get("cms")
                        if new_cms != old_cms:
                            log.info("cms_corrected", ip=ip, old=old_cms, new=new_cms,
                                     reason=correction.get("reasoning", ""))
                        profile["cms"] = correction.get("cms")
                        profile["cms_version"] = correction.get("cms_version")
                        profile["cms_confidence"] = correction.get("cms_confidence", 0)
                        if correction.get("is_spa") is not None:
                            profile["is_spa"] = correction["is_spa"]
        else:
            log.info("no_redirect_data_from_phase1", msg="Skipping AI tech analysis")
    except Exception as e:
        log.warning("redirect_probe_failed", error=str(e))

    # ── AI Phase 2 Config (all hosts, after all Phase 1) ──
    adaptive_configs: dict[str, dict[str, Any]] = {}

    for host, profile in zip(scan_hosts, tech_profiles):
        ip = host["ip"]
        if profile.get("skipped"):
            continue

        _check_timeout()

        adaptive_config = plan_phase2_config(profile, host_inventory, package, order_id=order_id)
        adaptive_configs[ip] = adaptive_config

        adaptive_json = json.dumps(adaptive_config, indent=2, ensure_ascii=False)
        _save_result(order_id=order_id, host_ip=ip, phase=1,
                     tool_name="ai_phase2_config", raw_output=adaptive_json,
                     exit_code=0, duration_ms=0)
        publish_event(order_id, {"type": "ai_config", "ip": ip, "config": adaptive_config})

    log.info("ai_phase2_configs_complete", order_id=order_id, configs=len(adaptive_configs))

    # ── Phase 2: Deep Scan (parallel, max 3 hosts) ────────
    scannable = [(h, p) for h, p in zip(scan_hosts, tech_profiles) if not p.get("skipped")]
    scannable_total = len(scannable)

    def _run_phase2_host(idx: int, host: dict[str, Any], tech_profile: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        ip = host["ip"]
        fqdns = host["fqdns"]

        _check_timeout()

        def p2_callback(oid: str, tool: str, status: str, _ip: str = ip) -> None:
            update_progress(oid, "scan_phase2", tool, host=_ip,
                            hosts_completed=0, hosts_total=scannable_total)
            _check_timeout()

        result = run_phase2(ip, fqdns, tech_profile, scan_dir, order_id, p2_callback, config,
                            adaptive_config=adaptive_configs.get(ip, {}))
        return idx, result

    phase2_results: list[dict[str, Any] | None] = [None] * len(scannable)
    # Sequential host processing — each worker has ONE ZAP daemon,
    # parallel hosts would cause ZAP context conflicts and alert mixing.
    max_parallel_p2 = 1
    with ThreadPoolExecutor(max_workers=max_parallel_p2, thread_name_prefix="phase2") as pool:
        futures = {
            pool.submit(_run_phase2_host, idx, host, tp): idx
            for idx, (host, tp) in enumerate(scannable)
        }
        p2_completed = 0
        for future in as_completed(futures):
            try:
                idx, result = future.result()
                phase2_results[idx] = result
            except Exception as e:
                idx = futures[future]
                ip = scannable[idx][0]["ip"]
                phase2_results[idx] = {"ip": ip, "fqdn": ip, "tools_run": [], "error": str(e)}
                log.error("phase2_host_failed", ip=ip, error=str(e))
            p2_completed += 1
            update_progress(order_id, "scan_phase2", "host_done",
                            hosts_completed=p2_completed, hosts_total=scannable_total)
            log.info("host_phase2_complete", order_id=order_id, idx=p2_completed, total=scannable_total)

    # Filter out None entries
    phase2_results = [r for r in phase2_results if r is not None]

    # ── Phase 3: Correlation & Enrichment ──────────────────
    phase3_result: dict[str, Any] = {}
    phase3_tools = config.get("phase3_tools", [])
    if phase3_tools and phase2_results:
        _check_timeout()

        update_progress(order_id, "scan_phase3", "starting")

        def p3_callback(oid: str, tool: str, status: str) -> None:
            update_progress(oid, "scan_phase3", tool)
            _check_timeout()

        config["package"] = package  # Ensure package is in config for Phase 3
        phase3_result = run_phase3(
            phase2_results=phase2_results,
            tech_profiles=tech_profiles,
            scan_dir=scan_dir,
            order_id=order_id,
            config=config,
            progress_callback=p3_callback,
            phase0a_results=phase0a_results if phase0a_results else None,
        )

        # Persist correlation data and business impact score to DB
        _save_phase3_data(order_id, phase3_result)

        # Save to scan_results for event replay
        _save_result(order_id=order_id, host_ip=None, phase=3,
                     tool_name="phase3_correlation",
                     raw_output=json.dumps(phase3_result.get("phase3_summary", {}),
                                           indent=2, ensure_ascii=False),
                     exit_code=0, duration_ms=0)

        publish_event(order_id, {
            "type": "phase3_complete",
            "summary": phase3_result.get("phase3_summary", {}),
        })

        log.info("phase3_integrated", order_id=order_id,
                 findings=phase3_result.get("phase3_summary", {}).get("valid_findings", 0))

    # ── Finalize ────────────────────────────────────────────
    _finalize(order_id, scan_dir, host_inventory, tech_profiles, package,
              phase3_result=phase3_result)


def _finalize(
    order_id: str,
    scan_dir: str,
    host_inventory: dict[str, Any],
    tech_profiles: list[dict[str, Any]],
    package: str = "perimeter",
    phase3_result: dict[str, Any] | None = None,
) -> None:
    """Pack results, upload to MinIO, enqueue report job."""
    hosts_total = len(host_inventory.get("hosts", []))

    update_progress(order_id, "scan_complete", "uploading",
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
    archive_path = pack_results(scan_dir, order_id)
    minio_path = upload_to_minio(archive_path, order_id)

    # Enqueue report generation (with Phase 3 enrichment data if available)
    enqueue_report_job(order_id, minio_path, host_inventory, tech_profiles, package,
                       phase3_result=phase3_result)

    # Mark scan as complete
    set_scan_complete(order_id)

    # Cleanup scan directory
    try:
        shutil.rmtree(scan_dir)
        log.info("scan_dir_cleaned", scan_dir=scan_dir)
    except Exception as e:
        log.warning("scan_dir_cleanup_failed", error=str(e))

    log.info("scan_complete", order_id=order_id)


def _handle_diagnose(redis_client: redis.Redis, job: dict) -> None:
    """Run diagnostics and publish result to Redis."""
    request_id = job.get("requestId", "unknown")
    probe_domain = job.get("probe")

    log.info("diagnose_start", request_id=request_id, probe=probe_domain)

    from scanner.diagnose import diagnose_tools, check_environment, probe_domain as run_probe

    env = check_environment()
    tools = diagnose_tools()

    probe_results = []
    if probe_domain:
        probe_results = run_probe(probe_domain)

    result = {
        "requestId": request_id,
        "environment": env,
        "tools": tools,
        "probe": probe_results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Write result to Redis (API will poll for it)
    redis_client.set(
        f"diagnose:result:{request_id}",
        json.dumps(result, default=str),
        ex=300,  # 5 min TTL
    )
    log.info("diagnose_complete", request_id=request_id,
             ok=sum(1 for t in tools if t["ok"]),
             fail=sum(1 for t in tools if not t["ok"]))


def wait_for_jobs(redis_client: redis.Redis) -> None:
    """Block and wait for scan jobs and diagnose requests on Redis queues."""
    log.info("waiting_for_jobs", queues=["scan-pending", "diagnose-pending"])
    while True:
        try:
            result = redis_client.blpop(["scan-pending", "diagnose-pending"], timeout=5)
            if result is None:
                continue

            queue_name, job_data = result
            queue = queue_name.decode() if isinstance(queue_name, bytes) else queue_name
            job = json.loads(job_data.decode() if isinstance(job_data, bytes) else job_data)

            if queue == "diagnose-pending":
                try:
                    _handle_diagnose(redis_client, job)
                except Exception as e:
                    log.error("diagnose_failed", error=str(e))
                continue

            order_id = job["orderId"]
            domain = job["targetDomain"]
            package = job.get("package", "perimeter")

            log.info("job_received", order_id=order_id, domain=domain)

            try:
                _process_job(order_id, domain, package)
            except ScanCancelled:
                log.info("scan_cancelled", order_id=order_id)
                scan_dir = f"/tmp/scan-{order_id}"
                if os.path.exists(scan_dir):
                    shutil.rmtree(scan_dir, ignore_errors=True)
            except TimeoutError as e:
                log.error("scan_timeout", order_id=order_id, error=str(e))
                set_scan_failed(order_id, str(e))
                scan_dir = f"/tmp/scan-{order_id}"
                if os.path.exists(scan_dir):
                    shutil.rmtree(scan_dir, ignore_errors=True)
            except Exception as e:
                log.error("scan_failed", order_id=order_id, error=str(e))
                set_scan_failed(order_id, str(e))
                scan_dir = f"/tmp/scan-{order_id}"
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
