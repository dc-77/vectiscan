"""BullMQ Consumer — Orchestrates the three scan phases."""

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
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
from scanner import scope as scope_module
from scanner import zap_pool
from scanner.tools.zap_client import set_thread_zap_id as _set_thread_zap_id

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


def _process_job_multi_target(order_id: str, package: str = "perimeter") -> None:
    """Multi-Target-Variante: Targets aus scan_targets WHERE status='approved'."""
    targets = scope_module.load_approved_targets(order_id)
    if not targets:
        log.error("multi_target_no_approved", order_id=order_id)
        set_scan_failed(order_id, "Keine freigegebenen Targets.")
        return
    primary = scope_module.derive_primary_domain(targets)
    scope_module.snapshot_run_targets(order_id, targets)
    log.info("multi_target_dispatch", order_id=order_id, primary=primary,
             targets=len(targets))
    _process_job(order_id, primary, package, multi_target_context={"targets": targets})


def _process_job(order_id: str, domain: str, package: str = "perimeter",
                 multi_target_context: dict[str, Any] | None = None) -> None:
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

    # Performance-Tracking: Dauer pro Phase in Millisekunden.
    phase_durations_ms: dict[str, int] = {}
    _phase_cursor = {"t": time.monotonic()}

    def _phase_checkpoint(name: str) -> None:
        now = time.monotonic()
        phase_durations_ms[name] = int((now - _phase_cursor["t"]) * 1000)
        _phase_cursor["t"] = now

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

    _phase_checkpoint("phase0a")

    # ── Phase 0b: DNS Reconnaissance (active discovery) ────
    update_progress(order_id, "dns_recon", "starting")
    host_inventory = run_phase0(domain, scan_dir, order_id, config)

    # ── Multi-Target: non-enumerate Targets dazumergen + Scope-Enforcement ──
    if multi_target_context:
        mt_targets = multi_target_context["targets"]
        extra_hosts = scope_module.build_partial_inventory_for_non_enumerate(mt_targets)
        if extra_hosts:
            host_inventory = scope_module.merge_inventories(host_inventory, extra_hosts)
            log.info("multi_target_merged_partial", order_id=order_id,
                     extra_hosts=len(extra_hosts))
        host_inventory, out_of_scope = scope_module.enforce_scope(host_inventory, mt_targets)
        if out_of_scope:
            log.info("multi_target_out_of_scope", order_id=order_id,
                     removed=len(out_of_scope))
        live_count = sum(
            1 for h in host_inventory.get("hosts", [])
            if (h.get("web_probe") or {}).get("has_web") or h.get("ports")
        )
        scope_module.update_live_hosts_count(order_id, live_count)

    set_discovered_hosts(order_id, host_inventory)

    hosts = host_inventory.get("hosts", [])
    log.info("phase0b_done", order_id=order_id, hosts_found=len(hosts))

    # Discovery-Health-Abbruch (PR-Robustheits-Plan, 2026-05-02):
    # Wenn Phase 0 mit 0 Hosts endet, ist DNS-Resolution komplett
    # gescheitert (Domain nicht aufloesbar oder alle Discovery-Quellen down).
    # Statt scheinheiligen Report ueber nichts zu produzieren brechen wir
    # mit klarer Fehlermeldung ab.
    if len(hosts) == 0:
        health = host_inventory.get("discovery_health", {})
        msg = (
            "Phase 0 Discovery hat 0 lebende Hosts gefunden. "
            f"Domain '{domain}' ggf. nicht aufloesbar oder alle "
            "DNS-/Discovery-Quellen ausgefallen. "
            f"Tool-Counts: {health.get('tool_counts', {})}, "
            f"CT-Sources leer: {health.get('ct_sources_empty', False)}."
        )
        log.error("phase0_no_hosts_abort", order_id=order_id, message=msg)
        set_scan_failed(order_id, msg)
        return

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
    skip_ai = config.get("skip_ai_decisions", False)
    from scanner.tools import _save_result

    if skip_ai:
        # TLS-Compliance: scan ALL hosts, no AI filtering
        scan_hosts = list(hosts)
        strategy = {"hosts": [{"ip": h["ip"], "action": "scan"} for h in hosts]}
        log.info("ai_strategy_skipped", reason="skip_ai_decisions=True", hosts=len(scan_hosts))
    else:
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

        _save_result(order_id=order_id, host_ip=None, phase=0,
                     tool_name="ai_host_strategy", raw_output=strategy_json,
                     exit_code=0, duration_ms=0)

        # Build scan list from strategy
        ip_to_host = {h["ip"]: h for h in hosts}
        scan_hosts = []
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

    _phase_checkpoint("phase0b")

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

        web_probe = host.get("web_probe", {})
        tech_profile = run_phase1(ip, fqdns, scan_dir, order_id, p1_callback, config,
                                  web_probe=web_probe)

        # Carry web_probe data from Phase 0 into tech_profile
        tech_profile["has_web"] = web_probe.get("has_web", True)
        tech_profile["web_fqdn"] = web_probe.get("web_fqdn")

        return idx, tech_profile

    try:
        phase1_cap = int(os.getenv("PHASE1_MAX_WORKERS", "3"))
    except ValueError:
        phase1_cap = 3
    phase1_cap = max(1, phase1_cap)
    # max(1, ...) garantiert dass auch bei `len(scan_hosts) == 0` der
    # ThreadPool startet (sonst ValueError "max_workers must be > 0").
    # Bei 0 Hosts ist der Pool leer → kein Future submitted, sauberer No-Op.
    max_parallel = max(1, min(phase1_cap, len(scan_hosts)))
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
    adaptive_configs: dict[str, dict[str, Any]] = {}

    if skip_ai:
        log.info("ai_tech_analysis_skipped", reason="skip_ai_decisions=True")
        log.info("ai_phase2_configs_skipped", reason="skip_ai_decisions=True")
    else:
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

    _phase_checkpoint("phase1")

    # ── Phase 2: Deep Scan (parallel, max 3 hosts) ────────
    scannable = [(h, p) for h, p in zip(scan_hosts, tech_profiles) if not p.get("skipped")]
    scannable_total = len(scannable)

    has_zap = any(t in (config.get("phase2_tools") or [])
                  for t in ("zap_spider", "zap_active", "zap_passive"))
    pool_enabled = has_zap and os.environ.get("ZAP_POOL_ENABLED", "false").lower() == "true"
    worker_id = os.environ.get("WORKER_ID", _socket.gethostname())

    redis_client_pool = None
    if pool_enabled:
        redis_url_pool = os.environ.get("REDIS_URL", "redis://localhost:6379")
        try:
            redis_client_pool = redis.from_url(redis_url_pool)
            zap_pool.init_zap_pool(redis_client_pool)
        except Exception as pool_err:
            log.warning("zap_pool_init_failed, falling back to singleton", error=str(pool_err))
            pool_enabled = False
            redis_client_pool = None

    def _run_phase2_host(idx: int, host: dict[str, Any], tech_profile: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        ip = host["ip"]
        fqdns = host["fqdns"]

        _check_timeout()

        def p2_callback(oid: str, tool: str, status: str, _ip: str = ip) -> None:
            update_progress(oid, "scan_phase2", tool, host=_ip,
                            hosts_completed=0, hosts_total=scannable_total)
            _check_timeout()

        if not pool_enabled:
            result = run_phase2(ip, fqdns, tech_profile, scan_dir, order_id, p2_callback, config,
                                adaptive_config=adaptive_configs.get(ip, {}))
            return idx, result

        # Pool-Mode: lease a ZAP, run, release — even on error.
        lease = zap_pool.acquire_zap(redis_client_pool, order_id, ip, worker_id)
        if lease is None:
            log.error("zap_lease_timeout", order_id=order_id, ip=ip)
            return idx, {"ip": ip, "fqdn": ip, "tools_run": [], "error": "zap_lease_timeout"}

        zap_id, lease_value = lease
        log.info("zap_lease_acquired", zap_id=zap_id, order_id=order_id, host_ip=ip,
                 worker_id=worker_id)

        hb_stop = threading.Event()

        def _heartbeat_loop() -> None:
            while not hb_stop.wait(zap_pool.HEARTBEAT_INTERVAL_SEC):
                if not zap_pool.heartbeat_zap(redis_client_pool, zap_id, lease_value):
                    log.warning("zap_heartbeat_lost", zap_id=zap_id, order_id=order_id, ip=ip)
                    return

        hb_thread = threading.Thread(target=_heartbeat_loop, daemon=True,
                                     name=f"zap-hb-{zap_id}")
        hb_thread.start()
        lease_start = time.monotonic()

        try:
            _set_thread_zap_id(zap_id)
            # Clean up any stale contexts left by a crashed prior lease.
            try:
                from scanner.tools.zap_client import ZapClient
                _cleanup_client = ZapClient(zap_id=zap_id)
                active_ctx_names = zap_pool.get_all_active_context_names(redis_client_pool)
                # Exclude our own soon-to-be-created context from the deletion set —
                # it's not listed yet so this is informational only.
                _cleanup_client.cleanup_stale_contexts(active_ctx_names)
            except Exception as cleanup_err:
                log.warning("zap_cleanup_skipped", zap_id=zap_id, error=str(cleanup_err))

            result = run_phase2(ip, fqdns, tech_profile, scan_dir, order_id, p2_callback, config,
                                adaptive_config=adaptive_configs.get(ip, {}))
            return idx, result
        finally:
            hb_stop.set()
            _set_thread_zap_id(None)
            duration_ms = int((time.monotonic() - lease_start) * 1000)
            zap_pool.release_zap(redis_client_pool, zap_id, lease_value)
            log.info("zap_lease_released", zap_id=zap_id, order_id=order_id, host_ip=ip,
                     duration_ms=duration_ms)

    phase2_results: list[dict[str, Any] | None] = [None] * len(scannable)
    if pool_enabled:
        max_parallel_p2 = min(zap_pool.get_max_parallel_per_order(), len(scannable))
    else:
        # Legacy Mode: ZAP Singleton — parallel hosts cause context conflicts.
        # Packages without ZAP (e.g. tlscompliance) can safely parallelize.
        max_parallel_p2 = min(5, len(scannable)) if not has_zap else 1
    # max(1, ...) verhindert ValueError wenn `scannable` leer ist (Pool ist
    # dann ohnehin No-Op, aber ThreadPoolExecutor braucht >=1 worker).
    max_parallel_p2 = max(1, max_parallel_p2)
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

    _phase_checkpoint("phase2")

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

        summary = phase3_result.get("phase3_summary", {})
        valid = summary.get("valid_findings", 0) if isinstance(summary, dict) else 0
        log.info("phase3_integrated", order_id=order_id, findings=valid)

    _phase_checkpoint("phase3")

    # Performance-Metriken fuer orders.performance_metrics (Migration 015).
    performance_metrics = _build_performance_metrics(phase_durations_ms=phase_durations_ms)

    # ── Finalize ────────────────────────────────────────────
    _finalize(order_id, scan_dir, host_inventory, tech_profiles, package,
              phase3_result=phase3_result,
              performance_metrics=performance_metrics)


def _build_performance_metrics(phase_durations_ms: dict[str, int]) -> dict[str, Any]:
    """Sammelt Scan-Performance-Metriken fuer orders.performance_metrics.

    Quelle sind die lokalen Phasen-Timer sowie die Pool-Stats aus Redis
    (falls ZAP_POOL_ENABLED aktiv war). Fehler beim Redis-Zugriff werden
    leise verschluckt — fehlende Pool-Felder sind fuer die Migration 015
    erlaubt (JSONB, kein NOT NULL).
    """
    pool_enabled = os.getenv("ZAP_POOL_ENABLED", "false").lower() == "true"
    pool_members = zap_pool.get_pool_members() if pool_enabled else []
    max_parallel_configured = zap_pool.get_max_parallel_per_order() if pool_enabled else 1

    metrics: dict[str, Any] = {
        "phase_durations_ms": phase_durations_ms,
        "zap_pool_size": len(pool_members),
        "zap_pool_enabled": pool_enabled,
        "zap_max_parallel_per_order": max_parallel_configured,
        "parallelism_effective": {
            "phase1_max_workers": max(1, int(os.getenv("PHASE1_MAX_WORKERS", "3") or "3")),
            "phase2_stage2_waf_safe_enabled":
                os.getenv("PHASE2_STAGE2_WAF_SAFE", "true").lower() == "true",
            "zap_pool_enabled": pool_enabled,
        },
    }

    if pool_enabled:
        try:
            redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
            rc = redis.from_url(redis_url)
            samples = zap_pool.get_lease_wait_ms_samples(rc)
            metrics["zap_leases_total"] = zap_pool.get_leases_total(rc)
            if samples:
                metrics["zap_avg_lease_wait_ms"] = int(sum(samples) / len(samples))
                metrics["zap_max_lease_wait_ms"] = max(samples)
            else:
                metrics["zap_avg_lease_wait_ms"] = 0
                metrics["zap_max_lease_wait_ms"] = 0
        except Exception as e:
            log.warning("performance_metrics_pool_read_failed", error=str(e))

    return metrics


def _persist_performance_metrics(order_id: str, metrics: dict[str, Any]) -> None:
    """Schreibt orders.performance_metrics. Fehler loggen, nicht werfen."""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE orders SET performance_metrics = %s::jsonb WHERE id = %s",
                (json.dumps(metrics), order_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("performance_metrics_write_failed", order_id=order_id, error=str(e))


def _finalize(
    order_id: str,
    scan_dir: str,
    host_inventory: dict[str, Any],
    tech_profiles: list[dict[str, Any]],
    package: str = "perimeter",
    phase3_result: dict[str, Any] | None = None,
    performance_metrics: dict[str, Any] | None = None,
) -> None:
    """Pack results, upload to MinIO, set status to pending_review.

    Report generation is NOT triggered here — it happens after admin approval.
    """
    if performance_metrics is not None:
        _persist_performance_metrics(order_id, performance_metrics)
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

    # Enqueue report generation for Claude analysis + findings (needed for admin review).
    # The report-worker will generate findings_data but set status to pending_review,
    # NOT report_complete. The PDF + email only happen after admin approval.
    enqueue_report_job(order_id, minio_path, host_inventory, tech_profiles, package,
                       phase3_result=phase3_result)

    # Mark scan as complete (report-worker will set pending_review after Claude analysis)
    set_scan_complete(order_id)

    # PR-VPN: VPN-Activations-Audit-Trail in orders.vpn_activations persistieren
    try:
        from scanner.vpn_switch import cleanup_switch
        activations = cleanup_switch(order_id)
        if activations:
            import psycopg2
            conn = psycopg2.connect(
                os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan"),
                connect_timeout=5,
            )
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE orders SET vpn_activations = %s WHERE id = %s",
                        (json.dumps(activations), order_id),
                    )
                conn.commit()
            finally:
                conn.close()
            log.info("vpn_audit_persisted", order_id=order_id, count=len(activations))
    except Exception as e:
        log.warning("vpn_audit_persist_failed", error=str(e))

    publish_event(order_id, {
        "type": "status",
        "orderId": order_id,
        "status": "pending_review",
    })

    # Cleanup scan directory
    try:
        shutil.rmtree(scan_dir)
        log.info("scan_dir_cleaned", scan_dir=scan_dir)
    except Exception as e:
        log.warning("scan_dir_cleanup_failed", error=str(e))

    log.info("scan_pending_review", order_id=order_id)


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
            domain = job.get("targetDomain")  # Optional — Multi-Target-Jobs haben keinen einzelnen
            package = job.get("package", "perimeter")

            log.info("job_received", order_id=order_id, domain=domain, multi_target=domain is None)

            try:
                if domain:
                    _process_job(order_id, domain, package)
                else:
                    _process_job_multi_target(order_id, package)
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

    # Register this container's ZAP pool membership at boot so newly added
    # daemons (e.g. scaling from 2 to 4 ZAPs) are picked up on the next restart.
    if os.environ.get("ZAP_POOL_ENABLED", "false").lower() == "true":
        try:
            zap_pool.init_zap_pool(redis_client)
        except Exception as e:
            log.warning("zap_pool_init_failed_at_startup", error=str(e))

    def shutdown(signum: int, frame: object) -> None:
        log.info("scan_worker_shutdown", signal=signum)
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    wait_for_jobs(redis_client)


if __name__ == "__main__":
    main()
