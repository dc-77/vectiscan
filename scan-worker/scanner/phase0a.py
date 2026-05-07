"""Phase 0a — Passive Intelligence collection (no contact to target).

Gathers data from public APIs and OSINT sources before any active scanning.
Results enrich the AI Host Strategy with better context.
"""

import json
import os
import time
from typing import Any

import structlog

from scanner.passive.shodan_client import ShodanClient
from scanner.passive.abuseipdb_client import AbuseIPDBClient
from scanner.passive.securitytrails_client import SecurityTrailsClient
from scanner.passive.whois_client import WhoisClient
from scanner.passive.dns_security import run_all_dns_security
from scanner.progress import publish_event

log = structlog.get_logger()


def run_phase0a(
    domain: str,
    ips: list[str],
    scan_dir: str,
    order_id: str,
    config: dict[str, Any],
    progress_callback: Any = None,
) -> dict[str, Any]:
    """Run passive intelligence collection for Phase 0a.

    Args:
        domain: Target domain
        ips: Known IPs from Phase 0b (may be empty if called before 0b)
        scan_dir: Scan directory for persisting results
        order_id: Order UUID
        config: Package config (determines which tools run)
        progress_callback: Optional callback for progress updates

    Returns:
        Passive intelligence summary dict with keys:
        - shodan: per-IP Shodan data
        - abuseipdb: per-IP reputation scores
        - securitytrails: domain + subdomain data
        - whois: registrar data
        - dns_security: DNSSEC, CAA, MTA-STS, DANE results
    """
    phase0a_tools = config.get("phase0a_tools", [])
    start = time.monotonic()

    # Create output directory
    phase0a_dir = os.path.join(scan_dir, "phase0a")
    os.makedirs(phase0a_dir, exist_ok=True)

    results: dict[str, Any] = {}
    package = config.get("package", "perimeter")

    # --- F-P0A-005: IP-Cap (paketabhaengig + ENV-Override) ---
    ip_cap_env = os.environ.get("PHASE0A_IP_CAP")
    if ip_cap_env and ip_cap_env.strip().isdigit():
        ip_cap = int(ip_cap_env.strip())
    else:
        ip_cap = int(config.get("phase0a_ip_cap", 15))
    capped_ips = ips[:ip_cap]

    # --- F-P0A-001: Inner-Parallelization-Konfiguration ---
    # Default 3 (schont Free-Tier ~1 req/s); ENV-Override fuer Premium-Keys.
    passive_concurrency_env = os.environ.get("PASSIVE_INTEL_CONCURRENCY")
    if passive_concurrency_env and passive_concurrency_env.strip().isdigit():
        passive_concurrency = max(1, int(passive_concurrency_env.strip()))
    else:
        passive_concurrency = 3

    from concurrent.futures import ThreadPoolExecutor, as_completed

    # --- Helper functions for parallel execution ---

    def _run_whois() -> tuple[str, dict[str, Any] | None]:
        publish_event(order_id, {"type": "tool_starting", "tool": "whois", "host": domain})
        whois = WhoisClient()
        data = whois.lookup(domain)
        if data:
            _save_json(phase0a_dir, "whois.json", data)
        return "whois", data

    def _run_shodan() -> tuple[str, dict[str, Any] | None]:
        publish_event(order_id, {"type": "tool_starting", "tool": "shodan", "host": domain})
        shodan = ShodanClient()
        if not shodan.available:
            log.info("shodan_skipped", reason="no_api_key")
            return "shodan", None
        result: dict[str, Any] = {}
        domain_data = shodan.lookup_domain(domain)
        if domain_data:
            result["shodan_domain"] = domain_data
            _save_json(phase0a_dir, "shodan_domain.json", domain_data)
        # F-P0A-001 (Option B): IP-Loop parallel via ThreadPoolExecutor.
        shodan_hosts: dict[str, Any] = {}
        if capped_ips:
            with ThreadPoolExecutor(
                max_workers=passive_concurrency,
                thread_name_prefix="shodan_ips",
            ) as inner:
                futures = {inner.submit(shodan.lookup_host, ip): ip for ip in capped_ips}
                for fut in as_completed(futures):
                    ip = futures[fut]
                    try:
                        host_data = fut.result()
                    except Exception as e:
                        log.warning("shodan_ip_lookup_failed", ip=ip, error=str(e))
                        continue
                    if host_data:
                        shodan_hosts[ip] = host_data
        if shodan_hosts:
            result["shodan_hosts"] = shodan_hosts
            _save_json(phase0a_dir, "shodan_hosts.json", shodan_hosts)
        return "shodan", result

    def _run_abuseipdb() -> tuple[str, dict[str, Any] | None]:
        publish_event(order_id, {"type": "tool_starting", "tool": "abuseipdb", "host": domain})
        client = AbuseIPDBClient()
        if not client.available:
            log.info("abuseipdb_skipped", reason="no_api_key")
            return "abuseipdb", None
        # F-P0A-001 (Option B): IP-Loop parallel via ThreadPoolExecutor.
        abuse_results: dict[str, Any] = {}
        if capped_ips:
            with ThreadPoolExecutor(
                max_workers=passive_concurrency,
                thread_name_prefix="abuseipdb_ips",
            ) as inner:
                futures = {inner.submit(client.check_ip, ip): ip for ip in capped_ips}
                for fut in as_completed(futures):
                    ip = futures[fut]
                    try:
                        abuse_data = fut.result()
                    except Exception as e:
                        log.warning("abuseipdb_ip_lookup_failed", ip=ip, error=str(e))
                        continue
                    if abuse_data:
                        abuse_results[ip] = abuse_data
        if abuse_results:
            _save_json(phase0a_dir, "abuseipdb.json", abuse_results)
        return "abuseipdb", abuse_results or None

    def _run_securitytrails() -> tuple[str, dict[str, Any] | None]:
        publish_event(order_id, {"type": "tool_starting", "tool": "securitytrails", "host": domain})
        st = SecurityTrailsClient()
        if not st.available:
            log.info("securitytrails_skipped", reason="no_api_key")
            return "securitytrails", None
        # F-P0A-001 (Option C): drei API-Calls parallel.
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="securitytrails") as inner:
            f_domain = inner.submit(st.lookup_domain, domain)
            f_subs = inner.submit(st.get_subdomains, domain)
            f_hist = inner.submit(st.get_dns_history, domain)
            st_data = {
                "domain": f_domain.result(),
                "subdomains": f_subs.result(),
                "dns_history": f_hist.result(),
            }
        _save_json(phase0a_dir, "securitytrails.json", st_data)
        return "securitytrails", st_data

    def _run_dns_security() -> tuple[str, dict[str, Any] | None]:
        publish_event(order_id, {"type": "tool_starting", "tool": "dns_security", "host": domain})
        dns_sec = run_all_dns_security(domain, package)
        _save_json(phase0a_dir, "dns_security.json", dns_sec)
        return "dns_security", dns_sec

    # --- Run all tools in parallel (Top-Level: ThreadPool importiert oben) ---
    phase0a_timeout = config.get("phase0a_timeout", 120)
    futures: dict[Any, str] = {}

    with ThreadPoolExecutor(max_workers=5, thread_name_prefix="phase0a") as pool:
        if "whois" in phase0a_tools:
            futures[pool.submit(_run_whois)] = "whois"
        if "shodan" in phase0a_tools:
            futures[pool.submit(_run_shodan)] = "shodan"
        if "abuseipdb" in phase0a_tools:
            futures[pool.submit(_run_abuseipdb)] = "abuseipdb"
        if "securitytrails" in phase0a_tools:
            futures[pool.submit(_run_securitytrails)] = "securitytrails"
        futures[pool.submit(_run_dns_security)] = "dns_security"

        for future in as_completed(futures, timeout=phase0a_timeout):
            tool_name = futures[future]
            try:
                key, data = future.result()
                if data:
                    if key == "shodan" and isinstance(data, dict):
                        # Shodan returns a composite dict
                        results.update(data)
                    else:
                        results[key] = data
            except Exception as e:
                log.error("phase0a_tool_failed", tool=tool_name, error=str(e))
            if progress_callback:
                progress_callback(order_id, tool_name, "complete")

    duration_ms = int((time.monotonic() - start) * 1000)
    log.info("phase0a_complete", order_id=order_id, duration_ms=duration_ms,
             tools_run=list(results.keys()))

    # Save combined summary
    _save_json(phase0a_dir, "summary.json", results)

    return results


def build_passive_intel_for_ai(
    phase0a_results: dict[str, Any],
    ip: str,
) -> dict[str, Any]:
    """Extract passive intelligence relevant for AI Host Strategy for a specific IP.

    Returns a compact dict suitable for inclusion in the AI prompt.
    """
    intel: dict[str, Any] = {}

    # Shodan data for this IP
    shodan_hosts = phase0a_results.get("shodan_hosts", {})
    if ip in shodan_hosts:
        sh = shodan_hosts[ip]
        intel["shodan_ports"] = sh.get("ports", [])
        intel["shodan_services"] = {
            str(s["port"]): f"{s.get('product', '')} {s.get('version', '')}".strip()
            for s in sh.get("services", [])
            if s.get("product")
        }

    # AbuseIPDB score for this IP
    abuse = phase0a_results.get("abuseipdb", {})
    if ip in abuse:
        intel["abuseipdb_score"] = abuse[ip].get("abuseConfidenceScore", 0)
        intel["is_tor"] = abuse[ip].get("isTor", False)

    # WHOIS (domain-level, not per-IP)
    whois = phase0a_results.get("whois")
    if whois:
        intel["whois_dnssec"] = whois.get("dnssec", "unknown")
        intel["whois_expiration"] = whois.get("expiration_date")

    # DNS security (domain-level)
    dns_sec = phase0a_results.get("dns_security", {})
    dnssec = dns_sec.get("dnssec", {})
    if dnssec:
        intel["dnssec_signed"] = dnssec.get("dnssec_signed", False)
        if dnssec.get("nsec3_rfc9276_violation"):
            intel["nsec3_rfc9276_violation"] = True

    # F-P0A-002: Mail-Security-Marker fuer KI #1
    tls_rpt = dns_sec.get("tls_rpt") or {}
    if tls_rpt:
        intel["tlsrpt_present"] = bool(tls_rpt.get("tlsrpt_present"))
    dmarc = dns_sec.get("dmarc") or {}
    if dmarc.get("dmarc_present"):
        intel["dmarc_p"] = dmarc.get("p")
        intel["dmarc_pct"] = dmarc.get("pct")

    return intel


def _save_json(directory: str, filename: str, data: Any) -> None:
    """Save data as JSON file (best-effort, no exceptions)."""
    try:
        path = os.path.join(directory, filename)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        log.warning("phase0a_save_failed", file=filename, error=str(e))
