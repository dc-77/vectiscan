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

    # --- WHOIS (all packages) ---
    if "whois" in phase0a_tools:
        if progress_callback:
            progress_callback(order_id, "whois", "running")
        whois = WhoisClient()
        whois_data = whois.lookup(domain)
        if whois_data:
            results["whois"] = whois_data
            _save_json(phase0a_dir, "whois.json", whois_data)
        if progress_callback:
            progress_callback(order_id, "whois", "complete")

    # --- Shodan (Perimeter+ only) ---
    if "shodan" in phase0a_tools:
        if progress_callback:
            progress_callback(order_id, "shodan", "running")
        shodan = ShodanClient()
        if shodan.available:
            # Domain lookup
            domain_data = shodan.lookup_domain(domain)
            if domain_data:
                results["shodan_domain"] = domain_data
                _save_json(phase0a_dir, "shodan_domain.json", domain_data)

            # Host lookups for known IPs
            shodan_hosts: dict[str, Any] = {}
            for ip in ips[:15]:  # Cap at max_hosts
                host_data = shodan.lookup_host(ip)
                if host_data:
                    shodan_hosts[ip] = host_data
            if shodan_hosts:
                results["shodan_hosts"] = shodan_hosts
                _save_json(phase0a_dir, "shodan_hosts.json", shodan_hosts)
        else:
            log.info("shodan_skipped", reason="no_api_key")
        if progress_callback:
            progress_callback(order_id, "shodan", "complete")

    # --- AbuseIPDB (Perimeter+ only) ---
    if "abuseipdb" in phase0a_tools:
        if progress_callback:
            progress_callback(order_id, "abuseipdb", "running")
        abuseipdb = AbuseIPDBClient()
        if abuseipdb.available:
            abuse_results: dict[str, Any] = {}
            for ip in ips[:15]:
                abuse_data = abuseipdb.check_ip(ip)
                if abuse_data:
                    abuse_results[ip] = abuse_data
            if abuse_results:
                results["abuseipdb"] = abuse_results
                _save_json(phase0a_dir, "abuseipdb.json", abuse_results)
        else:
            log.info("abuseipdb_skipped", reason="no_api_key")
        if progress_callback:
            progress_callback(order_id, "abuseipdb", "complete")

    # --- SecurityTrails (Perimeter+ only) ---
    if "securitytrails" in phase0a_tools:
        if progress_callback:
            progress_callback(order_id, "securitytrails", "running")
        st = SecurityTrailsClient()
        if st.available:
            st_domain = st.lookup_domain(domain)
            st_subs = st.get_subdomains(domain)
            st_history = st.get_dns_history(domain)
            st_data = {
                "domain": st_domain,
                "subdomains": st_subs,
                "dns_history": st_history,
            }
            results["securitytrails"] = st_data
            _save_json(phase0a_dir, "securitytrails.json", st_data)
        else:
            log.info("securitytrails_skipped", reason="no_api_key")
        if progress_callback:
            progress_callback(order_id, "securitytrails", "complete")

    # --- DNS Security (all packages, detail varies) ---
    package = config.get("package", "perimeter")
    if progress_callback:
        progress_callback(order_id, "dns_security", "running")
    dns_sec = run_all_dns_security(domain, package)
    results["dns_security"] = dns_sec
    _save_json(phase0a_dir, "dns_security.json", dns_sec)
    if progress_callback:
        progress_callback(order_id, "dns_security", "complete")

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

    return intel


def _save_json(directory: str, filename: str, data: Any) -> None:
    """Save data as JSON file (best-effort, no exceptions)."""
    try:
        path = os.path.join(directory, filename)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        log.warning("phase0a_save_failed", file=filename, error=str(e))
