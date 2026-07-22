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
from scanner.passive.urlhaus_client import URLhausClient
from scanner.passive.greynoise_client import GreyNoiseClient
from scanner.passive.otx_client import OTXClient
from scanner.passive.virustotal_client import VirusTotalClient
from scanner.passive.dns_security import run_all_dns_security
from scanner.progress import publish_event
from scanner.tools import record_tool_run

log = structlog.get_logger()

# A7 (Jul 2026): Soll-Liste der Passive-Intel-Tools. Bis A7 war Phase 0a in
# scan_results komplett unsichtbar — weder Lauf noch Skip wurden protokolliert.
PHASE0A_EXPECTED_TOOLS: tuple[str, ...] = (
    "whois", "shodan", "abuseipdb", "securitytrails",
    "urlhaus", "greynoise", "otx", "virustotal",
)


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
        - urlhaus: per-host compromise / malware-distribution hits (F-P0A-003)
        - greynoise: per-IP background-noise classification (F-P0A-003)
        - otx: domain reputation incl. pulse-count (F-P0A-003)
        - virustotal: domain AV-engine voting summary (F-P0A-003)
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

    # --- A7: Ergebniszeile pro Passive-Intel-Tool -----------------------
    recorded_tools: set[str] = set()

    def _record_passive(tool: str, status: str, reason: str | None = None,
                        data: Any = None) -> None:
        """Genau eine scan_results-Zeile pro Tool (erster Aufruf gewinnt).

        Der Guard verhindert Doppelzeilen, wenn ein Tool bereits wegen
        fehlendem API-Key als 'skipped' vermerkt wurde und die Ergebnis-
        schleife danach nochmal ueber dasselbe Tool laeuft.
        """
        if tool in recorded_tools:
            return
        recorded_tools.add(tool)
        raw: str | None = None
        if data:
            try:
                raw = json.dumps(data, ensure_ascii=False, default=str)[:50000]
            except Exception:
                raw = None
        record_tool_run(order_id, None, 0, tool, status,
                        reason=reason, raw_output=raw)

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
            _record_passive("shodan", "skipped", "no_api_key")
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
            _record_passive("abuseipdb", "skipped", "no_api_key")
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
            _record_passive("securitytrails", "skipped", "no_api_key")
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

    # ------------------------------------------------------------------
    # F-P0A-003 — neue Threat-Intel-Clients (URLhaus, GreyNoise, OTX, VT)
    # ------------------------------------------------------------------
    def _run_urlhaus() -> tuple[str, dict[str, Any] | None]:
        publish_event(order_id, {"type": "tool_starting", "tool": "urlhaus", "host": domain})
        client = URLhausClient()
        # URLhaus: 1x Domain-Lookup + ggf. per IP (begrenzt auf capped_ips).
        domain_resp = client.lookup_host(domain)
        per_ip: dict[str, Any] = {}
        if capped_ips:
            with ThreadPoolExecutor(
                max_workers=passive_concurrency,
                thread_name_prefix="urlhaus_ips",
            ) as inner:
                futures = {inner.submit(client.lookup_host, ip): ip for ip in capped_ips}
                for fut in as_completed(futures):
                    ip = futures[fut]
                    try:
                        ip_resp = fut.result()
                    except Exception as e:
                        log.warning("urlhaus_ip_lookup_failed", ip=ip, error=str(e))
                        continue
                    if ip_resp:
                        per_ip[ip] = ip_resp
        result: dict[str, Any] = {}
        if domain_resp:
            result["domain"] = domain_resp
            result["compromised"] = client.is_compromised(domain_resp)
        if per_ip:
            result["per_ip"] = per_ip
            # Aggregat-Flag: irgendein IP-Treffer kompromittiert?
            if not result.get("compromised"):
                result["compromised"] = any(
                    client.is_compromised(v) for v in per_ip.values()
                )
        if result:
            _save_json(phase0a_dir, "urlhaus.json", result)
        return "urlhaus", result or None

    def _run_greynoise() -> tuple[str, dict[str, Any] | None]:
        publish_event(order_id, {"type": "tool_starting", "tool": "greynoise", "host": domain})
        client = GreyNoiseClient()
        gn_results: dict[str, Any] = {}
        if capped_ips:
            with ThreadPoolExecutor(
                max_workers=passive_concurrency,
                thread_name_prefix="greynoise_ips",
            ) as inner:
                futures = {inner.submit(client.lookup_ip, ip): ip for ip in capped_ips}
                for fut in as_completed(futures):
                    ip = futures[fut]
                    try:
                        gn_data = fut.result()
                    except Exception as e:
                        log.warning("greynoise_ip_lookup_failed", ip=ip, error=str(e))
                        continue
                    if gn_data:
                        gn_results[ip] = gn_data
        if gn_results:
            _save_json(phase0a_dir, "greynoise.json", gn_results)
        return "greynoise", gn_results or None

    def _run_otx() -> tuple[str, dict[str, Any] | None]:
        publish_event(order_id, {"type": "tool_starting", "tool": "otx", "host": domain})
        client = OTXClient()
        domain_resp = client.lookup_domain(domain)
        result: dict[str, Any] = {}
        if domain_resp:
            result["domain"] = domain_resp
        # IP-Lookups optional (Free-Tier: 10 req/s, sicher fuer capped_ips).
        per_ip: dict[str, Any] = {}
        if capped_ips:
            with ThreadPoolExecutor(
                max_workers=passive_concurrency,
                thread_name_prefix="otx_ips",
            ) as inner:
                futures = {inner.submit(client.lookup_ip, ip): ip for ip in capped_ips}
                for fut in as_completed(futures):
                    ip = futures[fut]
                    try:
                        ip_resp = fut.result()
                    except Exception as e:
                        log.warning("otx_ip_lookup_failed", ip=ip, error=str(e))
                        continue
                    if ip_resp:
                        per_ip[ip] = ip_resp
        if per_ip:
            result["per_ip"] = per_ip
        if result:
            _save_json(phase0a_dir, "otx.json", result)
        return "otx", result or None

    def _run_virustotal() -> tuple[str, dict[str, Any] | None]:
        publish_event(order_id, {"type": "tool_starting", "tool": "virustotal", "host": domain})
        client = VirusTotalClient()
        if not client.available:
            log.info("virustotal_skipped", reason="no_api_key")
            _record_passive("virustotal", "skipped", "no_api_key")
            return "virustotal", None
        domain_resp = client.lookup_domain(domain)
        if not domain_resp:
            return "virustotal", None
        _save_json(phase0a_dir, "virustotal.json", domain_resp)
        return "virustotal", domain_resp

    # --- Run all tools in parallel (Top-Level: ThreadPool importiert oben) ---
    phase0a_timeout = config.get("phase0a_timeout", 120)
    futures: dict[Any, str] = {}

    # A7: nicht gelistete Tools bekommen ihre Zeile, bevor der Pool startet.
    for passive_tool in PHASE0A_EXPECTED_TOOLS:
        if passive_tool not in phase0a_tools:
            _record_passive(passive_tool, "skipped", "not_in_package")

    with ThreadPoolExecutor(max_workers=8, thread_name_prefix="phase0a") as pool:
        if "whois" in phase0a_tools:
            futures[pool.submit(_run_whois)] = "whois"
        if "shodan" in phase0a_tools:
            futures[pool.submit(_run_shodan)] = "shodan"
        if "abuseipdb" in phase0a_tools:
            futures[pool.submit(_run_abuseipdb)] = "abuseipdb"
        if "securitytrails" in phase0a_tools:
            futures[pool.submit(_run_securitytrails)] = "securitytrails"
        # F-P0A-003 — Threat-Intel-Clients
        if "urlhaus" in phase0a_tools:
            futures[pool.submit(_run_urlhaus)] = "urlhaus"
        if "greynoise" in phase0a_tools:
            futures[pool.submit(_run_greynoise)] = "greynoise"
        if "otx" in phase0a_tools:
            futures[pool.submit(_run_otx)] = "otx"
        if "virustotal" in phase0a_tools:
            futures[pool.submit(_run_virustotal)] = "virustotal"
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
                _record_passive(tool_name, "ok",
                                None if data else "no_data", data)
            except Exception as e:
                log.error("phase0a_tool_failed", tool=tool_name, error=str(e))
                _record_passive(tool_name, "failed", str(e))
            if progress_callback:
                progress_callback(order_id, tool_name, "complete")

    # ------------------------------------------------------------------
    # F-P0A-004 (Mai 2026): Phase-0a-Subdomains an Phase 0b durchreichen.
    # Phase 0a sammelt bereits `shodan_domain.subdomains[]` und
    # `securitytrails.subdomains[]` — frueher hat Phase 0b denselben
    # SecurityTrails-Call nochmal ausgefuehrt. Jetzt geben wir das
    # vereinigte sortierte Set als `passive_subdomains` zurueck, das
    # `worker.py` als `seed_subdomains` an `run_phase0` weiterreicht.
    # SecurityTrails-Subdomains kommen bereits als FQDNs (mit Domain
    # angehaengt), Shodan liefert nur Labels — wir normalisieren beide.
    # ------------------------------------------------------------------
    passive_subdomains: set[str] = set()
    domain_norm = (domain or "").strip().lower().rstrip(".")
    shodan_domain = results.get("shodan_domain") or {}
    for s in shodan_domain.get("subdomains") or []:
        if not s:
            continue
        label = str(s).strip().lower().rstrip(".")
        if not label:
            continue
        # Shodan liefert Labels (z.B. "www") — an domain anhaengen wenn noetig.
        if domain_norm and not label.endswith(f".{domain_norm}") and label != domain_norm:
            fqdn = f"{label}.{domain_norm}"
        else:
            fqdn = label
        passive_subdomains.add(fqdn)
    st = results.get("securitytrails") or {}
    for fq in st.get("subdomains") or []:
        if not fq:
            continue
        passive_subdomains.add(str(fq).strip().lower().rstrip("."))
    results["passive_subdomains"] = sorted(passive_subdomains)

    duration_ms = int((time.monotonic() - start) * 1000)
    log.info("phase0a_complete", order_id=order_id, duration_ms=duration_ms,
             tools_run=list(results.keys()),
             passive_subdomains=len(results["passive_subdomains"]))

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

    # F-P0A-003: URLhaus / GreyNoise / OTX / VT-Marker fuer KI #1 + Reporter
    urlhaus = phase0a_results.get("urlhaus") or {}
    if urlhaus.get("compromised"):
        intel["urlhaus_compromised"] = True
        domain_resp = urlhaus.get("domain") or {}
        urls = domain_resp.get("urls") or []
        if isinstance(urls, list) and urls:
            intel["urlhaus_url_count"] = len(urls)
        per_ip = urlhaus.get("per_ip") or {}
        if ip in per_ip:
            ip_urls = (per_ip[ip] or {}).get("urls") or []
            if isinstance(ip_urls, list) and ip_urls:
                intel["urlhaus_url_count_ip"] = len(ip_urls)

    greynoise = phase0a_results.get("greynoise") or {}
    if ip in greynoise:
        gn = greynoise[ip]
        intel["greynoise_classification"] = gn.get("classification")
        intel["greynoise_noise"] = gn.get("noise")
        intel["greynoise_riot"] = gn.get("riot")

    otx = phase0a_results.get("otx") or {}
    otx_domain = otx.get("domain") or {}
    if otx_domain:
        intel["otx_pulse_count"] = otx_domain.get("pulse_count", 0)

    vt = phase0a_results.get("virustotal") or {}
    if vt:
        intel["vt_malicious"] = vt.get("malicious", 0)
        intel["vt_suspicious"] = vt.get("suspicious", 0)
        intel["vt_total_engines"] = vt.get("total_engines", 0)

    return intel


def _save_json(directory: str, filename: str, data: Any) -> None:
    """Save data as JSON file (best-effort, no exceptions)."""
    try:
        path = os.path.join(directory, filename)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        log.warning("phase0a_save_failed", file=filename, error=str(e))
