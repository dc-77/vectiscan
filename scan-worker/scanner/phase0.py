"""Phase 0: DNS-Reconnaissance — Subdomain-Enumeration und Host-Gruppierung."""

import json
import os
import socket
import subprocess
import tempfile
import time
from collections import defaultdict
from typing import Any, Optional

import structlog

from scanner.tools import run_tool

log = structlog.get_logger()

PHASE0_TIMEOUT = 600  # 10 Minuten Gesamt-Timeout
MAX_HOSTS = 10


def run_crtsh(domain: str, scan_dir: str, order_id: str) -> list[str]:
    """Query crt.sh for certificate transparency subdomains. Timeout 30s."""
    output_path = os.path.join(scan_dir, "phase0", "crtsh.json")
    subdomains: list[str] = []

    cmd = ["curl", "-s", f"https://crt.sh/?q=%.{domain}&output=json"]
    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=30,
        output_path=output_path,
        order_id=order_id,
        phase=0,
        tool_name="crtsh",
    )

    if exit_code != 0:
        log.warning("crtsh_failed", exit_code=exit_code)
        return subdomains

    # Re-run curl to capture stdout (run_tool logs to DB but doesn't return stdout)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            entries = json.loads(result.stdout)
            seen: set[str] = set()
            for entry in entries:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name.startswith("*."):
                        name = name[2:]
                    if name and (name.endswith(f".{domain}") or name == domain):
                        seen.add(name)
            subdomains = sorted(seen)

            with open(output_path, "w") as f:
                json.dump({"subdomains": subdomains, "raw_count": len(entries)}, f, indent=2)

            log.info("crtsh_complete", subdomains_found=len(subdomains))
    except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception) as e:
        log.warning("crtsh_parse_error", error=str(e))

    return subdomains


def run_subfinder(domain: str, scan_dir: str, order_id: str) -> list[str]:
    """Run subfinder for passive subdomain enumeration. Timeout 120s."""
    output_path = os.path.join(scan_dir, "phase0", "subfinder.json")
    subdomains: list[str] = []

    cmd = [
        "subfinder", "-d", domain,
        "-silent", "-json",
        "-o", output_path,
    ]
    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=120,
        output_path=output_path,
        order_id=order_id,
        phase=0,
        tool_name="subfinder",
    )

    if exit_code not in (0,):
        log.warning("subfinder_failed", exit_code=exit_code)

    # Parse JSON lines output
    try:
        if os.path.exists(output_path):
            with open(output_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        host = entry.get("host", "").strip().lower()
                        if host:
                            subdomains.append(host)
                    except json.JSONDecodeError:
                        continue
            log.info("subfinder_complete", subdomains_found=len(subdomains))
    except Exception as e:
        log.warning("subfinder_parse_error", error=str(e))

    return subdomains


def run_amass(domain: str, scan_dir: str, order_id: str) -> list[str]:
    """Run amass passive enumeration. Timeout 300s (5 Min)."""
    output_path = os.path.join(scan_dir, "phase0", "amass.json")
    subdomains: list[str] = []

    cmd = [
        "amass", "enum", "-passive",
        "-d", domain,
        "-json", output_path,
    ]
    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=300,
        output_path=output_path,
        order_id=order_id,
        phase=0,
        tool_name="amass",
    )

    if exit_code not in (0,):
        log.warning("amass_failed", exit_code=exit_code)

    # Parse JSON lines output
    try:
        if os.path.exists(output_path):
            with open(output_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        name = entry.get("name", "").strip().lower()
                        if name:
                            subdomains.append(name)
                    except json.JSONDecodeError:
                        continue
            log.info("amass_complete", subdomains_found=len(subdomains))
    except Exception as e:
        log.warning("amass_parse_error", error=str(e))

    return subdomains


def run_gobuster_dns(domain: str, scan_dir: str, order_id: str) -> list[str]:
    """Run gobuster DNS brute-force. Timeout 180s (3 Min)."""
    output_path = os.path.join(scan_dir, "phase0", "gobuster_dns.txt")
    subdomains: list[str] = []

    cmd = [
        "gobuster", "dns",
        "-d", domain,
        "-w", "/usr/share/wordlists/subdomains-top5000.txt",
        "-q",
        "-o", output_path,
    ]
    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=180,
        output_path=output_path,
        order_id=order_id,
        phase=0,
        tool_name="gobuster_dns",
    )

    if exit_code not in (0,):
        log.warning("gobuster_dns_failed", exit_code=exit_code)

    # Parse text output: "Found: sub.example.com" or just "sub.example.com"
    try:
        if os.path.exists(output_path):
            with open(output_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    # gobuster output: "Found: subdomain.example.com"
                    if line.startswith("Found:"):
                        host = line.split("Found:")[-1].strip().lower()
                    else:
                        host = line.strip().lower()
                    if host:
                        subdomains.append(host)
            log.info("gobuster_dns_complete", subdomains_found=len(subdomains))
    except Exception as e:
        log.warning("gobuster_dns_parse_error", error=str(e))

    return subdomains


def run_zone_transfer(domain: str, scan_dir: str, order_id: str) -> dict[str, Any]:
    """Attempt DNS zone transfer via AXFR. Timeout 30s per NS."""
    output_path = os.path.join(scan_dir, "phase0", "zone_transfer.txt")
    result_data: dict[str, Any] = {"success": False, "data": {}}
    all_output: list[str] = []

    # Step 1: resolve NS records
    try:
        ns_result = subprocess.run(
            ["dig", "NS", domain, "+short"],
            capture_output=True, text=True, timeout=15,
        )
        nameservers = [
            ns.strip().rstrip(".")
            for ns in ns_result.stdout.strip().split("\n")
            if ns.strip()
        ]
    except Exception as e:
        log.warning("zone_transfer_ns_lookup_failed", error=str(e))
        return result_data

    if not nameservers:
        log.info("zone_transfer_no_ns", domain=domain)
        return result_data

    log.info("zone_transfer_attempting", nameservers=nameservers)

    # Step 2: try AXFR against each NS
    for ns in nameservers:
        cmd = ["dig", f"@{ns}", domain, "AXFR"]
        exit_code, duration_ms = run_tool(
            cmd=cmd,
            timeout=30,
            order_id=order_id,
            phase=0,
            tool_name=f"zone_transfer_{ns}",
        )

        try:
            axfr_result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
            output = axfr_result.stdout
            all_output.append(f"=== NS: {ns} ===\n{output}\n")

            # Check if transfer succeeded (contains actual records, not just SOA)
            lines = [
                l for l in output.split("\n")
                if l.strip() and not l.startswith(";")
            ]
            if len(lines) > 2:  # More than just SOA records = successful transfer
                result_data["success"] = True
                result_data["data"][ns] = output
                log.warning("zone_transfer_success", ns=ns, domain=domain)
        except Exception as e:
            all_output.append(f"=== NS: {ns} === ERROR: {e}\n")
            log.warning("zone_transfer_error", ns=ns, error=str(e))

    # Save all output
    try:
        with open(output_path, "w") as f:
            f.write("\n".join(all_output))
    except Exception as e:
        log.warning("zone_transfer_save_error", error=str(e))

    return result_data


def run_dnsx(subdomains: list[str], scan_dir: str, order_id: str) -> list[dict[str, Any]]:
    """Validate subdomains with dnsx and resolve IPs. Timeout 60s."""
    output_path = os.path.join(scan_dir, "phase0", "dnsx_validation.json")
    validated: list[dict[str, Any]] = []

    if not subdomains:
        log.info("dnsx_skip", reason="no subdomains to validate")
        return validated

    # Write subdomains to temp file
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(subdomains))
            tmp_path = tmp.name
    except Exception as e:
        log.error("dnsx_tempfile_error", error=str(e))
        return validated

    try:
        cmd = [
            "dnsx",
            "-l", tmp_path,
            "-a", "-aaaa", "-cname",
            "-resp", "-json",
            "-o", output_path,
        ]
        exit_code, duration_ms = run_tool(
            cmd=cmd,
            timeout=60,
            output_path=output_path,
            order_id=order_id,
            phase=0,
            tool_name="dnsx",
        )

        if exit_code not in (0,):
            log.warning("dnsx_failed", exit_code=exit_code)

        # Parse JSON lines output
        if os.path.exists(output_path):
            with open(output_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        validated.append(entry)
                    except json.JSONDecodeError:
                        continue

        log.info("dnsx_complete", validated_count=len(validated))

    except Exception as e:
        log.warning("dnsx_parse_error", error=str(e))
    finally:
        # Clean up temp file
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return validated


def collect_dns_records(domain: str, scan_dir: str, order_id: str) -> dict[str, Any]:
    """Collect SPF, DMARC, DKIM, MX, NS records via dig. Saves to dns_records.json."""
    output_path = os.path.join(scan_dir, "phase0", "dns_records.json")
    records: dict[str, Any] = {
        "spf": None,
        "dmarc": None,
        "dkim": False,
        "mx": [],
        "ns": [],
    }

    def _dig_query(qname: str, qtype: str, timeout: int = 10) -> str:
        """Run a dig query and return stdout."""
        try:
            result = subprocess.run(
                ["dig", qname, qtype, "+short"],
                capture_output=True, text=True, timeout=timeout,
            )
            return result.stdout.strip()
        except Exception as e:
            log.warning("dig_query_error", qname=qname, qtype=qtype, error=str(e))
            return ""

    # SPF (TXT record)
    try:
        txt_output = _dig_query(domain, "TXT")
        for line in txt_output.split("\n"):
            line = line.strip().strip('"')
            if "v=spf1" in line.lower():
                records["spf"] = line
                break
    except Exception as e:
        log.warning("spf_lookup_error", error=str(e))

    # DMARC
    try:
        dmarc_output = _dig_query(f"_dmarc.{domain}", "TXT")
        for line in dmarc_output.split("\n"):
            line = line.strip().strip('"')
            if "v=dmarc1" in line.lower():
                records["dmarc"] = line
                break
    except Exception as e:
        log.warning("dmarc_lookup_error", error=str(e))

    # DKIM (check default._domainkey)
    try:
        dkim_output = _dig_query(f"default._domainkey.{domain}", "TXT")
        records["dkim"] = bool(dkim_output and "v=dkim1" in dkim_output.lower())
    except Exception as e:
        log.warning("dkim_lookup_error", error=str(e))

    # MX records
    try:
        mx_output = _dig_query(domain, "MX")
        for line in mx_output.split("\n"):
            line = line.strip()
            if line:
                # MX output: "10 mx1.example.com."
                parts = line.split()
                if len(parts) >= 2:
                    records["mx"].append(parts[-1].rstrip("."))
                else:
                    records["mx"].append(line.rstrip("."))
    except Exception as e:
        log.warning("mx_lookup_error", error=str(e))

    # NS records
    try:
        ns_output = _dig_query(domain, "NS")
        for line in ns_output.split("\n"):
            line = line.strip().rstrip(".")
            if line:
                records["ns"].append(line)
    except Exception as e:
        log.warning("ns_lookup_error", error=str(e))

    # Save result and log to DB
    try:
        with open(output_path, "w") as f:
            json.dump(records, f, indent=2)
    except Exception as e:
        log.warning("dns_records_save_error", error=str(e))

    run_tool(
        cmd=["echo", "dns_records_collected"],
        timeout=5,
        order_id=order_id,
        phase=0,
        tool_name="dns_records",
    )

    log.info("dns_records_complete", records=records)
    return records


def merge_and_group(
    domain: str,
    all_subdomains: list[str],
    dnsx_results: list[dict[str, Any]],
    dns_records: dict[str, Any],
    zone_transfer: dict[str, Any],
    scan_dir: str,
    max_hosts: int = 10,
) -> dict[str, Any]:
    """Deduplicate subdomains, group by IP, create host_inventory.json."""
    output_path = os.path.join(scan_dir, "phase0", "host_inventory.json")

    # Deduplicate subdomains
    unique_subs = sorted(set(s.lower().rstrip(".") for s in all_subdomains if s))
    log.info("merge_dedup", total_raw=len(all_subdomains), unique=len(unique_subs))

    # Group by IP from dnsx results
    ip_to_fqdns: dict[str, set[str]] = defaultdict(set)
    dangling_cnames: list[str] = []

    for entry in dnsx_results:
        host = entry.get("host", "").lower().rstrip(".")
        if not host:
            continue

        # Collect A record IPs
        a_records = entry.get("a", [])
        aaaa_records = entry.get("aaaa", [])
        cname = entry.get("cname", [])

        ips = (a_records or []) + (aaaa_records or [])

        if ips:
            for ip in ips:
                ip_to_fqdns[ip].add(host)
        elif cname and not ips:
            # CNAME exists but no A/AAAA -> dangling CNAME
            dangling_cnames.append(host)

    # Ensure base domain is present — fallback via socket if dnsx missed it
    domain_in_results = any(
        domain.lower() in (h.lower().rstrip(".") for h in fqdns)
        for fqdns in ip_to_fqdns.values()
    )
    if not domain_in_results:
        try:
            infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
            fallback_ips = sorted({info[4][0] for info in infos})
            for fb_ip in fallback_ips:
                ip_to_fqdns[fb_ip].add(domain.lower())
            log.info("base_domain_fallback", domain=domain, ips=fallback_ips)
        except (socket.gaierror, OSError) as e:
            log.warning("base_domain_resolve_failed", domain=domain, error=str(e))

    # Build hosts list
    hosts: list[dict[str, Any]] = []
    for ip, fqdns in sorted(ip_to_fqdns.items()):
        # Attempt reverse DNS
        rdns = ""
        try:
            rdns = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            pass

        hosts.append({
            "ip": ip,
            "fqdns": sorted(fqdns),
            "rdns": rdns,
        })

    # Prioritize hosts: base domain first, then web hosts, then others
    # Mail/autodiscover hosts are deprioritized so web assets get scanned
    def _host_priority(host: dict[str, Any]) -> tuple[int, str]:
        fqdns_lower = [f.lower() for f in host["fqdns"]]
        # Priority 0: host that serves the base domain itself
        if domain.lower() in fqdns_lower:
            return (0, host["ip"])
        # Priority 1: www subdomain
        if f"www.{domain.lower()}" in fqdns_lower:
            return (1, host["ip"])
        # Priority 3: mail/autodiscover/mx — deprioritize
        mail_keywords = ("mail.", "mx.", "smtp.", "imap.", "pop.", "autodiscover.", "exchange.")
        if any(f.startswith(kw) for f in fqdns_lower for kw in mail_keywords):
            return (3, host["ip"])
        # Priority 2: everything else (web hosts, portals, apps)
        return (2, host["ip"])

    hosts.sort(key=_host_priority)

    # Limit to max_hosts
    skipped_hosts: list[dict[str, Any]] = []
    if len(hosts) > max_hosts:
        log.warning("hosts_limited", total=len(hosts), max=max_hosts,
                    kept=[h["ip"] for h in hosts[:max_hosts]],
                    skipped=[h["ip"] for h in hosts[max_hosts:]])
        skipped_hosts = hosts[max_hosts:]
        hosts = hosts[:max_hosts]

    inventory: dict[str, Any] = {
        "domain": domain,
        "hosts": hosts,
        "dns_findings": {
            "zone_transfer": zone_transfer.get("success", False),
            "spf": dns_records.get("spf"),
            "dmarc": dns_records.get("dmarc"),
            "dkim": dns_records.get("dkim", False),
            "mx": dns_records.get("mx", []),
            "ns": dns_records.get("ns", []),
            "dangling_cnames": dangling_cnames,
        },
        "skipped_hosts": skipped_hosts,
    }

    # Save host_inventory.json
    try:
        with open(output_path, "w") as f:
            json.dump(inventory, f, indent=2)
        log.info(
            "host_inventory_saved",
            hosts=len(hosts),
            skipped=len(skipped_hosts),
            dangling_cnames=len(dangling_cnames),
        )
    except Exception as e:
        log.error("host_inventory_save_error", error=str(e))

    return inventory


def run_phase0(domain: str, scan_dir: str, order_id: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Orchestrate Phase 0: DNS Reconnaissance.

    Runs all enumeration tools, collects and deduplicates subdomains,
    validates with dnsx, and creates the host inventory.

    Overall timeout: 10 minutes.
    """
    # Use config if provided, otherwise default to professional
    phase0_timeout = config["phase0_timeout"] if config else PHASE0_TIMEOUT
    max_hosts = config["max_hosts"] if config else MAX_HOSTS
    phase0_tools = config["phase0_tools"] if config else ["crtsh", "subfinder", "amass", "gobuster_dns", "axfr", "dnsx"]

    phase0_start = time.monotonic()
    phase0_dir = os.path.join(scan_dir, "phase0")
    os.makedirs(phase0_dir, exist_ok=True)

    log.info("phase0_start", domain=domain, order_id=order_id)

    all_subdomains: list[str] = []

    def _time_remaining() -> float:
        elapsed = time.monotonic() - phase0_start
        return max(0, phase0_timeout - elapsed)

    # --- crt.sh ---
    if _time_remaining() > 0 and "crtsh" in phase0_tools:
        try:
            subs = run_crtsh(domain, scan_dir, order_id)
            all_subdomains.extend(subs)
            log.info("phase0_crtsh_done", found=len(subs))
        except Exception as e:
            log.error("phase0_crtsh_error", error=str(e))

    # --- subfinder ---
    if _time_remaining() > 0 and "subfinder" in phase0_tools:
        try:
            subs = run_subfinder(domain, scan_dir, order_id)
            all_subdomains.extend(subs)
            log.info("phase0_subfinder_done", found=len(subs))
        except Exception as e:
            log.error("phase0_subfinder_error", error=str(e))

    # --- amass ---
    if _time_remaining() > 0 and "amass" in phase0_tools:
        try:
            subs = run_amass(domain, scan_dir, order_id)
            all_subdomains.extend(subs)
            log.info("phase0_amass_done", found=len(subs))
        except Exception as e:
            log.error("phase0_amass_error", error=str(e))

    # --- gobuster dns ---
    if _time_remaining() > 0 and "gobuster_dns" in phase0_tools:
        try:
            subs = run_gobuster_dns(domain, scan_dir, order_id)
            all_subdomains.extend(subs)
            log.info("phase0_gobuster_done", found=len(subs))
        except Exception as e:
            log.error("phase0_gobuster_error", error=str(e))

    # --- zone transfer ---
    zone_transfer: dict[str, Any] = {"success": False, "data": {}}
    if _time_remaining() > 0 and "axfr" in phase0_tools:
        try:
            zone_transfer = run_zone_transfer(domain, scan_dir, order_id)
            log.info("phase0_zone_transfer_done", success=zone_transfer["success"])
        except Exception as e:
            log.error("phase0_zone_transfer_error", error=str(e))

    # --- DNS records (SPF, DMARC, DKIM, MX, NS) ---
    dns_records: dict[str, Any] = {"spf": None, "dmarc": None, "dkim": False, "mx": [], "ns": []}
    if _time_remaining() > 0:
        try:
            dns_records = collect_dns_records(domain, scan_dir, order_id)
            log.info("phase0_dns_records_done")
        except Exception as e:
            log.error("phase0_dns_records_error", error=str(e))

    # Always include the base domain
    all_subdomains.append(domain)

    # --- dnsx validation ---
    dnsx_results: list[dict[str, Any]] = []
    if _time_remaining() > 0 and "dnsx" in phase0_tools:
        try:
            unique_subs = sorted(set(s.lower() for s in all_subdomains if s))
            dnsx_results = run_dnsx(unique_subs, scan_dir, order_id)
            log.info("phase0_dnsx_done", validated=len(dnsx_results))
        except Exception as e:
            log.error("phase0_dnsx_error", error=str(e))

    # --- Merge and group ---
    inventory = merge_and_group(
        domain=domain,
        all_subdomains=all_subdomains,
        dnsx_results=dnsx_results,
        dns_records=dns_records,
        zone_transfer=zone_transfer,
        scan_dir=scan_dir,
        max_hosts=max_hosts,
    )

    elapsed_ms = int((time.monotonic() - phase0_start) * 1000)
    log.info(
        "phase0_complete",
        domain=domain,
        hosts_found=len(inventory.get("hosts", [])),
        skipped=len(inventory.get("skipped_hosts", [])),
        duration_ms=elapsed_ms,
    )

    return inventory
