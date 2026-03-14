"""Phase 1 — Technology detection per host."""

import json
import os
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Callable, Optional

import structlog

from scanner.tools import run_tool

log = structlog.get_logger()


def _parse_nmap_xml(xml_path: str) -> dict[str, Any]:
    """Parse nmap XML output into a structured dict."""
    result: dict[str, Any] = {
        "open_ports": [],
        "services": [],
    }

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for host in root.findall("host"):
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue
            for port in ports_elem.findall("port"):
                state_elem = port.find("state")
                if state_elem is None:
                    continue
                if state_elem.get("state") != "open":
                    continue

                port_id = int(port.get("portid", "0"))
                protocol = port.get("protocol", "tcp")
                result["open_ports"].append(port_id)

                service_elem = port.find("service")
                service_info: dict[str, Any] = {
                    "port": port_id,
                    "protocol": protocol,
                }
                if service_elem is not None:
                    service_info["name"] = service_elem.get("name", "")
                    service_info["product"] = service_elem.get("product", "")
                    service_info["version"] = service_elem.get("version", "")
                    service_info["extrainfo"] = service_elem.get("extrainfo", "")

                result["services"].append(service_info)

    except Exception as e:
        log.error("nmap_xml_parse_error", error=str(e), path=xml_path)

    return result


def run_nmap(ip: str, scan_dir: str, scan_id: str, nmap_ports: str = "--top-ports 1000") -> dict[str, Any]:
    """Run nmap service/version scan against a host.

    Returns parsed results dict with open ports and services.
    """
    host_dir = f"{scan_dir}/hosts/{ip}"
    phase1_dir = f"{host_dir}/phase1"
    os.makedirs(phase1_dir, exist_ok=True)

    xml_path = f"{phase1_dir}/nmap.xml"
    txt_path = f"{phase1_dir}/nmap.txt"

    # Parse nmap_ports string into args (e.g. "--top-ports 100" -> ["--top-ports", "100"])
    nmap_port_args = nmap_ports.split()

    cmd = [
        "nmap", "-sV", "-sC", "-T4",
        *nmap_port_args,
        "-oX", xml_path,
        "-oN", txt_path,
        ip,
    ]

    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=300,
        output_path=xml_path,
        scan_id=scan_id,
        host_ip=ip,
        phase=1,
        tool_name="nmap",
    )

    if exit_code != 0:
        log.warning("nmap_failed", ip=ip, exit_code=exit_code)
        return {"open_ports": [], "services": []}

    return _parse_nmap_xml(xml_path)


def run_webtech(fqdn: str, host_dir: str, scan_id: str) -> dict[str, Any]:
    """Run webtech to detect web technologies.

    Captures stdout as JSON and saves to host_dir/phase1/webtech.json.
    Returns tech dict.
    """
    phase1_dir = f"{host_dir}/phase1"
    os.makedirs(phase1_dir, exist_ok=True)

    output_path = f"{phase1_dir}/webtech.json"

    cmd = ["webtech", "-u", f"https://{fqdn}", "--json"]

    # webtech outputs JSON to stdout; capture it via subprocess
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )

        if proc.stdout:
            tech_data = json.loads(proc.stdout)
            with open(output_path, "w") as f:
                json.dump(tech_data, f, indent=2)
            log.info("webtech_complete", fqdn=fqdn, techs=len(tech_data) if isinstance(tech_data, list) else 1)
            return tech_data
        else:
            log.warning("webtech_no_output", fqdn=fqdn)
            return {}

    except subprocess.TimeoutExpired:
        log.warning("webtech_timeout", fqdn=fqdn)
        return {}
    except json.JSONDecodeError as e:
        log.warning("webtech_json_error", fqdn=fqdn, error=str(e))
        return {}
    except Exception as e:
        log.error("webtech_error", fqdn=fqdn, error=str(e))
        return {}


def run_wafw00f(fqdn: str, ip: str, host_dir: str, scan_id: str) -> Optional[dict[str, Any]]:
    """Run wafw00f to detect WAF.

    Returns WAF info dict or None if no WAF detected.
    """
    phase1_dir = f"{host_dir}/phase1"
    os.makedirs(phase1_dir, exist_ok=True)

    output_path = f"{phase1_dir}/wafw00f.json"

    cmd = ["wafw00f", fqdn, "-o", output_path, "-f", "json"]

    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=30,
        output_path=output_path,
        scan_id=scan_id,
        host_ip=ip,
        phase=1,
        tool_name="wafw00f",
    )

    if exit_code != 0:
        log.warning("wafw00f_failed", fqdn=fqdn, exit_code=exit_code)
        return None

    try:
        with open(output_path, "r") as f:
            waf_data = json.load(f)

        # wafw00f JSON is typically a list of results
        if isinstance(waf_data, list) and len(waf_data) > 0:
            entry = waf_data[0]
            if entry.get("firewall") and entry["firewall"].lower() != "none":
                log.info("waf_detected", fqdn=fqdn, waf=entry["firewall"])
                return entry
            else:
                log.info("no_waf_detected", fqdn=fqdn)
                return None
        return None

    except (json.JSONDecodeError, FileNotFoundError) as e:
        log.warning("wafw00f_parse_error", fqdn=fqdn, error=str(e))
        return None


def build_tech_profile(
    ip: str,
    fqdns: list[str],
    nmap_result: dict[str, Any],
    webtech_result: dict[str, Any],
    wafw00f_result: Optional[dict[str, Any]],
    host_dir: str,
) -> dict[str, Any]:
    """Combine Phase 1 results into a unified tech profile.

    Saves tech_profile.json and returns the profile dict.
    """
    open_ports = nmap_result.get("open_ports", [])
    services = nmap_result.get("services", [])

    # Determine server from nmap services (HTTP/HTTPS)
    server = None
    for svc in services:
        if svc.get("name") in ("http", "https", "http-proxy"):
            product = svc.get("product", "")
            version = svc.get("version", "")
            if product:
                server = f"{product}/{version}".rstrip("/") if version else product
                break

    # Determine CMS and version from webtech
    cms = None
    cms_version = None
    if isinstance(webtech_result, dict):
        techs = webtech_result.get("tech", [])
    elif isinstance(webtech_result, list):
        techs = webtech_result
    else:
        techs = []

    cms_names = {"wordpress", "joomla", "drupal", "typo3", "magento", "shopify", "wix"}
    for tech in techs:
        if isinstance(tech, dict):
            name = tech.get("name", "").lower()
            if name in cms_names:
                cms = tech.get("name")
                cms_version = tech.get("version")
                break
        elif isinstance(tech, str):
            if tech.lower() in cms_names:
                cms = tech
                break

    # Determine WAF
    waf = None
    if wafw00f_result:
        waf = wafw00f_result.get("firewall")

    # Determine service flags from open ports
    has_ssl = 443 in open_ports
    if not has_ssl:
        for svc in services:
            if svc.get("name") in ("ssl", "https"):
                has_ssl = True
                break

    mail_ports = {25, 465, 587, 993, 995}
    mail_services = bool(mail_ports & set(open_ports))

    ftp_service = 21 in open_ports

    profile: dict[str, Any] = {
        "ip": ip,
        "fqdns": fqdns,
        "cms": cms,
        "cms_version": cms_version,
        "server": server,
        "waf": waf,
        "open_ports": sorted(open_ports),
        "mail_services": mail_services,
        "ftp_service": ftp_service,
        "has_ssl": has_ssl,
    }

    # Save to disk
    phase1_dir = f"{host_dir}/phase1"
    os.makedirs(phase1_dir, exist_ok=True)
    profile_path = f"{phase1_dir}/tech_profile.json"
    with open(profile_path, "w") as f:
        json.dump(profile, f, indent=2)

    log.info("tech_profile_built", ip=ip, open_ports=len(open_ports), has_ssl=has_ssl)
    return profile


def run_phase1(
    ip: str,
    fqdns: list[str],
    scan_dir: str,
    scan_id: str,
    progress_callback: Callable[[str, str, str], None],
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Orchestrate Phase 1 (technology detection) for a single host.

    Args:
        ip: Host IP address.
        fqdns: List of FQDNs resolving to this IP.
        scan_dir: Base scan directory (e.g. /tmp/scan-<scanId>).
        scan_id: Scan UUID.
        progress_callback: Called after each tool with (scan_id, tool_name, status).
        config: Package configuration dict (optional).

    Returns:
        Tech profile dict for this host.
    """
    nmap_ports = config["nmap_ports"] if config else "--top-ports 1000"

    host_dir = f"{scan_dir}/hosts/{ip}"
    phase1_dir = f"{host_dir}/phase1"
    os.makedirs(phase1_dir, exist_ok=True)

    log.info("phase1_start", ip=ip, fqdns=fqdns, scan_id=scan_id)

    # Run nmap
    nmap_result = run_nmap(ip, scan_dir, scan_id, nmap_ports)
    progress_callback(scan_id, "nmap", "complete")

    # Use first FQDN for web-based tools
    primary_fqdn = fqdns[0] if fqdns else ip

    # Run webtech
    webtech_result = run_webtech(primary_fqdn, host_dir, scan_id)
    progress_callback(scan_id, "webtech", "complete")

    # Run wafw00f
    wafw00f_result = run_wafw00f(primary_fqdn, ip, host_dir, scan_id)
    progress_callback(scan_id, "wafw00f", "complete")

    # Build combined tech profile
    tech_profile = build_tech_profile(
        ip=ip,
        fqdns=fqdns,
        nmap_result=nmap_result,
        webtech_result=webtech_result,
        wafw00f_result=wafw00f_result,
        host_dir=host_dir,
    )

    log.info("phase1_complete", ip=ip, scan_id=scan_id)
    return tech_profile
