"""Phase 2 — Deep scan per host."""

import json
import os
import signal
import subprocess
from typing import Any, Callable, Optional

import structlog

from scanner.progress import publish_tool_output
from scanner.tools import run_tool

log = structlog.get_logger()

SECURITY_HEADERS = [
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "content-security-policy",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
]


def run_testssl(fqdn: str, ip: str, host_dir: str, order_id: str) -> Optional[dict[str, Any]]:
    """Run testssl.sh to check TLS/SSL configuration.

    Only called when has_ssl=true. Returns parsed results or None on failure.
    """
    phase2_dir = f"{host_dir}/phase2"
    os.makedirs(phase2_dir, exist_ok=True)

    output_path = f"{phase2_dir}/testssl.json"

    cmd = [
        "bash", "/opt/testssl.sh/testssl.sh",
        "--jsonfile", output_path,
        "--quiet",
        "--ip", "one",
        "--warnings", "off",
        f"https://{fqdn}",
    ]

    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=300,
        output_path=output_path,
        order_id=order_id,
        host_ip=ip,
        phase=2,
        tool_name="testssl",
    )

    if exit_code not in (0, 1):
        # testssl returns 1 for findings, which is normal
        log.warning("testssl_failed", fqdn=fqdn, exit_code=exit_code)
        return None

    try:
        with open(output_path, "r") as f:
            data = json.load(f)
        log.info("testssl_complete", fqdn=fqdn, findings=len(data) if isinstance(data, list) else 1)
        return data
    except (json.JSONDecodeError, FileNotFoundError) as e:
        log.warning("testssl_parse_error", fqdn=fqdn, error=str(e))
        return None


def run_nikto(fqdn: str, ip: str, host_dir: str, order_id: str,
              adaptive_config: dict[str, Any] | None = None) -> Optional[dict[str, Any]]:
    """Run nikto web server scanner.

    Returns parsed results or None on failure.
    """
    phase2_dir = f"{host_dir}/phase2"
    os.makedirs(phase2_dir, exist_ok=True)

    output_path = f"{phase2_dir}/nikto.json"

    # AI-adaptive tuning
    tuning = "1234567890"
    if adaptive_config and adaptive_config.get("nikto_tuning"):
        tuning = adaptive_config["nikto_tuning"]
        log.info("nikto_adaptive_tuning", ip=ip, tuning=tuning)

    cmd = [
        "perl", "/opt/nikto/program/nikto.pl",
        "-h", fqdn,
        "-Format", "json",
        "-output", output_path,
        "-Tuning", tuning,
    ]

    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=600,
        output_path=output_path,
        order_id=order_id,
        host_ip=ip,
        phase=2,
        tool_name="nikto",
    )

    if exit_code != 0 and exit_code != 1:
        log.warning("nikto_failed", fqdn=fqdn, exit_code=exit_code)
        return None

    try:
        with open(output_path, "r") as f:
            data = json.load(f)
        log.info("nikto_complete", fqdn=fqdn)
        return data
    except (json.JSONDecodeError, FileNotFoundError) as e:
        log.warning("nikto_parse_error", fqdn=fqdn, error=str(e))
        return None


def run_nuclei(fqdn: str, ip: str, host_dir: str, order_id: str,
               adaptive_config: dict[str, Any] | None = None,
               timeout: int = 1500,
               severity: str = "low,medium,high,critical") -> list[dict[str, Any]]:
    """Run nuclei vulnerability scanner.

    Returns list of findings or empty list on failure.
    Nuclei writes JSONL incrementally — partial results are preserved on timeout.
    """
    phase2_dir = f"{host_dir}/phase2"
    os.makedirs(phase2_dir, exist_ok=True)

    output_path = f"{phase2_dir}/nuclei.json"

    cmd = [
        "nuclei",
        "-u", fqdn,
        "-severity", severity,
        "-jsonl",
        "-o", output_path,
        "-timeout", "5",           # Per-request timeout: 5s (default: 10)
        "-retries", "1",           # 1 retry (default: 1)
        "-no-interactsh",          # Skip out-of-band interaction checks (saves time)
        "-c", "25",                # Concurrency: 25 templates parallel
        "-rl", "150",              # Rate limit: 150 req/s
    ]

    # AI-adaptive: filter templates by technology tags
    if adaptive_config:
        tags = adaptive_config.get("nuclei_tags")
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
            log.info("nuclei_adaptive_tags", ip=ip, tags=tags)
        exclude_tags = adaptive_config.get("nuclei_exclude_tags")
        if exclude_tags:
            cmd.extend(["-exclude-tags", ",".join(exclude_tags)])
            log.info("nuclei_adaptive_exclude", ip=ip, exclude=exclude_tags)

    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=timeout,
        output_path=output_path,
        order_id=order_id,
        host_ip=ip,
        phase=2,
        tool_name="nuclei",
    )

    # exit 0/1 = success, -1 = timeout (partial results in output file)
    if exit_code not in (0, 1, -1):
        log.warning("nuclei_failed", fqdn=fqdn, exit_code=exit_code)
        return []

    if exit_code == -1:
        log.info("nuclei_timeout_partial", fqdn=fqdn, timeout=timeout,
                 msg="Reading partial results from output file")

    findings: list[dict[str, Any]] = []
    try:
        with open(output_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    findings.append(json.loads(line))
        log.info("nuclei_complete", fqdn=fqdn, findings=len(findings))
    except (json.JSONDecodeError, FileNotFoundError) as e:
        log.warning("nuclei_parse_error", fqdn=fqdn, error=str(e))

    return findings


WORDLIST_MAP = {
    "common": "/usr/share/wordlists/common.txt",
    "wordpress": "/usr/share/wordlists/wordpress.txt",
    "api": "/usr/share/wordlists/api-endpoints.txt",
    "cms": "/usr/share/wordlists/cms-common.txt",
}


def run_gobuster_dir(fqdn: str, ip: str, host_dir: str, order_id: str,
                     adaptive_config: dict[str, Any] | None = None) -> Optional[str]:
    """Run gobuster directory brute-force.

    Returns path to output file or None on failure.
    """
    phase2_dir = f"{host_dir}/phase2"
    os.makedirs(phase2_dir, exist_ok=True)

    output_path = f"{phase2_dir}/gobuster_dir.txt"

    # AI-adaptive wordlist selection
    wl_key = "common"
    if adaptive_config and adaptive_config.get("gobuster_wordlist"):
        wl_key = adaptive_config["gobuster_wordlist"]
    wordlist = WORDLIST_MAP.get(wl_key, WORDLIST_MAP["common"])
    # Fallback to common.txt if selected wordlist doesn't exist on disk
    if not os.path.isfile(wordlist):
        wordlist = WORDLIST_MAP["common"]
    if wl_key != "common":
        log.info("gobuster_adaptive_wordlist", ip=ip, wordlist=wl_key)

    cmd = [
        "gobuster", "dir",
        "-u", f"https://{fqdn}",
        "-w", wordlist,
        "-o", output_path,
        "-q",
    ]

    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=120,
        output_path=output_path,
        order_id=order_id,
        host_ip=ip,
        phase=2,
        tool_name="gobuster_dir",
    )

    if exit_code != 0:
        log.warning("gobuster_dir_failed", fqdn=fqdn, exit_code=exit_code)
        return None

    log.info("gobuster_dir_complete", fqdn=fqdn)
    return output_path


def run_gowitness(fqdn: str, ip: str, host_dir: str, order_id: str) -> Optional[str]:
    """Run gowitness to take a screenshot.

    Returns path to screenshot directory or None on failure.
    """
    phase2_dir = f"{host_dir}/phase2"
    os.makedirs(phase2_dir, exist_ok=True)

    chrome_path = os.environ.get("CHROME_PATH", "/usr/bin/chromium")
    cmd = [
        "gowitness", "scan", "single",
        "-u", f"https://{fqdn}",
        "--screenshot-path", f"{phase2_dir}/",
        "--chrome-path", chrome_path,
        "--chrome-arg=--no-sandbox",
        "--chrome-arg=--disable-gpu",
        "--chrome-arg=--disable-dev-shm-usage",
    ]

    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=30,
        output_path=None,
        order_id=order_id,
        host_ip=ip,
        phase=2,
        tool_name="gowitness",
    )

    if exit_code != 0:
        log.warning("gowitness_failed", fqdn=fqdn, exit_code=exit_code)
        return None

    log.info("gowitness_complete", fqdn=fqdn)
    return phase2_dir


def run_header_check(fqdn: str, ip: str, host_dir: str, order_id: str) -> dict[str, Any]:
    """Check HTTP security headers using curl.

    Evaluates presence of key security headers and produces a score.
    Saves analysis to {host_dir}/phase2/headers.json.
    Returns the analysis dict.
    """
    phase2_dir = f"{host_dir}/phase2"
    os.makedirs(phase2_dir, exist_ok=True)

    output_path = f"{phase2_dir}/headers.json"
    url = f"https://{fqdn}"

    cmd = ["curl", "-sI", url]

    # Capture stdout directly for header parsing — use Popen with process group
    raw_headers = ""
    curl_proc = None
    try:
        curl_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        raw_headers, _ = curl_proc.communicate(timeout=10)
        log.info("header_check_fetched", fqdn=fqdn, exit_code=curl_proc.returncode)
    except subprocess.TimeoutExpired:
        log.warning("header_check_timeout", fqdn=fqdn)
        if curl_proc is not None:
            try:
                os.killpg(curl_proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                curl_proc.kill()
            curl_proc.wait()
    except Exception as e:
        log.error("header_check_error", fqdn=fqdn, error=str(e))

    # Parse headers into dict
    headers: dict[str, str] = {}
    for line in raw_headers.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip()] = value.strip()

    # Evaluate security headers
    security_headers: dict[str, dict[str, Any]] = {}
    present_count = 0

    for header_name in SECURITY_HEADERS:
        # Find header case-insensitively
        value = None
        for k, v in headers.items():
            if k.lower() == header_name:
                value = v
                break

        present = value is not None
        if present:
            present_count += 1

        security_headers[header_name] = {
            "present": present,
            "value": value,
        }

    total = len(SECURITY_HEADERS)
    score = f"{present_count}/{total}"

    analysis: dict[str, Any] = {
        "url": url,
        "headers": headers,
        "security_headers": security_headers,
        "score": score,
    }

    # Save to disk
    try:
        with open(output_path, "w") as f:
            json.dump(analysis, f, indent=2)
    except Exception as e:
        log.error("header_check_save_error", fqdn=fqdn, error=str(e))

    log.info("header_check_complete", fqdn=fqdn, score=score)
    return analysis


def run_httpx(fqdn: str, ip: str, host_dir: str, order_id: str) -> Optional[dict[str, Any]]:
    """Run httpx for HTTP probing and technology detection."""
    phase2_dir = f"{host_dir}/phase2"
    os.makedirs(phase2_dir, exist_ok=True)
    output_path = f"{phase2_dir}/httpx.json"

    cmd = [
        "httpx",
        "-u", fqdn,
        "-json",
        "-o", output_path,
        "-status-code",
        "-title",
        "-tech-detect",
        "-server",
        "-content-length",
        "-follow-redirects",
        "-silent",
    ]

    exit_code, duration_ms = run_tool(
        cmd=cmd, timeout=60, output_path=output_path,
        order_id=order_id, host_ip=ip, phase=2, tool_name="httpx",
    )

    if exit_code != 0:
        log.warning("httpx_failed", fqdn=fqdn, exit_code=exit_code)
        return None

    try:
        results = []
        with open(output_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    results.append(json.loads(line))
        log.info("httpx_complete", fqdn=fqdn, results=len(results))
        return results[0] if results else None
    except (json.JSONDecodeError, FileNotFoundError) as e:
        log.warning("httpx_parse_error", fqdn=fqdn, error=str(e))
        return None


def run_katana(fqdn: str, ip: str, host_dir: str, order_id: str) -> list[str]:
    """Run katana web crawler to discover endpoints."""
    phase2_dir = f"{host_dir}/phase2"
    os.makedirs(phase2_dir, exist_ok=True)
    output_path = f"{phase2_dir}/katana.txt"

    cmd = [
        "katana",
        "-u", f"https://{fqdn}",
        "-o", output_path,
        "-depth", "3",
        "-jsluice",
        "-known-files", "all",
        "-silent",
    ]

    exit_code, duration_ms = run_tool(
        cmd=cmd, timeout=300, output_path=output_path,
        order_id=order_id, host_ip=ip, phase=2, tool_name="katana",
    )

    if exit_code != 0:
        log.warning("katana_failed", fqdn=fqdn, exit_code=exit_code)
        return []

    try:
        with open(output_path, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
        log.info("katana_complete", fqdn=fqdn, urls_found=len(urls))
        return urls
    except FileNotFoundError:
        return []


def run_wpscan(fqdn: str, ip: str, host_dir: str, order_id: str) -> Optional[dict[str, Any]]:
    """Run WPScan WordPress vulnerability scanner.

    Only called when CMS is detected as WordPress.
    """
    phase2_dir = f"{host_dir}/phase2"
    os.makedirs(phase2_dir, exist_ok=True)
    output_path = f"{phase2_dir}/wpscan.json"

    api_token = os.environ.get("WPSCAN_API_TOKEN", "")

    cmd = [
        "wpscan",
        "--url", f"https://{fqdn}",
        "--format", "json",
        "--output", output_path,
        "--enumerate", "vp,vt,u1-5",  # vulnerable plugins, themes, users
        "--random-user-agent",
        "--no-banner",
    ]
    if api_token:
        cmd.extend(["--api-token", api_token])

    exit_code, duration_ms = run_tool(
        cmd=cmd, timeout=600, output_path=output_path,
        order_id=order_id, host_ip=ip, phase=2, tool_name="wpscan",
    )

    # WPScan returns various exit codes: 0=ok, 5=vulnerabilities found
    if exit_code not in (0, 5):
        log.warning("wpscan_failed", fqdn=fqdn, exit_code=exit_code)
        return None

    try:
        with open(output_path, "r") as f:
            data = json.load(f)
        vuln_count = len(data.get("interesting_findings", []))
        plugins = len(data.get("plugins", {}))
        log.info("wpscan_complete", fqdn=fqdn, vulns=vuln_count, plugins=plugins)
        return data
    except (json.JSONDecodeError, FileNotFoundError) as e:
        log.warning("wpscan_parse_error", fqdn=fqdn, error=str(e))
        return None


def run_phase2(
    ip: str,
    fqdns: list[str],
    tech_profile: dict[str, Any],
    scan_dir: str,
    order_id: str,
    progress_callback: Callable[[str, str, str], None],
    config: dict[str, Any] | None = None,
    adaptive_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Orchestrate Phase 2 (deep scan) for a single host.

    Args:
        ip: Host IP address.
        fqdns: List of FQDNs resolving to this IP.
        tech_profile: Tech profile from Phase 1.
        scan_dir: Base scan directory (e.g. /tmp/scan-<orderId>).
        order_id: Order UUID.
        progress_callback: Called after each tool with (order_id, tool_name, status).
        config: Package configuration dict (optional).

    Returns:
        Results summary dict.
    """
    phase2_tools = None
    if config:
        phase2_tools = config.get("phase2_tools")

    # AI-adaptive skip list
    ai_skip = set(adaptive_config.get("skip_tools", [])) if adaptive_config else set()

    host_dir = f"{scan_dir}/hosts/{ip}"
    phase2_dir = f"{host_dir}/phase2"
    os.makedirs(phase2_dir, exist_ok=True)

    # fqdns list is already sorted by relevance from phase0 (base domain first)
    primary_fqdn = fqdns[0] if fqdns else ip
    has_ssl = tech_profile.get("has_ssl", False)

    log.info("phase2_start", ip=ip, fqdn=primary_fqdn, order_id=order_id, has_ssl=has_ssl,
             ai_skip=list(ai_skip) if ai_skip else None)

    results: dict[str, Any] = {
        "ip": ip,
        "fqdn": primary_fqdn,
        "tools_run": [],
    }

    # testssl (only if SSL present and in package)
    if has_ssl and (phase2_tools is None or "testssl" in phase2_tools):
        testssl_result = run_testssl(primary_fqdn, ip, host_dir, order_id)
        results["testssl"] = testssl_result
        results["tools_run"].append("testssl")
        progress_callback(order_id, "testssl", "complete")
        # Publish tool output summary
        if testssl_result:
            count = len(testssl_result) if isinstance(testssl_result, list) else 1
            publish_tool_output(order_id, "testssl", ip, f"{count} SSL/TLS checks completed")
        else:
            publish_tool_output(order_id, "testssl", ip, "No SSL findings")
    else:
        if not has_ssl:
            log.info("testssl_skipped", ip=ip, reason="no_ssl")
        else:
            log.info("testssl_skipped", ip=ip, reason="not_in_package")

    # nikto
    if (phase2_tools is None or "nikto" in phase2_tools) and "nikto" not in ai_skip:
        nikto_result = run_nikto(primary_fqdn, ip, host_dir, order_id, adaptive_config=adaptive_config)
        results["nikto"] = nikto_result
        results["tools_run"].append("nikto")
        progress_callback(order_id, "nikto", "complete")
        if nikto_result:
            items = nikto_result.get("vulnerabilities", []) if isinstance(nikto_result, dict) else []
            publish_tool_output(order_id, "nikto", ip, f"{len(items)} items found")
        else:
            publish_tool_output(order_id, "nikto", ip, "No findings")
    else:
        log.info("nikto_skipped", ip=ip, reason="not_in_package")

    # nuclei
    if (phase2_tools is None or "nuclei" in phase2_tools) and "nuclei" not in ai_skip:
        # Basic: 10 min, high/critical only. Pro/NIS2: 25 min, all severities.
        is_basic = config.get("package") == "basic"
        nuclei_timeout = 600 if is_basic else 1500
        nuclei_severity = "high,critical" if is_basic else "low,medium,high,critical"
        nuclei_result = run_nuclei(primary_fqdn, ip, host_dir, order_id,
                                   adaptive_config=adaptive_config,
                                   timeout=nuclei_timeout,
                                   severity=nuclei_severity)
        results["nuclei"] = nuclei_result
        results["tools_run"].append("nuclei")
        progress_callback(order_id, "nuclei", "complete")
        if nuclei_result:
            severities = {}
            for f in nuclei_result:
                sev = f.get("info", {}).get("severity", "unknown")
                severities[sev] = severities.get(sev, 0) + 1
            parts = [f"{v} {k}" for k, v in sorted(severities.items())]
            publish_tool_output(order_id, "nuclei", ip, f"{len(nuclei_result)} findings ({', '.join(parts)})")
        else:
            publish_tool_output(order_id, "nuclei", ip, "No vulnerabilities found")
    else:
        log.info("nuclei_skipped", ip=ip, reason="not_in_package")

    # gobuster dir
    if (phase2_tools is None or "gobuster_dir" in phase2_tools) and "gobuster_dir" not in ai_skip:
        gobuster_result = run_gobuster_dir(primary_fqdn, ip, host_dir, order_id, adaptive_config=adaptive_config)
        results["gobuster_dir"] = gobuster_result
        results["tools_run"].append("gobuster_dir")
        progress_callback(order_id, "gobuster_dir", "complete")
        if gobuster_result:
            try:
                with open(gobuster_result, "r") as _f:
                    line_count = sum(1 for _ in _f)
                publish_tool_output(order_id, "gobuster_dir", ip, f"{line_count} paths discovered")
            except Exception:
                publish_tool_output(order_id, "gobuster_dir", ip, "Directory scan complete")
        else:
            publish_tool_output(order_id, "gobuster_dir", ip, "No paths found")
    else:
        log.info("gobuster_dir_skipped", ip=ip, reason="not_in_package")

    # gowitness
    if (phase2_tools is None or "gowitness" in phase2_tools) and "gowitness" not in ai_skip:
        gowitness_result = run_gowitness(primary_fqdn, ip, host_dir, order_id)
        results["gowitness"] = gowitness_result
        results["tools_run"].append("gowitness")
        progress_callback(order_id, "gowitness", "complete")
        if gowitness_result:
            publish_tool_output(order_id, "gowitness", ip, "Screenshot captured")
        else:
            publish_tool_output(order_id, "gowitness", ip, "Screenshot failed")
    else:
        log.info("gowitness_skipped", ip=ip, reason="not_in_package")

    # header check
    if phase2_tools is None or "headers" in phase2_tools:
        header_result = run_header_check(primary_fqdn, ip, host_dir, order_id)
        results["headers"] = header_result
        results["tools_run"].append("header_check")
        progress_callback(order_id, "header_check", "complete")
        if header_result:
            score = header_result.get("score", "?/?")
            publish_tool_output(order_id, "header_check", ip, f"Security headers: {score}")
        else:
            publish_tool_output(order_id, "header_check", ip, "Header check failed")
    else:
        log.info("headers_skipped", ip=ip, reason="not_in_package")

    # httpx — HTTP probing
    if phase2_tools is None or "httpx" in phase2_tools:
        httpx_result = run_httpx(primary_fqdn, ip, host_dir, order_id)
        results["httpx"] = httpx_result
        results["tools_run"].append("httpx")
        progress_callback(order_id, "httpx", "complete")
        if httpx_result:
            status_code = httpx_result.get("status_code", "?")
            title = (httpx_result.get("title", "") or "")[:40]
            techs = httpx_result.get("tech", [])
            tech_str = f", {len(techs)} technologies" if techs else ""
            publish_tool_output(order_id, "httpx", ip, f"HTTP {status_code} {title}{tech_str}")
        else:
            publish_tool_output(order_id, "httpx", ip, "HTTP probe failed")
    else:
        log.info("httpx_skipped", ip=ip, reason="not_in_package")

    # katana — web crawler
    if (phase2_tools is None or "katana" in phase2_tools) and "katana" not in ai_skip:
        katana_result = run_katana(primary_fqdn, ip, host_dir, order_id)
        results["katana"] = katana_result
        results["tools_run"].append("katana")
        progress_callback(order_id, "katana", "complete")
        if katana_result:
            publish_tool_output(order_id, "katana", ip, f"{len(katana_result)} URLs crawled")
        else:
            publish_tool_output(order_id, "katana", ip, "No URLs discovered")
    else:
        log.info("katana_skipped", ip=ip, reason="not_in_package")

    # wpscan — CMS-adaptive: only if WordPress detected
    cms = tech_profile.get("cms", "")
    if (phase2_tools is None or "wpscan" in phase2_tools) and cms and cms.lower() == "wordpress":
        wpscan_result = run_wpscan(primary_fqdn, ip, host_dir, order_id)
        results["wpscan"] = wpscan_result
        results["tools_run"].append("wpscan")
        progress_callback(order_id, "wpscan", "complete")
        if wpscan_result:
            vulns = len(wpscan_result.get("interesting_findings", []))
            plugins = len(wpscan_result.get("plugins", {}))
            publish_tool_output(order_id, "wpscan", ip, f"{vulns} findings, {plugins} plugins")
        else:
            publish_tool_output(order_id, "wpscan", ip, "WPScan failed")
    elif cms and cms.lower() != "wordpress":
        log.info("wpscan_skipped", ip=ip, reason=f"cms_is_{cms}")
    else:
        log.info("wpscan_skipped", ip=ip, reason="no_cms_or_not_in_package")

    log.info("phase2_complete", ip=ip, order_id=order_id, tools_run=len(results["tools_run"]))
    return results
