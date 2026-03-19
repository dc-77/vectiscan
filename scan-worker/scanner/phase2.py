"""Phase 2 — Deep scan per host."""

import json
import os
import signal
import subprocess
from typing import Any, Callable, Optional

import structlog

from scanner.progress import publish_event, publish_tool_output
from scanner.tools import run_tool, _save_result

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
        "--sneaky",              # less traces in target logs
        "--hints",               # additional remediation hints for report
        "--severity", "LOW",     # filter out pure INFO noise from JSON
        "--nodns", "min",        # minimal DNS (we already have it from Phase 0)
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
        timeout=180,
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

# SecLists paths for ffuf (installed from SecLists in Dockerfile)
SECLISTS_DIR = "/usr/share/wordlists/seclists"
FFUF_WORDLISTS = {
    "dir": f"{SECLISTS_DIR}/Discovery/Web-Content/common.txt",
    "vhost": f"{SECLISTS_DIR}/Discovery/DNS/subdomains-top1million-5000.txt",
    "param": f"{SECLISTS_DIR}/Discovery/Web-Content/burp-parameter-names.txt",
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
    # gowitness 3.x: chrome flags via environment, not --chrome-arg
    os.environ["CHROMIUM_FLAGS"] = "--no-sandbox --disable-gpu --disable-dev-shm-usage"
    cmd = [
        "gowitness", "scan", "single",
        "-u", f"https://{fqdn}",
        "--screenshot-path", f"{phase2_dir}/",
        "--chrome-path", chrome_path,
    ]

    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=45,
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
        "--ignore-main-redirect",      # follow redirects (e.g. www → non-www)
        "--disable-tls-checks",        # handle self-signed certs
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


def run_ffuf(fqdn: str, ip: str, host_dir: str, order_id: str,
             adaptive_config: dict[str, Any] | None = None,
             domain: str = "",
             katana_urls: list[str] | None = None) -> Optional[list[dict[str, Any]]]:
    """Run ffuf web fuzzer in AI-selected mode (dir, vhost, or param).

    Returns list of findings or None on failure.
    """
    phase2_dir = f"{host_dir}/phase2"
    os.makedirs(phase2_dir, exist_ok=True)

    # Determine mode from AI config (default: dir)
    mode = "dir"
    if adaptive_config:
        mode = adaptive_config.get("ffuf_mode", "dir")

    output_path = f"{phase2_dir}/ffuf_{mode}.json"

    if mode == "dir":
        # Directory/file discovery with extensions
        extensions = ".php,.html,.js,.bak"
        if adaptive_config and adaptive_config.get("ffuf_extensions"):
            # Cap at 4 extensions to keep runtime within timeout
            ext_list = adaptive_config["ffuf_extensions"].split(",")[:4]
            extensions = ",".join(ext_list)

        wordlist = FFUF_WORDLISTS.get("dir", WORDLIST_MAP["common"])
        if not os.path.isfile(wordlist):
            wordlist = WORDLIST_MAP["common"]

        cmd = [
            "ffuf",
            "-u", f"https://{fqdn}/FUZZ",
            "-w", wordlist,
            "-e", extensions,
            "-mc", "200,301,302,403",
            "-fc", "404",
            "-t", "40",
            "-rate", "100",
            "-timeout", "5",
            "-json",
            "-o", output_path,
            "-s",  # silent (no banner)
        ]

    elif mode == "vhost":
        # Virtual host discovery
        wordlist = FFUF_WORDLISTS.get("vhost", WORDLIST_MAP["common"])
        if not os.path.isfile(wordlist):
            log.warning("ffuf_vhost_wordlist_missing", path=wordlist)
            return None

        target_domain = domain or fqdn
        cmd = [
            "ffuf",
            "-u", f"https://{ip}/",
            "-H", f"Host: FUZZ.{target_domain}",
            "-w", wordlist,
            "-mc", "200,301,302",
            "-json",
            "-o", output_path,
            "-t", "40",
            "-rate", "100",
            "-timeout", "5",
            "-s",
        ]

    elif mode == "param":
        # Parameter discovery on katana endpoints
        if not katana_urls:
            log.info("ffuf_param_skipped", ip=ip, reason="no_katana_urls")
            return None

        # Pick first URL with query string or first URL
        target_url = None
        for u in katana_urls:
            if "?" in u:
                # Use the base URL part
                target_url = u.split("?")[0]
                break
        if not target_url:
            target_url = katana_urls[0] if katana_urls else f"https://{fqdn}/"

        wordlist = FFUF_WORDLISTS.get("param", WORDLIST_MAP["common"])
        if not os.path.isfile(wordlist):
            log.warning("ffuf_param_wordlist_missing", path=wordlist)
            return None

        cmd = [
            "ffuf",
            "-u", f"{target_url}?FUZZ=test",
            "-w", wordlist,
            "-mc", "200",
            "-json",
            "-o", output_path,
            "-t", "40",
            "-rate", "100",
            "-timeout", "5",
            "-s",
        ]
    else:
        log.warning("ffuf_unknown_mode", mode=mode)
        return None

    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=180,
        output_path=output_path,
        order_id=order_id,
        host_ip=ip,
        phase=2,
        tool_name=f"ffuf_{mode}",
    )

    if exit_code not in (0, 1, -1):
        log.warning("ffuf_failed", fqdn=fqdn, mode=mode, exit_code=exit_code)
        return None

    try:
        with open(output_path, "r") as f:
            data = json.load(f)
        results = data.get("results", []) if isinstance(data, dict) else data
        log.info("ffuf_complete", fqdn=fqdn, mode=mode, findings=len(results))
        return results
    except (json.JSONDecodeError, FileNotFoundError) as e:
        log.warning("ffuf_parse_error", fqdn=fqdn, mode=mode, error=str(e))
        return None


def run_feroxbuster(fqdn: str, ip: str, host_dir: str, order_id: str,
                    adaptive_config: dict[str, Any] | None = None,
                    known_paths: set[str] | None = None) -> Optional[list[dict[str, Any]]]:
    """Run feroxbuster for recursive directory brute-force.

    Args:
        known_paths: Paths already found by gobuster/ffuf — used for dedup.

    Returns list of findings or None on failure.
    """
    phase2_dir = f"{host_dir}/phase2"
    os.makedirs(phase2_dir, exist_ok=True)

    output_path = f"{phase2_dir}/feroxbuster.json"

    # AI-controlled recursion depth (default: 2)
    depth = 2
    if adaptive_config and adaptive_config.get("feroxbuster_depth"):
        depth = min(int(adaptive_config["feroxbuster_depth"]), 4)

    wordlist = WORDLIST_MAP["common"]
    if not os.path.isfile(wordlist):
        log.warning("feroxbuster_wordlist_missing", path=wordlist)
        return None

    cmd = [
        "feroxbuster",
        "-u", f"https://{fqdn}",
        "-w", wordlist,
        "-d", str(depth),
        "-t", "30",
        "--rate-limit", "100",
        "-s", "200,301,302,403",
        "--json",
        "-o", output_path,
        "--dont-scan", "logout|signout|delete",
        "--timeout", "5",
        "--no-recursion",
        "--silent",
    ]

    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=120,
        output_path=output_path,
        order_id=order_id,
        host_ip=ip,
        phase=2,
        tool_name="feroxbuster",
    )

    if exit_code not in (0, 1, -1):
        log.warning("feroxbuster_failed", fqdn=fqdn, exit_code=exit_code)
        return None

    # Parse JSONL output (feroxbuster writes one JSON object per line)
    findings: list[dict[str, Any]] = []
    dedup_count = 0
    try:
        with open(output_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # Dedup against gobuster/ffuf known paths
                path = entry.get("url", "")
                if known_paths and path:
                    # Extract path from URL
                    from urllib.parse import urlparse
                    parsed_path = urlparse(path).path
                    if parsed_path in known_paths:
                        dedup_count += 1
                        continue
                findings.append(entry)

        log.info("feroxbuster_complete", fqdn=fqdn, findings=len(findings),
                 dedup_removed=dedup_count, depth=depth)
    except FileNotFoundError:
        log.warning("feroxbuster_no_output", fqdn=fqdn)
        return None

    return findings if findings else None


def run_dalfox(fqdn: str, ip: str, host_dir: str, order_id: str,
               katana_urls: list[str] | None = None) -> Optional[list[dict[str, Any]]]:
    """Run dalfox XSS scanner on URLs with parameters discovered by katana.

    Only runs if katana found URLs with query parameters.
    Returns list of XSS findings or None.
    """
    phase2_dir = f"{host_dir}/phase2"
    os.makedirs(phase2_dir, exist_ok=True)

    if not katana_urls:
        log.info("dalfox_skipped", ip=ip, reason="no_katana_urls")
        return None

    # Filter only URLs with meaningful parameters (skip asset versioning)
    NOISE_PARAMS = {"ver", "v", "format", "type", "css", "js"}
    param_urls: list[str] = []
    for u in katana_urls:
        if "?" not in u:
            continue
        # Skip URLs where the only params are noise (e.g. ?ver=6.4.2)
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(u).query)
        meaningful = [k for k in qs if k.lower() not in NOISE_PARAMS]
        if meaningful:
            param_urls.append(u)

    if not param_urls:
        log.info("dalfox_skipped", ip=ip, reason="no_urls_with_meaningful_params",
                 total_param_urls=sum(1 for u in katana_urls if "?" in u))
        return None

    # Write URLs to a temp file for piping into dalfox
    urls_file = f"{phase2_dir}/dalfox_input.txt"
    with open(urls_file, "w") as f:
        for url in param_urls[:30]:  # Cap at 30 URLs (was 100, caused timeouts)
            f.write(url + "\n")
    log.info("dalfox_input", ip=ip, meaningful_urls=len(param_urls),
             capped_to=min(len(param_urls), 30))

    output_path = f"{phase2_dir}/dalfox.json"

    cmd = [
        "dalfox", "file", urls_file,
        "--silence",
        "--no-color",
        "--format", "json",
        "-o", output_path,
        "--timeout", "5",
        "--delay", "100",
        "--skip-bav",  # Skip Blind XSS (too invasive for automated scanner)
    ]

    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=300,
        output_path=output_path,
        order_id=order_id,
        host_ip=ip,
        phase=2,
        tool_name="dalfox",
    )

    if exit_code not in (0, 1, -1):
        log.warning("dalfox_failed", fqdn=fqdn, exit_code=exit_code)
        return None

    # Parse JSONL output
    findings: list[dict[str, Any]] = []
    try:
        with open(output_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        log.info("dalfox_complete", fqdn=fqdn, findings=len(findings),
                 input_urls=len(param_urls))
    except FileNotFoundError:
        log.warning("dalfox_no_output", fqdn=fqdn)
        return None

    return findings if findings else None


def _extract_paths_from_gobuster(output_path: str) -> set[str]:
    """Extract discovered paths from gobuster output for dedup."""
    paths: set[str] = set()
    try:
        with open(output_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    # gobuster dir output format: /path (Status: 200) [Size: 1234]
                    parts = line.split()
                    if parts:
                        paths.add(parts[0])
    except (FileNotFoundError, Exception):
        pass
    return paths


def _extract_paths_from_ffuf(results: list[dict[str, Any]] | None) -> set[str]:
    """Extract discovered paths from ffuf results for dedup."""
    paths: set[str] = set()
    if not results:
        return paths
    for r in results:
        url = r.get("url", "") or r.get("input", {}).get("FUZZ", "")
        if url:
            from urllib.parse import urlparse
            paths.add(urlparse(url).path)
    return paths


def run_zap_scan(
    fqdn: str,
    ip: str,
    host_dir: str,
    order_id: str,
    adaptive_config: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
    progress_callback: Callable[[str, str, str], None] | None = None,
) -> dict[str, Any]:
    """Run OWASP ZAP scan sequence for a single host.

    Sequence: Spider → [AJAX Spider] → [Forced Browse] → [Active Scan].
    Passive Scanner runs automatically on all traffic.

    Returns dict with: alerts, findings, spider_urls, tools_run, duration_ms.
    """
    import re
    import time as _time

    from scanner.tools.zap_client import ZapClient, ZapError
    from scanner.tools.zap_mapper import ZapAlertMapper

    zap = ZapClient()
    result: dict[str, Any] = {
        "alerts": [],
        "findings": [],
        "spider_urls": [],
        "tools_run": [],
        "duration_ms": 0,
    }
    start_ms = int(_time.monotonic() * 1000)

    # Health check
    if not zap.health_check():
        log.warning("zap_daemon_unavailable", ip=ip, fqdn=fqdn)
        publish_tool_output(order_id, "zap", ip, "ZAP daemon unavailable, skipping")
        return result

    ac = adaptive_config or {}
    phase2_dir = f"{host_dir}/phase2"
    context_name = f"ctx-{order_id[:8]}-{ip.replace('.', '_')}"
    policy_name = f"policy-{order_id[:8]}-{ip.replace('.', '_')}"
    target_url = f"https://{fqdn}"
    context_id: int | None = None
    ai_skip = set(ac.get("skip_tools", []))

    try:
        # 1. Create isolated context
        context_id = zap.create_context(context_name)
        zap.include_in_context(context_name, f".*{re.escape(fqdn)}.*")

        # 2. Configure rate limiting (WAF-adaptive)
        zap.configure_rate_limit(
            req_per_sec=ac.get("zap_rate_req_per_sec", 80),
            threads=ac.get("zap_threads", 5),
            delay_ms=ac.get("zap_spider_delay_ms", 0),
        )

        # 3. Traditional Spider
        publish_event(order_id, {"type": "tool_starting", "tool": "zap_spider", "host": ip})
        spider_start = int(_time.monotonic() * 1000)
        spider_depth = ac.get("zap_spider_max_depth", 5)
        spider_id = zap.start_spider(target_url, context_name=context_name, max_depth=spider_depth)
        zap.poll_until_complete(
            lambda: zap.spider_status(spider_id),
            timeout=180, interval=5, stop_value=100,
            order_id=order_id, tool_name="zap_spider",
        )
        spider_urls = zap.spider_results(spider_id)
        spider_duration = int(_time.monotonic() * 1000) - spider_start
        result["spider_urls"] = spider_urls
        result["tools_run"].append("zap_spider")
        publish_tool_output(order_id, "zap_spider", ip, f"{len(spider_urls)} URLs discovered")
        _save_result(order_id, ip, 2, "zap_spider",
                     json.dumps({"urls_found": len(spider_urls), "depth": spider_depth,
                                 "urls": spider_urls[:50]}, indent=2),
                     0, spider_duration)
        if progress_callback:
            progress_callback(order_id, "zap_spider", "complete")

        # 4. AJAX Spider (conditional on SPA detection)
        ajax_enabled = ac.get("zap_ajax_spider_enabled", False)
        if ajax_enabled and "zap_ajax_spider" not in ai_skip:
            publish_event(order_id, {"type": "tool_starting", "tool": "zap_ajax_spider", "host": ip})
            ajax_start = int(_time.monotonic() * 1000)
            zap.start_ajax_spider(target_url, context_name=context_name)
            completed = zap.poll_until_complete(
                lambda: 100 if zap.ajax_spider_status() == "stopped" else 50,
                timeout=240, interval=10, stop_value=100,
                order_id=order_id, tool_name="zap_ajax_spider",
            )
            if not completed:
                zap.stop_ajax_spider()
            ajax_duration = int(_time.monotonic() * 1000) - ajax_start
            result["tools_run"].append("zap_ajax_spider")
            publish_tool_output(order_id, "zap_ajax_spider", ip, "AJAX crawl complete")
            _save_result(order_id, ip, 2, "zap_ajax_spider",
                         json.dumps({"status": "complete" if completed else "timeout",
                                     "duration_ms": ajax_duration}),
                         0, ajax_duration)
            if progress_callback:
                progress_callback(order_id, "zap_ajax_spider", "complete")

        # 5. Active Scan (package-dependent: not for webcheck/passive-only)
        scan_policy = ac.get("zap_scan_policy", "standard")
        is_webcheck = (config or {}).get("package") in ("basic", "webcheck")
        phase2_tools = (config or {}).get("phase2_tools", [])
        run_active = (not is_webcheck and scan_policy != "passive-only"
                      and "zap_active" in phase2_tools)
        if run_active:
            publish_event(order_id, {"type": "tool_starting", "tool": "zap_active", "host": ip})
            active_start = int(_time.monotonic() * 1000)
            categories = ac.get("zap_active_categories", ["sqli", "xss", "lfi", "ssrf", "cmdi"])
            zap.create_scan_policy(policy_name, categories, scan_policy)

            scan_id = zap.start_active_scan(target_url, context_id=context_id, scan_policy=policy_name)
            completed = zap.poll_until_complete(
                lambda: zap.active_scan_status(scan_id),
                timeout=600, interval=10, stop_value=100,
                order_id=order_id, tool_name="zap_active",
            )
            if not completed:
                zap.stop_active_scan(scan_id)
            active_duration = int(_time.monotonic() * 1000) - active_start
            result["tools_run"].append("zap_active")
            publish_tool_output(order_id, "zap_active", ip, "Active scan complete")
            # Save active scan results to DB (alerts collected later)
            _save_result(order_id, ip, 2, "zap_active",
                         json.dumps({"status": "complete" if completed else "timeout",
                                     "policy": scan_policy, "categories": categories,
                                     "duration_ms": active_duration}),
                         0, active_duration)
            if progress_callback:
                progress_callback(order_id, "zap_active", "complete")

        # 6b. Wait for passive scanner to finish processing queued items
        log.info("zap_waiting_for_passive", ip=ip)
        zap.wait_for_passive_scan(timeout=30)

        # 7. Collect all alerts (no baseurl filter — context isolation is sufficient)
        all_alerts = zap.get_alerts()
        log.info("zap_alerts_collected", ip=ip, fqdn=fqdn, count=len(all_alerts))
        result["alerts"] = all_alerts

        # 8. Map to Finding dicts
        mapper = ZapAlertMapper()
        findings = mapper.map_alerts(all_alerts, ip, fqdn)
        result["findings"] = findings

        # Save alerts to disk
        alerts_path = f"{phase2_dir}/zap_alerts.json"
        with open(alerts_path, "w") as f:
            json.dump(all_alerts, f, indent=2)

        passive_count = sum(1 for fd in findings if fd.get("tool") == "zap_passive")
        active_count = len(findings) - passive_count
        publish_tool_output(order_id, "zap", ip,
                            f"{len(all_alerts)} alerts ({passive_count} passive, {active_count} active)")

    except ZapError as e:
        log.error("zap_scan_failed", fqdn=fqdn, ip=ip, error=str(e))
        publish_tool_output(order_id, "zap", ip, f"ZAP error: {e}")
    finally:
        # Always clean up context and policy
        try:
            zap.remove_context(context_name)
        except Exception:
            pass
        try:
            zap.remove_scan_policy(policy_name)
        except Exception:
            pass

    result["duration_ms"] = int(_time.monotonic() * 1000) - start_ms

    # Save to DB
    raw_summary = json.dumps(result["alerts"][:50], indent=2)[:50000] if result["alerts"] else "[]"
    _save_result(
        order_id=order_id, host_ip=ip, phase=2,
        tool_name="zap", raw_output=raw_summary,
        exit_code=0, duration_ms=result["duration_ms"],
    )

    return result


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

    # Never skip tools on the base domain — it's the most important target
    domain = config.get("domain", "") if config else ""
    if domain:
        domain_lower = domain.lower()
        fqdns_lower = [f.lower() for f in fqdns]
        if domain_lower in fqdns_lower or f"www.{domain_lower}" in fqdns_lower:
            if ai_skip:
                log.info("ai_skip_overridden_base_domain", ip=ip, fqdn=primary_fqdn,
                         original_skip=list(ai_skip))
                ai_skip = set()  # Override: full scan on base domain
    has_ssl = tech_profile.get("has_ssl", False)
    has_web = tech_profile.get("has_web", True)  # default True for safety

    log.info("phase2_start", ip=ip, fqdn=primary_fqdn, order_id=order_id,
             has_ssl=has_ssl, has_web=has_web,
             ai_skip=list(ai_skip) if ai_skip else None)

    results: dict[str, Any] = {
        "ip": ip,
        "fqdn": primary_fqdn,
        "tools_run": [],
    }

    # ── Parallel Tool Groups ─────────────────────────────────
    # Since ZAP integration, all active phase2 tools are independent.
    # Run testssl, ZAP, nuclei, and quick tools (gowitness/headers/httpx/wpscan)
    # in parallel to reduce per-host scan time.
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _run_testssl_group() -> dict[str, Any]:
        """Run testssl (SSL/TLS audit)."""
        r: dict[str, Any] = {}
        if has_ssl and (phase2_tools is None or "testssl" in phase2_tools):
            publish_event(order_id, {"type": "tool_starting", "tool": "testssl", "host": ip})
            testssl_result = run_testssl(primary_fqdn, ip, host_dir, order_id)
            r["testssl"] = testssl_result
            r["_tools"] = ["testssl"]
            progress_callback(order_id, "testssl", "complete")
            if testssl_result:
                count = len(testssl_result) if isinstance(testssl_result, list) else 1
                publish_tool_output(order_id, "testssl", ip, f"{count} SSL/TLS checks completed")
            else:
                publish_tool_output(order_id, "testssl", ip, "No SSL findings")
        return r

    def _run_zap_group() -> dict[str, Any]:
        """Run ZAP scan (spider + ajax + active)."""
        r: dict[str, Any] = {}
        if has_web and (phase2_tools is None or any(
            t in (phase2_tools or []) for t in ("zap_spider", "zap_passive", "zap_active")
        )):
            zap_result = run_zap_scan(
                primary_fqdn, ip, host_dir, order_id,
                adaptive_config=adaptive_config,
                config=config,
                progress_callback=progress_callback,
            )
            r["zap_alerts"] = zap_result.get("alerts", [])
            r["zap_findings"] = zap_result.get("findings", [])
            r["zap_spider_urls"] = zap_result.get("spider_urls", [])
            r["_tools"] = zap_result.get("tools_run", [])
        return r

    def _run_nuclei_group() -> dict[str, Any]:
        """Run nuclei (CVE + default-login scanning)."""
        r: dict[str, Any] = {}
        if (phase2_tools is None or "nuclei" in phase2_tools) and "nuclei" not in ai_skip and has_web:
            publish_event(order_id, {"type": "tool_starting", "tool": "nuclei", "host": ip})
            nuclei_config = dict(adaptive_config) if adaptive_config else {}
            tags = list(nuclei_config.get("nuclei_tags", []))
            # Only auto-add "default-login". "cve" tag removed — matches 3000+ templates
            # causing timeouts. Tech-specific tags (wordpress, nginx, etc.) already cover CVEs.
            if "default-login" not in tags:
                tags.append("default-login")
            nuclei_config["nuclei_tags"] = tags
            exclude = list(nuclei_config.get("nuclei_exclude_tags", []))
            # Keep misconfig+exposure in nuclei until ZAP active scanner is verified working
            nuclei_config["nuclei_exclude_tags"] = exclude
            is_wc = config.get("package") in ("basic", "webcheck")
            nuclei_timeout = 600 if is_wc else 600
            nuclei_severity = config.get("nuclei_severity", "high,critical" if is_wc else "low,medium,high,critical")
            nuclei_result = run_nuclei(primary_fqdn, ip, host_dir, order_id,
                                       adaptive_config=nuclei_config,
                                       timeout=nuclei_timeout,
                                       severity=nuclei_severity)
            r["nuclei"] = nuclei_result
            r["_tools"] = ["nuclei"]
            progress_callback(order_id, "nuclei", "complete")
            if nuclei_result:
                severities: dict[str, int] = {}
                for f in nuclei_result:
                    sev = f.get("info", {}).get("severity", "unknown")
                    severities[sev] = severities.get(sev, 0) + 1
                parts = [f"{v} {k}" for k, v in sorted(severities.items())]
                publish_tool_output(order_id, "nuclei", ip, f"{len(nuclei_result)} findings ({', '.join(parts)})")
            else:
                publish_tool_output(order_id, "nuclei", ip, "No vulnerabilities found")
        return r

    def _run_quick_tools() -> dict[str, Any]:
        """Run fast tools: gowitness, header_check, httpx, wpscan."""
        r: dict[str, Any] = {"_tools": []}

        # gowitness
        if (phase2_tools is None or "gowitness" in phase2_tools) and "gowitness" not in ai_skip:
            publish_event(order_id, {"type": "tool_starting", "tool": "gowitness", "host": ip})
            gowitness_result = run_gowitness(primary_fqdn, ip, host_dir, order_id)
            r["gowitness"] = gowitness_result
            r["_tools"].append("gowitness")
            progress_callback(order_id, "gowitness", "complete")
            if gowitness_result:
                publish_tool_output(order_id, "gowitness", ip, "Screenshot captured")
            else:
                publish_tool_output(order_id, "gowitness", ip, "Screenshot failed")

        # header_check
        if phase2_tools is None or "headers" in phase2_tools:
            publish_event(order_id, {"type": "tool_starting", "tool": "header_check", "host": ip})
            header_result = run_header_check(primary_fqdn, ip, host_dir, order_id)
            r["headers"] = header_result
            r["_tools"].append("header_check")
            progress_callback(order_id, "header_check", "complete")
            if header_result:
                score = header_result.get("score", "?/?")
                publish_tool_output(order_id, "header_check", ip, f"Security headers: {score}")
            else:
                publish_tool_output(order_id, "header_check", ip, "Header check failed")

        # httpx
        if phase2_tools is None or "httpx" in phase2_tools:
            publish_event(order_id, {"type": "tool_starting", "tool": "httpx", "host": ip})
            httpx_result = run_httpx(primary_fqdn, ip, host_dir, order_id)
            r["httpx"] = httpx_result
            r["_tools"].append("httpx")
            progress_callback(order_id, "httpx", "complete")
            if httpx_result:
                status_code = httpx_result.get("status_code", "?")
                title = (httpx_result.get("title", "") or "")[:40]
                techs = httpx_result.get("tech", [])
                tech_str = f", {len(techs)} technologies" if techs else ""
                publish_tool_output(order_id, "httpx", ip, f"HTTP {status_code} {title}{tech_str}")
            else:
                publish_tool_output(order_id, "httpx", ip, "HTTP probe failed")

        # wpscan (conditional on WordPress)
        cms = tech_profile.get("cms", "")
        if (phase2_tools is None or "wpscan" in phase2_tools) and cms and cms.lower() == "wordpress":
            publish_event(order_id, {"type": "tool_starting", "tool": "wpscan", "host": ip})
            wpscan_result = run_wpscan(primary_fqdn, ip, host_dir, order_id)
            r["wpscan"] = wpscan_result
            r["_tools"].append("wpscan")
            progress_callback(order_id, "wpscan", "complete")
            if wpscan_result:
                vulns = len(wpscan_result.get("interesting_findings", []))
                plugins = len(wpscan_result.get("plugins", {}))
                publish_tool_output(order_id, "wpscan", ip, f"{vulns} findings, {plugins} plugins")
            else:
                publish_tool_output(order_id, "wpscan", ip, "WPScan failed")

        return r

    # Launch all 4 groups in parallel
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="phase2t") as pool:
        group_futures = {
            pool.submit(_run_testssl_group): "testssl",
            pool.submit(_run_zap_group): "zap",
            pool.submit(_run_nuclei_group): "nuclei",
            pool.submit(_run_quick_tools): "quick",
        }

        for future in as_completed(group_futures):
            group_name = group_futures[future]
            try:
                group_result = future.result()
                # Merge results (except _tools key)
                tools = group_result.pop("_tools", [])
                results.update(group_result)
                results["tools_run"].extend(tools)
            except Exception as e:
                log.error("phase2_group_failed", group=group_name, ip=ip, error=str(e))

    # ── Legacy tools (kept for rollback, not in phase2_tools) ──
    # nikto, nuclei, testssl, gowitness, headers, httpx, wpscan now run
    # in parallel tool groups above. Only gobuster/ffuf/feroxbuster/katana/dalfox
    # remain here as dead legacy code (not in phase2_tools since ZAP integration).

    # gobuster dir (web-only)
    gobuster_output_path: Optional[str] = None
    if (phase2_tools is None or "gobuster_dir" in phase2_tools) and "gobuster_dir" not in ai_skip and has_web:
        publish_event(order_id, {"type": "tool_starting", "tool": "gobuster_dir", "host": ip})
        gobuster_result = run_gobuster_dir(primary_fqdn, ip, host_dir, order_id, adaptive_config=adaptive_config)
        results["gobuster_dir"] = gobuster_result
        gobuster_output_path = gobuster_result
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

    # ffuf — web fuzzer (Perimeter+ only, web-only)
    ffuf_result: Optional[list[dict[str, Any]]] = None
    if (phase2_tools is not None and "ffuf" in phase2_tools) and "ffuf" not in ai_skip and has_web:
        ffuf_mode = adaptive_config.get("ffuf_mode", "dir") if adaptive_config else "dir"
        publish_event(order_id, {"type": "tool_starting", "tool": f"ffuf_{ffuf_mode}", "host": ip})
        ffuf_result = run_ffuf(
            primary_fqdn, ip, host_dir, order_id,
            adaptive_config=adaptive_config,
            domain=domain,
        )
        results["ffuf"] = ffuf_result
        results["tools_run"].append("ffuf")
        progress_callback(order_id, "ffuf", "complete")
        if ffuf_result:
            mode = adaptive_config.get("ffuf_mode", "dir") if adaptive_config else "dir"
            publish_tool_output(order_id, "ffuf", ip, f"{len(ffuf_result)} results ({mode} mode)")
        else:
            publish_tool_output(order_id, "ffuf", ip, "No results")
    else:
        log.info("ffuf_skipped", ip=ip, reason="not_in_package_or_ai_skip")

    # feroxbuster — recursive directory brute-force (Perimeter+ only, web-only)
    # Dependency: runs after gobuster/ffuf, deduplicates known paths
    if (phase2_tools is not None and "feroxbuster" in phase2_tools) and "feroxbuster" not in ai_skip and has_web:
        ferox_enabled = True
        if adaptive_config and adaptive_config.get("feroxbuster_enabled") is False:
            ferox_enabled = False
            log.info("feroxbuster_skipped", ip=ip, reason="ai_disabled")

        if ferox_enabled:
            publish_event(order_id, {"type": "tool_starting", "tool": "feroxbuster", "host": ip})
            # Collect known paths from gobuster + ffuf for dedup
            known_paths: set[str] = set()
            if gobuster_output_path:
                known_paths.update(_extract_paths_from_gobuster(gobuster_output_path))
            if ffuf_result:
                known_paths.update(_extract_paths_from_ffuf(ffuf_result))

            ferox_result = run_feroxbuster(
                primary_fqdn, ip, host_dir, order_id,
                adaptive_config=adaptive_config,
                known_paths=known_paths if known_paths else None,
            )
            results["feroxbuster"] = ferox_result
            results["tools_run"].append("feroxbuster")
            progress_callback(order_id, "feroxbuster", "complete")
            if ferox_result:
                publish_tool_output(order_id, "feroxbuster", ip,
                                    f"{len(ferox_result)} paths (recursive, dedup applied)")
            else:
                publish_tool_output(order_id, "feroxbuster", ip, "No new paths found")
    else:
        log.info("feroxbuster_skipped", ip=ip, reason="not_in_package")

    # katana — web crawler (web-only, before dalfox which depends on katana URLs)
    katana_result: list[str] = []
    if (phase2_tools is None or "katana" in phase2_tools) and "katana" not in ai_skip and has_web:
        publish_event(order_id, {"type": "tool_starting", "tool": "katana", "host": ip})
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

    # dalfox — XSS scanner (Perimeter+ only, web-only)
    # Dependency: needs katana URLs with parameters
    if (phase2_tools is not None and "dalfox" in phase2_tools) and "dalfox" not in ai_skip and has_web:
        dalfox_enabled = True
        if adaptive_config and adaptive_config.get("dalfox_enabled") is False:
            dalfox_enabled = False
            log.info("dalfox_skipped", ip=ip, reason="ai_disabled")

        if dalfox_enabled:
            publish_event(order_id, {"type": "tool_starting", "tool": "dalfox", "host": ip})
            dalfox_result = run_dalfox(
                primary_fqdn, ip, host_dir, order_id,
                katana_urls=katana_result if katana_result else None,
            )
            results["dalfox"] = dalfox_result
            results["tools_run"].append("dalfox")
            progress_callback(order_id, "dalfox", "complete")
            if dalfox_result:
                publish_tool_output(order_id, "dalfox", ip, f"{len(dalfox_result)} XSS findings")
            else:
                publish_tool_output(order_id, "dalfox", ip, "No XSS vulnerabilities found")
    else:
        log.info("dalfox_skipped", ip=ip, reason="not_in_package")

    # gowitness, headers, httpx, wpscan — now in _run_quick_tools() above

    log.info("phase2_complete", ip=ip, order_id=order_id, tools_run=len(results["tools_run"]))
    return results
