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


def _waf_detected(tech_profile: dict[str, Any] | None) -> bool:
    """True wenn Phase 1 einen WAF erkannt hat.

    wafw00f schreibt den Treffer in tech_profile["waf"] (Liste oder str).
    Spaetere Layer koennen ``waf_detected`` setzen — wir pruefen beides.
    """
    if not tech_profile:
        return False
    if tech_profile.get("waf_detected"):
        return True
    waf = tech_profile.get("waf")
    if isinstance(waf, str):
        return bool(waf.strip())
    if isinstance(waf, list):
        return any(w for w in waf if w)
    return bool(waf)


def should_parallelize_stage2(
    adaptive_config: dict[str, Any] | None,
    tech_profile: dict[str, Any] | None,
) -> bool:
    """Entscheidet, ob Stage 2 (ZAP Active + ffuf/ferox/wpscan) parallel laeuft.

    Sequenziell bei WAF, bei AI-Policy ``waf-safe`` oder wenn der
    PHASE2_STAGE2_WAF_SAFE-Kill-Switch deaktiviert ist (dann immer parallel).
    Default der Env-Variable: ``true`` (defensiv).
    """
    flag = os.getenv("PHASE2_STAGE2_WAF_SAFE", "true").lower() == "true"
    if not flag:
        return True
    if adaptive_config and adaptive_config.get("zap_scan_policy") == "waf-safe":
        return False
    if _waf_detected(tech_profile):
        return False
    return True


def _run_testssl_once(fqdn: str, ip: str, output_path: str, order_id: str,
                      severity: str = "MEDIUM", tool_name: str = "testssl",
                      fast_mode: bool = False) -> Optional[list]:
    """Run a single testssl pass. Returns parsed JSON list or None.

    `fast_mode=True` (WebCheck-Paket): nutzt `--fast` (skip schwere
    Cipher-Tests) — bei Schnellscans ausreichend.
    """
    cmd = [
        "bash", "/opt/testssl.sh/testssl.sh",
        "--jsonfile", output_path,
        "--quiet",
        "--ip", "one",
        "--warnings", "off",
        "--sneaky",
        "--hints",
        # Connect-Timeout: bei langsamen Servern sonst Default 30s pro
        # Cipher-Test → kann 5+ Min Scan kosten.
        "--connect-timeout", "10",
        "--openssl-timeout", "10",
        # OCSP-Stapling-Check kostet 5-10s pro Host und bringt selten
        # neue Findings; in Compliance-Tiefenscan trotzdem drin lassen.
    ]
    if fast_mode:
        cmd.extend([
            "--fast",  # skip CSV/JSON-output overhead per cipher
            "-p",      # nur Protocols (kein Cipher-Walk)
            "-S",      # nur Server-Defaults
            "-h",      # nur Header-Check
        ])
    # Omit --severity to get ALL entries (incl. OK/INFO) for TR-03116-4
    if severity:
        cmd.extend(["--severity", severity])
    cmd.extend([
        "--nodns", "min",
        f"https://{fqdn}",
    ])

    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=300,
        output_path=output_path,
        order_id=order_id,
        host_ip=ip,
        phase=2,
        tool_name=tool_name,
    )

    if exit_code not in (0, 1):
        return None

    try:
        with open(output_path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return None


def run_testssl(fqdn: str, ip: str, host_dir: str, order_id: str,
                severity: str = "MEDIUM",
                fast_mode: bool = False) -> Optional[list]:
    """Run testssl.sh and return parsed JSON findings.

    `fast_mode` aktiviert `--fast`-Pfad fuer WebCheck-Paket
    (skip schwere Cipher-Walks, ~3x schneller).

    Single-pass execution — the previous double-verification strategy was
    removed because results were consistently identical in production.
    """
    phase2_dir = f"{host_dir}/phase2"
    os.makedirs(phase2_dir, exist_ok=True)

    output_path = f"{phase2_dir}/testssl.json"
    return _run_testssl_once(fqdn, ip, output_path, order_id,
                              severity=severity, tool_name="testssl",
                              fast_mode=fast_mode)


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
        # Default 10 threads = sehr langsam → 50
        "-t", "50",
        # Default-Extensions: PHP/Backup/Static → findet `.bak`-Files,
        # vergessene `.old`-Backups, `.zip`-Releases.
        "-x", "php,bak,txt,old,zip,html",
        # Status-Codes: 200/301/302 als Treffer; 403 NICHT (zu viel Noise
        # bei modernen WAFs, die alles auf 403 mappen).
        "-s", "200,301,302,307",
        # `-b ""` deaktiviert die `-s`-Negation (default 404,403);
        # wir wollen explizit nur `-s` kontrollieren.
        "-b", "404",
        # Timeout pro Request — bei langsamem Backend sonst Haenger
        "--timeout", "10s",
        # Kein Banner spammen
        "--no-error",
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

    # Strategie: erst HEAD (billig). Wenn der Server Security-Header
    # nur bei GET liefert (manche Apache-Setups, viele SPA-Backends),
    # GET-Fallback. Header werden bei beiden ueber `-D -` gesammelt.
    head_cmd = [
        "curl", "-sI",
        "--max-time", "10",
        "--retry", "1",
        "-A", "Mozilla/5.0 vectiscan",
        url,
    ]
    get_cmd = [
        "curl", "-s",
        "-X", "GET",
        "-D", "-",        # dump headers to stdout
        "-o", "/dev/null", # body weg
        "--max-time", "10",
        "--retry", "1",
        "-L",             # follow redirects
        "-A", "Mozilla/5.0 vectiscan",
        url,
    ]

    def _fetch(cmd_to_run: list[str]) -> str:
        proc = None
        try:
            proc = subprocess.Popen(
                cmd_to_run, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, start_new_session=True,
            )
            out, _ = proc.communicate(timeout=15)
            return out or ""
        except subprocess.TimeoutExpired:
            if proc is not None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    proc.kill()
                proc.wait()
            return ""
        except Exception:
            return ""

    raw_headers = _fetch(head_cmd)
    log.info("header_check_fetched", fqdn=fqdn, method="HEAD", bytes=len(raw_headers))
    # Wenn HEAD weniger als 2 Header (= leeres oder nur Status-Line)
    # liefert, GET-Fallback. Anti-WAF: einige WAFs blocken HEAD,
    # lassen aber GET durch.
    if raw_headers.count(":") < 2:
        raw_headers = _fetch(get_cmd)
        log.info("header_check_fallback_get", fqdn=fqdn, bytes=len(raw_headers))

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
        # Meta-refresh-follow zusaetzlich zu HTTP-Redirects (SPA/CMS-Wartung)
        "-fr",
        # Web-Server-Header + IP + ASN-Info — billig zu sammeln, gut fuer KI
        "-ip",
        "-cdn",
        "-asn",
        "-tls-grab",
        # Methods + Probe-Path-Set
        "-method",
        # Bei Packet-Loss/transient-Fehler 1 Retry — sonst false-negative
        "-retries", "1",
        # Festes Timeout pro Probe
        "-timeout", "10",
        # User-Agent festlegen damit WAF nicht "python-requests" blockt
        "-H", "User-Agent: Mozilla/5.0 vectiscan",
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
        "--disable-tls-checks",        # handle self-signed certs
        # Rate-Limit: 200ms zwischen Requests = 5 req/s. Live-Kunden-
        # Sites koennen sonst kurzzeitig in Rate-Limit-Trigger laufen.
        "--throttle", "200",
        # Request-Timeout pro HTTP-Call (sonst Default 60s)
        "--request-timeout", "30",
        # Max Threads: 5 statt Default 5 (explizit fuer Determinismus)
        "--max-threads", "5",
        # `--detection-mode mixed` (Default) — passive zuerst, aggressive nur wo noetig
        "--detection-mode", "mixed",
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
            # 403 als Treffer war zu noisy bei modernen WAFs (CloudFlare
            # mappt alles auf 403). 200/301/302/307 reichen.
            "-mc", "200,301,302,307",
            "-fc", "404,403",
            # 40 Threads × 100 RPS = effektiv 100 RPS — Live-Sites
            # werden bei 50 RPS schonender behandelt.
            "-t", "30",
            "-rate", "50",
            "-timeout", "5",
            # `-recursion -recursion-depth 1` findet Subverzeichnisse
            "-recursion",
            "-recursion-depth", "1",
            # `-ac` autocalibrate filter (filtert false-positive Bursts
            # wenn Server alles auf 200 mappt — sehr haeufig bei SPAs)
            "-ac",
            # User-Agent setzen
            "-H", "User-Agent: Mozilla/5.0 vectiscan",
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
            "-H", "User-Agent: Mozilla/5.0 vectiscan",
            "-w", wordlist,
            "-mc", "200,301,302,307",
            "-json",
            "-o", output_path,
            "-t", "30",
            "-rate", "50",
            "-timeout", "5",
            "-ac",  # autocalibrate
            "-s",
        ]

    elif mode == "param":
        # Parameter discovery on spider-discovered endpoints
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
            "-H", "User-Agent: Mozilla/5.0 vectiscan",
            "-json",
            "-o", output_path,
            "-t", "30",
            "-rate", "50",
            "-timeout", "5",
            "-ac",
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
        depth = min(int(adaptive_config["feroxbuster_depth"]), 2)

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
        # `--auto-tune` passt rate-limit dynamisch an Server-Last an —
        # wichtig fuer Live-Sites; festes Limit konnte sonst 5xx ausloesen.
        "--auto-tune",
        # `-s` (status-codes als Whitelist) und `--filter-status` (Blacklist)
        # sind in feroxbuster mutually exclusive. Wir nehmen die Whitelist
        # (200/301/302/307) — 403/404 sind dann implizit ausgeschlossen.
        "-s", "200,301,302,307",
        # Filter sehr kleine Responses (typische "not found"-Pages 0-100b)
        "--filter-size", "0,1,2,3",
        "--json",
        "-o", output_path,
        "--dont-scan", "logout|signout|delete",
        "--timeout", "5",
        # `--no-recursion` zusammen mit `-d` ist redundant; `-d` bereits
        # Tiefen-Limit. `--no-recursion` entfernt — `-d` steuert.
        # User-Agent festlegen
        "-H", "User-Agent: Mozilla/5.0 vectiscan",
        # `-q` quiet, `--silent` = noch leiser
        "--silent",
    ]

    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=150,
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

        # 7. Collect alerts + domain filter (defense in depth)
        all_alerts_raw = zap.get_alerts()
        all_alerts = [a for a in all_alerts_raw
                      if fqdn.lower() in (a.get("url", "") or "").lower()]
        log.info("zap_alerts_collected", ip=ip, fqdn=fqdn,
                 raw=len(all_alerts_raw), filtered=len(all_alerts))
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

    # ══════════════════════════════════════════════════════════
    # 3-STAGE PIPELINE: Discovery → Deep Scan → Collect
    # Stage 1 runs ZAP Spider + independent tools in parallel.
    # Stage 2 uses Spider URLs to feed ffuf, feroxbuster, wpscan.
    # Stage 3 collects ZAP passive alerts after all scanning completes.
    # ══════════════════════════════════════════════════════════
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from urllib.parse import urlparse as _urlparse

    zap_in_tools = phase2_tools is None or any(
        t in (phase2_tools or []) for t in ("zap_spider", "zap_passive", "zap_active")
    )
    cms = tech_profile.get("cms", "")

    # ── Stage 1: Discovery (parallel) ─────────────────────────
    # ZAP Spider discovers URLs, testssl/headers/httpx run independently.

    def _run_zap_discovery() -> dict[str, Any]:
        """ZAP Spider on ALL FQDNs (not just primary). No active scan yet."""
        import re as _re
        import time as _time
        from scanner.tools.zap_client import ZapClient, ZapError
        r: dict[str, Any] = {"zap_spider_urls": [], "_tools": []}
        if not (has_web and zap_in_tools):
            return r

        zap = ZapClient()
        if not zap.health_check():
            log.warning("zap_daemon_unavailable", ip=ip)
            return r

        ac = adaptive_config or {}
        all_spider_urls: list[str] = []
        context_name = f"ctx-{order_id[:8]}-{ip.replace('.', '_')}"

        try:
            context_id = zap.create_context(context_name)
            # Include ALL FQDNs in context scope
            for fqdn_item in fqdns[:5]:
                zap.include_in_context(context_name, f".*{_re.escape(fqdn_item)}.*")

            zap.configure_rate_limit(
                req_per_sec=ac.get("zap_rate_req_per_sec", 80),
                threads=ac.get("zap_threads", 5),
                delay_ms=ac.get("zap_spider_delay_ms", 0),
            )

            # Spider each FQDN
            spider_depth = ac.get("zap_spider_max_depth", 5)
            for fqdn_item in fqdns[:5]:
                publish_event(order_id, {"type": "tool_starting", "tool": "zap_spider", "host": ip})
                spider_start = int(_time.monotonic() * 1000)
                spider_id = zap.start_spider(f"https://{fqdn_item}", context_name=context_name,
                                             max_depth=spider_depth)
                zap.poll_until_complete(
                    lambda: zap.spider_status(spider_id),
                    timeout=120, interval=5, stop_value=100,
                    order_id=order_id, tool_name="zap_spider",
                )
                urls = zap.spider_results(spider_id)
                spider_duration = int(_time.monotonic() * 1000) - spider_start
                all_spider_urls.extend(urls)
                log.info("zap_spider_fqdn_complete", fqdn=fqdn_item, urls=len(urls),
                         duration_ms=spider_duration)

            # AJAX Spider (conditional on SPA)
            if ac.get("zap_ajax_spider_enabled") and "zap_ajax_spider" not in set(ac.get("skip_tools", [])):
                publish_event(order_id, {"type": "tool_starting", "tool": "zap_ajax_spider", "host": ip})
                zap.start_ajax_spider(f"https://{primary_fqdn}", context_name=context_name)
                completed = zap.poll_until_complete(
                    lambda: 100 if zap.ajax_spider_status() == "stopped" else 50,
                    timeout=240, interval=10, stop_value=100,
                    order_id=order_id, tool_name="zap_ajax_spider",
                )
                if not completed:
                    zap.stop_ajax_spider()
                r["_tools"].append("zap_ajax_spider")

            unique_urls = sorted(set(all_spider_urls))
            r["zap_spider_urls"] = unique_urls
            r["_tools"].append("zap_spider")
            r["_zap_context"] = context_name
            r["_zap_context_id"] = context_id

            # Save spider results to DB
            _save_result(order_id, ip, 2, "zap_spider",
                         json.dumps({"urls_found": len(unique_urls), "fqdns_spidered": len(fqdns[:5]),
                                     "urls": unique_urls[:50]}, indent=2),
                         0, 0)
            publish_tool_output(order_id, "zap_spider", ip,
                                f"{len(unique_urls)} URLs from {len(fqdns[:5])} FQDNs")
            progress_callback(order_id, "zap_spider", "complete")

        except ZapError as e:
            log.error("zap_discovery_failed", ip=ip, error=str(e))
        # Note: DON'T clean up context here — Stage 2 needs it for active scan

        return r

    def _run_testssl_group() -> dict[str, Any]:
        r: dict[str, Any] = {}
        if has_ssl and (phase2_tools is None or "testssl" in phase2_tools):
            publish_event(order_id, {"type": "tool_starting", "tool": "testssl", "host": ip})
            testssl_sev = (config or {}).get("testssl_severity", "MEDIUM")
            # WebCheck = Schnellscan → fast_mode aktivieren.
            testssl_fast = (config or {}).get("package", "") in ("webcheck", "basic")
            testssl_result = run_testssl(primary_fqdn, ip, host_dir, order_id,
                                         severity=testssl_sev,
                                         fast_mode=testssl_fast)
            r["testssl"] = testssl_result
            r["_tools"] = ["testssl"]
            progress_callback(order_id, "testssl", "complete")
            if testssl_result:
                count = len(testssl_result) if isinstance(testssl_result, list) else 1
                publish_tool_output(order_id, "testssl", ip, f"{count} SSL/TLS checks completed")
            else:
                publish_tool_output(order_id, "testssl", ip, "No SSL findings")
        return r

    def _run_quick_tools_stage1() -> dict[str, Any]:
        """Fast independent tools: header_check, httpx.

        Each tool is isolated so a failure in one doesn't lose results from the other.
        """
        r: dict[str, Any] = {"_tools": []}
        if phase2_tools is None or "headers" in phase2_tools:
            try:
                publish_event(order_id, {"type": "tool_starting", "tool": "header_check", "host": ip})
                header_result = run_header_check(primary_fqdn, ip, host_dir, order_id)
                r["headers"] = header_result
                r["_tools"].append("header_check")
                progress_callback(order_id, "header_check", "complete")
                score = header_result.get("score", "?/?") if header_result else "failed"
                publish_tool_output(order_id, "header_check", ip, f"Security headers: {score}")
                _save_result(order_id, ip, 2, "header_check",
                             json.dumps(header_result, indent=2, ensure_ascii=False),
                             0, 0)
            except Exception as e:
                log.error("header_check_failed", fqdn=primary_fqdn, ip=ip, error=str(e))
        if phase2_tools is None or "httpx" in phase2_tools:
            try:
                publish_event(order_id, {"type": "tool_starting", "tool": "httpx", "host": ip})
                httpx_result = run_httpx(primary_fqdn, ip, host_dir, order_id)
                r["httpx"] = httpx_result
                r["_tools"].append("httpx")
                progress_callback(order_id, "httpx", "complete")
                if httpx_result:
                    publish_tool_output(order_id, "httpx", ip,
                                        f"HTTP {httpx_result.get('status_code', '?')}")
                else:
                    publish_tool_output(order_id, "httpx", ip, "HTTP probe failed")
            except Exception as e:
                log.error("httpx_failed", fqdn=primary_fqdn, ip=ip, error=str(e))
        return r

    log.info("phase2_stage1_start", ip=ip, tools="testssl+zap_spider+quick")
    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="p2s1") as pool:
        s1_futures = {
            pool.submit(_run_testssl_group): "testssl",
            pool.submit(_run_zap_discovery): "zap_discovery",
            pool.submit(_run_quick_tools_stage1): "quick",
        }
        for future in as_completed(s1_futures):
            group_name = s1_futures[future]
            try:
                group_result = future.result()
                tools = group_result.pop("_tools", [])
                # Keep internal keys (_zap_context etc.) but don't add to tools_run
                for k, v in group_result.items():
                    if not k.startswith("_"):
                        results[k] = v
                    else:
                        results[k] = v  # Keep internal state for Stage 2
                results["tools_run"].extend(tools)
            except Exception as e:
                log.error("phase2_stage1_failed", group=group_name, ip=ip, error=str(e))

    # Extract Spider URLs for Stage 2
    spider_urls = results.get("zap_spider_urls", [])
    zap_context = results.pop("_zap_context", None)
    zap_context_id = results.pop("_zap_context_id", None)
    log.info("phase2_stage1_complete", ip=ip, spider_urls=len(spider_urls))

    # ── Stage 2: Deep Scan (parallel, Spider URLs as input) ───
    # ZAP Active, ffuf, feroxbuster, wpscan — all receive spider URLs

    def _run_zap_active_stage2() -> dict[str, Any]:
        """ZAP Active Scan using the context from Stage 1."""
        import time as _time
        from scanner.tools.zap_client import ZapClient, ZapError
        from scanner.tools.zap_mapper import ZapAlertMapper
        r: dict[str, Any] = {"_tools": []}

        ac = adaptive_config or {}
        scan_policy = ac.get("zap_scan_policy", "standard")
        is_webcheck = (config or {}).get("package") in ("basic", "webcheck")
        run_active = (not is_webcheck and scan_policy != "passive-only"
                      and (phase2_tools is None or "zap_active" in (phase2_tools or [])))

        if not run_active or not zap_context:
            return r

        zap = ZapClient()
        policy_name = f"policy-{order_id[:8]}-{ip.replace('.', '_')}"

        try:
            publish_event(order_id, {"type": "tool_starting", "tool": "zap_active", "host": ip})
            active_start = int(_time.monotonic() * 1000)
            categories = ac.get("zap_active_categories", ["sqli", "xss", "lfi", "ssrf", "cmdi"])
            zap.create_scan_policy(policy_name, categories, scan_policy)

            target_url = f"https://{primary_fqdn}"
            scan_id = zap.start_active_scan(target_url, context_id=zap_context_id,
                                            scan_policy=policy_name)
            completed = zap.poll_until_complete(
                lambda: zap.active_scan_status(scan_id),
                timeout=600, interval=10, stop_value=100,
                order_id=order_id, tool_name="zap_active",
            )
            if not completed:
                zap.stop_active_scan(scan_id)

            active_duration = int(_time.monotonic() * 1000) - active_start
            r["_tools"].append("zap_active")
            _save_result(order_id, ip, 2, "zap_active",
                         json.dumps({"status": "complete" if completed else "timeout",
                                     "policy": scan_policy, "categories": categories,
                                     "duration_ms": active_duration}),
                         0, active_duration)
            publish_tool_output(order_id, "zap_active", ip, "Active scan complete")
            progress_callback(order_id, "zap_active", "complete")
        except ZapError as e:
            log.error("zap_active_failed", ip=ip, error=str(e))
        finally:
            try:
                zap.remove_scan_policy(policy_name)
            except Exception:
                pass
        return r

    def _run_deep_scan_extras() -> dict[str, Any]:
        """Run ffuf param, feroxbuster, wpscan with Spider URLs."""
        r: dict[str, Any] = {"_tools": []}

        # ffuf param: parameter discovery on API-like URLs
        api_urls = [u for u in spider_urls if "?" not in u and
                    any(p in u for p in ("/api/", "/graphql", "/rest/", "/v1/", "/v2/"))]
        if api_urls and (phase2_tools is not None and "ffuf" in phase2_tools) and "ffuf" not in ai_skip and has_web:
            publish_event(order_id, {"type": "tool_starting", "tool": "ffuf", "host": ip})
            ffuf_config = dict(adaptive_config) if adaptive_config else {}
            ffuf_config["ffuf_mode"] = "param"
            ffuf_result = run_ffuf(primary_fqdn, ip, host_dir, order_id,
                                    adaptive_config=ffuf_config,
                                    katana_urls=api_urls[:20])
            r["ffuf"] = ffuf_result
            r["_tools"].append("ffuf")
            progress_callback(order_id, "ffuf", "complete")
            if ffuf_result:
                publish_tool_output(order_id, "ffuf", ip, f"{len(ffuf_result)} params discovered")
            else:
                publish_tool_output(order_id, "ffuf", ip, "No parameters found")

        # feroxbuster: recursive directory scan, spider URLs as dedup
        if (phase2_tools is not None and "feroxbuster" in phase2_tools) and "feroxbuster" not in ai_skip and has_web:
            ferox_enabled = True
            if adaptive_config and adaptive_config.get("feroxbuster_enabled") is False:
                ferox_enabled = False
            if ferox_enabled:
                publish_event(order_id, {"type": "tool_starting", "tool": "feroxbuster", "host": ip})
                spider_paths = {_urlparse(u).path for u in spider_urls if u}
                ferox_result = run_feroxbuster(primary_fqdn, ip, host_dir, order_id,
                                               adaptive_config=adaptive_config,
                                               known_paths=spider_paths if spider_paths else None)
                r["feroxbuster"] = ferox_result
                r["_tools"].append("feroxbuster")
                progress_callback(order_id, "feroxbuster", "complete")
                if ferox_result:
                    publish_tool_output(order_id, "feroxbuster", ip,
                                        f"{len(ferox_result)} paths (recursive, dedup applied)")
                else:
                    publish_tool_output(order_id, "feroxbuster", ip, "No new paths")

        # wpscan (conditional on WordPress) — use final URL after redirects
        if (phase2_tools is None or "wpscan" in phase2_tools) and cms and cms.lower() == "wordpress":
            publish_event(order_id, {"type": "tool_starting", "tool": "wpscan", "host": ip})
            # Prefer final_url from web probe (follows redirects, e.g. securess.de → www.securess.de)
            wp_final = tech_profile.get("final_url", "")
            if wp_final:
                from urllib.parse import urlparse as _up
                wp_fqdn = _up(wp_final).hostname or primary_fqdn
            else:
                wp_fqdn = primary_fqdn
            wpscan_result = run_wpscan(wp_fqdn, ip, host_dir, order_id)
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

    stage2_parallel = should_parallelize_stage2(adaptive_config, tech_profile)
    stage2_workers = 4 if stage2_parallel else 1
    log.info("phase2_stage2_start", ip=ip, spider_urls=len(spider_urls),
             parallel=stage2_parallel, reason="waf_safe" if not stage2_parallel else "default")
    with ThreadPoolExecutor(max_workers=stage2_workers, thread_name_prefix="p2s2") as pool:
        s2_futures = {
            pool.submit(_run_zap_active_stage2): "zap_active",
            pool.submit(_run_deep_scan_extras): "extras",
        }
        for future in as_completed(s2_futures):
            group_name = s2_futures[future]
            try:
                group_result = future.result()
                tools = group_result.pop("_tools", [])
                results.update(group_result)
                results["tools_run"].extend(tools)
            except Exception as e:
                log.error("phase2_stage2_failed", group=group_name, ip=ip, error=str(e))

    # ── Stage 3: Collect ZAP alerts (passive + active) ────────
    if zap_context:
        from scanner.tools.zap_client import ZapClient, ZapError
        from scanner.tools.zap_mapper import ZapAlertMapper
        try:
            zap = ZapClient()
            log.info("zap_waiting_for_passive", ip=ip)
            zap.wait_for_passive_scan(timeout=30)

            all_alerts_raw = zap.get_alerts()

            # Domain filter — defense in depth against cross-contamination
            # Even with dedicated ZAP per worker, filter to only our FQDNs
            allowed_domains = set()
            for _fqdn in fqdns:
                allowed_domains.add(_fqdn.lower())
                if _fqdn.lower().startswith("www."):
                    allowed_domains.add(_fqdn.lower()[4:])
                else:
                    allowed_domains.add(f"www.{_fqdn.lower()}")

            def _alert_belongs(alert: dict) -> bool:
                url = alert.get("url", "") or alert.get("nodeName", "")
                if not url:
                    return True  # Keep alerts without URL (rare)
                try:
                    hostname = _urlparse(url).hostname or ""
                    return hostname.lower() in allowed_domains
                except Exception:
                    return True

            all_alerts = [a for a in all_alerts_raw if _alert_belongs(a)]
            log.info("zap_alerts_collected", ip=ip,
                     raw=len(all_alerts_raw), filtered=len(all_alerts),
                     domains=list(allowed_domains)[:5])
            results["zap_alerts"] = all_alerts

            mapper = ZapAlertMapper()
            findings = mapper.map_alerts(all_alerts, ip, primary_fqdn)
            results["zap_findings"] = findings

            # Save to disk
            alerts_path = f"{phase2_dir}/zap_alerts.json"
            with open(alerts_path, "w") as f:
                json.dump(all_alerts, f, indent=2)

            passive_count = sum(1 for fd in findings if fd.get("tool") == "zap_passive")
            active_count = len(findings) - passive_count
            publish_tool_output(order_id, "zap", ip,
                                f"{len(all_alerts)} alerts ({passive_count} passive, {active_count} active)")

            # Save alert summary (not full JSON — too large for 50K DB column)
            alert_summary = {
                "total_alerts": len(all_alerts),
                "passive": passive_count,
                "active": active_count,
                "unique_types": len(set(a.get("name", a.get("alert", "")) for a in all_alerts)),
                "top_alerts": [{"name": a.get("name",""), "risk": a.get("risk",""), "url": a.get("url","")[:80]}
                               for a in all_alerts[:20]],
            }
            _save_result(order_id, ip, 2, "zap",
                         json.dumps(alert_summary, indent=2),
                         0, 0)
        except ZapError as e:
            log.error("zap_alert_collection_failed", ip=ip, error=str(e))
        finally:
            try:
                zap = ZapClient()
                zap.remove_context(zap_context)
            except Exception:
                pass

    # Save spider URLs to disk for report-worker
    if spider_urls:
        spider_path = f"{phase2_dir}/zap_spider_urls.json"
        with open(spider_path, "w") as f:
            json.dump(spider_urls, f, indent=2)

    log.info("phase2_complete", ip=ip, order_id=order_id, tools_run=len(results["tools_run"]))
    return results
