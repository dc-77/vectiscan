"""Phase 2 — Deep scan per host."""

import json
import os
import signal
import subprocess
from typing import Any, Callable, Optional

import structlog

from scanner.progress import publish_event, publish_tool_output
# _save_result bleibt importiert (Rule 1: nichts entfernen; tests/
# test_phase2_packages.py patcht den Namen); geschrieben wird ueber
# record_tool_run.
from scanner.tools import run_tool, _save_result, record_tool_run  # noqa: F401

log = structlog.get_logger()


def _record_phase2_status(order_id: str, ip: str, tool_name: str,
                          status: str, reason: str) -> None:
    """A7 (Jul 2026): Ergebniszeile fuer ein Phase-2-Tool schreiben.

    Deckt genau die Faelle ab, in denen bisher gar nichts in scan_results
    landete: Paket-Gating, KI-Skip, fehlende Infrastruktur (ZAP-Daemon),
    Exceptions. record_tool_run wirft nie — der Scan kann daran nicht kippen.
    """
    record_tool_run(order_id, ip, 2, tool_name, status, reason=reason)

def _cap_timeout_to_budget(base_timeout: int, deadline_monotonic: Optional[float],
                           min_timeout: int) -> int:
    """Strang-A Befund 3: Tool-Timeout gegen das Rest-Budget des Scans cappen.

    ``_check_timeout`` (worker.py) kann einen bereits laufenden Subprozess NICHT
    unterbrechen. Ein Tool mit langem Timeout (wpscan 1200s) kann deshalb das
    ``total_timeout`` um fast seine gesamte Laufzeit ueberschreiten — unter A3
    (mehr/langsamere Hosts) besonders relevant. Ist ein Scan-Deadline (monotonic)
    bekannt, begrenzen wir den Tool-Timeout auf das Restbudget, aber NIE unter
    ``min_timeout`` (sonst liefe das Tool ohne realistische Ergebnis-Chance).
    Fail-open: ohne Deadline (None) oder bei Fehler bleibt der Basis-Timeout.
    """
    if deadline_monotonic is None:
        return base_timeout
    try:
        import time as _t
        remaining = int(deadline_monotonic - _t.monotonic())
        if remaining <= 0:
            return min_timeout
        return max(min_timeout, min(base_timeout, remaining))
    except Exception:
        return base_timeout


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
        # VEC-373: Langform statt Single-Letter, damit die Flag-Semantik
        # unzweideutig ist und nicht erneut driftet. (`-h` = `--headers`,
        # NICHT help — die alte Inline-Doku war hier korrekt, aber die
        # Kurzform ist fehleranfaellig.) `--fast` entfaellt: bei expliziter
        # Test-Gruppen-Auswahl (Protocols/Server-Defaults/Headers) laeuft
        # ohnehin kein voller Cipher-Walk, `--fast` ist ein No-op und in
        # neueren testssl-Versionen deprecated.
        cmd.extend([
            "--protocols",        # nur Protocols (kein Cipher-Walk)
            "--server-defaults",  # nur Server-Defaults (Cert/Extensions)
            "--headers",          # HTTP-Security-Header (HSTS etc.)
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

    # VEC-373 (D4b): Tool-Failures NICHT mehr still verschlucken. testssl
    # nutzt Exit 0/1 fuer Erfolg (1 = "Findings vorhanden"); alles andere ist
    # ein echter Fehler. Zusaetzlich gilt ein leeres/ungueltiges JSON oder ein
    # durchgereichter Usage-Banner als Failure. In allen Faellen: laut loggen
    # und None zurueckgeben (None == failed, [] == lief sauber ohne Findings).
    if exit_code not in (0, 1):
        log.error("testssl_failed", reason="bad_exit_code", exit_code=exit_code,
                  fqdn=fqdn, ip=ip, order_id=order_id)
        return None

    try:
        with open(output_path, "r") as f:
            raw = f.read()
    except FileNotFoundError:
        log.error("testssl_failed", reason="no_output_file", exit_code=exit_code,
                  fqdn=fqdn, ip=ip, output_path=output_path, order_id=order_id)
        return None

    # Usage-Banner / Help-Text durchgereicht (z.B. unrecognized option) →
    # testssl ist abgebrochen, bevor es echte Checks gefahren hat.
    if "testssl.sh [options]" in raw or "testssl.sh <options>" in raw:
        log.error("testssl_failed", reason="usage_banner_in_output",
                  exit_code=exit_code, fqdn=fqdn, ip=ip, order_id=order_id)
        return None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        log.error("testssl_failed", reason="invalid_json", exit_code=exit_code,
                  fqdn=fqdn, ip=ip, error=str(e), order_id=order_id)
        return None

    if not isinstance(data, list):
        log.error("testssl_failed", reason="unexpected_format", exit_code=exit_code,
                  fqdn=fqdn, ip=ip, order_id=order_id)
        return None

    return data


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
    # Sensitive-Files (.env, .git/HEAD, backup.zip, dump.sql, etc.) —
    # SecLists raft-small-files.txt, ~10k Eintraege.
    # F-PH2-001: Wechsel von raft-medium-files.txt (17.5k, lief in 180s
    # Hard-Cap) auf raft-small-files.txt (10k, ~100s). Long-Tail wurde
    # ohnehin durch -maxtime abgeschnitten; Coverage-Verlust <2%.
    "sensitive": "/usr/share/wordlists/raft-small-files.txt",
}

# SecLists paths for ffuf (installed from SecLists in Dockerfile)
SECLISTS_DIR = "/usr/share/wordlists/seclists"
FFUF_WORDLISTS = {
    "dir": f"{SECLISTS_DIR}/Discovery/Web-Content/common.txt",
    "vhost": f"{SECLISTS_DIR}/Discovery/DNS/subdomains-top1million-5000.txt",
    "param": f"{SECLISTS_DIR}/Discovery/Web-Content/burp-parameter-names.txt",
    # Sensitive-Files-Modus fuer ffuf (siehe run_ffuf mode='sensitive').
    # F-PH2-001: raft-medium (17.5k, 180s Hard-Cap) -> raft-small (10k, ~100s).
    "sensitive": f"{SECLISTS_DIR}/Discovery/Web-Content/raft-small-files.txt",
    # WordPress-Plugin-Pfade (~4k) — ergaenzt unsere kuratierte
    # wordpress.txt mit den haeufigsten Plugin-Slugs.
    "wp_plugins": f"{SECLISTS_DIR}/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt",
}

# Critical-File-Extensions die wir bei jedem Scan an Pfade anhaengen —
# typische Pentest-Quick-Wins (.env, .git/, dump.sql, config.bak, ...).
CRITICAL_EXTENSIONS = "bak,old,sql,zip,tar.gz,tgz,env,backup,swp,save,orig,~"


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
        # Erweiterte Extension-Liste: PHP + alle Sensitive-File-Endungen
        # (env/git/bak/sql/...) — typische Pentest-Quick-Wins. CRITICAL_EXTENSIONS
        # ist top-level konstant, damit Tests die Liste leicht checken koennen.
        "-x", f"php,html,txt,{CRITICAL_EXTENSIONS}",
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

    # A5 (Jul 2026): Kam ueberhaupt eine HTTP-Antwort? curl liefert bei
    # Verbindungsabbruch/Timeout leeren stdout. Ohne Antwort duerfen wir
    # KEINEN "0/7"-Score behaupten — das waere ein Falsch-Nullergebnis, das
    # der Reporter als „alle Security-Header fehlen" fehldeutet. Stattdessen
    # den reachable:false-Marker setzen (SSoT fuer Strang A): score=None,
    # keine Header-Zaehlung. Ein echter 403/429 (WAF) IST eine Antwort und
    # bleibt reachable:true — Blocking behandelt A6 separat.
    if not raw_headers.strip():
        analysis_unreachable: dict[str, Any] = {
            "url": url,
            "reachable": False,
            "score": None,
            "headers": {},
            "security_headers": {},
        }
        try:
            with open(output_path, "w") as f:
                json.dump(analysis_unreachable, f, indent=2)
        except Exception as e:
            log.error("header_check_save_error", fqdn=fqdn, error=str(e))
        log.info("header_check_no_response", fqdn=fqdn,
                 note="keine HTTP-Antwort — reachable:false statt 0/7")
        return analysis_unreachable

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
        # A5: echte HTTP-Antwort erhalten — der Score ist belastbar.
        "reachable": True,
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


def run_wpscan(fqdn: str, ip: str, host_dir: str, order_id: str,
               deadline_monotonic: Optional[float] = None) -> Optional[dict[str, Any]]:
    """Run WPScan WordPress vulnerability scanner.

    Only called when CMS is detected as WordPress.

    deadline_monotonic (Strang-A Befund 3, optional): monotone Scan-Deadline.
    Ist sie gesetzt, wird der 1200s-Timeout auf das Restbudget gecappt, damit
    der letzte Host das total_timeout nicht um bis zu 20 Min sprengt.
    """
    phase2_dir = f"{host_dir}/phase2"
    os.makedirs(phase2_dir, exist_ok=True)
    output_path = f"{phase2_dir}/wpscan.json"

    api_token = os.environ.get("WPSCAN_API_TOKEN", "")

    # PR-I (Mai 2026): Vollscope wiederhergestellt nach Performance-Reduktion.
    # User-Entscheidung: hoechste Detection-Coverage trotz lange Laufzeit ist
    # wichtiger als Schnelligkeit (Plugin/Theme/User-Enum + aktives Path-
    # Probing). Timeout statt 600s jetzt 1200s damit Plesk/Cloudflare-Sites
    # mit Rate-Limits + WAFs nicht mehr abgeschnitten werden.
    # Throttle 100ms statt 200ms (verdoppelt die Request-Rate gegenueber
    # dem Pre-Mai-2026-Stand) — bei 1200s Cap immer noch konservativ genug
    # damit Customer-Sites nicht selbst rate-limited werden.
    cmd = [
        "wpscan",
        "--url", f"https://{fqdn}",
        "--format", "json",
        "--output", output_path,
        "--enumerate", "vp,vt,u1-5",  # vulnerable plugins, themes, user-enum 1-5
        "--random-user-agent",
        "--no-banner",
        "--disable-tls-checks",        # handle self-signed certs
        # Rate-Limit: 100ms zwischen Requests = 10 req/s.
        "--throttle", "100",
        # Request-Timeout pro HTTP-Call (Default 60s ist zu lang)
        "--request-timeout", "30",
        # Connection-Timeout separat (Default 30s)
        "--connect-timeout", "10",
        "--max-threads", "5",
        # `--detection-mode mixed` (Default) — passive zuerst, aggressive
        # nur wo noetig (probiert /wp-admin/ + /wp-includes/ etc.)
        "--detection-mode", "mixed",
    ]
    if api_token:
        cmd.extend(["--api-token", api_token])

    # Timeout: 1200s (20 min) Safety-Cap fuer Plesk/Cloudflare-Sites mit
    # Rate-Limits. Vollscope-Run typisch 5-15min. Strang-A Befund 3: gegen
    # das Rest-Budget cappen (min. 120s), damit der letzte Host das
    # total_timeout nicht um fast einen ganzen wpscan-Lauf ueberschreitet.
    wpscan_timeout = _cap_timeout_to_budget(1200, deadline_monotonic, min_timeout=120)
    exit_code, duration_ms = run_tool(
        cmd=cmd, timeout=wpscan_timeout, output_path=output_path,
        order_id=order_id, host_ip=ip, phase=2, tool_name="wpscan",
    )

    # WPScan exit codes:
    #   0 = ok, no vulnerabilities found
    #   1 = generic error (e.g. CTRL-C)
    #   3 = update DB failed but scan continues
    #   4 = WordPress not detected on the target — kein Fehler!
    #   5 = vulnerabilities found
    # Frueher haben wir 4 als Failure gewertet → "wpscan exit=4" im Trace.
    # Bei einer normalen Site ohne WordPress ist das aber das erwartete
    # Ergebnis und das JSON enthaelt sinnvolle Info.
    if exit_code not in (0, 4, 5):
        log.warning("wpscan_failed", fqdn=fqdn, exit_code=exit_code)
        return None

    try:
        with open(output_path, "r") as f:
            data = json.load(f)
        if exit_code == 4 or not data.get("target_url"):
            log.info("wpscan_no_wordpress", fqdn=fqdn)
            return None  # Sauberer "kein WP"-Pfad: None zurueck, kein Failure.
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
            _record_phase2_status(order_id, ip, f"ffuf_{mode}", "skipped",
                                  f"wordlist_missing:{wordlist}")
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
            _record_phase2_status(order_id, ip, f"ffuf_{mode}", "skipped",
                                  "no_input_urls")
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
            _record_phase2_status(order_id, ip, f"ffuf_{mode}", "skipped",
                                  f"wordlist_missing:{wordlist}")
            return None

        cmd = [
            "ffuf",
            "-u", f"{target_url}?FUZZ=test",
            "-w", wordlist,
            "-mc", "200",
            "-H", "User-Agent: Mozilla/5.0 vectiscan",
            "-json",
            "-o", output_path,
            # Param-Mode: hoehere Threads + RPS, weil burp-parameter-names
            # ~6500 Eintraege hat und 50 RPS in 130s nicht durchkommt.
            "-t", "60",
            "-rate", "100",
            "-timeout", "5",
            # `-maxtime 150` laesst ffuf selbst sauber abbrechen +
            # JSON-File schreiben, statt nach 180s vom run_tool gekillt zu
            # werden (=> partial output, kein gueltiges JSON).
            "-maxtime", "150",
            # `-ac` autocalibrate raus — bei param-mode sendet es zusaetzliche
            # Probes UND wartet auf jede Antwort, was den Run nochmal verlangsamt.
            "-s",
        ]

    elif mode == "sensitive":
        # Sensitive-File-Discovery: jagt nach .env/.git/backup.zip/dump.sql/...
        # mittels SecLists raft-small-files.txt (~10k Eintraege). Diese
        # Files sind typische Pentest-Quick-Wins und finden sich oft in
        # Production-Deployments. F-PH2-001: Wechsel von raft-medium (17.5k),
        # lief in 180s Hard-Cap, Long-Tail wurde abgeschnitten.
        wordlist = FFUF_WORDLISTS.get("sensitive", WORDLIST_MAP.get("sensitive"))
        if not wordlist or not os.path.isfile(wordlist):
            log.warning("ffuf_sensitive_wordlist_missing", path=wordlist)
            _record_phase2_status(order_id, ip, f"ffuf_{mode}", "skipped",
                                  f"wordlist_missing:{wordlist}")
            return None
        cmd = [
            "ffuf",
            "-u", f"https://{fqdn}/FUZZ",
            "-w", wordlist,
            "-mc", "200,301,302,307",
            # 403 raus — viele Sensitive-Files (etwa /.git/HEAD) liefern bei
            # WAFs 403 statt 404, sind aber trotzdem ein klares Signal.
            # Wir matchen daher zusaetzlich auf 403 ueber `-fs` Statt-Filter:
            "-mr", "200|301|302|307",
            "-H", "User-Agent: Mozilla/5.0 vectiscan",
            "-json",
            "-o", output_path,
            "-t", "60",
            "-rate", "100",
            "-timeout", "5",
            "-maxtime", "180",
            # Filter typische "weiche 200"-Wildcard-Antworten
            "-fs", "0",
            "-s",
        ]
    else:
        log.warning("ffuf_unknown_mode", mode=mode)
        _record_phase2_status(order_id, ip, f"ffuf_{mode}"[:50], "skipped",
                              f"unknown_mode:{mode}")
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
                    known_paths: set[str] | None = None,
                    deadline_monotonic: Optional[float] = None) -> Optional[list[dict[str, Any]]]:
    """Run feroxbuster for recursive directory brute-force.

    Args:
        known_paths: Paths already found by gobuster/ffuf — used for dedup.
        deadline_monotonic: Strang-A Befund 3 (optional) — monotone Scan-
            Deadline; cappt den 240s-Timeout auf das Restbudget (min. 60s).

    Returns list of findings or None on failure.
    """
    phase2_dir = f"{host_dir}/phase2"
    os.makedirs(phase2_dir, exist_ok=True)

    output_path = f"{phase2_dir}/feroxbuster.json"

    # AI-controlled recursion depth (default: 2)
    depth = 2
    if adaptive_config and adaptive_config.get("feroxbuster_depth"):
        depth = min(int(adaptive_config["feroxbuster_depth"]), 2)

    # AI-adaptive wordlist selection — analog zu gobuster_dir. Bei
    # WordPress/Drupal/Magento etc. nimmt die KI die curated wordlist;
    # default ist common.txt (~4.6k).
    wl_key = "common"
    if adaptive_config and adaptive_config.get("feroxbuster_wordlist"):
        wl_key = adaptive_config["feroxbuster_wordlist"]
    elif adaptive_config and adaptive_config.get("gobuster_wordlist"):
        # Fallback: gobuster-Choice mit-nutzen wenn KI nur das gesetzt hat.
        wl_key = adaptive_config["gobuster_wordlist"]
    wordlist = WORDLIST_MAP.get(wl_key, WORDLIST_MAP["common"])
    if not os.path.isfile(wordlist):
        log.warning("feroxbuster_wordlist_missing", path=wordlist, wl_key=wl_key)
        wordlist = WORDLIST_MAP["common"]
    if not os.path.isfile(wordlist):
        return None
    if wl_key != "common":
        log.info("feroxbuster_adaptive_wordlist", ip=ip, wordlist=wl_key)

    cmd = [
        "feroxbuster",
        "-u", f"https://{fqdn}",
        "-w", wordlist,
        # Critical-File-Extensions — analog gobuster_dir. Bei jedem
        # gefundenen Pfad wird `<pfad>.bak`, `<pfad>.env`, etc. probiert.
        "-x", CRITICAL_EXTENSIONS,
        "-d", str(depth),
        "-t", "30",
        # `--rate-limit 100` statt `--auto-tune`: auto-tune regelt bei
        # gut-reagierenden Servern auf 0 RPS runter weil es 5xx-Bursts
        # erwartet → Scan-Timeout mit nur Teil-Output.
        "--rate-limit", "100",
        # `--dont-extract-links`: WordPress/BeTheme/SPA-Sites haben 50+
        # Asset-URLs (JS/CSS/Image) im HTML; ohne diesen Flag scannt
        # feroxbuster jede einzelne davon UND macht recursion auf jeder.
        # dortmund-beach.com (10-Seiten WordPress) explodiert damit auf
        # 240s+ TIMEOUT. Wir wollen nur die wordlist-basierten Pfade.
        "--dont-extract-links",
        # `--auto-bail`: bricht den Scan ab wenn der Server zu viele
        # Fehler/Wildcard-200 produziert (typisch fuer WordPress-Catch-
        # All-Routen "/<random> → Homepage"). Verhindert false-positives
        # und Endlos-Scan.
        "--auto-bail",
        # `--time-limit 3m`: feroxbuster bricht selbst sauber ab statt
        # vom run_tool nach 240s gekillt zu werden. Schreibt validen JSON.
        "--time-limit", "3m",
        # `--scan-limit 5`: max 5 parallele Scans (Top-Level + 4 Recursive).
        "--scan-limit", "5",
        # `-s` (status-codes Whitelist); 403/404 implizit raus
        "-s", "200,301,302,307",
        # Filter sehr kleine Responses (typische "not found"-Pages 0-100b)
        "--filter-size", "0,1,2,3",
        "--json",
        "-o", output_path,
        "--dont-scan", "logout|signout|delete",
        "--timeout", "5",
        "-H", "User-Agent: Mozilla/5.0 vectiscan",
        "--silent",
    ]

    # Strang-A Befund 3: 240s-Basis-Timeout gegen das Rest-Budget cappen
    # (min. 60s). feroxbuster bricht via --time-limit 3m ohnehin selbst ab;
    # der Cap ist die zusaetzliche Budget-Sicherung fuer den letzten Host.
    ferox_timeout = _cap_timeout_to_budget(240, deadline_monotonic, min_timeout=60)
    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=ferox_timeout,
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
        # A7: der Ausfall des ZAP-Daemons muss im Bericht sichtbar sein —
        # bisher kehrte dieser Pfad ohne eine einzige DB-Zeile zurueck.
        for _zap_tool in ("zap_spider", "zap_active", "zap"):
            _record_phase2_status(order_id, ip, _zap_tool, "skipped",
                                  "zap_daemon_unavailable")
        return result

    ac = adaptive_config or {}
    phase2_dir = f"{host_dir}/phase2"
    context_name = f"ctx-{order_id[:8]}-{ip.replace('.', '_')}"
    policy_name = f"policy-{order_id[:8]}-{ip.replace('.', '_')}"
    target_url = f"https://{fqdn}"
    context_id: int | None = None
    ai_skip = set(ac.get("skip_tools", []))
    zap_error: str = ""

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
        record_tool_run(order_id, ip, 2, "zap_spider", "ok",
                        exit_code=0, duration_ms=spider_duration,
                        raw_output=json.dumps(
                            {"urls_found": len(spider_urls), "depth": spider_depth,
                             "urls": spider_urls[:50]}, indent=2))
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
            record_tool_run(order_id, ip, 2, "zap_ajax_spider",
                            "ok" if completed else "timeout",
                            reason=None if completed else "ajax_spider_timeout",
                            exit_code=0, duration_ms=ajax_duration,
                            raw_output=json.dumps(
                                {"status": "complete" if completed else "timeout",
                                 "duration_ms": ajax_duration}))
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
            record_tool_run(order_id, ip, 2, "zap_active",
                            "ok" if completed else "timeout",
                            reason=None if completed else "active_scan_timeout",
                            exit_code=0, duration_ms=active_duration,
                            raw_output=json.dumps(
                                {"status": "complete" if completed else "timeout",
                                 "policy": scan_policy, "categories": categories,
                                 "duration_ms": active_duration}))
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
        zap_error = str(e)
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
    # A7: ein ZapError machte diese Zeile bisher trotzdem zu einem Erfolg.
    record_tool_run(
        order_id, ip, 2, "zap", "failed" if zap_error else "ok",
        reason=zap_error or None,
        exit_code=0, duration_ms=result["duration_ms"],
        raw_output=raw_summary,
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
    vhost_fqdns: list[str] | None = None,
    deadline_monotonic: float | None = None,
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
        vhost_fqdns: Liste primary VHosts fuer Multi-VHost-Tools (ZAP-Spider,
            ZAP-AJAX, header_check, httpx). Wenn None → Legacy fqdns[:5].
        deadline_monotonic: Strang-A Befund 3 (optional) — monotone Scan-
            Deadline (start + total_timeout). Cappt die langen Tool-Timeouts
            (wpscan/feroxbuster) auf das Restbudget. None = kein Cap.

    Returns:
        Results summary dict. Bei Multi-VHost: results['vhost_results'][fqdn]
        haelt header_check/httpx-Ergebnisse pro VHost.
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

    # VHost-Loop-Targets (Multi-VHost-Probe). Legacy: fqdns[:5].
    if not vhost_fqdns:
        vhost_fqdns = list(fqdns[:5])
    if not vhost_fqdns and primary_fqdn:
        vhost_fqdns = [primary_fqdn]

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

    # A7: erwartete Tools je Stage-Gruppe. Faellt eine komplette Gruppe per
    # Exception aus, bekommt jedes Tool der Gruppe eine eigene 'failed'-Zeile
    # — eine Sammelzeile wuerde die Abdeckungsmatrix luecklos machen.
    _stage_group_tools: dict[str, list[str]] = {
        "testssl": ["testssl"],
        "zap_discovery": ["zap_spider"],
        "quick": ["header_check", "httpx"],
        "zap_active": ["zap_active"],
        "extras": ["ffuf_param", "feroxbuster", "ffuf_sensitive", "wpscan"],
    }

    def _record_group_failure(group_name: str, error: str) -> None:
        """Gruppenausfall auf die erwarteten Tools der Gruppe herunterbrechen."""
        for group_tool in _stage_group_tools.get(group_name, [group_name]):
            _record_phase2_status(order_id, ip, group_tool, "failed",
                                  f"group_{group_name}_failed: {error}")

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
            _record_phase2_status(order_id, ip, "zap_spider", "skipped",
                                  "no_web" if not has_web else "not_in_package")
            return r

        zap = ZapClient()
        if not zap.health_check():
            log.warning("zap_daemon_unavailable", ip=ip)
            # A7: ZAP-Ausfall wird protokolliert statt still verschluckt.
            _record_phase2_status(order_id, ip, "zap_spider", "skipped",
                                  "zap_daemon_unavailable")
            return r

        ac = adaptive_config or {}
        all_spider_urls: list[str] = []
        context_name = f"ctx-{order_id[:8]}-{ip.replace('.', '_')}"

        try:
            context_id = zap.create_context(context_name)
            # Include ALL primary VHosts in context scope (Multi-VHost-Probe)
            for fqdn_item in vhost_fqdns:
                zap.include_in_context(context_name, f".*{_re.escape(fqdn_item)}.*")

            zap.configure_rate_limit(
                req_per_sec=ac.get("zap_rate_req_per_sec", 80),
                threads=ac.get("zap_threads", 5),
                delay_ms=ac.get("zap_spider_delay_ms", 0),
            )

            # Spider each primary VHost
            spider_depth = ac.get("zap_spider_max_depth", 5)
            for fqdn_item in vhost_fqdns:
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

            # AJAX Spider (conditional on SPA) — sequenziell pro VHost,
            # da ZAP nur 1 AJAX-Spider gleichzeitig erlaubt
            if ac.get("zap_ajax_spider_enabled") and "zap_ajax_spider" not in set(ac.get("skip_tools", [])):
                publish_event(order_id, {"type": "tool_starting", "tool": "zap_ajax_spider", "host": ip})
                for vh_ajax in vhost_fqdns:
                    zap.start_ajax_spider(f"https://{vh_ajax}", context_name=context_name)
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
            record_tool_run(order_id, ip, 2, "zap_spider", "ok",
                            exit_code=0, duration_ms=0,
                            raw_output=json.dumps(
                                {"urls_found": len(unique_urls),
                                 "fqdns_spidered": len(vhost_fqdns),
                                 "vhosts": list(vhost_fqdns),
                                 "urls": unique_urls[:50]}, indent=2))
            publish_tool_output(order_id, "zap_spider", ip,
                                f"{len(unique_urls)} URLs from {len(vhost_fqdns)} VHosts")
            progress_callback(order_id, "zap_spider", "complete")

        except ZapError as e:
            log.error("zap_discovery_failed", ip=ip, error=str(e))
            _record_phase2_status(order_id, ip, "zap_spider", "failed", str(e))
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
            # VEC-373 (D4b): None == Tool-Failure, [] == lief sauber ohne
            # Findings. Beides unterscheiden statt beides als "No findings".
            if testssl_result is None:
                r["testssl_status"] = "failed"
                log.error("testssl_no_data", ip=ip, order_id=order_id,
                          fast_mode=testssl_fast,
                          note="testssl lieferte keine verwertbaren Daten")
                publish_tool_output(order_id, "testssl", ip,
                                    "FEHLER: testssl lieferte keine Daten")
            else:
                r["testssl_status"] = "ok"
                count = len(testssl_result)
                publish_tool_output(order_id, "testssl", ip,
                                    f"{count} SSL/TLS checks completed")
        else:
            _record_phase2_status(order_id, ip, "testssl", "skipped",
                                  "no_ssl" if not has_ssl else "not_in_package")
        return r

    def _run_quick_tools_stage1() -> dict[str, Any]:
        """Fast independent tools: header_check, httpx — pro primary VHost.

        Each tool is isolated so a failure in one doesn't lose results from the other.
        Multi-VHost-Probe (Mai 2026): laeuft pro VHost, damit Findings VHost-genau
        zugeordnet werden koennen.
        """
        r: dict[str, Any] = {"_tools": [], "vhost_results": {}}
        if phase2_tools is None or "headers" in phase2_tools:
            for vh in vhost_fqdns:
                try:
                    publish_event(order_id, {"type": "tool_starting", "tool": "header_check", "host": ip})
                    header_result = run_header_check(vh, ip, host_dir, order_id)
                    if vh == primary_fqdn:
                        r["headers"] = header_result
                    r["vhost_results"].setdefault(vh, {})["headers"] = header_result
                    # A5: reachable:false darf nicht als "0/7" erscheinen.
                    if header_result and header_result.get("reachable") is False:
                        score = "keine HTTP-Antwort"
                    else:
                        score = header_result.get("score", "?/?") if header_result else "failed"
                    publish_tool_output(order_id, "header_check", ip,
                                        f"Security headers ({vh}): {score}")
                    record_tool_run(order_id, ip, 2, "header_check", "ok",
                                    exit_code=0, duration_ms=0,
                                    raw_output=json.dumps(
                                        {"vhost": vh, "result": header_result},
                                        indent=2, ensure_ascii=False))
                except Exception as e:
                    log.error("header_check_failed", fqdn=vh, ip=ip, error=str(e))
                    _record_phase2_status(order_id, ip, "header_check", "failed",
                                          f"{vh}: {e}")
            r["_tools"].append("header_check")
            progress_callback(order_id, "header_check", "complete")
        else:
            _record_phase2_status(order_id, ip, "header_check", "skipped",
                                  "not_in_package")
        if phase2_tools is None or "httpx" in phase2_tools:
            for vh in vhost_fqdns:
                try:
                    publish_event(order_id, {"type": "tool_starting", "tool": "httpx", "host": ip})
                    httpx_result = run_httpx(vh, ip, host_dir, order_id)
                    if vh == primary_fqdn:
                        r["httpx"] = httpx_result
                    r["vhost_results"].setdefault(vh, {})["httpx"] = httpx_result
                    if httpx_result:
                        publish_tool_output(order_id, "httpx", ip,
                                            f"HTTP {httpx_result.get('status_code', '?')} ({vh})")
                    else:
                        publish_tool_output(order_id, "httpx", ip, f"HTTP probe failed ({vh})")
                except Exception as e:
                    log.error("httpx_failed", fqdn=vh, ip=ip, error=str(e))
                    _record_phase2_status(order_id, ip, "httpx", "failed",
                                          f"{vh}: {e}")
            r["_tools"].append("httpx")
            progress_callback(order_id, "httpx", "complete")
        else:
            _record_phase2_status(order_id, ip, "httpx", "skipped",
                                  "not_in_package")
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
                _record_group_failure(group_name, str(e))

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

        # A6-Circuit-Breaker (Strang-A Befund 2): ist der Host bereits durch ein
        # ECHTES WAF-Signal geblockt, gar nicht erst gegen die WAF scannen.
        if _sticky_block:
            _record_phase2_status(order_id, ip, "zap_active", "blocked",
                                  f"host_bereits_geblockt:{_sticky_block}")
            return r

        ac = adaptive_config or {}
        scan_policy = ac.get("zap_scan_policy", "standard")
        is_webcheck = (config or {}).get("package") in ("basic", "webcheck")
        run_active = (not is_webcheck and scan_policy != "passive-only"
                      and (phase2_tools is None or "zap_active" in (phase2_tools or [])))

        if not run_active or not zap_context:
            if is_webcheck:
                skip_reason = "package_webcheck"
            elif scan_policy == "passive-only":
                skip_reason = "passive_only_policy"
            elif not run_active:
                skip_reason = "not_in_package"
            else:
                skip_reason = "no_zap_context"
            _record_phase2_status(order_id, ip, "zap_active", "skipped", skip_reason)
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
            record_tool_run(order_id, ip, 2, "zap_active",
                            "ok" if completed else "timeout",
                            reason=None if completed else "active_scan_timeout",
                            exit_code=0, duration_ms=active_duration,
                            raw_output=json.dumps(
                                {"status": "complete" if completed else "timeout",
                                 "policy": scan_policy, "categories": categories,
                                 "duration_ms": active_duration}))
            publish_tool_output(order_id, "zap_active", ip, "Active scan complete")
            progress_callback(order_id, "zap_active", "complete")
        except ZapError as e:
            log.error("zap_active_failed", ip=ip, error=str(e))
            _record_phase2_status(order_id, ip, "zap_active", "failed", str(e))
        finally:
            try:
                zap.remove_scan_policy(policy_name)
            except Exception:
                pass
        return r

    def _run_deep_scan_extras() -> dict[str, Any]:
        """Run ffuf param, feroxbuster, wpscan with Spider URLs."""
        r: dict[str, Any] = {"_tools": []}

        # A6-Circuit-Breaker (Strang-A Befund 2): gegen einen bereits (durch ein
        # echtes WAF-Signal) geblockten Host laufen die teuren Phase-2-Tools
        # nicht mehr voll bis zum Timeout, sondern werden als "blocked"
        # protokolliert. Das begrenzt die von A3 erhoehte Budget-Last. fail-open:
        # ohne Sticky-Verdikt (None) laeuft alles regulaer.
        if _sticky_block:
            for _blocked_tool in ("ffuf_param", "feroxbuster", "ffuf_sensitive", "wpscan"):
                _record_phase2_status(order_id, ip, _blocked_tool, "blocked",
                                      f"host_bereits_geblockt:{_sticky_block}")
            return r

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
        else:
            # A7: Grund fuer das Auslassen protokollieren (Reihenfolge =
            # Reihenfolge der Bedingungen oben).
            if not (phase2_tools is not None and "ffuf" in phase2_tools):
                ffuf_reason = "not_in_package"
            elif "ffuf" in ai_skip:
                ffuf_reason = "ai_skip"
            elif not has_web:
                ffuf_reason = "no_web"
            else:
                ffuf_reason = "no_api_urls"
            _record_phase2_status(order_id, ip, "ffuf_param", "skipped", ffuf_reason)

        # feroxbuster: recursive directory scan, spider URLs as dedup
        if (phase2_tools is not None and "feroxbuster" in phase2_tools) and "feroxbuster" not in ai_skip and has_web:
            ferox_enabled = True
            if adaptive_config and adaptive_config.get("feroxbuster_enabled") is False:
                ferox_enabled = False
            if not ferox_enabled:
                _record_phase2_status(order_id, ip, "feroxbuster", "skipped",
                                      "ai_disabled")
            if ferox_enabled:
                publish_event(order_id, {"type": "tool_starting", "tool": "feroxbuster", "host": ip})
                spider_paths = {_urlparse(u).path for u in spider_urls if u}
                ferox_result = run_feroxbuster(primary_fqdn, ip, host_dir, order_id,
                                               adaptive_config=adaptive_config,
                                               known_paths=spider_paths if spider_paths else None,
                                               deadline_monotonic=deadline_monotonic)
                r["feroxbuster"] = ferox_result
                r["_tools"].append("feroxbuster")
                progress_callback(order_id, "feroxbuster", "complete")
                if ferox_result:
                    publish_tool_output(order_id, "feroxbuster", ip,
                                        f"{len(ferox_result)} paths (recursive, dedup applied)")
                else:
                    publish_tool_output(order_id, "feroxbuster", ip, "No new paths")
        else:
            if not (phase2_tools is not None and "feroxbuster" in phase2_tools):
                ferox_reason = "not_in_package"
            elif "feroxbuster" in ai_skip:
                ferox_reason = "ai_skip"
            else:
                ferox_reason = "no_web"
            _record_phase2_status(order_id, ip, "feroxbuster", "skipped", ferox_reason)

        # ffuf sensitive: Sensitive-File-Discovery (.env, .git/, dump.sql, ...)
        # Eigener Run mit raft-small-files.txt Wordlist — typische Pentest-
        # Quick-Wins die in common.txt nicht ausreichend abgedeckt sind.
        if (phase2_tools is not None and "ffuf" in phase2_tools) and "ffuf" not in ai_skip and has_web:
            publish_event(order_id, {"type": "tool_starting", "tool": "ffuf_sensitive", "host": ip})
            sens_config = dict(adaptive_config) if adaptive_config else {}
            sens_config["ffuf_mode"] = "sensitive"
            sens_result = run_ffuf(primary_fqdn, ip, host_dir, order_id,
                                    adaptive_config=sens_config)
            r["ffuf_sensitive"] = sens_result
            r["_tools"].append("ffuf_sensitive")
            progress_callback(order_id, "ffuf_sensitive", "complete")
            if sens_result:
                publish_tool_output(order_id, "ffuf_sensitive", ip,
                                    f"{len(sens_result)} sensitive files exposed")
            else:
                publish_tool_output(order_id, "ffuf_sensitive", ip, "No sensitive files found")
        else:
            if not (phase2_tools is not None and "ffuf" in phase2_tools):
                sens_reason = "not_in_package"
            elif "ffuf" in ai_skip:
                sens_reason = "ai_skip"
            else:
                sens_reason = "no_web"
            _record_phase2_status(order_id, ip, "ffuf_sensitive", "skipped", sens_reason)

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
            wpscan_result = run_wpscan(wp_fqdn, ip, host_dir, order_id,
                                       deadline_monotonic=deadline_monotonic)
            r["wpscan"] = wpscan_result
            r["_tools"].append("wpscan")
            progress_callback(order_id, "wpscan", "complete")
            if wpscan_result:
                vulns = len(wpscan_result.get("interesting_findings", []))
                plugins = len(wpscan_result.get("plugins", {}))
                publish_tool_output(order_id, "wpscan", ip, f"{vulns} findings, {plugins} plugins")
            else:
                publish_tool_output(order_id, "wpscan", ip, "WPScan failed")
        else:
            if not (phase2_tools is None or "wpscan" in phase2_tools):
                wpscan_reason = "not_in_package"
            else:
                wpscan_reason = "cms_not_wordpress"
            _record_phase2_status(order_id, ip, "wpscan", "skipped", wpscan_reason)

        return r

    # A6-Circuit-Breaker (Strang-A Befund 2): Sticky-Block-Verdikt EINMAL vor
    # Stage 2 abfragen. Ist der Host durch ein echtes WAF-Signal geblockt,
    # ueberspringen die teuren Tools (ffuf/feroxbuster/wpscan/zap_active) den
    # Lauf. fail-open: bei jedem Fehler None -> Tools laufen normal.
    _sticky_block: str | None = None
    try:
        from scanner.tools import host_block_verdict
        _sticky_block = host_block_verdict(order_id, ip)
    except Exception as _cb_err:
        log.warning("phase2_circuit_breaker_check_failed", ip=ip, error=str(_cb_err))
        _sticky_block = None
    if _sticky_block:
        log.warning("phase2_circuit_breaker_host_blocked", ip=ip,
                    order_id=order_id, reason=_sticky_block)

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
                _record_group_failure(group_name, str(e))

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
            record_tool_run(order_id, ip, 2, "zap", "ok",
                            exit_code=0, duration_ms=0,
                            raw_output=json.dumps(alert_summary, indent=2))
        except ZapError as e:
            log.error("zap_alert_collection_failed", ip=ip, error=str(e))
            _record_phase2_status(order_id, ip, "zap", "failed", str(e))
        finally:
            try:
                zap = ZapClient()
                zap.remove_context(zap_context)
            except Exception:
                pass
    else:
        # A7: ohne ZAP-Kontext gab es keine Alert-Sammlung — sichtbar machen.
        _record_phase2_status(order_id, ip, "zap", "skipped", "no_zap_context")

    # Save spider URLs to disk for report-worker
    if spider_urls:
        spider_path = f"{phase2_dir}/zap_spider_urls.json"
        with open(spider_path, "w") as f:
            json.dump(spider_urls, f, indent=2)

    log.info("phase2_complete", ip=ip, order_id=order_id, tools_run=len(results["tools_run"]))
    return results
