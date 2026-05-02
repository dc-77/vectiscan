"""Phase 1 — Technology detection per host."""

import json
import os
import signal
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Callable, Optional

import structlog

from scanner.cms_fingerprinter import CMSFingerprinter, CMSResult
from scanner.tools import run_tool
from scanner.progress import publish_event

log = structlog.get_logger()


# ---------------------------------------------------------------------------
# Tech-Signal-Extraktion fuer Playwright-basierte Tech-Detection
# ---------------------------------------------------------------------------
# Pattern-Matching nach Wappalyzer-Vorbild — leicht erweiterbar.
# Quelle: bewaehrte Cookie-/Script-/Header-Patterns die in der Praxis
# zuverlaessig sind. Bewusst klein gehalten — wir wollen keine Wappalyzer-
# Komplettkopie, sondern die "stillen" SPAs (Next.js, Vue, React) erfassen.

_COOKIE_PATTERNS: list[tuple[str, str]] = [
    ("next-auth", "Next.js (auth)"),
    ("__Secure-next-auth", "Next.js (auth)"),
    ("_next", "Next.js"),
    ("connect.sid", "Express"),
    ("XSRF-TOKEN", "Laravel/Angular (XSRF)"),
    ("laravel_session", "Laravel"),
    ("ci_session", "CodeIgniter"),
    ("PHPSESSID", "PHP"),
    ("JSESSIONID", "Java/Servlet"),
    ("ASP.NET_SessionId", "ASP.NET"),
    ("wp-settings-", "WordPress"),
    ("wordpress_logged_in", "WordPress"),
    ("typo3-", "TYPO3"),
    ("frontend_typo", "TYPO3"),
    ("magento", "Magento"),
    ("shopware", "Shopware"),
    ("OptanonConsent", "OneTrust (Consent)"),
    ("CookieConsent", "Cookiebot"),
    ("_ga", "Google Analytics"),
    ("_fbp", "Facebook Pixel"),
    ("__cf_bm", "Cloudflare Bot Management"),
    ("cfduid", "Cloudflare"),
]

_SCRIPT_PATTERNS: list[tuple[str, str]] = [
    ("/_next/static/", "Next.js"),
    ("/_nuxt/", "Nuxt.js"),
    ("/wp-includes/", "WordPress"),
    ("/wp-content/", "WordPress"),
    ("/typo3temp/", "TYPO3"),
    ("/sites/default/files/", "Drupal"),
    ("/skin/frontend/", "Magento"),
    ("/static/version", "Magento 2"),
    ("/build/_buildManifest", "Next.js"),
    ("/_app-", "Next.js (app router)"),
    ("react-dom", "React"),
    ("/vue.runtime", "Vue.js"),
    ("/vue.global", "Vue.js"),
    ("@angular/core", "Angular"),
    ("svelte/internal", "Svelte"),
    ("turbopack", "Turbopack/Next.js"),
    ("googletagmanager.com", "Google Tag Manager"),
    ("hotjar.com", "Hotjar"),
    ("intercom.io", "Intercom"),
    ("zendesk.com", "Zendesk"),
    ("/cdn-cgi/", "Cloudflare CDN"),
]

_BODY_CLASS_PATTERNS: list[tuple[str, str]] = [
    ("wp-", "WordPress"),
    ("page-template", "WordPress"),
    ("typo3", "TYPO3"),
    ("drupal", "Drupal"),
    ("joomla", "Joomla"),
]

_HEADER_PATTERNS: list[tuple[str, str, str]] = [
    # (header_name, value_substring or "*", tech_name)
    ("cf-ray", "*", "Cloudflare"),
    ("x-vercel-id", "*", "Vercel"),
    ("x-vercel-cache", "*", "Vercel"),
    ("server-timing", "vercel", "Vercel"),
    ("x-served-by", "*", "Fastly"),
    ("x-cache", "varnish", "Varnish"),
    ("x-amz-cf-id", "*", "AWS CloudFront"),
    ("x-amzn-requestid", "*", "AWS API Gateway"),
    ("x-azure-ref", "*", "Azure Front Door"),
    ("x-github-request-id", "*", "GitHub Pages"),
    ("x-pingback", "*", "WordPress (XML-RPC)"),
    ("x-shopify-stage", "*", "Shopify"),
    ("x-shopid", "*", "Shopify"),
    ("x-drupal-cache", "*", "Drupal"),
    ("x-typo3-parsetime", "*", "TYPO3"),
    ("x-magento-tags", "*", "Magento"),
]


def _extract_all_tech_signals(redirect_data: dict[str, Any]) -> list[dict[str, str]]:
    """Wandelt Playwright-`redirect_data` in eine webtech-aehnliche Liste um.

    Wappalyzer-Lite: prueft Cookies, Script-URLs, Body-Classes, Meta-Tags
    und Response-Headers gegen ein bewaehrtes Pattern-Set. Liefert auch
    bei modernen SPAs (Next.js, Vue, Vercel) konkrete Tech-Eintraege —
    vorher kam dort nur "no data".
    """
    seen: set[str] = set()
    tech_list: list[dict[str, str]] = []

    def _add(name: str, version: str = "") -> None:
        key = name.strip().lower()
        if key and key not in seen:
            seen.add(key)
            tech_list.append({"name": name, "version": version})

    for fqdn_key, probe in (redirect_data or {}).items():
        tech_info = probe.get("tech_info") or {}
        headers = probe.get("response_headers") or {}

        # 1. generator + powered_by + server (klassisch)
        if tech_info.get("generator"):
            _add(tech_info["generator"])
        srv = headers.get("server", "")
        if srv:
            parts = srv.split("/", 1)
            _add(parts[0], parts[1] if len(parts) > 1 else "")
        powered = headers.get("x-powered-by", "") or tech_info.get("powered_by", "")
        if powered:
            _add(powered)

        # 2. Cookies (Framework / CMS)
        cookies = (tech_info.get("cookies") or "").lower()
        if cookies:
            for pat, name in _COOKIE_PATTERNS:
                if pat.lower() in cookies:
                    _add(name)

        # 3. Scripts (Framework / 3rd-Party)
        for src in tech_info.get("scripts") or []:
            src_l = (src or "").lower()
            for pat, name in _SCRIPT_PATTERNS:
                if pat in src_l:
                    _add(name)

        # 4. Body-Classes (CMS)
        body_classes = (tech_info.get("body_classes") or "").lower()
        if body_classes:
            for pat, name in _BODY_CLASS_PATTERNS:
                if pat in body_classes:
                    _add(name)

        # 5. Header-Patterns (CDN / Hosting / CMS-Footprint)
        headers_l = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
        for h_name, h_val, name in _HEADER_PATTERNS:
            v = headers_l.get(h_name, "")
            if v and (h_val == "*" or h_val in v):
                _add(name)

    return tech_list


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


def run_nmap(ip: str, scan_dir: str, order_id: str, nmap_ports: str = "--top-ports 1000") -> dict[str, Any]:
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
        "nmap",
        # ── Discovery ──────────────────────────────────────────────────
        # `-Pn` skip ICMP-Ping; wir wissen aus phase0 web_probe dass der
        # Host lebt. Spart 1-3s pro Host und vermeidet false-negative
        # bei ICMP-blockenden Firewalls.
        "-Pn",
        # `-n` keine reverse-DNS-Resolution waehrend Scan (haben wir
        # bereits aus phase0 / merge_and_group). Spart oft 5-10s.
        "-n",
        # ── Service-Detection ─────────────────────────────────────────
        "-sV",
        # `--version-intensity 7` (Default 7, aber explizit fuer Determinismus)
        # `--version-light` waere schneller aber ungenauer; lassen wir bei
        # 7 fuer Compliance-/Insurance-Pakete; fuer WebCheck reicht 5.
        "--version-intensity", "7",
        # ── NSE Scripts ───────────────────────────────────────────────
        # `-sC` lädt default-Scripts. Wir kappen pro Script auf 60s damit
        # ein langsames NSE (z.B. http-enum) nicht den ganzen Scan blockt.
        "-sC",
        "--script-timeout", "60s",
        # ── Performance / Reliability ─────────────────────────────────
        "-T4",
        # `--max-retries 2` reduziert default 10 → 2; verhindert dass
        # gefilterte Ports den Scan auf Minuten ziehen. Mit `-T4` ohnehin
        # schon aggressiv.
        "--max-retries", "2",
        # `--host-timeout` haerter als run_tool-Timeout (300s), damit
        # nmap selbst kontrolliert abbricht und einen partial-XML schreibt
        # statt SIGKILL ohne Output.
        "--host-timeout", "240s",
        # `--min-rate 100` garantiert Mindest-Paket-Rate; auf gefilterten
        # Hosts (das was du gepostet hast: "997 filtered tcp ports
        # no-response") laeuft sonst der Scan fast leer.
        "--min-rate", "100",
        # `--defeat-rst-ratelimit` umgeht RST-Throttling vieler Firewalls
        # (Cisco/Fortinet) → mehr offene Ports detektiert.
        "--defeat-rst-ratelimit",
        # ── Ports ──────────────────────────────────────────────────────
        *nmap_port_args,
        # ── Output ─────────────────────────────────────────────────────
        "--open",  # nur offene Ports im NORMAL-Output (XML hat alles)
        "-oX", xml_path,
        "-oN", txt_path,
        # `--reason` zeigt warum nmap eine Port-Klassifikation getroffen
        # hat (syn-ack, no-response, ...) — gut fuer KI-Korrelation.
        "--reason",
        ip,
    ]

    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=300,
        output_path=xml_path,
        order_id=order_id,
        host_ip=ip,
        phase=1,
        tool_name="nmap",
    )

    if exit_code != 0:
        log.warning("nmap_failed", ip=ip, exit_code=exit_code)
        return {"open_ports": [], "services": []}

    return _parse_nmap_xml(xml_path)


def run_webtech(fqdn: str, host_dir: str, order_id: str) -> dict[str, Any]:
    """Run webtech to detect web technologies.

    Captures stdout as JSON and saves to host_dir/phase1/webtech.json.
    Returns tech dict.
    """
    phase1_dir = f"{host_dir}/phase1"
    os.makedirs(phase1_dir, exist_ok=True)

    output_path = f"{phase1_dir}/webtech.json"

    # Try HTTPS first, fall back to HTTP if it fails
    for scheme in ("https", "http"):
        url = f"{scheme}://{fqdn}"
        cmd = [
            "webtech", "-u", url, "--json",
            # User-Agent setzen damit WAF nicht "python-requests" blockt
            "--user-agent", "Mozilla/5.0 vectiscan",
            # Verbose ausschalten (sonst stderr zumuellt)
            "--quiet",
        ]

        webtech_proc = None
        try:
            webtech_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            stdout, stderr = webtech_proc.communicate(timeout=60)

            if stderr:
                log.debug("webtech_stderr", fqdn=fqdn, scheme=scheme, stderr=stderr[:300])

            if stdout:
                tech_data = json.loads(stdout)
                with open(output_path, "w") as f:
                    json.dump(tech_data, f, indent=2)
                log.info("webtech_complete", fqdn=fqdn, scheme=scheme,
                         techs=len(tech_data) if isinstance(tech_data, list) else 1)
                return tech_data

            # No stdout — try next scheme
            log.warning("webtech_no_output", fqdn=fqdn, scheme=scheme)
            continue

        except subprocess.TimeoutExpired:
            log.warning("webtech_timeout", fqdn=fqdn, scheme=scheme)
            if webtech_proc is not None:
                try:
                    os.killpg(webtech_proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    webtech_proc.kill()
                webtech_proc.wait()
            continue  # try next scheme
        except json.JSONDecodeError as e:
            log.warning("webtech_json_error", fqdn=fqdn, scheme=scheme, error=str(e))
            continue  # try next scheme
        except Exception as e:
            log.error("webtech_error", fqdn=fqdn, scheme=scheme, error=str(e))
            continue  # try next scheme

    # Both schemes failed
    log.warning("webtech_all_schemes_failed", fqdn=fqdn)
    return {}


def run_wafw00f(fqdn: str, ip: str, host_dir: str, order_id: str) -> Optional[dict[str, Any]]:
    """Run wafw00f to detect WAF.

    Returns WAF info dict or None if no WAF detected.
    """
    phase1_dir = f"{host_dir}/phase1"
    os.makedirs(phase1_dir, exist_ok=True)

    output_path = f"{phase1_dir}/wafw00f.json"

    cmd = [
        "wafw00f", fqdn,
        # `-a` = "scan ALL detections, don't stop on first" — wichtig fuer
        # Multi-WAF-Setups (z.B. CloudFlare vor F5 oder ModSecurity hinter
        # nginx). Default stoppt nach erstem Treffer und untergewichtet.
        "-a",
        "-o", output_path, "-f", "json",
    ]

    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=60,
        output_path=output_path,
        order_id=order_id,
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

    # CMS detection via fingerprinting engine (replaces old webtech+fallback logic)
    cms = None
    cms_version = None
    cms_confidence = 0.0
    cms_details: dict[str, Any] = {}
    primary_fqdn = fqdns[0] if fqdns else None

    if primary_fqdn:
        fingerprinter = CMSFingerprinter(max_requests=20)
        cms_result: CMSResult = fingerprinter.fingerprint(primary_fqdn, webtech_result=webtech_result)
        if cms_result.cms and cms_result.confidence >= 0.5:
            cms = cms_result.cms
            cms_version = cms_result.version
            cms_confidence = cms_result.confidence
            cms_details = cms_result.to_dict()
    else:
        # No FQDN — fall back to webtech-only
        if isinstance(webtech_result, dict):
            techs = webtech_result.get("tech", [])
        elif isinstance(webtech_result, list):
            techs = webtech_result
        else:
            techs = []
        cms_names = {"wordpress", "joomla", "drupal", "typo3", "magento", "shopify",
                      "shopware", "wix", "prestashop", "contao", "neos", "craft", "strapi", "ghost"}
        for tech in techs:
            if isinstance(tech, dict):
                name = tech.get("name", "").lower()
                if name in cms_names:
                    cms = tech.get("name")
                    cms_version = tech.get("version")
                    break
            elif isinstance(tech, str) and tech.lower() in cms_names:
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
        "cms_confidence": cms_confidence,
        "cms_details": cms_details,
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
    order_id: str,
    progress_callback: Callable[[str, str, str], None],
    config: dict[str, Any] | None = None,
    web_probe: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Orchestrate Phase 1 (technology detection) for a single host.

    Args:
        ip: Host IP address.
        fqdns: List of FQDNs resolving to this IP.
        scan_dir: Base scan directory (e.g. /tmp/scan-<orderId>).
        order_id: Order UUID.
        progress_callback: Called after each tool with (order_id, tool_name, status).
        config: Package configuration dict (optional).
        web_probe: Phase 0 web_probe data with final_url for redirect-aware probing.

    Returns:
        Tech profile dict for this host.
    """
    nmap_ports = config["nmap_ports"] if config else "--top-ports 1000"

    host_dir = f"{scan_dir}/hosts/{ip}"
    phase1_dir = f"{host_dir}/phase1"
    os.makedirs(phase1_dir, exist_ok=True)

    log.info("phase1_start", ip=ip, fqdns=fqdns, order_id=order_id)

    phase1_tools = (config or {}).get("phase1_tools", ["nmap", "webtech", "wafw00f", "cms_fingerprint"])

    # Run nmap
    publish_event(order_id, {"type": "tool_starting", "tool": "nmap", "host": ip})
    nmap_result = run_nmap(ip, scan_dir, order_id, nmap_ports)
    progress_callback(order_id, "nmap", "complete")

    # Use the most relevant FQDN for web tools (base domain > www > subdomains > mail)
    # fqdns list is already sorted by relevance from phase0
    primary_fqdn = fqdns[0] if fqdns else ip

    # Probe multiple non-mail FQDNs to detect different services per IP
    from scanner.phase0 import _is_mail_only_fqdn
    probe_fqdns = [f for f in fqdns if not _is_mail_only_fqdn(f)][:3]
    if not probe_fqdns:
        probe_fqdns = [primary_fqdn]

    # Use Playwright tech detection instead of webtech (which fails on all domains)
    from scanner.tools.redirect_probe import probe_redirects, _is_playwright_available
    webtech_result: list[dict] | dict | None = None
    if "webtech" in phase1_tools:
        publish_event(order_id, {"type": "tool_starting", "tool": "webtech", "host": ip})
        if _is_playwright_available():
            try:
                pw_fqdns = [f for f in fqdns[:8] if f]  # Screenshot + tech probe per FQDN
                # Build web_probe URL map: use Phase 0 final_url if it redirected
                wp_urls: dict[str, str] = {}
                if web_probe and web_probe.get("final_url"):
                    wp_fqdn = web_probe.get("web_fqdn", "")
                    wp_final = web_probe["final_url"]
                    if wp_fqdn and wp_final:
                        wp_urls[wp_fqdn] = wp_final
                redirect_data = probe_redirects(
                    pw_fqdns, order_id=order_id,
                    scan_dir=scan_dir, ip=ip,
                    web_probe_urls=wp_urls if wp_urls else None,
                )
                # Convert Playwright tech_info to webtech-compatible format.
                # Frueher haben wir nur generator/Server/X-Powered-By gelesen
                # — das laesst moderne SPAs (Next.js auf Vercel, etc.) ohne
                # Tech-Erkennung dastehen, weil die diese Header gar nicht
                # senden. Wir nutzen jetzt zusaetzlich scripts, cookies,
                # meta_tags, body_classes + Header-Signaturen (cf-ray etc.)
                # — Wappalyzer-style.
                tech_list = _extract_all_tech_signals(redirect_data)
                if tech_list:
                    webtech_result = {"tech": tech_list}
            except Exception as e:
                log.warning("playwright_tech_failed", error=str(e))
        else:
            log.info("playwright_not_available", msg="Falling back to no webtech data")
        progress_callback(order_id, "webtech", "complete")

        # Save webtech result to scan_results
        from scanner.tools import _save_result
        _save_result(order_id=order_id, host_ip=ip, phase=1,
                     tool_name="webtech",
                     raw_output=json.dumps(webtech_result, indent=2, ensure_ascii=False) if webtech_result
                         else (
                             f"Keine Tech-Signaturen erkennbar fuer {', '.join(probe_fqdns)} "
                             "(moderne SPA ohne Server/X-Powered-By/generator-Header und "
                             "ohne Cookie-/Script-/Header-Pattern-Match). "
                             "Phase 2 (httpx -tech-detect, nuclei) liefert weitere Signale."
                         ),
                     exit_code=0 if webtech_result else 1,
                     duration_ms=0)

    # Run wafw00f on primary FQDN
    wafw00f_result = None
    if "wafw00f" in phase1_tools:
        publish_event(order_id, {"type": "tool_starting", "tool": "wafw00f", "host": ip})
        wafw00f_result = run_wafw00f(primary_fqdn, ip, host_dir, order_id)
        progress_callback(order_id, "wafw00f", "complete")

    # wafw00f already saved to scan_results by run_tool() inside run_wafw00f()

    # Build combined tech profile
    tech_profile = build_tech_profile(
        ip=ip,
        fqdns=fqdns,
        nmap_result=nmap_result,
        webtech_result=webtech_result,
        wafw00f_result=wafw00f_result,
        host_dir=host_dir,
    )

    # Save redirect data for later use (AI Tech Analysis, CMS fingerprinter)
    if _is_playwright_available():
        try:
            tech_profile["redirect_data"] = redirect_data  # type: ignore[possibly-undefined]
        except NameError:
            pass  # redirect_data not set if Playwright failed

    log.info("phase1_complete", ip=ip, order_id=order_id)
    return tech_profile
