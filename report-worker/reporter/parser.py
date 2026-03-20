"""Tool-Output-Parser — JSON/XML → strukturierte Findings."""

from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger()

# Severity ordering for sorting (lower number = more severe).
_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "critical": 0,
    "HIGH": 1,
    "high": 1,
    "MEDIUM": 2,
    "medium": 2,
    "WARN": 2,
    "LOW": 3,
    "low": 3,
    "INFO": 4,
    "info": 4,
    "unknown": 5,
}


def _severity_key(severity: str) -> int:
    """Return sort key for a severity string (lower = more severe)."""
    return _SEVERITY_ORDER.get(severity, 5)


def _read_json(path: str) -> Any:
    """Read and parse a JSON file.  Returns ``None`` on any error."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        log.warning("file_not_found", path=path)
        return None
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("json_parse_error", path=path, error=str(exc))
        return None


# ---------------------------------------------------------------------------
# Individual tool parsers
# ---------------------------------------------------------------------------


def parse_nmap_xml(path: str) -> dict[str, Any]:
    """Parse nmap XML output into structured dict.

    Returns::

        {
            "open_ports": [{"port": 80, "protocol": "tcp", "service": "http",
                            "product": "nginx", "version": "1.24.0"}],
            "os_detection": "...",
            "summary": "3 open ports: 22/ssh, 80/http, 443/https"
        }

    On missing or invalid files, returns ``{"open_ports": []}``.
    """
    empty: dict[str, Any] = {"open_ports": []}

    try:
        tree = ET.parse(path)  # noqa: S314 – trusted local file
    except FileNotFoundError:
        log.warning("file_not_found", path=path)
        return empty
    except (ET.ParseError, OSError) as exc:
        log.warning("nmap_xml_parse_error", path=path, error=str(exc))
        return empty

    root = tree.getroot()
    open_ports: list[dict[str, Any]] = []

    for host_el in root.findall(".//host"):
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            service_el = port_el.find("service")
            entry: dict[str, Any] = {
                "port": int(port_el.get("portid", "0")),
                "protocol": port_el.get("protocol", "tcp"),
                "service": (
                    service_el.get("name", "unknown")
                    if service_el is not None
                    else "unknown"
                ),
                "product": (
                    service_el.get("product", "")
                    if service_el is not None
                    else ""
                ),
                "version": (
                    service_el.get("version", "")
                    if service_el is not None
                    else ""
                ),
            }
            open_ports.append(entry)

    result: dict[str, Any] = {"open_ports": open_ports}

    # OS detection — take the <osmatch> with the highest accuracy.
    os_matches = root.findall(".//osmatch")
    if os_matches:
        best = max(os_matches, key=lambda m: int(m.get("accuracy", "0")))
        result["os_detection"] = best.get("name", "")
    else:
        result["os_detection"] = ""

    # Human-readable summary
    if open_ports:
        port_strs = [f"{p['port']}/{p['service']}" for p in open_ports]
        result["summary"] = (
            f"{len(open_ports)} open ports: {', '.join(port_strs)}"
        )
    else:
        result["summary"] = "No open ports detected"

    log.info("nmap_parsed", path=path, open_ports=len(open_ports))
    return result


def parse_nuclei_json(path: str) -> list[dict[str, Any]]:
    """Parse nuclei JSONL output (one JSON object per line).

    Returns list of finding dicts sorted by severity (critical first).
    Each dict contains::

        {
            "template_id": "...",
            "name": "...",
            "severity": "high",
            "matched_at": "https://...",
            "description": "...",
            "reference": ["..."],
            "tool": "nuclei"
        }
    """
    findings: list[dict[str, Any]] = []

    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line_num, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as exc:
                    log.warning(
                        "nuclei_line_parse_error",
                        path=path,
                        line=line_num,
                        error=str(exc),
                    )
                    continue

                info = obj.get("info", {})
                findings.append(
                    {
                        "template_id": obj.get(
                            "template-id", obj.get("templateID", "")
                        ),
                        "name": info.get("name", obj.get("name", "")),
                        "severity": info.get(
                            "severity", obj.get("severity", "unknown")
                        ),
                        "matched_at": obj.get(
                            "matched-at", obj.get("matched", "")
                        ),
                        "description": info.get("description", ""),
                        "reference": info.get("reference", []),
                        "tool": "nuclei",
                    }
                )
    except FileNotFoundError:
        log.warning("file_not_found", path=path)
        return []
    except OSError as exc:
        log.warning("nuclei_read_error", path=path, error=str(exc))
        return []

    findings.sort(key=lambda f: _severity_key(f.get("severity", "unknown")))
    log.info("nuclei_parsed", path=path, findings=len(findings))
    return findings


def parse_testssl_json(path: str) -> list[dict[str, Any]]:
    """Parse testssl.sh JSON output.

    Filters out findings whose severity is ``OK`` or ``INFO`` — only actual
    issues (WARN, LOW, MEDIUM, HIGH, CRITICAL) are returned.

    Returns list of::

        {"id": "...", "severity": "...", "finding": "..."}
    """
    data = _read_json(path)
    if data is None:
        return []

    # testssl output can be a bare list or a dict wrapping one.
    items: list[Any]
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        # Flatten all lists found at the top level.
        items = []
        for val in data.values():
            if isinstance(val, list):
                items.extend(
                    entry for entry in val if isinstance(entry, dict)
                )
    else:
        log.warning("testssl_unexpected_format", path=path)
        return []

    skip_severities = {"OK", "ok", "INFO", "info"}
    findings: list[dict[str, Any]] = []

    for item in items:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity", ""))
        if severity in skip_severities or not severity:
            continue
        findings.append(
            {
                "id": item.get("id", ""),
                "severity": severity,
                "finding": item.get("finding", ""),
            }
        )

    findings.sort(key=lambda f: _severity_key(f.get("severity", "unknown")))
    log.info("testssl_parsed", path=path, findings=len(findings))
    return findings


def parse_nikto_json(path: str) -> list[dict[str, Any]]:
    """Parse nikto JSON output.

    Returns list of::

        {"id": "...", "msg": "...", "url": "...", "method": "..."}
    """
    data = _read_json(path)
    if data is None:
        return []

    # nikto JSON can be a single object or a list of host results.
    host_results: list[dict[str, Any]]
    if isinstance(data, list):
        host_results = [d for d in data if isinstance(d, dict)]
    elif isinstance(data, dict):
        host_results = [data]
    else:
        return []

    vulns: list[dict[str, Any]] = []
    for host_result in host_results:
        for v in host_result.get("vulnerabilities", []):
            if not isinstance(v, dict):
                continue
            vulns.append(
                {
                    "id": str(v.get("id", v.get("OSVDB", ""))),
                    "msg": v.get("msg", v.get("message", "")),
                    "url": v.get("url", v.get("uri", "")),
                    "method": v.get("method", "GET"),
                }
            )

    log.info("nikto_parsed", path=path, vulnerabilities=len(vulns))
    return vulns


def parse_zap_alerts_json(path: str) -> list[dict[str, Any]]:
    """Parse OWASP ZAP alerts JSON output.

    Returns list of alert dicts sorted by severity.
    """
    _SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
    _RISK_MAP = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}

    data = _read_json(path)
    if data is None:
        return []

    alerts_raw = data if isinstance(data, list) else data.get("alerts", [])
    alerts: list[dict[str, Any]] = []
    for a in alerts_raw:
        severity = _RISK_MAP.get(a.get("risk", "Informational"), "info")
        alerts.append({
            "name": a.get("name", a.get("alert", "")),
            "severity": severity,
            "description": a.get("description", "")[:300],
            "url": a.get("url", ""),
            "cweid": a.get("cweid", ""),
            "solution": a.get("solution", "")[:300],
            "evidence": a.get("evidence", ""),
            "confidence": a.get("confidence", ""),
            "method": a.get("method", ""),
            "param": a.get("param", ""),
        })

    alerts.sort(key=lambda x: _SEVERITY_ORDER.get(x.get("severity", "info"), 3))
    log.info("zap_parsed", path=path, alerts=len(alerts))
    return alerts


def parse_headers_json(path: str) -> dict[str, Any]:
    """Parse security headers analysis JSON.

    Returns::

        {
            "url": "...",
            "score": "3/7",
            "missing": ["strict-transport-security", ...],
            "present": ["x-frame-options", ...],
            "details": {...}
        }

    On missing / malformed files returns a dict with empty defaults.
    """
    default: dict[str, Any] = {
        "url": "",
        "score": "0/0",
        "missing": [],
        "present": [],
        "details": {},
    }

    data = _read_json(path)
    if data is None:
        return default

    result: dict[str, Any] = {
        "url": data.get("url", ""),
        "details": data,
    }

    # The seven standard security headers we evaluate.
    security_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "x-xss-protection",
        "referrer-policy",
        "permissions-policy",
    ]

    # Determine which dict contains the actual header evaluation.
    raw_headers: dict[str, Any]
    if isinstance(data.get("security_headers"), dict):
        raw_headers = data["security_headers"]
    elif isinstance(data.get("headers"), dict):
        raw_headers = data["headers"]
    else:
        # Treat the whole file as a flat header->value mapping.
        raw_headers = data

    # Build a lowercase lookup of keys that are marked present.
    # If entries are dicts with a "present" boolean, use that; otherwise
    # assume a key's mere existence means it is present.
    present_lower: set[str] = set()
    for key, val in raw_headers.items():
        k_lower = str(key).lower()
        if isinstance(val, dict):
            if val.get("present", False):
                present_lower.add(k_lower)
        else:
            present_lower.add(k_lower)

    missing: list[str] = []
    present: list[str] = []
    for hdr in security_headers:
        if hdr in present_lower:
            present.append(hdr)
        else:
            missing.append(hdr)

    result["missing"] = missing
    result["present"] = present
    result["score"] = f"{len(present)}/{len(security_headers)}"

    log.info("headers_parsed", path=path, score=result["score"])
    return result


def find_gowitness_screenshots(phase2_dir: str) -> list[str]:
    """Find screenshot files (PNG/JPEG) in a phase2 directory.

    Looks for image files produced by Playwright (or legacy gowitness).
    Common locations:
    - ``<phase2>/gowitness/screenshots/*.png``
    - ``<phase2>/gowitness/*.png``
    - ``<phase2>/screenshots/*.png``
    - ``<phase2>/screenshot_*.png`` (Playwright output, fallback)

    Returns:
        Sorted list of absolute file paths to screenshot images.
    """
    phase2_path = Path(phase2_dir)
    image_extensions = {".png", ".jpg", ".jpeg"}
    screenshots: list[str] = []

    # Priority search locations
    search_dirs = [
        phase2_path / "gowitness" / "screenshots",
        phase2_path / "gowitness",
        phase2_path / "screenshots",
    ]

    for search_dir in search_dirs:
        if search_dir.is_dir():
            for f in sorted(search_dir.iterdir()):
                if f.is_file() and f.suffix.lower() in image_extensions:
                    screenshots.append(str(f))
            if screenshots:
                break  # Stop at the first directory that has screenshots

    # Fallback: look for screenshot*.png directly in phase2 (Playwright output)
    if not screenshots:
        for f in sorted(phase2_path.iterdir()):
            if (
                f.is_file()
                and f.suffix.lower() in image_extensions
                and f.stem.lower().startswith("screenshot")
            ):
                screenshots.append(str(f))

    if screenshots:
        log.info(
            "gowitness_screenshots_found",
            dir=phase2_dir,
            count=len(screenshots),
        )
    else:
        log.debug("no_gowitness_screenshots", dir=phase2_dir)

    return screenshots


def parse_httpx(httpx_data: dict | None) -> dict[str, Any]:
    """Parse httpx probe results."""
    if not httpx_data:
        return {}
    return {
        "status_code": httpx_data.get("status_code"),
        "title": httpx_data.get("title", ""),
        "server": httpx_data.get("webserver", ""),
        "technologies": httpx_data.get("tech", []),
        "content_length": httpx_data.get("content_length"),
        "final_url": httpx_data.get("url", ""),
    }


def parse_katana(urls: list[str]) -> dict[str, Any]:
    """Parse katana crawler results."""
    if not urls:
        return {}

    # Categorize discovered URLs
    interesting = []
    forms = []
    api_endpoints = []

    for url in urls:
        lower = url.lower()
        if any(kw in lower for kw in ["/admin", "/login", "/wp-admin", "/config", "/backup", "/.env", "/.git"]):
            interesting.append(url)
        elif any(kw in lower for kw in ["/api/", "/graphql", "/rest/", "/v1/", "/v2/"]):
            api_endpoints.append(url)
        elif "?" in url:
            forms.append(url)

    return {
        "total_urls": len(urls),
        "interesting_paths": interesting[:20],  # Cap at 20
        "api_endpoints": api_endpoints[:20],
        "parameterized_urls": forms[:20],
    }


def parse_wpscan(wpscan_data: dict | None) -> dict[str, Any]:
    """Parse WPScan results."""
    if not wpscan_data:
        return {}

    wp_version = wpscan_data.get("version", {})
    plugins = wpscan_data.get("plugins", {})
    themes = wpscan_data.get("themes", {})
    users = wpscan_data.get("users", {})
    interesting = wpscan_data.get("interesting_findings", [])

    # Extract vulnerable plugins
    vulnerable_plugins = []
    for name, info in plugins.items():
        vulns = info.get("vulnerabilities", [])
        if vulns:
            vulnerable_plugins.append({
                "name": name,
                "version": info.get("version", {}).get("number", "unknown"),
                "vulnerabilities": [
                    {"title": v.get("title", ""), "cve": v.get("references", {}).get("cve", []), "fixed_in": v.get("fixed_in")}
                    for v in vulns
                ],
            })

    # Extract vulnerable themes
    vulnerable_themes = []
    for name, info in themes.items():
        vulns = info.get("vulnerabilities", [])
        if vulns:
            vulnerable_themes.append({
                "name": name,
                "version": info.get("version", {}).get("number", "unknown"),
                "vulnerabilities": [
                    {"title": v.get("title", ""), "cve": v.get("references", {}).get("cve", [])}
                    for v in vulns
                ],
            })

    return {
        "wordpress_version": wp_version.get("number", "unknown") if isinstance(wp_version, dict) else str(wp_version),
        "wp_version_vulnerable": wp_version.get("status", "") == "insecure" if isinstance(wp_version, dict) else False,
        "plugins_found": len(plugins),
        "vulnerable_plugins": vulnerable_plugins,
        "themes_found": len(themes),
        "vulnerable_themes": vulnerable_themes,
        "users_found": list(users.keys()) if isinstance(users, dict) else [],
        "interesting_findings": [
            {"url": f.get("url", ""), "type": f.get("type", ""), "description": ", ".join(f.get("interesting_entries", []))}
            for f in interesting
        ],
    }


def parse_gobuster_dir(path: str) -> list[str]:
    """Parse gobuster directory scan output.

    Returns list of discovered paths / URLs.
    """
    paths: list[str] = []

    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # gobuster dir lines look like:
                #   /admin                (Status: 200) [Size: 1234]
                # With -q only the path is printed.
                token = line.split()[0] if line.split() else line
                if token.startswith("/") or token.startswith("http"):
                    paths.append(token)
    except FileNotFoundError:
        log.warning("file_not_found", path=path)
    except OSError as exc:
        log.warning("gobuster_dir_read_error", path=path, error=str(exc))

    log.info("gobuster_dir_parsed", path=path, discovered_paths=len(paths))
    return paths


# ---------------------------------------------------------------------------
# Consolidation helpers
# ---------------------------------------------------------------------------


def _consolidate_findings(all_findings: list[dict[str, Any]]) -> str:
    """Deduplicate, sort by severity, and format all findings into readable
    text grouped by host.

    This is used internally to collapse individually-parsed findings into a
    flat text block suitable for the Claude prompt.  Each finding dict should
    carry a ``"host"`` key (set during ``parse_scan_data``).
    """
    # --- Deduplicate ---
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []

    for f in all_findings:
        tool = f.get("tool", "unknown")
        title = (
            f.get("name")
            or f.get("template_id")
            or f.get("finding")
            or f.get("msg")
            or f.get("id", "")
        )
        key = (tool, title)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    # --- Sort by severity ---
    unique.sort(key=lambda f: _severity_key(f.get("severity", "unknown")))

    # --- Group by host ---
    by_host: dict[str, list[dict[str, Any]]] = {}
    for f in unique:
        host = f.get("host", "global")
        by_host.setdefault(host, []).append(f)

    # --- Format ---
    sections: list[str] = []

    for host, findings in by_host.items():
        lines: list[str] = [f"=== Host: {host} ==="]
        for f in findings:
            tool = f.get("tool", "unknown")
            severity = f.get("severity", "unknown").upper()
            title = (
                f.get("name")
                or f.get("template_id")
                or f.get("finding")
                or f.get("msg")
                or f.get("id", "")
            )
            lines.append(f"  [{severity}] ({tool}) {title}")

            if f.get("matched_at"):
                lines.append(f"    matched-at: {f['matched_at']}")
            if f.get("description"):
                lines.append(f"    description: {f['description']}")
            if f.get("reference"):
                refs = f["reference"]
                if isinstance(refs, list):
                    refs = ", ".join(str(r) for r in refs)
                lines.append(f"    reference: {refs}")
            if f.get("cve"):
                lines.append(f"    CVE: {f['cve']}")
            if f.get("cwe"):
                lines.append(f"    CWE: {f['cwe']}")
            if f.get("finding") and f.get("tool") != "unknown":
                lines.append(f"    detail: {f['finding']}")
            if f.get("msg"):
                lines.append(f"    detail: {f['msg']}")
            if f.get("url"):
                lines.append(f"    url: {f['url']}")

            lines.append("")  # blank line between findings

        sections.append("\n".join(lines))

    return "\n\n".join(sections)


def consolidate_findings(
    host_results: dict[str, dict[str, Any]],
    dns_records: dict[str, Any],
) -> str:
    """Consolidate all per-host tool outputs into a single text string for
    the Claude prompt.

    Groups findings by host with clear section headers, including:
    - Nmap port scan summary per host
    - Nuclei vulnerability findings per host
    - SSL/TLS issues from testssl per host
    - Nikto web findings per host
    - Security header analysis per host
    - Discovered directories per host
    - DNS findings (SPF, DMARC, DKIM, zone transfer)

    Returns a formatted text string suitable for the Claude API prompt.
    """
    sections: list[str] = []

    for ip, data in host_results.items():
        fqdns = data.get("fqdns", [])
        host_label = f"{ip} ({', '.join(fqdns)})" if fqdns else ip
        lines: list[str] = [
            "=" * 72,
            f"HOST: {host_label}",
            "=" * 72,
        ]

        # === Section order: most important first, most verbose last ===
        # 1. nmap (ports), 2. nuclei (CVEs), 3. testssl (SSL/TLS),
        # 4. wpscan (WordPress vulns), 5. nikto (legacy),
        # 6. headers (security headers), 7. httpx, 8. katana,
        # 9. gobuster, 10. ZAP (most verbose — LAST), 11. Endpoints (also verbose)

        # --- 1. Nmap ---
        nmap = data.get("nmap", {})
        if nmap.get("open_ports") or nmap.get("summary"):
            lines.append("")
            lines.append("--- PORT SCAN (nmap) ---")
            if nmap.get("summary"):
                lines.append(nmap["summary"])
            if nmap.get("os_detection"):
                lines.append(f"OS Detection: {nmap['os_detection']}")
            for p in nmap.get("open_ports", []):
                product_str = f" {p['product']}" if p.get("product") else ""
                version_str = f" {p['version']}" if p.get("version") else ""
                lines.append(
                    f"  {p['port']}/{p['protocol']}  "
                    f"{p['service']}{product_str}{version_str}"
                )

        # --- 2. Nuclei (sorted by severity) ---
        nuclei = data.get("nuclei", [])
        if nuclei:
            nuclei_sorted = sorted(
                nuclei,
                key=lambda f: _severity_key(f.get("severity", "unknown")),
            )
            lines.append("")
            lines.append("--- VULNERABILITY SCAN (nuclei) ---")
            for finding in nuclei_sorted:
                sev = finding.get("severity", "unknown").upper()
                name = finding.get("name") or finding.get("template_id", "")
                lines.append(f"  [{sev}] {name}")
                if finding.get("matched_at"):
                    lines.append(f"    URL: {finding['matched_at']}")
                if finding.get("description"):
                    lines.append(f"    {finding['description']}")
                if finding.get("reference"):
                    refs = finding["reference"]
                    if isinstance(refs, list):
                        lines.append(f"    Refs: {', '.join(refs[:3])}")

        # --- 3. testssl ---
        testssl = data.get("testssl", [])
        if testssl:
            lines.append("")
            lines.append("--- SSL/TLS ANALYSIS (testssl.sh) ---")
            # Only show MEDIUM+ findings in detail, summarize LOW/INFO
            important = [t for t in testssl if t.get("severity", "").lower() in ("high", "critical", "medium", "warn")]
            low_count = sum(1 for t in testssl if t.get("severity", "").lower() in ("low",))
            info_count = sum(1 for t in testssl if t.get("severity", "").lower() in ("ok", "info", ""))

            for item in sorted(important, key=lambda f: _severity_key(f.get("severity", "unknown"))):
                sev = item.get("severity", "").upper()
                lines.append(
                    f"  [{sev}] {item.get('id', '')}: "
                    f"{item.get('finding', '')}"
                )
            if low_count > 0:
                lines.append(f"  [{low_count} LOW findings omitted — cipher/protocol details]")
            if info_count > 0:
                lines.append(f"  [{info_count} INFO/OK checks passed]")

        # --- 4. wpscan (before nikto — WordPress vulns are high-value) ---
        wpscan = data.get("wpscan", {})
        if wpscan:
            lines.append("")
            lines.append("--- WORDPRESS SCAN (wpscan) ---")
            lines.append(f"  WordPress Version: {wpscan.get('wordpress_version', 'unknown')}")
            if wpscan.get("wp_version_vulnerable"):
                lines.append("  [WARNING] WordPress version is INSECURE")
            lines.append(f"  Plugins found: {wpscan.get('plugins_found', 0)}")
            for vp in wpscan.get("vulnerable_plugins", []):
                lines.append(f"  [VULN] Plugin: {vp['name']} ({vp.get('version', 'unknown')})")
                for v in vp.get("vulnerabilities", []):
                    lines.append(f"    - {v.get('title', '')}")
                    if v.get("cve"):
                        lines.append(f"      CVE: {', '.join(v['cve'])}")
            for vt in wpscan.get("vulnerable_themes", []):
                lines.append(f"  [VULN] Theme: {vt['name']} ({vt.get('version', 'unknown')})")
                for v in vt.get("vulnerabilities", []):
                    lines.append(f"    - {v.get('title', '')}")
            if wpscan.get("users_found"):
                lines.append(f"  Users enumerated: {', '.join(wpscan['users_found'])}")

        # --- 5. Nikto ---
        nikto = data.get("nikto", [])
        if nikto:
            lines.append("")
            lines.append("--- WEB VULNERABILITY SCAN (nikto) ---")
            for item in nikto:
                lines.append(
                    f"  [{item.get('method', 'GET')}] {item.get('url', '')}"
                )
                lines.append(f"    {item.get('msg', '')}")

        # --- 6. Security headers ---
        headers = data.get("headers", {})
        if headers.get("missing") or headers.get("present"):
            lines.append("")
            lines.append("--- SECURITY HEADERS ---")
            if headers.get("url"):
                lines.append(f"  URL: {headers['url']}")
            lines.append(f"  Score: {headers.get('score', 'N/A')}")
            if headers.get("present"):
                lines.append(f"  Present: {', '.join(headers['present'])}")
            if headers.get("missing"):
                lines.append(f"  Missing: {', '.join(headers['missing'])}")

        # --- 7. httpx ---
        httpx = data.get("httpx", {})
        if httpx:
            lines.append("")
            lines.append("--- HTTP PROBE (httpx) ---")
            if httpx.get("status_code"):
                lines.append(f"  Status: {httpx['status_code']}")
            if httpx.get("title"):
                lines.append(f"  Title: {httpx['title']}")
            if httpx.get("server"):
                lines.append(f"  Server: {httpx['server']}")
            if httpx.get("final_url"):
                lines.append(f"  Final URL: {httpx['final_url']}")
            if httpx.get("technologies"):
                lines.append(f"  Technologies: {', '.join(httpx['technologies'])}")

        # --- 8. katana ---
        katana = data.get("katana", {})
        if katana:
            lines.append("")
            lines.append("--- WEB CRAWLER (katana) ---")
            lines.append(f"  Total URLs discovered: {katana.get('total_urls', 0)}")
            if katana.get("interesting_paths"):
                lines.append("  Interesting paths:")
                for p in katana["interesting_paths"][:10]:
                    lines.append(f"    {p}")
            if katana.get("api_endpoints"):
                lines.append("  API endpoints:")
                for p in katana["api_endpoints"][:10]:
                    lines.append(f"    {p}")
            if katana.get("parameterized_urls"):
                lines.append(f"  Parameterized URLs: {len(katana['parameterized_urls'])}")

        # --- 9. Gobuster directories ---
        gobuster = data.get("gobuster_dir", [])
        if gobuster:
            lines.append("")
            lines.append("--- DISCOVERED DIRECTORIES (gobuster) ---")
            for p in gobuster[:50]:
                lines.append(f"  {p}")
            if len(gobuster) > 50:
                lines.append(f"  ... and {len(gobuster) - 50} more")

        # --- 10. ZAP Web Application Scan (most verbose — put LAST so truncation hits it first) ---
        zap = data.get("zap", [])
        if zap:
            lines.append("")
            lines.append("--- WEB APPLICATION SCAN (OWASP ZAP) ---")
            # Group by alert name to avoid duplicates
            alert_groups: dict[str, list] = {}
            for item in zap:
                name = item.get("name", item.get("alert", "unknown"))
                alert_groups.setdefault(name, []).append(item)

            lines.append(f"  {len(zap)} total alerts, {len(alert_groups)} unique types:")
            # Show each unique alert type once, with count
            for name, items in sorted(alert_groups.items(),
                                       key=lambda x: {"high":0,"medium":1,"low":2,"info":3}.get(x[1][0].get("severity","info"), 3)):
                sev = items[0].get("severity", "info").upper()
                count = len(items)
                urls = list(set(i.get("url","")[:60] for i in items[:3]))
                lines.append(f"  [{sev}] {name} ({count}x)")
                if items[0].get("cweid"):
                    lines.append(f"    CWE: {items[0]['cweid']}")
                for u in urls[:2]:
                    lines.append(f"    URL: {u}")

        # --- 11. Discovered Endpoints (ZAP Spider — also verbose) ---
        spider_urls = data.get("zap_spider_urls", [])
        if spider_urls:
            lines.append("")
            lines.append(f"--- DISCOVERED ENDPOINTS ({len(spider_urls)} URLs) ---")
            api_urls = [u for u in spider_urls if any(p in u for p in ("/api/", "/graphql", "/rest/", "/v1/", "/v2/"))]
            admin_urls = [u for u in spider_urls if any(p in u for p in ("/admin", "/login", "/auth", "/wp-admin"))]
            if api_urls:
                lines.append(f"  API-Endpoints ({len(api_urls)}):")
                for u in api_urls[:10]:
                    lines.append(f"    {u}")
                if len(api_urls) > 10:
                    lines.append(f"    ... und {len(api_urls) - 10} weitere")
            if admin_urls:
                lines.append(f"  Admin/Login ({len(admin_urls)}):")
                for u in admin_urls[:5]:
                    lines.append(f"    {u}")

        sections.append("\n".join(lines))

    # --- DNS section ---
    if dns_records:
        dns_lines: list[str] = [
            "",
            "=" * 72,
            "DNS RECORDS & FINDINGS",
            "=" * 72,
        ]
        for key in ("spf", "dmarc", "dkim", "mx", "ns"):
            val = dns_records.get(key)
            if val is not None:
                dns_lines.append(f"  {key.upper()}: {val}")

        zone = dns_records.get("zone_transfer")
        if zone is not None:
            dns_lines.append(
                "  Zone Transfer (AXFR): "
                + (
                    "POSSIBLE — records exposed"
                    if zone
                    else "Not possible (good)"
                )
            )

        dangles = dns_records.get("dangling_cnames", [])
        if dangles:
            dns_lines.append(f"  Dangling CNAMEs: {', '.join(dangles)}")

        sections.append("\n".join(dns_lines))

    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def parse_scan_data(scan_dir: str) -> dict[str, Any]:
    """Main entry point: parse all scan data from a scan directory.

    Args:
        scan_dir: Path to the extracted scan directory,
                  e.g. ``/tmp/report-{orderId}/{orderId}``

    Returns::

        {
            "host_inventory": dict,
            "tech_profiles": [dict, ...],
            "consolidated_findings": str,   # formatted text for Claude prompt
            "meta": dict,
        }
    """
    scan_path = Path(scan_dir)

    # 1. Load meta.json
    meta = _read_json(str(scan_path / "meta.json"))
    if meta is None:
        log.warning("meta_json_missing", scan_dir=scan_dir)
        meta = {}

    # 2. Load host_inventory.json from phase0/
    host_inventory = _read_json(
        str(scan_path / "phase0" / "host_inventory.json")
    )
    if host_inventory is None:
        log.error("host_inventory_missing", scan_dir=scan_dir)
        host_inventory = {"domain": "unknown", "hosts": []}

    hosts: list[dict[str, Any]] = host_inventory.get("hosts", [])
    log.info("scan_data_hosts", count=len(hosts))

    # 3. Load dns_records.json from phase0/
    dns_records = (
        _read_json(str(scan_path / "phase0" / "dns_records.json")) or {}
    )
    # Fallback: dns_findings may live inside host_inventory
    if not dns_records and isinstance(host_inventory, dict):
        dns_records = host_inventory.get("dns_findings", {})

    # 4. Parse per-host tool outputs
    hosts_dir = scan_path / "hosts"
    tech_profiles: list[dict[str, Any]] = []
    host_results: dict[str, dict[str, Any]] = {}

    for host_entry in hosts:
        ip = host_entry.get("ip", "")
        if not ip:
            continue

        fqdns = host_entry.get("fqdns", [])
        host_path = hosts_dir / ip

        if not host_path.is_dir():
            log.warning("host_dir_missing", ip=ip, path=str(host_path))
            continue

        log.info("parsing_host", ip=ip, fqdns=fqdns)

        host_data: dict[str, Any] = {"fqdns": fqdns}

        # Phase 1
        phase1 = host_path / "phase1"
        tp = _read_json(str(phase1 / "tech_profile.json"))
        if tp is not None:
            tech_profiles.append(tp)

        host_data["nmap"] = parse_nmap_xml(str(phase1 / "nmap.xml"))

        # Phase 2
        phase2 = host_path / "phase2"
        host_data["nuclei"] = parse_nuclei_json(str(phase2 / "nuclei.json"))
        host_data["testssl"] = parse_testssl_json(
            str(phase2 / "testssl.json")
        )

        host_data["nikto"] = parse_nikto_json(str(phase2 / "nikto.json"))

        host_data["headers"] = parse_headers_json(
            str(phase2 / "headers.json")
        )
        host_data["gobuster_dir"] = parse_gobuster_dir(
            str(phase2 / "gobuster_dir.txt")
        )

        host_data["screenshots"] = find_gowitness_screenshots(
            str(phase2)
        )

        # httpx
        httpx_path = os.path.join(str(phase2), "httpx.json")
        if os.path.isfile(httpx_path):
            try:
                with open(httpx_path) as f:
                    lines = [json.loads(l) for l in f if l.strip()]
                    host_data["httpx"] = parse_httpx(lines[0] if lines else None)
            except Exception:
                pass

        # katana
        katana_path = os.path.join(str(phase2), "katana.txt")
        if os.path.isfile(katana_path):
            try:
                with open(katana_path) as f:
                    urls = [l.strip() for l in f if l.strip()]
                host_data["katana"] = parse_katana(urls)
            except Exception:
                pass

        # wpscan
        wpscan_path = os.path.join(str(phase2), "wpscan.json")
        if os.path.isfile(wpscan_path):
            try:
                with open(wpscan_path) as f:
                    host_data["wpscan"] = parse_wpscan(json.load(f))
            except Exception:
                pass

        # ZAP alerts
        zap_path = os.path.join(str(phase2), "zap_alerts.json")
        if os.path.isfile(zap_path):
            host_data["zap"] = parse_zap_alerts_json(zap_path)

        # ZAP Spider URLs (for endpoint discovery section in Claude prompt)
        spider_path = os.path.join(str(phase2), "zap_spider_urls.json")
        if os.path.isfile(spider_path):
            try:
                host_data["zap_spider_urls"] = json.loads(Path(spider_path).read_text())
            except Exception:
                pass

        host_results[ip] = host_data

    # Defensive fallback: if inventory listed no hosts but the hosts/ directory
    # contains subdirectories, parse them anyway.
    if not host_results and hosts_dir.is_dir():
        log.warning(
            "falling_back_to_directory_scan", hosts_dir=str(hosts_dir)
        )
        for ip_dir in sorted(hosts_dir.iterdir()):
            if not ip_dir.is_dir():
                continue
            ip = ip_dir.name
            log.info("parsing_host_fallback", ip=ip)

            host_data = {"fqdns": []}
            phase1 = ip_dir / "phase1"
            tp = _read_json(str(phase1 / "tech_profile.json"))
            if tp is not None:
                tech_profiles.append(tp)

            host_data["nmap"] = parse_nmap_xml(str(phase1 / "nmap.xml"))

            phase2 = ip_dir / "phase2"
            host_data["nuclei"] = parse_nuclei_json(
                str(phase2 / "nuclei.json")
            )
            host_data["testssl"] = parse_testssl_json(
                str(phase2 / "testssl.json")
            )
            host_data["nikto"] = parse_nikto_json(str(phase2 / "nikto.json"))
            host_data["headers"] = parse_headers_json(
                str(phase2 / "headers.json")
            )
            host_data["gobuster_dir"] = parse_gobuster_dir(
                str(phase2 / "gobuster_dir.txt")
            )
            host_data["screenshots"] = find_gowitness_screenshots(
                str(phase2)
            )

            # httpx
            httpx_path = os.path.join(str(phase2), "httpx.json")
            if os.path.isfile(httpx_path):
                try:
                    with open(httpx_path) as f:
                        lines = [json.loads(l) for l in f if l.strip()]
                        host_data["httpx"] = parse_httpx(lines[0] if lines else None)
                except Exception:
                    pass

            # katana
            katana_path = os.path.join(str(phase2), "katana.txt")
            if os.path.isfile(katana_path):
                try:
                    with open(katana_path) as f:
                        urls = [l.strip() for l in f if l.strip()]
                    host_data["katana"] = parse_katana(urls)
                except Exception:
                    pass

            # wpscan
            wpscan_path = os.path.join(str(phase2), "wpscan.json")
            if os.path.isfile(wpscan_path):
                try:
                    with open(wpscan_path) as f:
                        host_data["wpscan"] = parse_wpscan(json.load(f))
                except Exception:
                    pass

            host_results[ip] = host_data

    # 5. Consolidate all findings into prompt text
    consolidated = consolidate_findings(host_results, dns_records)

    log.info(
        "scan_data_parsed",
        hosts=len(host_results),
        tech_profiles=len(tech_profiles),
        findings_length=len(consolidated),
    )

    # 6. Collect gowitness screenshots per host
    host_screenshots: dict[str, list[str]] = {}
    for ip, data in host_results.items():
        shots = data.get("screenshots", [])
        if shots:
            host_screenshots[ip] = shots

    if host_screenshots:
        log.info(
            "gowitness_screenshots_total",
            hosts_with_screenshots=len(host_screenshots),
            total_screenshots=sum(len(v) for v in host_screenshots.values()),
        )

    return {
        "host_inventory": host_inventory,
        "tech_profiles": tech_profiles,
        "consolidated_findings": consolidated,
        "host_screenshots": host_screenshots,
        "meta": meta,
    }
