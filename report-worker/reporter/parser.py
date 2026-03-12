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


def parse_nikto_json(path: str) -> dict[str, Any]:
    """Parse nikto JSON output.

    Returns dict with key ``"vulnerabilities"`` containing a list of::

        {"id": "...", "msg": "...", "url": "...", "method": "...", "tool": "nikto"}
    """
    data = _read_json(path)
    if data is None:
        return {"vulnerabilities": []}

    # nikto JSON can be a single object or a list of host results.
    host_results: list[dict[str, Any]]
    if isinstance(data, list):
        host_results = [d for d in data if isinstance(d, dict)]
    elif isinstance(data, dict):
        host_results = [data]
    else:
        return {"vulnerabilities": []}

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
                    "tool": "nikto",
                }
            )

    log.info("nikto_parsed", path=path, vulnerabilities=len(vulns))
    return {"vulnerabilities": vulns}


def parse_headers_json(path: str) -> dict[str, Any]:
    """Parse security headers analysis JSON.

    Returns the parsed JSON structure directly (passthrough).  The scan-worker
    already writes a structured ``headers.json`` with ``url``,
    ``security_headers`` and ``score`` keys.

    Returns an empty dict on missing / malformed files.
    """
    data = _read_json(path)
    if data is None:
        return {}

    log.info("headers_parsed", path=path)
    return data


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

        # --- Nmap ---
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

        # --- Nuclei (sorted by severity) ---
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

        # --- testssl ---
        testssl = data.get("testssl", [])
        if testssl:
            testssl_sorted = sorted(
                testssl,
                key=lambda f: _severity_key(f.get("severity", "unknown")),
            )
            lines.append("")
            lines.append("--- SSL/TLS ANALYSIS (testssl.sh) ---")
            for item in testssl_sorted:
                sev = item.get("severity", "").upper()
                lines.append(
                    f"  [{sev}] {item.get('id', '')}: "
                    f"{item.get('finding', '')}"
                )

        # --- Nikto ---
        nikto = data.get("nikto", [])
        if nikto:
            lines.append("")
            lines.append("--- WEB VULNERABILITY SCAN (nikto) ---")
            for item in nikto:
                lines.append(
                    f"  [{item.get('method', 'GET')}] {item.get('url', '')}"
                )
                lines.append(f"    {item.get('msg', '')}")

        # --- Security headers ---
        headers = data.get("headers", {})
        sec_hdrs = headers.get("security_headers", {})
        if sec_hdrs:
            present_names = [
                k for k, v in sec_hdrs.items()
                if isinstance(v, dict) and v.get("present")
            ]
            missing_names = [
                k for k, v in sec_hdrs.items()
                if isinstance(v, dict) and not v.get("present")
            ]
            lines.append("")
            lines.append("--- SECURITY HEADERS ---")
            if headers.get("url"):
                lines.append(f"  URL: {headers['url']}")
            score = headers.get("score")
            if score is not None:
                lines.append(f"  Score: {score}")
            if present_names:
                lines.append(f"  Present: {', '.join(present_names)}")
            if missing_names:
                lines.append(f"  Missing: {', '.join(missing_names)}")

        # --- Gobuster directories ---
        gobuster = data.get("gobuster_dir", [])
        if gobuster:
            lines.append("")
            lines.append("--- DISCOVERED DIRECTORIES (gobuster) ---")
            for p in gobuster[:50]:
                lines.append(f"  {p}")
            if len(gobuster) > 50:
                lines.append(f"  ... and {len(gobuster) - 50} more")

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
                  e.g. ``/tmp/report-{scanId}/{scanId}``

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

        nikto_result = parse_nikto_json(str(phase2 / "nikto.json"))
        host_data["nikto"] = nikto_result.get("vulnerabilities", [])

        host_data["headers"] = parse_headers_json(
            str(phase2 / "headers.json")
        )
        host_data["gobuster_dir"] = parse_gobuster_dir(
            str(phase2 / "gobuster_dir.txt")
        )

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
            nikto_result = parse_nikto_json(str(phase2 / "nikto.json"))
            host_data["nikto"] = nikto_result.get("vulnerabilities", [])
            host_data["headers"] = parse_headers_json(
                str(phase2 / "headers.json")
            )
            host_data["gobuster_dir"] = parse_gobuster_dir(
                str(phase2 / "gobuster_dir.txt")
            )
            host_results[ip] = host_data

    # 5. Consolidate all findings into prompt text
    consolidated = consolidate_findings(host_results, dns_records)

    log.info(
        "scan_data_parsed",
        hosts=len(host_results),
        tech_profiles=len(tech_profiles),
        findings_length=len(consolidated),
    )

    return {
        "host_inventory": host_inventory,
        "tech_profiles": tech_profiles,
        "consolidated_findings": consolidated,
        "meta": meta,
    }
