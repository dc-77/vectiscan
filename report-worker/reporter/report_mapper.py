"""Report Mapper — Claude-Output -> report_data Dict fuer PDF-Engine."""

from datetime import datetime
from typing import Any
from xml.sax.saxutils import escape as xml_escape

_CURRENT_YEAR = datetime.now().year

from reportlab.lib.units import mm
from reportlab.platypus import Paragraph

from reporter.generate_report import create_styles, severity_badge_text
from reporter.pdf.branding import CLASSIFICATION_LABEL_DE

import structlog

log = structlog.get_logger()


def _safe(text: str | None) -> str:
    """Escape XML-special characters so ReportLab Paragraph doesn't crash.

    Converts <, >, & to &lt;, &gt;, &amp; — but preserves known safe
    markup tags like <b>, <i>, <br/> that ReportLab supports.

    Strips unsupported HTML tags (code, ul, li, ol, p, div, span, pre, h1-h6,
    a, table, tr, td, th) while keeping their text content.
    """
    if not text:
        return "—"
    import re
    s = str(text)

    # 1. Convert unsupported tags to text equivalents BEFORE escaping
    # <code>...</code> → bold
    s = re.sub(r"<code>(.*?)</code>", r"<b>\1</b>", s, flags=re.DOTALL)
    # <li> → bullet point
    s = re.sub(r"<li>\s*", "• ", s)
    s = re.sub(r"</li>", "<br/>", s)
    # Strip remaining unsupported tags (keep content)
    for tag in ("ul", "ol", "p", "div", "span", "pre", "h1", "h2", "h3",
                "h4", "h5", "h6", "a", "table", "tr", "td", "th", "code",
                "strong", "em", "dl", "dt", "dd", "blockquote"):
        s = re.sub(rf"</?{tag}[^>]*>", "", s, flags=re.IGNORECASE)

    # 2. Escape everything for XML safety
    escaped = xml_escape(s)

    # 3. Restore ReportLab-safe tags
    for tag in ("b", "i", "u"):
        escaped = re.sub(rf"&lt;({tag})&gt;", rf"<\1>", escaped)
        escaped = re.sub(rf"&lt;/({tag})&gt;", rf"</\1>", escaped)
    # <br/> and <br> → <br/>
    escaped = re.sub(r"&lt;(br\s*/?)&gt;", "<br/>", escaped)

    return escaped

# Severity order for sorting findings
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Comprehensive list of all scan tools used in the VectiScan pipeline
SCAN_TOOLS = [
    {"tool": "subfinder", "description": "Passive Subdomain-Enumeration", "phase": "Phase 0"},
    {"tool": "amass", "description": "OWASP Subdomain-Enumeration", "phase": "Phase 0"},
    {"tool": "gobuster", "description": "DNS-Bruteforce / Directory-Enumeration", "phase": "Phase 0/2"},
    {"tool": "dnsx", "description": "DNS-Validierung und -Auflösung", "phase": "Phase 0"},
    {"tool": "httpx", "description": "HTTP-Probe und Service-Erkennung", "phase": "Phase 0"},
    {"tool": "nmap", "description": "Port-Scanning und Service-Erkennung", "phase": "Phase 1"},
    {"tool": "webtech", "description": "Web-Technologie-Identifikation", "phase": "Phase 1"},
    {"tool": "wafw00f", "description": "WAF-Erkennung", "phase": "Phase 1"},
    {"tool": "testssl.sh", "description": "SSL/TLS-Konfigurationsanalyse", "phase": "Phase 2"},
    {"tool": "ZAP Spider", "description": "Web-Crawling und Sitemap-Erstellung", "phase": "Phase 2"},
    {"tool": "ZAP Ajax Spider", "description": "JavaScript-basiertes Web-Crawling", "phase": "Phase 2"},
    {"tool": "ZAP Active Scan", "description": "Automatisierte Schwachstellenprüfung", "phase": "Phase 2"},
    {"tool": "ffuf", "description": "Web-Fuzzing und Parameter-Discovery", "phase": "Phase 2"},
    {"tool": "feroxbuster", "description": "Rekursive Directory-Enumeration", "phase": "Phase 2"},
    {"tool": "wpscan", "description": "WordPress-Schwachstellen-Scanner", "phase": "Phase 2"},
    {"tool": "NVD/EPSS/KEV", "description": "Threat-Intelligence-Enrichment (NIST, FIRST, CISA)", "phase": "Phase 3"},
]


# ---------------------------------------------------------------------------
# Helper: Severity counting
# ---------------------------------------------------------------------------


def _count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings by severity level, ordered by criticality."""
    counts: dict[str, int] = {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = sum(1 for f in findings if f.get("severity", "").upper() == sev)
        if count > 0:
            counts[sev] = count
    return counts


# ---------------------------------------------------------------------------
# Helper: Finding mapping
# ---------------------------------------------------------------------------


def _attach_thumbnails(
    findings: list[dict[str, Any]],
    host_screenshots: dict[str, list[str]] | None,
) -> None:
    """Attach the first matching screenshot path to each finding (in-place).

    Matches by checking if any host IP appears in the finding's 'affected' text.
    Sets finding["thumbnail"] to the first screenshot path found, or None.
    """
    if not host_screenshots:
        log.debug("attach_thumbnails.no_screenshots")
        return
    log.info("attach_thumbnails.start",
             screenshot_ips=list(host_screenshots.keys()),
             finding_count=len(findings))
    matched = 0
    for f in findings:
        affected = f.get("affected", "")
        for ip, paths in host_screenshots.items():
            if ip in affected and paths:
                f["thumbnail"] = paths[0]
                matched += 1
                log.debug("attach_thumbnails.match",
                          finding=f.get("id"), ip=ip, path=paths[0])
                break
    log.info("attach_thumbnails.done", matched=matched, total=len(findings))


def _map_finding(f: dict[str, Any]) -> dict[str, Any]:
    """Map a Claude finding to the Skill finding format with German labels."""
    return {
        "id": _safe(f["id"]),
        "title": _safe(f["title"]),
        "severity": f["severity"],
        "cvss_score": f["cvss_score"],
        "cvss_vector": _safe(f["cvss_vector"]),
        "cwe": _safe(f["cwe"]),
        "affected": _safe(f["affected"]),
        "description": _safe(f["description"]),
        "evidence": _safe(f["evidence"]),
        "impact": _safe(f["impact"]),
        "recommendation": _safe(f["recommendation"]),
        # Deutsche Labels
        "label_description": "Beschreibung",
        "label_evidence": "Nachweis",
        "label_impact": "Geschäftsauswirkung",
        "label_recommendation": "Empfehlung",
    }


def _map_basic_finding(f: dict[str, Any]) -> dict[str, Any]:
    """Map a basic-package Claude finding."""
    return {
        "id": _safe(f["id"]),
        "title": _safe(f["title"]),
        "severity": f["severity"],
        "cvss_score": f.get("cvss_score", "—"),
        "cvss_vector": _safe(f.get("cvss_vector", "—")),
        "cwe": _safe(f.get("cwe", "—")),
        "affected": _safe(f["affected"]),
        "description": _safe(f["description"]),
        "evidence": _safe(f.get("evidence", "—")),
        "impact": _safe(f.get("impact", "—")),
        "recommendation": _safe(f["recommendation"]),
        # Deutsche Labels
        "label_description": "Beschreibung",
        "label_evidence": "Nachweis",
        "label_impact": "Geschäftsauswirkung",
        "label_recommendation": "Empfehlung",
    }


def _map_positive_finding(f: dict[str, Any]) -> dict[str, Any]:
    """Map a positive finding (INFO severity) with German labels."""
    return {
        "id": f.get("id", f"VS-{_CURRENT_YEAR}-POS"),
        "title": _safe(f["title"]),
        "severity": "INFO",
        "cvss_score": "—",
        "cvss_vector": "—",
        "cwe": "—",
        "affected": _safe(f.get("affected", "Gesamte Infrastruktur")),
        "description": _safe(f["description"]),
        "evidence": _safe(f.get("evidence", "—")),
        "impact": "Positiver Befund — korrekte Konfiguration.",
        "recommendation": "Aktuelle Konfiguration beibehalten.",
        "label_description": "Beschreibung",
        "label_evidence": "Nachweis",
        "label_impact": "Bewertung",
        "label_recommendation": "Empfehlung",
    }


# ---------------------------------------------------------------------------
# Helper: Table of Contents
# ---------------------------------------------------------------------------


def _build_toc(
    findings: list[dict[str, Any]],
    positive_findings: list[dict[str, Any]],
) -> list[tuple[str, str, bool]]:
    """Build TOC entries as list of (number, title, is_sub) tuples."""
    toc: list[tuple[str, str, bool]] = [
        ("1", "Zusammenfassung", False),
        ("1.1", "Gesamtbewertung", True),
        ("1.2", "Befundübersicht", True),
        ("2", "Umfang &amp; Methodik", False),
        ("2.1", "Prüfungsumfang", True),
        ("2.2", "Methodik", True),
        ("3", "Befunde", False),
    ]

    idx = 1
    for f in findings:
        finding_id = f.get("id", f"VS-{_CURRENT_YEAR}-{idx:03d}")
        title = f.get("title", "Befund")
        toc.append((f"3.{idx}", f"{finding_id} — {title}", True))
        idx += 1

    for f in positive_findings:
        title = f.get("title", "Positiver Befund")
        toc.append((f"3.{idx}", f"VS-{_CURRENT_YEAR}-POS — {title}", True))
        idx += 1

    toc.append(("4", "Maßnahmenplan", False))
    toc.append(("A", "Anhang: CVSS-Referenz", False))

    return toc


def _build_basic_toc() -> list[tuple[str, str, bool]]:
    """Build simplified TOC for basic package (no sub-items)."""
    return [
        ("1", "Zusammenfassung", False),
        ("2", "Umfang &amp; Methodik", False),
        ("3", "Befunde", False),
        ("4", "Empfehlungen", False),
    ]


# ---------------------------------------------------------------------------
# Helper: Executive Summary
# ---------------------------------------------------------------------------


def _build_executive_summary(
    claude_output: dict[str, Any],
    domain: str,
    styles: Any,
    severity_counts: dict[str, int],
) -> dict[str, Any]:
    """Build the executive summary section."""
    overall_risk = claude_output.get("overall_risk", "MEDIUM")
    overall_desc = _safe(claude_output.get(
        "overall_description",
        f"Die Sicherheitsbewertung von {domain} ergab mehrere Befunde.",
    ))

    total_findings = sum(severity_counts.values())

    # Build severity overview table rows using Paragraph with colored badges
    severity_rows = []
    for sev, count in severity_counts.items():
        severity_rows.append(
            [
                Paragraph(severity_badge_text(sev), styles["TableCellCenter"]),
                Paragraph(str(count), styles["TableCellCenter"]),
            ]
        )

    subsections = [
        {
            "title": "1.1&nbsp;&nbsp;&nbsp;Gesamtbewertung",
            "paragraphs": [overall_desc],
            "risk_box": {
                "label": "Gesamtrisikobewertung",
                "level": overall_risk,
                "description": overall_desc,
            },
        },
        {
            "title": "1.2&nbsp;&nbsp;&nbsp;Befundübersicht",
            "paragraphs": [
                f"Im Rahmen der automatisierten Sicherheitsprüfung von <b>{domain}</b> "
                f"wurden insgesamt <b>{total_findings} Befunde</b> identifiziert.",
            ],
            "table": {
                "header": [
                    Paragraph("<b>Schweregrad</b>", styles["TableHeader"]),
                    Paragraph("<b>Anzahl</b>", styles["TableHeader"]),
                ],
                "rows": severity_rows,
                "widths": [85 * mm, 85 * mm],
            },
        },
    ]

    return {
        "section_label": "1&nbsp;&nbsp;&nbsp;Zusammenfassung",
        "subsections": subsections,
    }


# ---------------------------------------------------------------------------
# Helper: Scope & Methodology
# ---------------------------------------------------------------------------


def _build_scope(
    domain: str,
    host_inventory: dict[str, Any],
    scan_meta: dict[str, Any],
    styles: Any,
) -> dict[str, Any]:
    """Build the scope and methodology section."""
    hosts = host_inventory.get("hosts", [])
    scan_date = scan_meta.get("startedAt", datetime.now().isoformat())[:10]

    # Build host table rows
    host_rows = []
    for h in hosts:
        ip = h.get("ip", "N/A")
        fqdns = ", ".join(h.get("fqdns", []))
        host_rows.append(
            [
                Paragraph(ip, styles["TableCell"]),
                Paragraph(fqdns, styles["TableCell"]),
            ]
        )

    subsections = [
        {
            "title": "2.1&nbsp;&nbsp;&nbsp;Prüfungsumfang",
            "paragraphs": [
                f"Ziel der Prüfung war die Domain <b>{domain}</b>. "
                f"Im Rahmen der DNS-Reconnaissance wurden <b>{len(hosts)} Hosts</b> "
                f"identifiziert und in die Prüfung einbezogen.",
            ],
            "table": {
                "header": [
                    Paragraph("<b>IP-Adresse</b>", styles["TableHeader"]),
                    Paragraph("<b>FQDNs</b>", styles["TableHeader"]),
                ],
                "rows": host_rows,
                "widths": [50 * mm, 120 * mm],
            },
        },
        {
            "title": "2.2&nbsp;&nbsp;&nbsp;Methodik",
            "paragraphs": [
                "Die Prüfung wurde als automatisierter Security-Scan nach dem "
                "PTES-Standard (Penetration Testing Execution Standard) durchgeführt. "
                "Der Scan umfasste vier Phasen:",
                "<b>Phase 0 — Reconnaissance:</b> Passive Intelligence (Shodan, AbuseIPDB, WHOIS), "
                "DNS-Enumeration (subfinder, amass, gobuster, dnsx) und Web-Probe (httpx). "
                "KI-gestützte Host-Strategie bestimmt Scan-Prioritäten.",
                "<b>Phase 1 — Technologie-Erkennung:</b> Port-Scanning (nmap), "
                "Web-Technologie-Identifikation (webtech) und WAF-Erkennung (wafw00f) "
                "pro Host. KI-gestützte Tool-Konfiguration passt Phase-2-Parameter adaptiv an.",
                "<b>Phase 2 — Tiefer Scan:</b> SSL/TLS-Analyse (testssl.sh), "
                "Schwachstellen-Scan (ZAP Active Scan), Directory-Enumeration "
                "(ffuf, feroxbuster), HTTP-Header-Prüfung "
                "und WordPress-Scan (wpscan) pro Host.",
                "<b>Phase 3 — Korrelation &amp; Enrichment:</b> Cross-Tool-Korrelation, "
                "False-Positive-Filterung, Threat-Intelligence-Anreicherung (NVD, EPSS, CISA KEV) "
                "und KI-gestützte Priorisierung.",
                f"Die Prüfung wurde am <b>{scan_date}</b> durchgeführt. "
                "Die Bewertung erfolgt nach CVSS v3.1.",
            ],
        },
    ]

    return {
        "section_label": "2&nbsp;&nbsp;&nbsp;Umfang &amp; Methodik",
        "subsections": subsections,
    }


def _build_basic_scope(
    domain: str,
    host_inventory: dict[str, Any],
    scan_meta: dict[str, Any],
    styles: Any,
) -> dict[str, Any]:
    """Build simplified scope section for basic package."""
    hosts = host_inventory.get("hosts", [])
    scan_date = scan_meta.get("startedAt", datetime.now().isoformat())[:10]

    # Build host table rows
    host_rows = []
    for h in hosts:
        ip = h.get("ip", "N/A")
        fqdns = ", ".join(h.get("fqdns", []))
        host_rows.append(
            [
                Paragraph(ip, styles["TableCell"]),
                Paragraph(fqdns, styles["TableCell"]),
            ]
        )

    subsections = [
        {
            "title": "2.1&nbsp;&nbsp;&nbsp;Prüfungsumfang",
            "paragraphs": [
                f"Ziel der Prüfung war die Domain <b>{domain}</b>. "
                f"Es wurden <b>{len(hosts)} Hosts</b> identifiziert und geprüft.",
            ],
            "table": {
                "header": [
                    Paragraph("<b>IP-Adresse</b>", styles["TableHeader"]),
                    Paragraph("<b>FQDNs</b>", styles["TableHeader"]),
                ],
                "rows": host_rows,
                "widths": [50 * mm, 120 * mm],
            },
        },
        {
            "title": "2.2&nbsp;&nbsp;&nbsp;Methodik",
            "paragraphs": [
                "Die Prüfung wurde als automatisierter Schnellscan durchgeführt. "
                "Folgende Prüfungen wurden vorgenommen:",
                "<b>Port-Scan:</b> Identifikation offener Ports und Dienste (nmap).",
                "<b>Header-Analyse:</b> Prüfung der HTTP-Sicherheitsheader.",
                "<b>SSL-Check:</b> Bewertung der SSL/TLS-Konfiguration (testssl.sh).",
                "<b>Web-Scan:</b> Schwachstellenprüfung (ZAP Spider + Passive Scan).",
                f"Die Prüfung wurde am <b>{scan_date}</b> durchgeführt.",
            ],
        },
    ]

    return {
        "section_label": "2&nbsp;&nbsp;&nbsp;Umfang &amp; Methodik",
        "subsections": subsections,
    }


# ---------------------------------------------------------------------------
# Helper: Recommendations
# ---------------------------------------------------------------------------


def _normalize_finding_ref(ref: str) -> str:
    """Ensure finding reference uses the full VS-YYYY-NNN format.

    If the ref is just a number (e.g. "001"), prefix it with VS-{year}-.
    If it already has the full format, return as-is.
    """
    ref = ref.strip()
    if ref.upper().startswith("VS-"):
        return ref
    # Bare number like "001" or "1" — expand to full ID
    try:
        num = int(ref)
        return f"VS-{_CURRENT_YEAR}-{num:03d}"
    except ValueError:
        return ref


def _build_recommendations(
    recommendations: list[dict[str, Any]],
    styles: Any,
) -> dict[str, Any]:
    """Build the recommendations section with a Paragraph-based table."""
    table_rows = []
    for rec in recommendations:
        timeframe = _safe(rec.get("timeframe", "—"))
        action = _safe(rec.get("action", "—"))
        raw_refs = rec.get("finding_refs", [])
        refs = _safe(", ".join(_normalize_finding_ref(r) for r in raw_refs))
        effort = _safe(rec.get("effort", "—"))

        table_rows.append(
            [
                Paragraph(timeframe, styles["TableCell"]),
                Paragraph(action, styles["TableCell"]),
                Paragraph(refs, styles["TableCellCenter"]),
                Paragraph(effort, styles["TableCellCenter"]),
            ]
        )

    header = [
        Paragraph("<b>Zeitrahmen</b>", styles["TableHeader"]),
        Paragraph("<b>Maßnahme</b>", styles["TableHeader"]),
        Paragraph("<b>Befund-Ref.</b>", styles["TableHeader"]),
        Paragraph("<b>Aufwand</b>", styles["TableHeader"]),
    ]

    return {
        "section_label": "4&nbsp;&nbsp;&nbsp;Maßnahmenplan",
        "paragraphs": [
            "Die folgende Tabelle fasst die empfohlenen Maßnahmen zusammen, "
            "priorisiert nach Dringlichkeit und Schweregrad der zugrunde liegenden Befunde.",
        ],
        "table": {
            "header": header,
            "rows": table_rows,
            "widths": [28 * mm, 80 * mm, 37 * mm, 25 * mm],
        },
    }


def _build_basic_recommendations(
    top_recommendations: list[dict[str, Any]],
    styles: Any,
) -> dict[str, Any]:
    """Build simplified recommendations for basic package (2 columns only)."""
    table_rows = []
    for rec in top_recommendations[:3]:
        action = _safe(rec.get("action", "—"))
        timeframe = _safe(rec.get("timeframe", "—"))

        table_rows.append(
            [
                Paragraph(action, styles["TableCell"]),
                Paragraph(timeframe, styles["TableCellCenter"]),
            ]
        )

    header = [
        Paragraph("<b>Maßnahme</b>", styles["TableHeader"]),
        Paragraph("<b>Zeitrahmen</b>", styles["TableHeader"]),
    ]

    return {
        "section_label": "4&nbsp;&nbsp;&nbsp;Empfehlungen",
        "paragraphs": [
            "Die folgende Tabelle fasst die wichtigsten empfohlenen Maßnahmen zusammen.",
        ],
        "table": {
            "header": header,
            "rows": table_rows,
            "widths": [130 * mm, 40 * mm],
        },
    }


# ---------------------------------------------------------------------------
# Helper: Appendices
# ---------------------------------------------------------------------------


def _build_appendices(
    findings: list[dict[str, Any]],
    styles: Any,
) -> list[dict[str, Any]]:
    """Build appendix sections (CVSS reference table, tool list)."""
    appendices: list[dict[str, Any]] = []

    # Appendix A: CVSS reference table for all findings
    cvss_rows = []
    for f in findings:
        cvss_rows.append(
            [
                Paragraph(f.get("id", "—"), styles["TableCellCenter"]),
                Paragraph(f.get("title", "—"), styles["TableCell"]),
                Paragraph(f.get("severity", "—"), styles["TableCellCenter"]),
                Paragraph(str(f.get("cvss_score", "—")), styles["TableCellCenter"]),
                Paragraph(f.get("cvss_vector", "—"), styles["TableCell"]),
            ]
        )

    if cvss_rows:
        appendices.append(
            {
                "title": "A&nbsp;&nbsp;&nbsp;CVSS-Referenz",
                "table": {
                    "header": [
                        Paragraph("<b>ID</b>", styles["TableHeader"]),
                        Paragraph("<b>Titel</b>", styles["TableHeader"]),
                        Paragraph("<b>Schweregrad</b>", styles["TableHeader"]),
                        Paragraph("<b>Score</b>", styles["TableHeader"]),
                        Paragraph("<b>CVSS-Vektor</b>", styles["TableHeader"]),
                    ],
                    "rows": cvss_rows,
                    "widths": [22 * mm, 52 * mm, 22 * mm, 14 * mm, 60 * mm],
                },
                "paragraphs": [],
            }
        )

    # Appendix B: Tool list (from SCAN_TOOLS constant)
    tool_rows = [
        [
            Paragraph(t["tool"], styles["TableCell"]),
            Paragraph(t["description"], styles["TableCell"]),
            Paragraph(t["phase"], styles["TableCellCenter"]),
        ]
        for t in SCAN_TOOLS
    ]

    appendices.append(
        {
            "title": "B&nbsp;&nbsp;&nbsp;Eingesetzte Tools",
            "table": {
                "header": [
                    Paragraph("<b>Tool</b>", styles["TableHeader"]),
                    Paragraph("<b>Beschreibung</b>", styles["TableHeader"]),
                    Paragraph("<b>Phase</b>", styles["TableHeader"]),
                ],
                "rows": tool_rows,
                "widths": [30 * mm, 110 * mm, 30 * mm],
            },
            "paragraphs": [],
        }
    )

    return appendices


# ---------------------------------------------------------------------------
# Helper: Screenshot data for PDF embedding
# ---------------------------------------------------------------------------


def _build_screenshot_data(
    host_inventory: dict[str, Any],
    host_screenshots: dict[str, list[str]] | None,
) -> list[dict[str, Any]]:
    """Build a list of screenshot entries for the PDF generator.

    Returns a list of dicts, each with:
        - label: human-readable host label (IP + FQDNs)
        - paths: list of absolute file paths to screenshot images
    Only includes hosts that actually have screenshots.
    """
    if not host_screenshots:
        return []

    hosts = host_inventory.get("hosts", [])
    # Build IP -> FQDNs lookup
    fqdn_lookup: dict[str, list[str]] = {}
    for h in hosts:
        ip = h.get("ip", "")
        if ip:
            fqdn_lookup[ip] = h.get("fqdns", [])

    entries: list[dict[str, Any]] = []
    for ip, paths in host_screenshots.items():
        if not paths:
            continue
        fqdns = fqdn_lookup.get(ip, [])
        label = f"{ip} ({', '.join(fqdns)})" if fqdns else ip
        # Show only the first screenshot per host to avoid duplicates
        # (multiple FQDNs on the same IP often show the same page)
        entries.append({"label": label, "paths": [paths[0]]})

    return entries


# ===========================================================================
# Package-specific mappers
# ===========================================================================


def map_professional_report(
    claude_output: dict[str, Any],
    scan_meta: dict[str, Any],
    host_inventory: dict[str, Any],
    host_screenshots: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Map Claude API output to report_data for the Professional package.

    German labels throughout. VectiScan branding.

    Args:
        claude_output: Parsed JSON from Claude API (overall_risk, findings, etc.)
        scan_meta: Scan metadata dict with domain, startedAt, orderId, etc.
        host_inventory: Host inventory JSON from phase 0

    Returns:
        report_data dict ready for generate_report()
    """
    styles = create_styles()

    domain = scan_meta.get("domain", "unknown")
    scan_date = scan_meta.get("startedAt", datetime.now().isoformat())[:10]
    order_id = scan_meta.get("orderId", scan_meta.get("scanId", "unknown"))
    hosts = host_inventory.get("hosts", [])
    hosts_count = len(hosts)

    findings = claude_output.get("findings", [])
    positive_findings = claude_output.get("positive_findings", [])
    recommendations = claude_output.get("recommendations", [])

    severity_counts = _count_by_severity(findings)
    finding_summary = ", ".join(
        f"{count} {sev}" for sev, count in severity_counts.items() if count > 0
    )

    # Map findings to report format and attach thumbnails
    mapped_findings = [_map_finding(f) for f in findings]
    mapped_findings += [_map_positive_finding(f) for f in positive_findings]
    _attach_thumbnails(mapped_findings, host_screenshots)

    thumb_count = sum(1 for f in mapped_findings if f.get("thumbnail"))
    log.info(
        "report_mapper.professional",
        domain=domain,
        findings=len(mapped_findings),
        severities=severity_counts,
        thumbnails_attached=thumb_count,
        screenshot_hosts=list((host_screenshots or {}).keys()),
    )

    return {
        "meta": {
            "title": f"Security Assessment — {domain}",
            "author": "VectiScan Automated Security Assessment",
            "header_left": "VECTISCAN — SECURITY ASSESSMENT",
            "header_right": domain,
            "footer_left": f"Vertraulich  |  {scan_date}",
            "classification_label": CLASSIFICATION_LABEL_DE,
        },
        "cover": {
            "cover_subtitle": "AUTOMATED SECURITY ASSESSMENT",
            "cover_title": f"Sicherheitsbewertung<br/>{domain}",
            "package": "professional",
            "cover_meta": [
                ["Ziel:", f"{domain} ({hosts_count} Hosts)"],
                ["Datum:", scan_date],
                ["Paket:", "PerimeterScan"],
                ["Methodik:", "PTES (automatisiert)"],
                ["Scoring:", "CVSS v3.1"],
                ["Klassifizierung:", "Vertraulich"],
                ["Befunde:", finding_summary],
            ],
        },
        "toc": _build_toc(findings, positive_findings),
        "executive_summary": _build_executive_summary(
            claude_output, domain, styles, severity_counts
        ),
        "scope": _build_scope(domain, host_inventory, scan_meta, styles),
        "findings_section_label": "3&nbsp;&nbsp;&nbsp;Befunde",
        "findings": mapped_findings,
        "recommendations": _build_recommendations(recommendations, styles),
        "appendices": _build_appendices(findings, styles),
        "screenshots": _build_screenshot_data(host_inventory, host_screenshots),
        "disclaimer": (
            "<b>Haftungsausschluss:</b> Dieser Bericht gibt den Sicherheitsstatus "
            "zum Zeitpunkt der Prüfung wieder. Sicherheitsbewertungen sind "
            "Momentaufnahmen. Regelmäßige Wiederholungsprüfungen werden empfohlen."
        ),
    }


def map_basic_report(
    claude_output: dict[str, Any],
    scan_meta: dict[str, Any],
    host_inventory: dict[str, Any],
    host_screenshots: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Map Claude API output to report_data for the Basic package.

    Simplified report: no CVSS vectors/scores, no appendices, no evidence,
    max 3 top recommendations, simplified TOC and scope.

    Args:
        claude_output: Parsed JSON from Claude API (basic schema)
        scan_meta: Scan metadata dict with domain, startedAt, orderId, etc.
        host_inventory: Host inventory JSON from phase 0

    Returns:
        report_data dict ready for generate_report()
    """
    styles = create_styles()

    domain = scan_meta.get("domain", "unknown")
    scan_date = scan_meta.get("startedAt", datetime.now().isoformat())[:10]
    order_id = scan_meta.get("orderId", scan_meta.get("scanId", "unknown"))
    hosts = host_inventory.get("hosts", [])
    hosts_count = len(hosts)

    findings = claude_output.get("findings", [])
    positive_findings = claude_output.get("positive_findings", [])
    top_recommendations = claude_output.get("top_recommendations", [])

    severity_counts = _count_by_severity(findings)
    finding_summary = ", ".join(
        f"{count} {sev}" for sev, count in severity_counts.items() if count > 0
    )

    # Map findings to basic report format (no CVSS, CWE, evidence)
    mapped_findings = [_map_basic_finding(f) for f in findings]
    mapped_findings += [_map_positive_finding(f) for f in positive_findings]
    _attach_thumbnails(mapped_findings, host_screenshots)

    log.info(
        "report_mapper.basic",
        domain=domain,
        findings=len(mapped_findings),
        severities=severity_counts,
    )

    return {
        "meta": {
            "title": f"Security Assessment — {domain}",
            "author": "VectiScan Automated Security Assessment",
            "header_left": "VECTISCAN — SECURITY ASSESSMENT",
            "header_right": domain,
            "footer_left": f"Vertraulich  |  {scan_date}",
            "classification_label": CLASSIFICATION_LABEL_DE,
        },
        "cover": {
            "cover_subtitle": "AUTOMATED SECURITY ASSESSMENT",
            "cover_title": f"Sicherheitsbewertung<br/>{domain}",
            "package": "basic",
            "cover_meta": [
                ["Ziel:", f"{domain} ({hosts_count} Hosts)"],
                ["Datum:", scan_date],
                ["Paket:", "WebCheck"],
                ["Methodik:", "Automatisierter Schnellscan"],
                ["Klassifizierung:", "Vertraulich"],
                ["Befunde:", finding_summary],
            ],
        },
        "toc": _build_basic_toc(),
        "executive_summary": _build_executive_summary(
            claude_output, domain, styles, severity_counts
        ),
        "scope": _build_basic_scope(domain, host_inventory, scan_meta, styles),
        "findings_section_label": "3&nbsp;&nbsp;&nbsp;Befunde",
        "findings": mapped_findings,
        "recommendations": _build_basic_recommendations(top_recommendations, styles),
        "screenshots": _build_screenshot_data(host_inventory, host_screenshots),
        "appendices": [],
        "disclaimer": (
            "<b>Haftungsausschluss:</b> Dieser Bericht gibt den Sicherheitsstatus "
            "zum Zeitpunkt der Prüfung wieder. Sicherheitsbewertungen sind "
            "Momentaufnahmen. Regelmäßige Wiederholungsprüfungen werden empfohlen."
        ),
    }


# ---------------------------------------------------------------------------
# Helper: Compliance Summary Validation
# ---------------------------------------------------------------------------

# Expected compliance values for scan-based assessment
_COMPLIANCE_OVERRIDES = {
    "nr1_risikoanalyse": "PARTIAL",        # Scan is only one part of risk analysis
    "nr2_vorfallbewaeltigung": "PARTIAL",   # Preventive scan, not reactive capability
    "nr4_lieferkette": "COVERED",           # Report itself is the proof
    "nr5_schwachstellenmanagement": "COVERED",  # Core scan function
    "nr6_wirksamkeitsbewertung": "COVERED",     # Scan evaluates effectiveness
}
# nr8_kryptografie is NOT overridden — depends on whether TLS was scanned

_VALID_COMPLIANCE_VALUES = {"COVERED", "PARTIAL", "NOT_IN_SCOPE"}


def _validate_compliance_summary(
    summary: dict[str, Any],
) -> dict[str, Any]:
    """Validate and correct obvious compliance summary errors.

    Enforces rules:
    - Nr. 1 (Risikoanalyse): always PARTIAL (scan is only part of risk analysis)
    - Nr. 2 (Vorfallbewältigung): always PARTIAL (preventive, not reactive)
    - Nr. 4 (Lieferkette): always COVERED (report is the proof)
    - Nr. 5 (Schwachstellenmanagement): always COVERED (core function)
    - Nr. 6 (Wirksamkeitsbewertung): always COVERED (scan evaluates effectiveness)
    - Nr. 8 (Kryptografie): NOT overridden — depends on TLS scan results

    Returns:
        Corrected compliance summary dict.
    """
    corrected = dict(summary)

    for key, expected_value in _COMPLIANCE_OVERRIDES.items():
        current = corrected.get(key)
        if current != expected_value:
            log.warning(
                "compliance_summary_corrected",
                field=key,
                was=current,
                now=expected_value,
            )
            corrected[key] = expected_value

    # Validate all values are valid
    for key, value in corrected.items():
        if key == "scope_note":
            continue
        if value not in _VALID_COMPLIANCE_VALUES:
            log.warning("invalid_compliance_value", field=key, value=value)
            corrected[key] = "PARTIAL"

    # Ensure scope_note exists
    if "scope_note" not in corrected:
        corrected["scope_note"] = (
            "Dieser Scan deckt die externe Angriffsoberfläche ab. "
            "Interne Prozesse, Schulungen und organisatorische Maßnahmen "
            "können durch einen externen Scan nicht bewertet werden."
        )

    return corrected


def map_nis2_report(
    claude_output: dict[str, Any],
    scan_meta: dict[str, Any],
    host_inventory: dict[str, Any],
    host_screenshots: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Map Claude API output to report_data for the NIS2 Compliance package.

    Extends professional mapper output with NIS2-specific sections:
    compliance summary, audit trail, and supply chain summary.

    Args:
        claude_output: Parsed JSON from Claude API (NIS2 schema with nis2_ref, etc.)
        scan_meta: Scan metadata dict with domain, startedAt, orderId, etc.
        host_inventory: Host inventory JSON from phase 0

    Returns:
        report_data dict ready for generate_report()
    """
    # Start with professional report as base
    report_data = map_professional_report(claude_output, scan_meta, host_inventory, host_screenshots)

    domain = scan_meta.get("domain", "unknown")
    scan_date = scan_meta.get("startedAt", datetime.now().isoformat())[:10]
    order_id = scan_meta.get("orderId", scan_meta.get("scanId", "unknown"))
    package = scan_meta.get("package", "nis2")

    # Update cover meta: change Paket to NIS2 Compliance, add Regulatorik row
    cover_meta = report_data["cover"]["cover_meta"]
    for i, row in enumerate(cover_meta):
        if row[0] == "Paket:":
            cover_meta[i] = ["Paket:", "ComplianceScan"]
            break
    # Insert Regulatorik row after Paket
    for i, row in enumerate(cover_meta):
        if row[0] == "Paket:":
            cover_meta.insert(i + 1, ["Regulatorik:", "§30 BSIG (NIS2)"])
            break

    # Update package badge
    report_data["cover"]["package"] = "nis2"

    # Add NIS2-specific TOC entries after section 4
    toc = report_data["toc"]
    # Remove appendix entries (they come after section 4)
    appendix_entries = [(n, t, s) for n, t, s in toc if n.startswith("A") or n.startswith("B")]
    toc = [entry for entry in toc if not (entry[0].startswith("A") or entry[0].startswith("B"))]
    # Add NIS2 sections
    toc.append(("5", "NIS2-Compliance-Übersicht", False))
    toc.append(("6", "Audit-Trail", False))
    toc.append(("7", "Lieferketten-Bewertung", False))
    # Re-add appendix entries
    toc.extend(appendix_entries)
    report_data["toc"] = toc

    # Add nis2_ref to findings if present in claude_output
    claude_findings = claude_output.get("findings", [])
    claude_findings_by_id = {f.get("id"): f for f in claude_findings}
    for finding in report_data["findings"]:
        finding_id = finding.get("id")
        claude_finding = claude_findings_by_id.get(finding_id, {})
        if claude_finding.get("nis2_ref"):
            finding["nis2_ref"] = claude_finding["nis2_ref"]

    # Build audit trail from scan_meta
    tool_versions = scan_meta.get("toolVersions", [])
    audit_trail = {
        "orderId": order_id,
        "domain": domain,
        "startedAt": scan_meta.get("startedAt", "—"),
        "completedAt": scan_meta.get("completedAt", "—"),
        "duration": scan_meta.get("duration", "—"),
        "hosts_scanned": len(host_inventory.get("hosts", [])),
        "package": package,
        "tools": tool_versions,
    }

    # Add NIS2 data to report_data
    report_data["nis2"] = {
        "compliance_summary": _validate_compliance_summary(
            claude_output.get("nis2_compliance_summary", {})
        ),
        "audit_trail": audit_trail,
        "supply_chain": claude_output.get("supply_chain_summary", {}),
    }

    # Store scan_meta for supply chain page rendering
    report_data["scan_meta"] = {
        "domain": domain,
        "date": scan_date,
    }

    log.info(
        "report_mapper.nis2",
        domain=domain,
        findings=len(report_data["findings"]),
        nis2_sections=list(report_data["nis2"].keys()),
    )

    return report_data


def map_supplychain_report(
    claude_output: dict[str, Any],
    scan_meta: dict[str, Any],
    host_inventory: dict[str, Any],
    host_screenshots: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Map Claude API output to report_data for the SupplyChain package.

    Extends professional report with ISO 27001 mapping and
    Auftraggeber-Nachweis (supplier attestation).
    """
    # Start with professional report as base
    report_data = map_professional_report(claude_output, scan_meta, host_inventory, host_screenshots)

    domain = scan_meta.get("domain", "unknown")
    scan_date = scan_meta.get("startedAt", "")[:10]
    order_id = scan_meta.get("orderId", scan_meta.get("scanId", "unknown"))

    # Update cover meta
    cover_meta = report_data["cover"]["cover_meta"]
    for i, row in enumerate(cover_meta):
        if row[0] == "Paket:":
            cover_meta[i] = ["Paket:", "SupplyChain"]
            break
    for i, row in enumerate(cover_meta):
        if row[0] == "Paket:":
            cover_meta.insert(i + 1, ["Regulatorik:", "ISO 27001 / NIS2 Lieferkette"])
            break

    report_data["cover"]["package"] = "supplychain"

    # Add SupplyChain-specific TOC entries
    toc = report_data["toc"]
    appendix_entries = [(n, t, s) for n, t, s in toc if n.startswith("A") or n.startswith("B")]
    toc = [entry for entry in toc if not (entry[0].startswith("A") or entry[0].startswith("B"))]
    toc.append(("5", "ISO 27001 Mapping", False))
    toc.append(("6", "Sicherheitsnachweis für Auftraggeber", False))
    toc.extend(appendix_entries)
    report_data["toc"] = toc

    # Add ISO 27001 ref to findings
    claude_findings = claude_output.get("findings", [])
    claude_findings_by_id = {f.get("id"): f for f in claude_findings}
    for finding in report_data["findings"]:
        finding_id = finding.get("id")
        claude_finding = claude_findings_by_id.get(finding_id, {})
        if claude_finding.get("iso27001_ref"):
            finding["iso27001_ref"] = claude_finding["iso27001_ref"]

    # Build ISO 27001 mapping from Claude output or generate programmatically
    iso27001_mapping = claude_output.get("iso27001_mapping", {})
    if not iso27001_mapping:
        from reporter.compliance.iso27001 import build_iso27001_summary
        iso27001_mapping = build_iso27001_summary(claude_findings)

    # Build supply chain attestation
    attestation = claude_output.get("supply_chain_attestation", {})
    if not attestation:
        findings = claude_output.get("findings", [])
        positive = claude_output.get("positive_findings", [])
        key_count = sum(1 for f in findings
                        if f.get("severity", "").upper() in ("CRITICAL", "HIGH"))
        attestation = {
            "overall_rating": claude_output.get("overall_risk", "MEDIUM"),
            "key_findings_count": key_count,
            "positive_count": len(positive),
            "assessed_areas": ["Netzwerksicherheit", "Kryptografie", "Schwachstellenmanagement",
                               "Web-Anwendungssicherheit"],
            "recommendation": (
                f"Die geprüfte Infrastruktur von {domain} weist "
                f"{key_count} kritische/hohe Befunde auf. "
                "Eine Behebung wird empfohlen."
            ),
        }

    # Build audit trail
    tool_versions = scan_meta.get("toolVersions", [])
    audit_trail = {
        "orderId": order_id,
        "domain": domain,
        "startedAt": scan_meta.get("startedAt", "—"),
        "completedAt": scan_meta.get("completedAt", "—"),
        "hosts_scanned": len(host_inventory.get("hosts", [])),
        "package": "supplychain",
        "tools": tool_versions,
    }

    report_data["supplychain"] = {
        "iso27001_mapping": iso27001_mapping,
        "attestation": attestation,
        "audit_trail": audit_trail,
    }

    report_data["scan_meta"] = {"domain": domain, "date": scan_date}

    log.info("report_mapper.supplychain", domain=domain,
             findings=len(report_data["findings"]),
             iso_controls=len(iso27001_mapping.get("controls_covered", [])))

    return report_data


def map_insurance_report(
    claude_output: dict[str, Any],
    scan_meta: dict[str, Any],
    host_inventory: dict[str, Any],
    host_screenshots: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Map Claude API output to report_data for the Insurance package.

    Extends professional report with insurance questionnaire,
    risk score, and ransomware indicator.
    """
    # Start with professional report as base
    report_data = map_professional_report(claude_output, scan_meta, host_inventory, host_screenshots)

    domain = scan_meta.get("domain", "unknown")
    scan_date = scan_meta.get("startedAt", "")[:10]

    # Update cover meta
    cover_meta = report_data["cover"]["cover_meta"]
    for i, row in enumerate(cover_meta):
        if row[0] == "Paket:":
            cover_meta[i] = ["Paket:", "InsuranceReport"]
            break
    for i, row in enumerate(cover_meta):
        if row[0] == "Paket:":
            cover_meta.insert(i + 1, ["Zweck:", "Cyberversicherungs-Nachweis"])
            break

    report_data["cover"]["package"] = "insurance"

    # Add Insurance-specific TOC entries
    toc = report_data["toc"]
    appendix_entries = [(n, t, s) for n, t, s in toc if n.startswith("A") or n.startswith("B")]
    toc = [entry for entry in toc if not (entry[0].startswith("A") or entry[0].startswith("B"))]
    toc.append(("5", "Versicherungs-Fragebogen", False))
    toc.append(("6", "Risikobewertung", False))
    toc.append(("7", "Maßnahmen zur Prämienreduktion", False))
    toc.extend(appendix_entries)
    report_data["toc"] = toc

    # Build questionnaire from Claude output or generate programmatically
    questionnaire = claude_output.get("insurance_questionnaire", [])
    if not questionnaire:
        from reporter.compliance.insurance import generate_questionnaire
        findings = claude_output.get("findings", [])
        positive = claude_output.get("positive_findings", [])
        tech_profiles = scan_meta.get("techProfiles", [])
        questionnaire = generate_questionnaire(findings, positive, tech_profiles)

    # Build risk score from Claude output or generate programmatically
    risk_score = claude_output.get("risk_score", {})
    if not risk_score:
        from reporter.compliance.insurance import calculate_risk_score
        findings = claude_output.get("findings", [])
        risk_score = calculate_risk_score(findings, questionnaire)

    report_data["insurance"] = {
        "questionnaire": questionnaire,
        "risk_score": risk_score,
    }

    report_data["scan_meta"] = {"domain": domain, "date": scan_date}

    log.info("report_mapper.insurance", domain=domain,
             findings=len(report_data["findings"]),
             risk_score=risk_score.get("score", "?"),
             ransomware=risk_score.get("ransomware_indicator", "?"))

    return report_data


# ===========================================================================
# TLS Compliance Mapper
# ===========================================================================


# Checkliste: nicht extern prüfbare TR-03116-4-Punkte
TR_MANUAL_CHECKLIST = [
    {
        "check_id": "2.5.3",
        "title": "truncated_hmac Extension deaktiviert",
        "section": "2.5 Extensions",
        "instruction": (
            "Serverkonfiguration prüfen (Apache: SSLOptions, Nginx: ssl_protocols). "
            "Die truncated_hmac Extension ist standardmäßig deaktiviert. "
            "Stellen Sie sicher, dass sie nicht manuell aktiviert wurde."
        ),
        "expected": "Extension ist nicht aktiv (Standard-Verhalten).",
    },
    {
        "check_id": "2.6.4",
        "title": "Encrypt-then-MAC Extension aktiv",
        "section": "2.6 Empfehlungen",
        "instruction": (
            "OpenSSL-Konfiguration prüfen:\n"
            "openssl s_client -connect <host>:443 -tlsextdebug 2>&1 | grep encrypt-then-mac\n"
            "Alternativ: In der Serverkonfiguration nach 'encrypt_then_mac' suchen."
        ),
        "expected": "'encrypt-then-mac' erscheint in der Extension-Liste.",
    },
    {
        "check_id": "2.6.5",
        "title": "Session-Ticket-Schlüssel werden regelmäßig rotiert",
        "section": "2.6 Empfehlungen",
        "instruction": (
            "Key-Rotation-Policy prüfen.\n"
            "Apache: SSLSessionTicketKeyFile mit Rotation via Cron.\n"
            "Nginx: ssl_session_ticket_key mit 2+ Keys (aktueller + vorheriger).\n"
            "Alternative: Session Tickets deaktivieren (ssl_session_tickets off)."
        ),
        "expected": "Rotation alle 24h oder kürzer, oder Session Tickets deaktiviert.",
    },
    {
        "check_id": "2.3.8",
        "title": "CRL Distribution Points im Zertifikat",
        "section": "2.3 Serverzertifikat",
        "instruction": (
            "Zertifikat prüfen:\n"
            "openssl x509 -in cert.pem -text -noout | grep -A2 'CRL Distribution'\n"
            "Let's-Encrypt-Zertifikate enthalten keine CRL-URLs (nur OCSP)."
        ),
        "expected": "CRL-URL vorhanden, oder OCSP als Alternative konfiguriert.",
    },
    {
        "check_id": "3.1",
        "title": "S/MIME-Konfiguration (falls E-Mail-Dienste betrieben werden)",
        "section": "3 S/MIME",
        "instruction": (
            "E-Mail-Gateway-Konfiguration prüfen. S/MIME-Zertifikate müssen "
            "TR-03116-4 Abschnitt 3 entsprechen:\n"
            "- Signatur: SHA-256 oder stärker\n"
            "- Schlüssel: RSA ≥ 2048 Bit oder ECDSA ≥ 256 Bit\n"
            "Falls keine E-Mail-Dienste betrieben werden: nicht anwendbar."
        ),
        "expected": "S/MIME mit SHA-256+ Signatur, RSA ≥ 2048 Bit / ECDSA ≥ 256 Bit.",
    },
    {
        "check_id": "4.1",
        "title": "SAML Token-Sicherheit (falls SAML-basierte Authentifizierung)",
        "section": "4 SAML",
        "instruction": (
            "SAML IdP/SP-Konfiguration prüfen:\n"
            "- Token-Transport über TLS 1.2+\n"
            "- XML-Signaturen mit SHA-256 oder stärker\n"
            "- Assertion-Verschlüsselung mit AES-128/256-GCM\n"
            "Falls kein SAML eingesetzt wird: nicht anwendbar."
        ),
        "expected": "XML-Signaturen mit SHA-256+, Transport über TLS 1.2+.",
    },
    {
        "check_id": "5.1",
        "title": "OpenPGP-Konfiguration (falls PGP-verschlüsselte Kommunikation)",
        "section": "5 OpenPGP",
        "instruction": (
            "PGP-Schlüssel und Algorithmen prüfen:\n"
            "- Schlüssel: RSA ≥ 2048 Bit oder ECC ≥ 256 Bit\n"
            "- Hash: SHA-256 oder stärker\n"
            "- Symmetrisch: AES-128/256\n"
            "Falls kein OpenPGP eingesetzt wird: nicht anwendbar."
        ),
        "expected": "RSA ≥ 2048 Bit oder ECC ≥ 256 Bit, SHA-256+.",
    },
]


def map_tlscompliance_report(
    claude_output: dict[str, Any],
    scan_meta: dict[str, Any],
    host_inventory: dict[str, Any],
    host_screenshots: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Map TR-03116-4 checker results to report_data for TLS Compliance package.

    claude_output contains overall_risk, executive_summary, findings, and
    recommendations from Sonnet based on the TR-03116-4 check results.
    """
    domain = scan_meta.get("domain", "unknown")
    scan_date = scan_meta.get("startedAt", "")[:10]
    hosts_count = len(host_inventory.get("hosts", []))

    executive_summary = claude_output.get("executive_summary", "")
    overall_risk = claude_output.get("overall_risk", "MEDIUM")

    # Map findings from Claude output
    mapped_findings = [_map_finding(f) for f in claude_output.get("findings", [])]
    positive_findings = [_map_positive_finding(f) for f in claude_output.get("positive_findings", [])]
    severity_counts = _count_by_severity(mapped_findings)

    # Build recommendations table from Claude output
    recommendations = claude_output.get("recommendations", [])
    styles = {}  # Not needed for data-only mapping
    recs_data = {}
    if recommendations:
        recs_data = {
            "section_label": "5&nbsp;&nbsp;&nbsp;Maßnahmenplan",
            "paragraphs": ["Die folgenden Maßnahmen sind nach Priorität sortiert:"],
            "table": {
                "header": ["Zeitrahmen", "Maßnahme", "Referenz", "Aufwand"],
                "rows": [
                    [_safe(r.get("timeframe", "")), _safe(r.get("action", "")),
                     _safe(", ".join(r.get("finding_refs", []))), _safe(r.get("effort", ""))]
                    for r in recommendations
                ],
                "widths": [55, 240, 70, 40],
            },
        }

    return {
        "meta": {
            "title": f"BSI TR-03116-4 TLS-Compliance — {domain}",
            "author": "VectiScan Automated TLS Compliance Audit",
            "header_left": "VECTISCAN — TLS-COMPLIANCE",
            "header_right": domain,
            "footer_left": f"Vertraulich  |  {scan_date}",
            "classification_label": CLASSIFICATION_LABEL_DE,
        },
        "cover": {
            "cover_subtitle": "BSI TR-03116-4 TLS-COMPLIANCE-PRÜFUNG",
            "cover_title": f"TLS-Compliance-Bericht<br/>{domain}",
            "package": "tlscompliance",
            "cover_meta": [
                ["Ziel:", f"{domain} ({hosts_count} Hosts)"],
                ["Datum:", scan_date],
                ["Paket:", "TLS-Compliance"],
                ["Prüfgrundlage:", "BSI TR-03116-4"],
                ["Methodik:", "testssl.sh + Header-Analyse"],
                ["Klassifizierung:", "Vertraulich"],
            ],
        },
        "toc": [
            ("1", "Zusammenfassung", False),
            ("2", "Umfang &amp; Methodik", False),
            ("3", "Befunde", False),
            ("4", "BSI TR-03116-4 Compliance-Prüfung", False),
            ("5", "Maßnahmenplan", False),
            ("6", "Manuelle Checkliste", False),
            ("7", "Compliance-Bescheinigung", False),
        ],
        "executive_summary": {
            "section_label": "1&nbsp;&nbsp;&nbsp;Zusammenfassung",
            "subsections": [
                {
                    "title": "Gesamtbewertung",
                    "paragraphs": [executive_summary] if executive_summary else [
                        f"Die TLS-Compliance-Prüfung der Domain {domain} wurde "
                        f"am {scan_date} durchgeführt. {hosts_count} Hosts wurden "
                        "gegen die BSI TR-03116-4 TLS-Checkliste geprüft."
                    ],
                    "risk_box": {
                        "label": "Gesamtrisiko",
                        "level": overall_risk,
                        "description": "",
                    },
                },
            ],
        },
        "scope": {
            "section_label": "2&nbsp;&nbsp;&nbsp;Umfang &amp; Methodik",
            "subsections": [
                {
                    "title": "Prüfungsumfang",
                    "paragraphs": [
                        f"<b>Ziel-Domain:</b> {domain}",
                        f"<b>Geprüfte Hosts:</b> {hosts_count}",
                        "<b>Prüfgrundlage:</b> BSI TR-03116-4 — Kryptographische Vorgaben "
                        "für TLS-Implementierungen (Diensteanbieter)",
                    ],
                },
                {
                    "title": "Methodik",
                    "paragraphs": [
                        "Die automatisierte Prüfung erfolgt mittels testssl.sh gegen alle "
                        "TLS-fähigen Ports. Jeder Host wird gegen die 34 Prüfpunkte der "
                        "BSI TLS-Checkliste (Abschnitte 2.1–2.6) geprüft.",
                        "Nicht extern prüfbare Punkte (Abschnitte 2.5 teilweise, 3–5) "
                        "werden als manuelle Checkliste im Report dokumentiert.",
                    ],
                },
            ],
        },
        "findings_section_label": "3&nbsp;&nbsp;&nbsp;Befunde",
        "findings": mapped_findings + positive_findings,
        "recommendations": recs_data,
        "appendices": [],
        "manual_checklist": TR_MANUAL_CHECKLIST,
        "disclaimer": (
            "<b>Haftungsausschluss:</b> Diese Prüfung bescheinigt den TLS-Compliance-Status "
            "zum Zeitpunkt der Analyse. Die Bescheinigung bezieht sich auf den extern prüfbaren "
            "Teil (Abschnitte 2.1–2.6). Intern zu prüfende Punkte sind in der Checkliste "
            "dokumentiert. Regelmäßige Wiederholungsprüfungen werden empfohlen."
        ),
    }


# ===========================================================================
# Dispatcher
# ===========================================================================


def map_to_report_data(
    claude_output: dict[str, Any],
    scan_meta: dict[str, Any],
    host_inventory: dict[str, Any],
    package: str = "professional",
    host_screenshots: dict[str, list[str]] | None = None,
    testssl_raw_by_host: dict[str, list[dict[str, Any]]] | None = None,
    headers_by_host: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Dispatch to the correct package-specific mapper.

    Args:
        claude_output: Parsed JSON from Claude API
        scan_meta: Scan metadata dict
        host_inventory: Host inventory JSON from phase 0
        package: One of 'basic', 'professional', 'nis2'
        host_screenshots: Dict mapping host IP to list of screenshot file paths
        testssl_raw_by_host: Raw testssl findings per host IP (for TR-03116-4)
        headers_by_host: Parsed security headers per host IP (for TR-03116-4)

    Returns:
        report_data dict ready for generate_report()
    """
    # v2 package names + legacy aliases
    mappers = {
        # v2 names
        "webcheck": map_basic_report,
        "perimeter": map_professional_report,
        "compliance": map_nis2_report,
        "supplychain": map_supplychain_report,
        "insurance": map_insurance_report,
        "tlscompliance": map_tlscompliance_report,
        # Legacy aliases
        "basic": map_basic_report,
        "professional": map_professional_report,
        "nis2": map_nis2_report,
    }
    mapper = mappers.get(package, map_professional_report)
    report_data = mapper(claude_output, scan_meta, host_inventory, host_screenshots)

    # TR-03116-4 compliance: for perimeter, compliance, supplychain, tlscompliance
    if package in ("perimeter", "compliance", "supplychain", "tlscompliance", "professional", "nis2") and testssl_raw_by_host:
        from reporter.tr03116_checker import check_tr03116_compliance

        hosts = host_inventory.get("hosts", [])
        ip_to_fqdn: dict[str, str] = {}
        for h in hosts:
            ip = h.get("ip", "")
            fqdns = h.get("fqdns", [])
            ip_to_fqdn[ip] = fqdns[0] if fqdns else ip

        tr03116_results = []
        for ip, raw_findings in testssl_raw_by_host.items():
            header_data = (headers_by_host or {}).get(ip)
            host_label = ip_to_fqdn.get(ip, ip)
            result = check_tr03116_compliance(raw_findings, header_data, host_label)
            tr03116_results.append(result)

        report_data["tr03116_compliance"] = tr03116_results

        # Insert TOC entry before Maßnahmenplan / appendices
        toc = report_data.get("toc", [])
        insert_idx = len(toc)
        for i, (num, _title, _sub) in enumerate(toc):
            if num in ("4", "5", "A", "B"):
                insert_idx = i
                break
        sec_num = str(insert_idx)  # dynamic number based on position
        # Use the number that comes after the last finding section
        for i, (num, _title, _sub) in enumerate(toc):
            if num.startswith("4") or num.startswith("A"):
                sec_num = num
                break
        toc.insert(insert_idx, (sec_num, "BSI TR-03116-4 TLS-Compliance", False))
        # Renumber subsequent entries if needed
        report_data["toc"] = toc

        log.info("tr03116_compliance_added", hosts=len(tr03116_results))

    return report_data
