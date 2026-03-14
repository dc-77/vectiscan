"""Report Mapper — Claude-Output -> report_data Dict fuer PDF-Engine."""

from datetime import datetime
from typing import Any

from reportlab.lib.units import mm
from reportlab.platypus import Paragraph

from reporter.generate_report import create_styles
from reporter.pdf.branding import CLASSIFICATION_LABEL_DE

import structlog

log = structlog.get_logger()

# Severity order for sorting findings
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


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


def _map_finding(f: dict[str, Any]) -> dict[str, Any]:
    """Map a Claude finding to the Skill finding format with German labels."""
    return {
        "id": f["id"],
        "title": f["title"],
        "severity": f["severity"],
        "cvss_score": f["cvss_score"],
        "cvss_vector": f["cvss_vector"],
        "cwe": f["cwe"],
        "affected": f["affected"],
        "description": f["description"],
        "evidence": f["evidence"],
        "impact": f["impact"],
        "recommendation": f["recommendation"],
        # Deutsche Labels
        "label_description": "Beschreibung",
        "label_evidence": "Nachweis",
        "label_impact": "Geschäftsauswirkung",
        "label_recommendation": "Empfehlung",
    }


def _map_basic_finding(f: dict[str, Any]) -> dict[str, Any]:
    """Map a basic-package Claude finding."""
    return {
        "id": f["id"],
        "title": f["title"],
        "severity": f["severity"],
        "cvss_score": f.get("cvss_score", "—"),
        "cvss_vector": f.get("cvss_vector", "—"),
        "cwe": f.get("cwe", "—"),
        "affected": f["affected"],
        "description": f["description"],
        "evidence": f.get("evidence", "—"),
        "impact": f.get("impact", "—"),
        "recommendation": f["recommendation"],
        # Deutsche Labels
        "label_description": "Beschreibung",
        "label_evidence": "Nachweis",
        "label_impact": "Geschäftsauswirkung",
        "label_recommendation": "Empfehlung",
    }


def _map_positive_finding(f: dict[str, Any]) -> dict[str, Any]:
    """Map a positive finding (INFO severity) with German labels."""
    return {
        "id": f.get("id", "VS-2026-POS"),
        "title": f["title"],
        "severity": "INFO",
        "cvss_score": "—",
        "cvss_vector": "—",
        "cwe": "—",
        "affected": f.get("affected", "Gesamte Infrastruktur"),
        "description": f["description"],
        "evidence": f.get("evidence", "—"),
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
        finding_id = f.get("id", f"VS-2026-{idx:03d}")
        title = f.get("title", "Befund")
        toc.append((f"3.{idx}", f"{finding_id} — {title}", True))
        idx += 1

    for f in positive_findings:
        title = f.get("title", "Positiver Befund")
        toc.append((f"3.{idx}", f"VS-2026-POS — {title}", True))
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
    overall_desc = claude_output.get(
        "overall_description",
        f"Die Sicherheitsbewertung von {domain} ergab mehrere Befunde.",
    )

    total_findings = sum(severity_counts.values())

    # Build severity overview table rows using Paragraph for proper formatting
    severity_rows = []
    for sev, count in severity_counts.items():
        severity_rows.append(
            [
                Paragraph(sev, styles["TableCellCenter"]),
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
                "Der Scan umfasste drei Phasen:",
                "<b>Phase 0 — DNS-Reconnaissance:</b> Subdomain-Enumeration mittels "
                "Certificate Transparency Logs, passiver Enumeration (subfinder), "
                "DNS-Bruteforce (gobuster) und Validierung (dnsx).",
                "<b>Phase 1 — Technologie-Erkennung:</b> Port-Scanning (nmap), "
                "Technologie-Identifikation (webtech) und WAF-Erkennung (wafw00f) "
                "pro Host.",
                "<b>Phase 2 — Tiefer Scan:</b> SSL/TLS-Analyse (testssl.sh), "
                "Schwachstellen-Scan (nikto, nuclei), Directory-Enumeration "
                "(gobuster) und Screenshots (gowitness) pro Host.",
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
                "<b>Screenshot:</b> Visuelle Dokumentation der Web-Oberflächen (gowitness).",
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


def _build_recommendations(
    recommendations: list[dict[str, Any]],
    styles: Any,
) -> dict[str, Any]:
    """Build the recommendations section with a Paragraph-based table."""
    table_rows = []
    for rec in recommendations:
        timeframe = rec.get("timeframe", "—")
        action = rec.get("action", "—")
        refs = ", ".join(rec.get("finding_refs", []))
        effort = rec.get("effort", "—")

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
            "widths": [28 * mm, 95 * mm, 22 * mm, 25 * mm],
        },
    }


def _build_basic_recommendations(
    top_recommendations: list[dict[str, Any]],
    styles: Any,
) -> dict[str, Any]:
    """Build simplified recommendations for basic package (2 columns only)."""
    table_rows = []
    for rec in top_recommendations[:3]:
        action = rec.get("action", "—")
        timeframe = rec.get("timeframe", "—")

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

    # Appendix B: Tool list
    tool_rows = [
        [
            Paragraph("subfinder", styles["TableCell"]),
            Paragraph("Passive Subdomain-Enumeration", styles["TableCell"]),
            Paragraph("Phase 0", styles["TableCellCenter"]),
        ],
        [
            Paragraph("amass", styles["TableCell"]),
            Paragraph("OWASP Subdomain-Enumeration", styles["TableCell"]),
            Paragraph("Phase 0", styles["TableCellCenter"]),
        ],
        [
            Paragraph("gobuster", styles["TableCell"]),
            Paragraph("DNS-Bruteforce / Directory-Enumeration", styles["TableCell"]),
            Paragraph("Phase 0/2", styles["TableCellCenter"]),
        ],
        [
            Paragraph("dnsx", styles["TableCell"]),
            Paragraph("DNS-Validierung und -Auflösung", styles["TableCell"]),
            Paragraph("Phase 0", styles["TableCellCenter"]),
        ],
        [
            Paragraph("nmap", styles["TableCell"]),
            Paragraph("Port-Scanning und Service-Erkennung", styles["TableCell"]),
            Paragraph("Phase 1", styles["TableCellCenter"]),
        ],
        [
            Paragraph("webtech", styles["TableCell"]),
            Paragraph("Web-Technologie-Identifikation", styles["TableCell"]),
            Paragraph("Phase 1", styles["TableCellCenter"]),
        ],
        [
            Paragraph("wafw00f", styles["TableCell"]),
            Paragraph("WAF-Erkennung", styles["TableCell"]),
            Paragraph("Phase 1", styles["TableCellCenter"]),
        ],
        [
            Paragraph("testssl.sh", styles["TableCell"]),
            Paragraph("SSL/TLS-Konfigurationsanalyse", styles["TableCell"]),
            Paragraph("Phase 2", styles["TableCellCenter"]),
        ],
        [
            Paragraph("nikto", styles["TableCell"]),
            Paragraph("Web-Schwachstellen-Scanner", styles["TableCell"]),
            Paragraph("Phase 2", styles["TableCellCenter"]),
        ],
        [
            Paragraph("nuclei", styles["TableCell"]),
            Paragraph("Template-basierter Schwachstellen-Scanner", styles["TableCell"]),
            Paragraph("Phase 2", styles["TableCellCenter"]),
        ],
        [
            Paragraph("gowitness", styles["TableCell"]),
            Paragraph("Web-Screenshot-Tool", styles["TableCell"]),
            Paragraph("Phase 2", styles["TableCellCenter"]),
        ],
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
        entries.append({"label": label, "paths": paths})

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

    # Map findings to report format
    mapped_findings = [_map_finding(f) for f in findings]
    mapped_findings += [_map_positive_finding(f) for f in positive_findings]

    log.info(
        "report_mapper.professional",
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
            "package": "professional",
            "cover_meta": [
                ["Ziel:", f"{domain} ({hosts_count} Hosts)"],
                ["Datum:", scan_date],
                ["Paket:", "Professional"],
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
                ["Paket:", "Basic"],
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
            cover_meta[i] = ["Paket:", "NIS2 Compliance"]
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


# ===========================================================================
# Dispatcher
# ===========================================================================


def map_to_report_data(
    claude_output: dict[str, Any],
    scan_meta: dict[str, Any],
    host_inventory: dict[str, Any],
    package: str = "professional",
    host_screenshots: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Dispatch to the correct package-specific mapper.

    Args:
        claude_output: Parsed JSON from Claude API
        scan_meta: Scan metadata dict
        host_inventory: Host inventory JSON from phase 0
        package: One of 'basic', 'professional', 'nis2'
        host_screenshots: Dict mapping host IP to list of screenshot file paths

    Returns:
        report_data dict ready for generate_report()
    """
    mappers = {
        "basic": map_basic_report,
        "professional": map_professional_report,
        "nis2": map_nis2_report,
    }
    mapper = mappers.get(package, map_professional_report)
    return mapper(claude_output, scan_meta, host_inventory, host_screenshots)
