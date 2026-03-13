"""Report Mapper — Claude-Output -> report_data Dict fuer PDF-Engine."""

from datetime import datetime
from typing import Any

from reportlab.lib.units import mm
from reportlab.platypus import Paragraph

from reporter.generate_report import create_styles

import structlog

log = structlog.get_logger()

# Severity order for sorting findings
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def map_to_report_data(
    claude_output: dict[str, Any],
    scan_meta: dict[str, Any],
    host_inventory: dict[str, Any],
) -> dict[str, Any]:
    """Map Claude API output to the report_data structure for PDF generation.

    German labels throughout. VectiScan branding.

    Args:
        claude_output: Parsed JSON from Claude API (overall_risk, findings, etc.)
        scan_meta: Scan metadata dict with domain, startedAt, scanId, etc.
        host_inventory: Host inventory JSON from phase 0

    Returns:
        report_data dict ready for generate_report()
    """
    styles = create_styles()

    domain = scan_meta.get("domain", "unknown")
    scan_date = scan_meta.get("startedAt", datetime.now().isoformat())[:10]
    scan_id = scan_meta.get("scanId", "unknown")
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
        "report_mapper",
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
            "classification_label": (
                "KLASSIFIZIERUNG: VERTRAULICH — NUR FÜR AUTORISIERTE EMPFÄNGER"
            ),
        },
        "cover": {
            "cover_subtitle": "AUTOMATED SECURITY ASSESSMENT",
            "cover_title": f"Sicherheitsbewertung<br/>{domain}",
            "cover_meta": [
                ["Ziel:", f"{domain} ({hosts_count} Hosts)"],
                ["Datum:", scan_date],
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
        "disclaimer": (
            "<b>Haftungsausschluss:</b> Dieser Bericht gibt den Sicherheitsstatus "
            "zum Zeitpunkt der Pr\u00fcfung wieder. Sicherheitsbewertungen sind "
            "Momentaufnahmen. Regelm\u00e4\u00dfige Wiederholungspr\u00fcfungen werden empfohlen."
        ),
    }


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
        "label_impact": "Gesch\u00e4ftsauswirkung",
        "label_recommendation": "Empfehlung",
    }


def _map_positive_finding(f: dict[str, Any]) -> dict[str, Any]:
    """Map a positive finding (INFO severity) with German labels."""
    return {
        "id": f.get("id", "VS-2026-POS"),
        "title": f["title"],
        "severity": "INFO",
        "cvss_score": "N/A",
        "cvss_vector": "N/A",
        "cwe": "N/A",
        "affected": f.get("affected", "Gesamte Infrastruktur"),
        "description": f["description"],
        "evidence": f.get("evidence", "\u2014"),
        "impact": "Positiver Befund \u2014 korrekte Konfiguration.",
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
        ("1.2", "Befund\u00fcbersicht", True),
        ("2", "Umfang &amp; Methodik", False),
        ("2.1", "Pr\u00fcfungsumfang", True),
        ("2.2", "Methodik", True),
        ("3", "Befunde", False),
    ]

    idx = 1
    for f in findings:
        finding_id = f.get("id", f"VS-2026-{idx:03d}")
        title = f.get("title", "Befund")
        toc.append((f"3.{idx}", f"{finding_id} \u2014 {title}", True))
        idx += 1

    for f in positive_findings:
        title = f.get("title", "Positiver Befund")
        toc.append((f"3.{idx}", f"VS-2026-POS \u2014 {title}", True))
        idx += 1

    toc.append(("4", "Ma\u00dfnahmenplan", False))
    toc.append(("A", "Anhang: CVSS-Referenz", False))

    return toc


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
            "title": "1.2&nbsp;&nbsp;&nbsp;Befund\u00fcbersicht",
            "paragraphs": [
                f"Im Rahmen der automatisierten Sicherheitspr\u00fcfung von <b>{domain}</b> "
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
            "title": "2.1&nbsp;&nbsp;&nbsp;Pr\u00fcfungsumfang",
            "paragraphs": [
                f"Ziel der Pr\u00fcfung war die Domain <b>{domain}</b>. "
                f"Im Rahmen der DNS-Reconnaissance wurden <b>{len(hosts)} Hosts</b> "
                f"identifiziert und in die Pr\u00fcfung einbezogen.",
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
                "Die Pr\u00fcfung wurde als automatisierter Security-Scan nach dem "
                "PTES-Standard (Penetration Testing Execution Standard) durchgef\u00fchrt. "
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
                f"Die Pr\u00fcfung wurde am <b>{scan_date}</b> durchgef\u00fchrt. "
                "Die Bewertung erfolgt nach CVSS v3.1.",
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
        Paragraph("<b>Ma\u00dfnahme</b>", styles["TableHeader"]),
        Paragraph("<b>Befund-Ref.</b>", styles["TableHeader"]),
        Paragraph("<b>Aufwand</b>", styles["TableHeader"]),
    ]

    return {
        "section_label": "4&nbsp;&nbsp;&nbsp;Ma\u00dfnahmenplan",
        "paragraphs": [
            "Die folgende Tabelle fasst die empfohlenen Ma\u00dfnahmen zusammen, "
            "priorisiert nach Dringlichkeit und Schweregrad der zugrunde liegenden Befunde.",
        ],
        "table": {
            "header": header,
            "rows": table_rows,
            "widths": [28 * mm, 95 * mm, 22 * mm, 25 * mm],
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
            Paragraph("DNS-Validierung und -Aufl\u00f6sung", styles["TableCell"]),
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
