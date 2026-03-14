#!/usr/bin/env python3
"""
Pentest Report PDF Generator — VectiScan Branded
=================================================
PDF rendering engine with VectiScan CI branding.
All colors, fonts, and company data come from reporter.pdf.branding.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    Paragraph, Spacer, Table, TableStyle,
    PageBreak, Frame, PageTemplate, BaseDocTemplate, NextPageTemplate, Flowable
)
import os

from reporter.pdf.branding import (
    COLORS, SEVERITY_COLORS, PACKAGE_BADGES,
    COMPANY_NAME, CLASSIFICATION_LABEL_DE, LOGO_PATH,
    FONT_BODY, FONT_HEADING, FONT_MONO,
    FONT_SIZE_BODY, FONT_SIZE_HEADING1, FONT_SIZE_HEADING2,
    FONT_SIZE_EVIDENCE, FONT_SIZE_TABLE_HEADER, FONT_SIZE_TABLE_CELL,
    FONT_SIZE_FOOTER, FONT_SIZE_COVER_TITLE, FONT_SIZE_COVER_SUBTITLE,
)

WIDTH, HEIGHT = A4


# ============================================================================
# CUSTOM FLOWABLES
# ============================================================================

class HorizontalLine(Flowable):
    def __init__(self, width, color=None, thickness=0.5):
        Flowable.__init__(self)
        self.line_width = width
        self.color = color or COLORS["light_accent"]
        self.thickness = thickness
        self.height = thickness + 2

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.thickness)
        self.canv.line(0, 0, self.line_width, 0)


class FindingHeader(Flowable):
    """Colored header bar for a finding with ID, title, and CVSS badge."""
    def __init__(self, finding_id, title, severity, cvss_score, color):
        Flowable.__init__(self)
        self.finding_id = finding_id
        self.title = title
        self.severity = severity
        self.cvss_score = cvss_score
        self.color = color
        self.width = 170 * mm
        self.height = 18 * mm

    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.roundRect(0, 0, self.width, self.height, 2 * mm, fill=1, stroke=0)
        self.canv.setFillColor(COLORS["white"])
        self.canv.setFont(FONT_HEADING, 9)
        self.canv.drawString(4 * mm, self.height - 5.5 * mm, self.finding_id)
        self.canv.setFont(FONT_HEADING, 11)
        # Truncate title if too long
        title = self.title
        if len(title) > 65:
            title = title[:62] + "..."
        self.canv.drawString(4 * mm, self.height - 12 * mm, title)
        badge_x = self.width - 30 * mm
        self.canv.setFillColor(HexColor("#00000033"))
        self.canv.roundRect(badge_x, 3 * mm, 26 * mm, 12 * mm, 2 * mm, fill=1, stroke=0)
        self.canv.setFillColor(COLORS["white"])
        self.canv.setFont(FONT_HEADING, 8)
        self.canv.drawCentredString(badge_x + 13 * mm, 11 * mm, "CVSS v3.1")
        self.canv.setFont(FONT_HEADING, 10)
        self.canv.drawCentredString(badge_x + 13 * mm, 4.5 * mm, str(self.cvss_score))


# ============================================================================
# STYLES
# ============================================================================

def create_styles():
    styles = getSampleStyleSheet()
    C = COLORS

    defs = {
        "CoverTitle":       dict(fontName=FONT_HEADING, fontSize=FONT_SIZE_COVER_TITLE, leading=34, textColor=C["white"]),
        "CoverSubtitle":    dict(fontName=FONT_BODY, fontSize=FONT_SIZE_COVER_SUBTITLE, leading=20, textColor=HexColor("#a0aec0")),
        "SectionTitle":     dict(fontName=FONT_HEADING, fontSize=FONT_SIZE_HEADING1, leading=24, textColor=C["primary"], spaceBefore=16, spaceAfter=8),
        "SubsectionTitle":  dict(fontName=FONT_HEADING, fontSize=FONT_SIZE_HEADING2, leading=18, textColor=C["accent"], spaceBefore=12, spaceAfter=6),
        "BodyText2":        dict(fontName=FONT_BODY, fontSize=FONT_SIZE_BODY, leading=14, textColor=C["text"], alignment=TA_JUSTIFY, spaceAfter=6),
        "FindingLabel":     dict(fontName=FONT_HEADING, fontSize=9, leading=13, textColor=C["accent"], spaceBefore=8, spaceAfter=3),
        "FindingBody":      dict(fontName=FONT_BODY, fontSize=9, leading=13, textColor=C["text"], alignment=TA_JUSTIFY, spaceAfter=4),
        "Evidence":         dict(fontName=FONT_MONO, fontSize=FONT_SIZE_EVIDENCE, leading=10.5, textColor=C["text"], backColor=C["bg_evidence"],
                                 borderPadding=(6, 8, 6, 8), spaceAfter=6, leftIndent=4*mm, rightIndent=4*mm),
        "TableHeader":      dict(fontName=FONT_HEADING, fontSize=FONT_SIZE_TABLE_HEADER, leading=11, textColor=C["white"], alignment=TA_CENTER),
        "TableCell":        dict(fontName=FONT_BODY, fontSize=FONT_SIZE_TABLE_CELL, leading=11, textColor=C["text"]),
        "TableCellCenter":  dict(fontName=FONT_BODY, fontSize=FONT_SIZE_TABLE_CELL, leading=11, textColor=C["text"], alignment=TA_CENTER),
        "TOCEntry":         dict(fontName=FONT_BODY, fontSize=10, leading=18, textColor=C["text"]),
        "TOCSubEntry":      dict(fontName=FONT_BODY, fontSize=9, leading=16, textColor=C["muted"], leftIndent=10*mm),
    }
    for name, kw in defs.items():
        styles.add(ParagraphStyle(name=name, **kw))
    return styles


# ============================================================================
# PAGE DRAWING FUNCTIONS
# ============================================================================

def draw_cover(canvas_obj, doc):
    """Draw cover page background with VectiScan branding."""
    canvas_obj.saveState()
    # Full cover background — dark navy
    canvas_obj.setFillColor(COLORS["cover_bg"])
    canvas_obj.rect(0, 0, WIDTH, HEIGHT, fill=1, stroke=0)
    # Left accent bar — cyan stripe
    canvas_obj.setFillColor(COLORS["cover_accent_bar"])
    canvas_obj.rect(0, 0, 8 * mm, HEIGHT, fill=1, stroke=0)
    # Right geometric overlay
    canvas_obj.setFillColor(COLORS["cover_overlay"])
    canvas_obj.setFillAlpha(0.12)
    canvas_obj.rect(120 * mm, 0, 90 * mm, HEIGHT, fill=1, stroke=0)
    canvas_obj.setFillAlpha(1.0)
    # Logo (if available)
    if LOGO_PATH and os.path.isfile(LOGO_PATH):
        canvas_obj.drawImage(
            LOGO_PATH,
            WIDTH - 50 * mm, HEIGHT - 45 * mm,
            width=30 * mm, height=30 * mm,
            preserveAspectRatio=True, mask="auto",
        )
    # Classification bar — cyan accent (not red)
    canvas_obj.setFillColor(COLORS["accent"])
    canvas_obj.rect(0, 0, WIDTH, 12 * mm, fill=1, stroke=0)
    # Classification text — dark on cyan
    canvas_obj.setFillColor(COLORS["primary"])
    canvas_obj.setFont(FONT_HEADING, 8)
    label = getattr(doc, "_classification_label", CLASSIFICATION_LABEL_DE)
    canvas_obj.drawCentredString(WIDTH / 2, 4 * mm, label)
    canvas_obj.restoreState()


def draw_normal(canvas_obj, doc):
    """Draw header/footer for content pages."""
    canvas_obj.saveState()
    meta = getattr(doc, "_meta", {})
    # Header bar — primary navy
    canvas_obj.setFillColor(COLORS["primary"])
    canvas_obj.rect(0, HEIGHT - 14 * mm, WIDTH, 14 * mm, fill=1, stroke=0)
    canvas_obj.setFillColor(COLORS["white"])
    canvas_obj.setFont(FONT_HEADING, 8)
    canvas_obj.drawString(20 * mm, HEIGHT - 9.5 * mm, meta.get("header_left", "VECTISCAN — SECURITY ASSESSMENT"))
    canvas_obj.setFont(FONT_BODY, 8)
    canvas_obj.drawRightString(WIDTH - 20 * mm, HEIGHT - 9.5 * mm, meta.get("header_right", ""))
    # Accent line under header — cyan, 0.8pt
    canvas_obj.setStrokeColor(COLORS["accent"])
    canvas_obj.setLineWidth(0.8)
    canvas_obj.line(20 * mm, HEIGHT - 14.5 * mm, WIDTH - 20 * mm, HEIGHT - 14.5 * mm)
    # Footer — muted text
    canvas_obj.setFillColor(COLORS["muted"])
    canvas_obj.setFont(FONT_BODY, FONT_SIZE_FOOTER)
    canvas_obj.drawString(20 * mm, 10 * mm, meta.get("footer_left", "Confidential"))
    canvas_obj.drawRightString(WIDTH - 20 * mm, 10 * mm, f"Page {doc.page}")
    # Footer divider — light_accent
    canvas_obj.setStrokeColor(COLORS["light_accent"])
    canvas_obj.setLineWidth(0.3)
    canvas_obj.line(20 * mm, 15 * mm, WIDTH - 20 * mm, 15 * mm)
    canvas_obj.restoreState()


# ============================================================================
# TABLE HELPER
# ============================================================================

def styled_table(header_row, data_rows, col_widths, styles):
    """Create a consistently styled table with header and alternating rows."""
    all_rows = [header_row] + data_rows
    table = Table(all_rows, colWidths=col_widths)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLORS["primary"]),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLORS["bg_light"], COLORS["white"]]),
        ("GRID", (0, 0), (-1, -1), 0.3, COLORS["light_accent"]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


# ============================================================================
# SECTION BUILDERS
# ============================================================================

class PackageBadge(Flowable):
    """Narrow badge bar showing the package type on the cover page."""
    def __init__(self, package_name):
        Flowable.__init__(self)
        badge = PACKAGE_BADGES.get(package_name, PACKAGE_BADGES["professional"])
        self.bg_color = badge["color"]
        self.text_color = badge["text_color"]
        self.label = badge["label"]
        self.width = 50 * mm
        self.height = 8 * mm

    def draw(self):
        self.canv.setFillColor(self.bg_color)
        self.canv.roundRect(0, 0, self.width, self.height, 2 * mm, fill=1, stroke=0)
        self.canv.setFillColor(self.text_color)
        self.canv.setFont(FONT_HEADING, 9)
        self.canv.drawCentredString(self.width / 2, 2.5 * mm, self.label)


def build_package_badge(story, package_name):
    """Add a package badge bar below the cover title."""
    story.append(Spacer(1, 3 * mm))
    story.append(PackageBadge(package_name))


def build_cover(story, styles, data):
    """Build cover page."""
    story.append(Spacer(1, 50 * mm))
    story.append(Paragraph(data.get("cover_subtitle", "AUTOMATED SECURITY ASSESSMENT"), styles["CoverSubtitle"]))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(data.get("cover_title", "Security Assessment"), styles["CoverTitle"]))
    story.append(Spacer(1, 3 * mm))
    # Package badge (if specified)
    package = data.get("package")
    if package and package in PACKAGE_BADGES:
        build_package_badge(story, package)
    story.append(Spacer(1, 8 * mm))
    story.append(HorizontalLine(80 * mm, COLORS["cover_rule"], 0.5))
    story.append(Spacer(1, 8 * mm))

    meta_rows = data.get("cover_meta", [])
    if meta_rows:
        meta_table = Table(meta_rows, colWidths=[35 * mm, 100 * mm])
        meta_table.setStyle(TableStyle([
            ("FONT", (0, 0), (0, -1), FONT_BODY, 9),
            ("FONT", (1, 0), (1, -1), FONT_HEADING, 9),
            ("TEXTCOLOR", (0, 0), (0, -1), COLORS["cover_meta_label"]),
            ("TEXTCOLOR", (1, 0), (1, -1), COLORS["cover_meta_value"]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ]))
        story.append(meta_table)

    story.append(NextPageTemplate("normal"))
    story.append(PageBreak())


def build_toc(story, styles, toc_entries):
    """Build table of contents from list of (number, title, is_sub) tuples."""
    story.append(Paragraph("Table of Contents", styles["SectionTitle"]))
    story.append(Spacer(1, 6 * mm))
    for num, title, is_sub in toc_entries:
        style = styles["TOCSubEntry"] if is_sub else styles["TOCEntry"]
        prefix = f"<b>{num}</b>&nbsp;&nbsp;&nbsp;&nbsp;" if not is_sub else f"{num}&nbsp;&nbsp;&nbsp;"
        story.append(Paragraph(f"{prefix}{title}", style))
    story.append(PageBreak())


def build_finding(story, styles, f):
    """
    Build a single finding section.
    f is a dict with keys: id, title, severity, cvss_score, cvss_vector, cwe,
                           affected, description, evidence, impact, recommendation
    """
    color = SEVERITY_COLORS.get(f["severity"].upper(), COLORS["info"])

    story.append(FindingHeader(f["id"], f["title"], f["severity"], f["cvss_score"], color))
    story.append(Spacer(1, 3 * mm))

    # Metadata row
    meta_data = [
        [Paragraph("<b>CVSS Vector</b>", ParagraphStyle("x", fontName=FONT_HEADING, fontSize=7, textColor=COLORS["muted"])),
         Paragraph("<b>CWE</b>", ParagraphStyle("x", fontName=FONT_HEADING, fontSize=7, textColor=COLORS["muted"])),
         Paragraph("<b>Affected Systems</b>", ParagraphStyle("x", fontName=FONT_HEADING, fontSize=7, textColor=COLORS["muted"]))],
        [Paragraph(f.get("cvss_vector", "N/A"), ParagraphStyle("x", fontName=FONT_MONO, fontSize=7, textColor=COLORS["text"])),
         Paragraph(f.get("cwe", "N/A"), ParagraphStyle("x", fontName=FONT_BODY, fontSize=7.5, textColor=COLORS["text"])),
         Paragraph(f.get("affected", "N/A"), ParagraphStyle("x", fontName=FONT_BODY, fontSize=7.5, textColor=COLORS["text"]))],
    ]
    meta_table = Table(meta_data, colWidths=[85 * mm, 25 * mm, 60 * mm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLORS["bg_light"]),
        ("TOPPADDING", (0, 0), (-1, 0), 4),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 1),
        ("TOPPADDING", (0, 1), (-1, 1), 1),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("ROUNDEDCORNERS", [2, 2, 2, 2]),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 3 * mm))

    # Description
    desc_label = f.get("label_description", "Description")
    story.append(Paragraph(desc_label, styles["FindingLabel"]))
    story.append(Paragraph(f["description"], styles["FindingBody"]))

    # Evidence
    ev_label = f.get("label_evidence", "Evidence")
    story.append(Paragraph(ev_label, styles["FindingLabel"]))
    story.append(Paragraph(f["evidence"], styles["Evidence"]))

    # Impact
    imp_label = f.get("label_impact", "Business Impact")
    story.append(Paragraph(imp_label, styles["FindingLabel"]))
    story.append(Paragraph(f["impact"], styles["FindingBody"]))

    # Recommendation
    rec_label = f.get("label_recommendation", "Recommendation")
    story.append(Paragraph(rec_label, styles["FindingLabel"]))
    story.append(Paragraph(f["recommendation"], styles["FindingBody"]))

    story.append(Spacer(1, 8 * mm))


def build_info_box(story, text, color=None):
    """Colored info box (for PCI-DSS notes, disclaimers, etc.)."""
    bg = color or HexColor("#ebf4ff")
    tc = COLORS["accent"] if color is None else COLORS["text"]
    data = [[Paragraph(text, ParagraphStyle("x", fontName=FONT_BODY, fontSize=8.5, leading=12, textColor=tc))]]
    table = Table(data, colWidths=[170 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("ROUNDEDCORNERS", [3, 3, 3, 3]),
    ]))
    story.append(table)


def build_risk_box(story, label, level, description):
    """Overall risk assessment colored box."""
    level_upper = level.upper()
    level_color = SEVERITY_COLORS.get(level_upper, COLORS["high"])
    data = [
        [Paragraph(f"<b>{label}</b>", ParagraphStyle("x", fontName=FONT_HEADING, fontSize=10, textColor=COLORS["white"], alignment=TA_CENTER)),
         Paragraph(f"<b>{level}</b>", ParagraphStyle("x", fontName=FONT_HEADING, fontSize=10, textColor=COLORS["white"], alignment=TA_CENTER))],
        [Paragraph(description, ParagraphStyle("x", fontName=FONT_BODY, fontSize=9, textColor=COLORS["white"], leading=13, alignment=TA_JUSTIFY)), ""],
    ]
    table = Table(data, colWidths=[130 * mm, 40 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), level_color),
        ("BACKGROUND", (1, 0), (1, 0), COLORS["critical"]),
        ("BACKGROUND", (0, 1), (-1, 1), HexColor("#2d3748")),
        ("SPAN", (0, 1), (1, 1)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(table)


# ============================================================================
# MAIN REPORT BUILDER
# ============================================================================

def generate_report(report_data, output_path):
    """
    Generate a complete pentest report PDF.

    report_data: dict with keys:
        - meta: dict with header_left, header_right, footer_left, classification_label
        - cover: dict with cover_subtitle, cover_title, cover_meta (list of [label, value])
        - toc: list of (number, title, is_sub) tuples
        - executive_summary: dict with paragraphs, risk_level, risk_label, risk_description,
                             distribution_table, recommendations_table
        - scope: dict with scope_table, methodology_paragraphs, limitations_paragraphs,
                 compliance_note (optional)
        - findings: list of finding dicts
        - recommendations: dict with intro_paragraph, roadmap_table
        - appendix_cvss: list of rows for CVSS table
        - appendix_tools: list of rows for tools table
        - appendix_raw: string of raw tool output (evidence-formatted)
        - disclaimer: string
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    meta = report_data.get("meta", {})

    doc = BaseDocTemplate(
        output_path, pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=22 * mm, bottomMargin=20 * mm,
        title=meta.get("title", "Penetration Test Report"),
        author=meta.get("author", "Security Assessment"),
    )

    # Store metadata on doc for page drawing functions
    doc._meta = meta
    doc._classification_label = meta.get("classification_label", "CLASSIFICATION: CONFIDENTIAL — AUTHORIZED RECIPIENTS ONLY")

    cover_frame = Frame(25 * mm, 20 * mm, WIDTH - 50 * mm, HEIGHT - 40 * mm, id="cover")
    normal_frame = Frame(20 * mm, 20 * mm, WIDTH - 40 * mm, HEIGHT - 40 * mm, id="normal")

    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[cover_frame], onPage=draw_cover),
        PageTemplate(id="normal", frames=[normal_frame], onPage=draw_normal),
    ])

    styles = create_styles()
    story = []

    # --- Cover ---
    build_cover(story, styles, report_data.get("cover", {}))

    # --- TOC ---
    toc = report_data.get("toc")
    if toc:
        build_toc(story, styles, toc)

    # --- Executive Summary ---
    es = report_data.get("executive_summary", {})
    if es:
        sec_label = es.get("section_label", "1&nbsp;&nbsp;&nbsp;Executive Summary")
        story.append(Paragraph(sec_label, styles["SectionTitle"]))
        story.append(HorizontalLine(170 * mm, COLORS["accent"], 1))
        story.append(Spacer(1, 4 * mm))

        for sub in es.get("subsections", []):
            story.append(Paragraph(sub["title"], styles["SubsectionTitle"]))
            for p in sub.get("paragraphs", []):
                story.append(Paragraph(p, styles["BodyText2"]))
            if sub.get("risk_box"):
                rb = sub["risk_box"]
                build_risk_box(story, rb["label"], rb["level"], rb["description"])
                story.append(Spacer(1, 6 * mm))
            if sub.get("table"):
                t = sub["table"]
                story.append(styled_table(t["header"], t["rows"], t["widths"], styles))
                story.append(Spacer(1, 6 * mm))

        story.append(PageBreak())

    # --- Scope & Methodology ---
    scope = report_data.get("scope", {})
    if scope:
        sec_label = scope.get("section_label", "2&nbsp;&nbsp;&nbsp;Scope &amp; Methodology")
        story.append(Paragraph(sec_label, styles["SectionTitle"]))
        story.append(HorizontalLine(170 * mm, COLORS["accent"], 1))
        story.append(Spacer(1, 4 * mm))

        for sub in scope.get("subsections", []):
            story.append(Paragraph(sub["title"], styles["SubsectionTitle"]))
            for p in sub.get("paragraphs", []):
                story.append(Paragraph(p, styles["BodyText2"]))
            if sub.get("table"):
                t = sub["table"]
                story.append(styled_table(t["header"], t["rows"], t["widths"], styles))
                story.append(Spacer(1, 4 * mm))
            if sub.get("info_box"):
                build_info_box(story, sub["info_box"])
                story.append(Spacer(1, 3 * mm))

        story.append(PageBreak())

    # --- Findings ---
    findings = report_data.get("findings", [])
    if findings:
        sec_label = report_data.get("findings_section_label", "3&nbsp;&nbsp;&nbsp;Findings")
        story.append(Paragraph(sec_label, styles["SectionTitle"]))
        story.append(HorizontalLine(170 * mm, COLORS["accent"], 1))
        story.append(Spacer(1, 6 * mm))

        for i, f in enumerate(findings):
            build_finding(story, styles, f)
            # Page break between findings if not the last one, and every 2 findings
            if i < len(findings) - 1 and (i + 1) % 2 == 0:
                story.append(PageBreak())

    story.append(PageBreak())

    # --- Recommendations ---
    recs = report_data.get("recommendations", {})
    if recs:
        sec_label = recs.get("section_label", "4&nbsp;&nbsp;&nbsp;Recommendations")
        story.append(Paragraph(sec_label, styles["SectionTitle"]))
        story.append(HorizontalLine(170 * mm, COLORS["accent"], 1))
        story.append(Spacer(1, 4 * mm))
        for p in recs.get("paragraphs", []):
            story.append(Paragraph(p, styles["BodyText2"]))
        story.append(Spacer(1, 4 * mm))
        if recs.get("table"):
            t = recs["table"]
            story.append(styled_table(t["header"], t["rows"], t["widths"], styles))
        story.append(PageBreak())

    # --- Appendices ---
    for appendix in report_data.get("appendices", []):
        story.append(Paragraph(appendix["title"], styles["SectionTitle"]))
        story.append(HorizontalLine(170 * mm, COLORS["accent"], 1))
        story.append(Spacer(1, 4 * mm))
        if appendix.get("table"):
            t = appendix["table"]
            story.append(styled_table(t["header"], t["rows"], t["widths"], styles))
            story.append(Spacer(1, 8 * mm))
        if appendix.get("evidence"):
            story.append(Paragraph(appendix["evidence"], styles["Evidence"]))
            story.append(Spacer(1, 8 * mm))
        for p in appendix.get("paragraphs", []):
            story.append(Paragraph(p, styles["BodyText2"]))

    # --- Disclaimer ---
    disclaimer = report_data.get("disclaimer")
    if disclaimer:
        story.append(Spacer(1, 8 * mm))
        build_info_box(story, disclaimer, COLORS["bg_light"])

    doc.build(story)
    print(f"Report generated: {output_path}")
    return output_path


# ============================================================================
# EXAMPLE USAGE / TEMPLATE
# ============================================================================

if __name__ == "__main__":
    """
    Example: Minimal report to demonstrate the template.
    Replace this with actual engagement data.
    """
    S = create_styles()
    P = lambda text, style_name: Paragraph(text, S[style_name])

    example_data = {
        "meta": {
            "title": "Penetration Test Report",
            "author": "Security Assessment",
            "header_left": "VECTISCAN — SECURITY ASSESSMENT",
            "header_right": "Example Target  |  example.com",
            "footer_left": "Confidential  |  11 March 2026",
            "classification_label": CLASSIFICATION_LABEL_DE,
        },
        "cover": {
            "cover_subtitle": "AUTOMATED SECURITY ASSESSMENT",
            "cover_title": "Security Assessment<br/>Example Target",
            "package": "professional",
            "cover_meta": [
                ["Target:", "example.com (192.168.1.1)"],
                ["Date:", "11 March 2026"],
                ["Methodology:", "PTES"],
                ["Scoring:", "CVSS v3.1"],
                ["Classification:", "Confidential"],
                ["Findings:", "2 (1 High, 1 Informational)"],
            ],
        },
        "toc": [
            ("1", "Executive Summary", False),
            ("2", "Scope & Methodology", False),
            ("3", "Findings", False),
            ("3.1", "EX-2026-001 — Example Finding", True),
            ("3.2", "EX-2026-002 — Positive Finding", True),
            ("4", "Recommendations", False),
        ],
        "executive_summary": {
            "section_label": "1&nbsp;&nbsp;&nbsp;Executive Summary",
            "subsections": [
                {
                    "title": "1.1&nbsp;&nbsp;&nbsp;Overall Assessment",
                    "paragraphs": [
                        "This is an example report demonstrating the template structure. "
                        "Replace this content with actual engagement findings."
                    ],
                    "risk_box": {
                        "label": "Overall Risk Assessment",
                        "level": "HIGH",
                        "description": "Example risk description. Replace with actual assessment.",
                    },
                },
            ],
        },
        "scope": {
            "section_label": "2&nbsp;&nbsp;&nbsp;Scope &amp; Methodology",
            "subsections": [
                {
                    "title": "2.1&nbsp;&nbsp;&nbsp;Scope",
                    "paragraphs": ["Replace with actual scope description."],
                },
            ],
        },
        "findings_section_label": "3&nbsp;&nbsp;&nbsp;Findings",
        "findings": [
            {
                "id": "EX-2026-001",
                "title": "Example High Finding",
                "severity": "HIGH",
                "cvss_score": "7.5",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cwe": "CWE-200",
                "affected": "192.168.1.1:8080",
                "description": "This is an example finding description.",
                "evidence": "$ example-command<br/>example output",
                "impact": "Example business impact description.",
                "recommendation": "<b>Short-term:</b> Example recommendation.",
            },
            {
                "id": "EX-2026-002",
                "title": "Good Security Configuration (Positive)",
                "severity": "INFO",
                "cvss_score": "N/A",
                "cvss_vector": "N/A",
                "cwe": "N/A",
                "affected": "https://example.com/",
                "description": "This is a <b>positive finding</b>. Example.",
                "evidence": "HTTP/2 200<br/>strict-transport-security: max-age=31536000",
                "impact": "Positive impact description.",
                "recommendation": "Continue maintaining this configuration.",
            },
        ],
        "recommendations": {
            "section_label": "4&nbsp;&nbsp;&nbsp;Recommendations",
            "paragraphs": ["Replace with consolidated recommendations overview."],
            "table": {
                "header": [P("<b>Timeframe</b>", "TableHeader"),
                           P("<b>Action</b>", "TableHeader"),
                           P("<b>Finding</b>", "TableHeader")],
                "rows": [
                    [P("Week 1", "TableCell"), P("Fix example finding", "TableCell"), P("001", "TableCellCenter")],
                ],
                "widths": [25 * mm, 120 * mm, 25 * mm],
            },
        },
        "appendices": [],
        "disclaimer": (
            "<b>Disclaimer:</b> This report represents the security posture at the time of testing. "
            "Security assessments are point-in-time snapshots. Regular retesting is recommended."
        ),
    }

    generate_report(example_data, "/mnt/user-data/outputs/vectiscan-branded-test.pdf")
