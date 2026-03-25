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
    Paragraph, Spacer, Table, TableStyle, Image,
    PageBreak, Frame, PageTemplate, BaseDocTemplate, NextPageTemplate, Flowable,
    KeepTogether,
)
import os

from reporter.pdf.branding import (
    COLORS, SEVERITY_COLORS, PACKAGE_BADGES,
    COMPANY_NAME, CLASSIFICATION_LABEL_DE, LOGO_PATH,
    FONT_BODY, FONT_HEADING, FONT_MONO,
    FONT_SIZE_BODY, FONT_SIZE_HEADING1, FONT_SIZE_HEADING2,
    FONT_SIZE_EVIDENCE, FONT_SIZE_TABLE_HEADER, FONT_SIZE_TABLE_CELL,
    FONT_SIZE_FOOTER, FONT_SIZE_COVER_TITLE, FONT_SIZE_COVER_SUBTITLE,
    SPACING_SECTION, SPACING_SUBSECTION, SPACING_FINDING, SPACING_PARAGRAPH,
    SPACING_COVER_ELEMENT,
)

WIDTH, HEIGHT = A4

# Maximum width for embedded screenshots (leaving margins)
_MAX_IMAGE_WIDTH = 160 * mm


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
    def __init__(self, finding_id, title, severity, cvss_score, color,
                 compact=False, show_badge=True):
        Flowable.__init__(self)
        self.finding_id = finding_id
        self.title = title
        self.severity = severity
        self.cvss_score = cvss_score
        self.color = color
        self.compact = compact          # smaller bar for positive findings
        self.show_badge = show_badge    # hide CVSS badge for positive findings
        self.width = 170 * mm
        # Determine if title needs two lines (break at ~60 chars on word boundary)
        self._line1, self._line2 = self._split_title(title)
        self._needs_two_lines = bool(self._line2)
        if compact:
            self.height = 12 * mm
        elif self._needs_two_lines:
            self.height = 22 * mm
        else:
            self.height = 18 * mm

    @staticmethod
    def _split_title(title, max_chars=60):
        """Split a long title into two lines, breaking at the last space before max_chars."""
        if len(title) <= max_chars:
            return title, ""
        # Find last space within the first max_chars characters
        break_pos = title.rfind(" ", 0, max_chars)
        if break_pos == -1:
            break_pos = max_chars
        return title[:break_pos].rstrip(), title[break_pos:].lstrip()

    def _is_unrated(self):
        """Check if this finding has no CVSS score (Basic package or positive finding)."""
        score = str(self.cvss_score)
        return score in ("\u2014", "", "N/A", "None")

    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.roundRect(0, 0, self.width, self.height, 2 * mm, fill=1, stroke=0)
        self.canv.setFillColor(COLORS["white"])
        self.canv.setFont(FONT_HEADING, 9)
        self.canv.drawString(4 * mm, self.height - 5.5 * mm, self.finding_id)

        if self._needs_two_lines:
            # Two-line title: use slightly smaller font
            self.canv.setFont(FONT_HEADING, 10)
            self.canv.drawString(4 * mm, self.height - 12 * mm, self._line1)
            self.canv.drawString(4 * mm, self.height - 16 * mm, self._line2)
        elif self.compact:
            self.canv.setFont(FONT_HEADING, 10)
            self.canv.drawString(4 * mm, self.height - 10 * mm, self._line1)
        else:
            self.canv.setFont(FONT_HEADING, 11)
            self.canv.drawString(4 * mm, self.height - 12 * mm, self._line1)

        if self.show_badge:
            badge_x = self.width - 30 * mm
            self.canv.setFillColor(HexColor("#00000033"))
            self.canv.roundRect(badge_x, 3 * mm, 26 * mm, 12 * mm, 2 * mm, fill=1, stroke=0)
            self.canv.setFillColor(COLORS["white"])

            if self._is_unrated():
                # Show prominent severity-only badge (no CVSS)
                self.canv.setFont(FONT_HEADING, 10)
                self.canv.drawCentredString(badge_x + 13 * mm, 7 * mm, self.severity.upper())
            else:
                self.canv.setFont(FONT_HEADING, 8)
                self.canv.drawCentredString(badge_x + 13 * mm, 11 * mm, "CVSS v3.1")
                self.canv.setFont(FONT_HEADING, 10)
                self.canv.drawCentredString(badge_x + 13 * mm, 4.5 * mm, str(self.cvss_score))


def severity_badge_text(severity_name):
    """Return severity name with a colored dot prefix for use in Paragraph HTML.

    Uses Unicode circle character colored via ReportLab's <font> tag.
    """
    sev_upper = severity_name.strip().upper()
    color_obj = SEVERITY_COLORS.get(sev_upper, COLORS["info"])
    # Convert HexColor to hex string for <font> tag
    hex_str = "#{:02x}{:02x}{:02x}".format(
        int(color_obj.red * 255),
        int(color_obj.green * 255),
        int(color_obj.blue * 255),
    )
    return f'<font color="{hex_str}">\u25cf</font>&nbsp;{severity_name}'


# ============================================================================
# STYLES
# ============================================================================

def create_styles():
    styles = getSampleStyleSheet()
    C = COLORS

    defs = {
        "CoverTitle":       dict(fontName=FONT_HEADING, fontSize=FONT_SIZE_COVER_TITLE, leading=34, textColor=C["white"]),
        "CoverSubtitle":    dict(fontName=FONT_BODY, fontSize=FONT_SIZE_COVER_SUBTITLE, leading=20, textColor=HexColor("#a0aec0")),
        "SectionTitle":     dict(fontName=FONT_HEADING, fontSize=FONT_SIZE_HEADING1, leading=24, textColor=C["primary"],
                                 spaceBefore=16, spaceAfter=10, keepWithNext=True),
        "SubsectionTitle":  dict(fontName=FONT_HEADING, fontSize=FONT_SIZE_HEADING2, leading=18, textColor=C["accent"],
                                 spaceBefore=14, spaceAfter=8, keepWithNext=True),
        "BodyText2":        dict(fontName=FONT_BODY, fontSize=FONT_SIZE_BODY, leading=15, textColor=C["text"],
                                 alignment=TA_JUSTIFY, spaceAfter=6),
        "FindingLabel":     dict(fontName=FONT_HEADING, fontSize=10, leading=14, textColor=C["accent"],
                                 spaceBefore=8, spaceAfter=3, keepWithNext=True),
        "FindingBody":      dict(fontName=FONT_BODY, fontSize=FONT_SIZE_BODY, leading=15, textColor=C["text"],
                                 alignment=TA_JUSTIFY, spaceAfter=4),
        "Evidence":         dict(fontName=FONT_MONO, fontSize=FONT_SIZE_EVIDENCE, leading=12, textColor=C["text"], backColor=C["bg_evidence"],
                                 borderPadding=(6, 8, 6, 8), spaceAfter=6, leftIndent=4*mm, rightIndent=4*mm),
        "TableHeader":      dict(fontName=FONT_HEADING, fontSize=FONT_SIZE_TABLE_HEADER, leading=13, textColor=C["white"], alignment=TA_CENTER),
        "TableCell":        dict(fontName=FONT_BODY, fontSize=FONT_SIZE_TABLE_CELL, leading=13, textColor=C["text"]),
        "TableCellCenter":  dict(fontName=FONT_BODY, fontSize=FONT_SIZE_TABLE_CELL, leading=13, textColor=C["text"], alignment=TA_CENTER),
        "TOCEntry":         dict(fontName=FONT_BODY, fontSize=10, leading=18, textColor=C["text"]),
        "TOCSubEntry":      dict(fontName=FONT_BODY, fontSize=9, leading=16, textColor=C["muted"], leftIndent=10*mm),
        "ScreenshotLabel":  dict(fontName=FONT_HEADING, fontSize=9, leading=13, textColor=C["accent"],
                                 spaceBefore=6, spaceAfter=4),
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
    # Left accent bar — cyan stripe (wider for more visual impact)
    canvas_obj.setFillColor(COLORS["cover_accent_bar"])
    canvas_obj.rect(0, 0, 10 * mm, HEIGHT, fill=1, stroke=0)
    # Right geometric overlay
    canvas_obj.setFillColor(COLORS["cover_overlay"])
    canvas_obj.setFillAlpha(0.12)
    canvas_obj.rect(120 * mm, 0, 90 * mm, HEIGHT, fill=1, stroke=0)
    canvas_obj.setFillAlpha(1.0)
    # Logo (if available)
    if LOGO_PATH and os.path.isfile(LOGO_PATH):
        canvas_obj.drawImage(
            LOGO_PATH,
            WIDTH - 55 * mm, HEIGHT - 50 * mm,
            width=35 * mm, height=35 * mm,
            preserveAspectRatio=True, mask="auto",
        )
    # VectiScan text branding (top-left, prominent)
    canvas_obj.setFillColor(COLORS["accent"])
    canvas_obj.setFont(FONT_HEADING, 14)
    canvas_obj.drawString(25 * mm, HEIGHT - 35 * mm, COMPANY_NAME.upper())
    # Classification bar — cyan accent, slightly taller
    canvas_obj.setFillColor(COLORS["accent"])
    canvas_obj.rect(0, 0, WIDTH, 14 * mm, fill=1, stroke=0)
    # Classification text — dark on cyan
    canvas_obj.setFillColor(COLORS["primary"])
    canvas_obj.setFont(FONT_HEADING, 8)
    label = getattr(doc, "_classification_label", CLASSIFICATION_LABEL_DE)
    canvas_obj.drawCentredString(WIDTH / 2, 5 * mm, label)
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
        badge = PACKAGE_BADGES.get(package_name, PACKAGE_BADGES["perimeter"])
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


class NIS2RefBadge(Flowable):
    """Narrow badge bar showing section 30 BSIG reference under a finding header."""
    def __init__(self, nis2_ref_text):
        Flowable.__init__(self)
        self.nis2_ref_text = nis2_ref_text
        self.width = 170 * mm
        self.height = 6 * mm

    def draw(self):
        # Background
        self.canv.setFillColor(COLORS["bg_light"])
        self.canv.rect(0, 0, self.width, self.height, fill=1, stroke=0)
        # Left accent border
        self.canv.setFillColor(COLORS["accent"])
        self.canv.rect(0, 0, 2 * mm, self.height, fill=1, stroke=0)
        # Text
        self.canv.setFillColor(COLORS["accent"])
        self.canv.setFont(FONT_BODY, 7.5)
        self.canv.drawString(5 * mm, 1.8 * mm, f"\u00a730 BSIG: {self.nis2_ref_text}")


def build_package_badge(story, package_name):
    """Add a package badge bar below the cover title."""
    story.append(Spacer(1, 4 * mm))
    story.append(PackageBadge(package_name))


def build_cover(story, styles, data):
    """Build cover page with improved spacing and branding."""
    story.append(Spacer(1, 55 * mm))
    story.append(Paragraph(data.get("cover_subtitle", "AUTOMATED SECURITY ASSESSMENT"), styles["CoverSubtitle"]))
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph(data.get("cover_title", "Security Assessment"), styles["CoverTitle"]))
    story.append(Spacer(1, 5 * mm))
    # Package badge (if specified)
    package = data.get("package")
    if package and package in PACKAGE_BADGES:
        build_package_badge(story, package)
    story.append(Spacer(1, SPACING_COVER_ELEMENT))
    story.append(HorizontalLine(80 * mm, COLORS["cover_rule"], 0.5))
    story.append(Spacer(1, SPACING_COVER_ELEMENT))

    meta_rows = data.get("cover_meta", [])
    if meta_rows:
        meta_table = Table(meta_rows, colWidths=[35 * mm, 100 * mm])
        meta_table.setStyle(TableStyle([
            ("FONT", (0, 0), (0, -1), FONT_BODY, 9),
            ("FONT", (1, 0), (1, -1), FONT_HEADING, 9),
            ("TEXTCOLOR", (0, 0), (0, -1), COLORS["cover_meta_label"]),
            ("TEXTCOLOR", (1, 0), (1, -1), COLORS["cover_meta_value"]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ]))
        story.append(meta_table)

    story.append(NextPageTemplate("normal"))
    story.append(PageBreak())


def build_toc(story, styles, toc_entries):
    """Build table of contents from list of (number, title, is_sub) tuples."""
    story.append(Paragraph("Table of Contents", styles["SectionTitle"]))
    story.append(Spacer(1, SPACING_SUBSECTION))
    for num, title, is_sub in toc_entries:
        style = styles["TOCSubEntry"] if is_sub else styles["TOCEntry"]
        prefix = f"<b>{num}</b>&nbsp;&nbsp;&nbsp;&nbsp;" if not is_sub else f"{num}&nbsp;&nbsp;&nbsp;"
        story.append(Paragraph(f"{prefix}{title}", style))
    story.append(PageBreak())


def _is_positive_finding(f):
    """Check if a finding is a positive/INFO finding."""
    return f.get("severity", "").upper() == "INFO"


def build_finding(story, styles, f, compact=False):
    """
    Build a single finding section using KeepTogether for intelligent page breaks.
    f is a dict with keys: id, title, severity, cvss_score, cvss_vector, cwe,
                           affected, description, evidence, impact, recommendation
    compact: if True, use smaller header, no CVSS badge, simplified metadata (positive findings)
    """
    color = SEVERITY_COLORS.get(f["severity"].upper(), COLORS["info"])

    # Build the finding header + metadata as a group that stays together
    header_group = []
    header_group.append(FindingHeader(
        f["id"], f["title"], f["severity"], f["cvss_score"], color,
        compact=compact, show_badge=(not compact),
    ))
    header_group.append(Spacer(1, 4 * mm))

    # NIS2 reference badge (if present)
    if f.get("nis2_ref"):
        header_group.append(NIS2RefBadge(f["nis2_ref"]))
        header_group.append(Spacer(1, 3 * mm))

    # For compact (positive) findings, show only "Betroffene Systeme" inline
    if compact:
        affected = f.get("affected", "\u2014")
        meta_data = [
            [Paragraph("<b>Betroffene Systeme</b>", ParagraphStyle("x", fontName=FONT_HEADING, fontSize=7.5, textColor=COLORS["muted"]))],
            [Paragraph(affected, ParagraphStyle("x", fontName=FONT_BODY, fontSize=8, textColor=COLORS["text"]))],
        ]
        meta_table = Table(meta_data, colWidths=[170 * mm])
        meta_style_cmds = [
            ("BACKGROUND", (0, 0), (-1, -1), COLORS["bg_light"]),
            ("TOPPADDING", (0, 0), (-1, 0), 4),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 1),
            ("TOPPADDING", (0, 1), (-1, 1), 1),
            ("BOTTOMPADDING", (0, 1), (-1, 1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("ROUNDEDCORNERS", [2, 2, 2, 2]),
        ]
        meta_table.setStyle(TableStyle(meta_style_cmds))
        header_group.append(meta_table)
        header_group.append(Spacer(1, SPACING_PARAGRAPH))

        # Description — keep with header
        desc_label = f.get("label_description", "Description")
        header_group.append(Paragraph(desc_label, styles["FindingLabel"]))
        header_group.append(Paragraph(f["description"], styles["FindingBody"]))

        # Use KeepTogether so the header + meta + description stays on one page
        story.append(KeepTogether(header_group))

        # Evidence (separate block, can flow to next page) — hide if empty
        evidence_text = f.get("evidence", "\u2014")
        if evidence_text not in ("\u2014", "", "N/A", None):
            story.append(Spacer(1, 2 * mm))
            ev_label = f.get("label_evidence", "Evidence")
            story.append(Paragraph(ev_label, styles["FindingLabel"]))
            story.append(Paragraph(evidence_text, styles["Evidence"]))

        # Recommendation
        story.append(Spacer(1, 2 * mm))
        rec_label = f.get("label_recommendation", "Recommendation")
        story.append(Paragraph(rec_label, styles["FindingLabel"]))
        story.append(Paragraph(f["recommendation"], styles["FindingBody"]))

        # Spacing after finding
        story.append(Spacer(1, SPACING_FINDING))
        return

    # --- Full (non-compact) finding rendering below ---

    # Metadata row — only show CVSS/CWE columns when they have real values
    _dash_values = ("\u2014", "", "N/A", "None", None)
    cvss_vector = f.get("cvss_vector", "\u2014")
    cwe = f.get("cwe", "\u2014")
    affected = f.get("affected", "\u2014")
    has_cvss_meta = cvss_vector not in _dash_values or cwe not in _dash_values

    # Build optional thumbnail image for the affected host
    thumb_cell = None
    thumbnail_path = f.get("thumbnail")
    if thumbnail_path:
        print(f"[THUMB] Finding {f.get('id')}: path={thumbnail_path}, exists={os.path.isfile(thumbnail_path)}")
    if thumbnail_path and os.path.isfile(thumbnail_path):
        try:
            thumb_img = Image(thumbnail_path)
            tw, th = thumb_img.drawWidth, thumb_img.drawHeight
            if tw > 0 and th > 0:
                _THUMB_W = 30 * mm
                scale = _THUMB_W / tw
                thumb_img.drawWidth = _THUMB_W
                thumb_img.drawHeight = th * scale
                if thumb_img.drawHeight > 22 * mm:
                    scale2 = 22 * mm / thumb_img.drawHeight
                    thumb_img.drawWidth *= scale2
                    thumb_img.drawHeight = 22 * mm
            thumb_cell = thumb_img
        except Exception:
            thumb_cell = None

    if has_cvss_meta:
        if thumb_cell:
            # Full metadata row with thumbnail
            meta_data = [
                [Paragraph("<b>CVSS Vector</b>", ParagraphStyle("x", fontName=FONT_HEADING, fontSize=7.5, textColor=COLORS["muted"])),
                 Paragraph("<b>CWE</b>", ParagraphStyle("x", fontName=FONT_HEADING, fontSize=7.5, textColor=COLORS["muted"])),
                 Paragraph("<b>Affected Systems</b>", ParagraphStyle("x", fontName=FONT_HEADING, fontSize=7.5, textColor=COLORS["muted"])),
                 ""],
                [Paragraph(cvss_vector, ParagraphStyle("x", fontName=FONT_MONO, fontSize=8.5, textColor=COLORS["text"])),
                 Paragraph(cwe, ParagraphStyle("x", fontName=FONT_BODY, fontSize=8, textColor=COLORS["text"])),
                 Paragraph(affected, ParagraphStyle("x", fontName=FONT_BODY, fontSize=8, textColor=COLORS["text"])),
                 thumb_cell],
            ]
            meta_table = Table(meta_data, colWidths=[75 * mm, 22 * mm, 38 * mm, 35 * mm])
        else:
            # Full metadata row without thumbnail
            meta_data = [
                [Paragraph("<b>CVSS Vector</b>", ParagraphStyle("x", fontName=FONT_HEADING, fontSize=7.5, textColor=COLORS["muted"])),
                 Paragraph("<b>CWE</b>", ParagraphStyle("x", fontName=FONT_HEADING, fontSize=7.5, textColor=COLORS["muted"])),
                 Paragraph("<b>Affected Systems</b>", ParagraphStyle("x", fontName=FONT_HEADING, fontSize=7.5, textColor=COLORS["muted"]))],
                [Paragraph(cvss_vector, ParagraphStyle("x", fontName=FONT_MONO, fontSize=8.5, textColor=COLORS["text"])),
                 Paragraph(cwe, ParagraphStyle("x", fontName=FONT_BODY, fontSize=8, textColor=COLORS["text"])),
                 Paragraph(affected, ParagraphStyle("x", fontName=FONT_BODY, fontSize=8, textColor=COLORS["text"]))],
            ]
            meta_table = Table(meta_data, colWidths=[85 * mm, 25 * mm, 60 * mm])
    else:
        if thumb_cell:
            # Simplified metadata row with thumbnail
            meta_data = [
                [Paragraph("<b>Betroffene Systeme</b>", ParagraphStyle("x", fontName=FONT_HEADING, fontSize=7.5, textColor=COLORS["muted"])),
                 ""],
                [Paragraph(affected, ParagraphStyle("x", fontName=FONT_BODY, fontSize=8, textColor=COLORS["text"])),
                 thumb_cell],
            ]
            meta_table = Table(meta_data, colWidths=[135 * mm, 35 * mm])
        else:
            # Simplified metadata row without thumbnail
            meta_data = [
                [Paragraph("<b>Betroffene Systeme</b>", ParagraphStyle("x", fontName=FONT_HEADING, fontSize=7.5, textColor=COLORS["muted"]))],
                [Paragraph(affected, ParagraphStyle("x", fontName=FONT_BODY, fontSize=8, textColor=COLORS["text"]))],
            ]
            meta_table = Table(meta_data, colWidths=[170 * mm])

    meta_style_cmds = [
        ("BACKGROUND", (0, 0), (-1, -1), COLORS["bg_light"]),
        ("TOPPADDING", (0, 0), (-1, 0), 4),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 1),
        ("TOPPADDING", (0, 1), (-1, 1), 1),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("ROUNDEDCORNERS", [2, 2, 2, 2]),
    ]
    if thumb_cell:
        # Span thumbnail cell across both rows, align center/middle
        last_col = len(meta_data[0]) - 1
        meta_style_cmds += [
            ("SPAN", (last_col, 0), (last_col, 1)),
            ("ALIGN", (last_col, 0), (last_col, 1), "CENTER"),
            ("VALIGN", (last_col, 0), (last_col, 1), "MIDDLE"),
        ]
    meta_table.setStyle(TableStyle(meta_style_cmds))
    header_group.append(meta_table)
    header_group.append(Spacer(1, SPACING_PARAGRAPH))

    # Description — keep with header
    desc_label = f.get("label_description", "Description")
    header_group.append(Paragraph(desc_label, styles["FindingLabel"]))
    header_group.append(Paragraph(f["description"], styles["FindingBody"]))

    # Use KeepTogether so the header + meta + description stays on one page
    story.append(KeepTogether(header_group))

    # Evidence (separate block, can flow to next page) — hide if empty
    evidence_text = f.get("evidence", "\u2014")
    if evidence_text not in ("\u2014", "", "N/A", None):
        story.append(Spacer(1, 2 * mm))
        ev_label = f.get("label_evidence", "Evidence")
        story.append(Paragraph(ev_label, styles["FindingLabel"]))
        story.append(Paragraph(evidence_text, styles["Evidence"]))

    # Impact — hide if empty
    impact_text = f.get("impact", "\u2014")
    if impact_text not in ("\u2014", "", "N/A", None):
        story.append(Spacer(1, 2 * mm))
        imp_label = f.get("label_impact", "Business Impact")
        story.append(Paragraph(imp_label, styles["FindingLabel"]))
        story.append(Paragraph(impact_text, styles["FindingBody"]))

    # Recommendation
    story.append(Spacer(1, 2 * mm))
    rec_label = f.get("label_recommendation", "Recommendation")
    story.append(Paragraph(rec_label, styles["FindingLabel"]))
    story.append(Paragraph(f["recommendation"], styles["FindingBody"]))

    # Spacing after finding
    story.append(Spacer(1, SPACING_FINDING))


def build_screenshots_section(story, styles, screenshots):
    """Build a 'Web-Oberflaechen' subsection with screenshots.

    Args:
        story: The story list to append to.
        styles: ReportLab paragraph styles dict.
        screenshots: List of dicts with 'label' (str) and 'paths' (list[str]).
    """
    if not screenshots:
        return

    story.append(Paragraph("2.3&nbsp;&nbsp;&nbsp;Web-Oberfl\u00e4chen", styles["SubsectionTitle"]))
    story.append(Paragraph(
        "Die folgenden Screenshots wurden automatisch aufgenommen "
        "und dokumentieren die Web-Oberfl\u00e4chen der identifizierten Hosts.",
        styles["BodyText2"],
    ))
    story.append(Spacer(1, SPACING_PARAGRAPH))

    for entry in screenshots:
        label = entry.get("label", "Host")
        paths = entry.get("paths", [])
        for img_path in paths:
            if not os.path.isfile(img_path):
                continue
            # Build label + image as a KeepTogether block
            img_block = []
            img_block.append(Paragraph(
                f"<b>{label}</b>",
                styles["ScreenshotLabel"],
            ))
            try:
                img = Image(img_path)
                # Scale to fit max width while preserving aspect ratio
                iw, ih = img.drawWidth, img.drawHeight
                if iw > 0 and ih > 0:
                    scale = min(_MAX_IMAGE_WIDTH / iw, 1.0)
                    img.drawWidth = iw * scale
                    img.drawHeight = ih * scale
                    # Enforce minimum height of 60mm for small screenshots
                    min_img_height = 60 * mm
                    if img.drawHeight < min_img_height:
                        scale_up = min_img_height / img.drawHeight
                        img.drawWidth *= scale_up
                        img.drawHeight = min_img_height
                        # Re-check max width after scaling up
                        if img.drawWidth > _MAX_IMAGE_WIDTH:
                            scale_down = _MAX_IMAGE_WIDTH / img.drawWidth
                            img.drawWidth = _MAX_IMAGE_WIDTH
                            img.drawHeight *= scale_down
                    # Also cap height to avoid full-page images
                    max_img_height = 120 * mm
                    if img.drawHeight > max_img_height:
                        scale2 = max_img_height / img.drawHeight
                        img.drawWidth *= scale2
                        img.drawHeight = max_img_height
                img_block.append(img)
                img_block.append(Spacer(1, SPACING_FINDING))
                story.append(KeepTogether(img_block))
            except Exception:
                # Skip unreadable images silently
                pass

    story.append(Spacer(1, SPACING_SUBSECTION))


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

    header_row = [
        Paragraph(f"<b>{label}</b>", ParagraphStyle("x", fontName=FONT_HEADING, fontSize=10, textColor=COLORS["white"], alignment=TA_CENTER)),
        Paragraph(f"<b>{level}</b>", ParagraphStyle("x", fontName=FONT_HEADING, fontSize=10, textColor=COLORS["white"], alignment=TA_CENTER)),
    ]

    style_cmds = [
        ("BACKGROUND", (0, 0), (0, 0), level_color),
        ("BACKGROUND", (1, 0), (1, 0), COLORS["critical"]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]

    if description:
        data = [
            header_row,
            [Paragraph(description, ParagraphStyle("x", fontName=FONT_BODY, fontSize=9, textColor=COLORS["white"], leading=13, alignment=TA_JUSTIFY)), ""],
        ]
        style_cmds += [
            ("BACKGROUND", (0, 1), (-1, 1), HexColor("#2d3748")),
            ("SPAN", (0, 1), (1, 1)),
        ]
    else:
        data = [header_row]

    table = Table(data, colWidths=[130 * mm, 40 * mm])
    table.setStyle(TableStyle(style_cmds))
    story.append(table)


# ============================================================================
# NIS2 FLOWABLES & SECTIONS
# ============================================================================

_NIS2_REQUIREMENTS = {
    "nr1_risikoanalyse": ("Nr. 1", "Risikoanalyse und Sicherheitskonzepte",
                          "CVSS-bewertete Findings liefern dokumentierte Risikoanalyse"),
    "nr2_vorfallbewaeltigung": ("Nr. 2", "Bew\u00e4ltigung von Sicherheitsvorf\u00e4llen",
                                "Identifizierte Angriffsvektoren erm\u00f6glichen proaktive Pr\u00e4vention"),
    "nr4_lieferkette": ("Nr. 4", "Sicherheit der Lieferkette",
                        "Report dient als Nachweis gepr\u00fcfter Web-Infrastruktur"),
    "nr5_schwachstellenmanagement": ("Nr. 5", "Schwachstellenmanagement",
                                     "Automatisierte Schwachstellenerkennung mit Priorisierung"),
    "nr6_wirksamkeitsbewertung": ("Nr. 6", "Bewertung der Wirksamkeit von Ma\u00dfnahmen",
                                   "Scan dokumentiert Wirksamkeit getroffener Ma\u00dfnahmen"),
    "nr8_kryptografie": ("Nr. 8", "Konzepte f\u00fcr Kryptografie und Verschl\u00fcsselung",
                          "testssl.sh bewertet TLS-Konfiguration und Cipher-Suites"),
}

_COVERAGE_LABELS = {
    "COVERED": ("\u2713 Abgedeckt", COLORS["nis2_covered"]),
    "PARTIAL": ("\u25d0 Teilweise", COLORS["nis2_partial"]),
    "NOT_IN_SCOPE": ("\u2014 Nicht im Scope", COLORS["nis2_out"]),
}


def build_compliance_summary(story, styles, nis2_data):
    """Build NIS2 compliance summary section with section 30 BSIG table."""
    story.append(PageBreak())
    story.append(Paragraph("NIS2-Compliance-\u00dcbersicht (\u00a730 BSIG)", styles["SectionTitle"]))
    story.append(HorizontalLine(170 * mm, COLORS["accent"], 1))
    story.append(Spacer(1, SPACING_PARAGRAPH))

    # Intro paragraph
    story.append(Paragraph(
        "Die folgende \u00dcbersicht zeigt, inwieweit die Ergebnisse dieses Security Assessments "
        "die Anforderungen des \u00a730 Abs. 2 BSIG (Umsetzungsgesetz der NIS2-Richtlinie) "
        "adressieren. Die Bewertung bezieht sich ausschlie\u00dflich auf die durch den externen "
        "Scan pr\u00fcfbaren Aspekte.",
        styles["BodyText2"],
    ))
    story.append(Spacer(1, SPACING_PARAGRAPH))

    # Scope note info box
    scope_note = nis2_data.get("scope_note", "")
    if scope_note:
        build_info_box(story, scope_note)
        story.append(Spacer(1, SPACING_PARAGRAPH))

    # Compliance table
    header_style = ParagraphStyle("th", fontName=FONT_HEADING, fontSize=FONT_SIZE_TABLE_HEADER,
                                   leading=11, textColor=COLORS["white"], alignment=TA_CENTER)
    cell_style = ParagraphStyle("td", fontName=FONT_BODY, fontSize=FONT_SIZE_TABLE_CELL,
                                 leading=11, textColor=COLORS["text"])

    header_row = [
        Paragraph("<b>\u00a730 BSIG</b>", header_style),
        Paragraph("<b>Anforderung</b>", header_style),
        Paragraph("<b>Abdeckung</b>", header_style),
        Paragraph("<b>Erl\u00e4uterung</b>", header_style),
    ]

    data_rows = []
    for key, (nr, req_name, explanation) in _NIS2_REQUIREMENTS.items():
        status = nis2_data.get(key, "NOT_IN_SCOPE")
        label_text, label_color = _COVERAGE_LABELS.get(status, _COVERAGE_LABELS["NOT_IN_SCOPE"])
        coverage_style = ParagraphStyle("cov", fontName=FONT_HEADING, fontSize=FONT_SIZE_TABLE_CELL,
                                         leading=11, textColor=label_color, alignment=TA_CENTER)
        data_rows.append([
            Paragraph(nr, cell_style),
            Paragraph(req_name, cell_style),
            Paragraph(label_text, coverage_style),
            Paragraph(explanation, cell_style),
        ])

    col_widths = [25 * mm, 45 * mm, 30 * mm, 70 * mm]
    table = styled_table(header_row, data_rows, col_widths, styles)
    story.append(table)
    story.append(Spacer(1, SPACING_FINDING))


def build_audit_trail(story, styles, audit_data):
    """Build audit trail section for NIS2 compliance."""
    story.append(Paragraph("Audit-Trail", styles["SectionTitle"]))
    story.append(HorizontalLine(170 * mm, COLORS["accent"], 1))
    story.append(Spacer(1, SPACING_PARAGRAPH))

    story.append(Paragraph(
        "Die folgenden Informationen dienen der Nachvollziehbarkeit "
        "f\u00fcr Auditzwecke gem\u00e4\u00df \u00a739 BSIG.",
        styles["BodyText2"],
    ))
    story.append(Spacer(1, SPACING_PARAGRAPH))

    # Audit data table
    cell_label = ParagraphStyle("al", fontName=FONT_HEADING, fontSize=FONT_SIZE_TABLE_CELL,
                                 leading=11, textColor=COLORS["text"])
    cell_value = ParagraphStyle("av", fontName=FONT_BODY, fontSize=FONT_SIZE_TABLE_CELL,
                                 leading=11, textColor=COLORS["text"])
    header_style = ParagraphStyle("th", fontName=FONT_HEADING, fontSize=FONT_SIZE_TABLE_HEADER,
                                   leading=11, textColor=COLORS["white"], alignment=TA_CENTER)

    header_row = [
        Paragraph("<b>Eigenschaft</b>", header_style),
        Paragraph("<b>Wert</b>", header_style),
    ]

    # Build tool versions string
    tools = audit_data.get("tools", [])
    tools_str = "<br/>".join(tools) if tools else "\u2014"

    data_rows = [
        [Paragraph("Scan-Zeitpunkt (Start)", cell_label),
         Paragraph(str(audit_data.get("scan_start", "\u2014")), cell_value)],
        [Paragraph("Scan-Zeitpunkt (Ende)", cell_label),
         Paragraph(str(audit_data.get("scan_end", "\u2014")), cell_value)],
        [Paragraph("Scan-Dauer", cell_label),
         Paragraph(str(audit_data.get("duration", "\u2014")), cell_value)],
        [Paragraph("Methodik", cell_label),
         Paragraph("PTES (automatisiert)", cell_value)],
        [Paragraph("Scoring-System", cell_label),
         Paragraph("CVSS v3.1", cell_value)],
        [Paragraph("Gescannte Hosts", cell_label),
         Paragraph(str(audit_data.get("hosts_scanned", "\u2014")), cell_value)],
        [Paragraph("Scan-Tiefe", cell_label),
         Paragraph("Professional", cell_value)],
        [Paragraph("Tool-Versionen", cell_label),
         Paragraph(tools_str, cell_value)],
    ]

    col_widths = [45 * mm, 125 * mm]
    table = styled_table(header_row, data_rows, col_widths, styles)
    story.append(table)
    story.append(Spacer(1, SPACING_FINDING))

    # Hint box
    build_info_box(story, "Alle Tool-Aufrufe werden geloggt und sind "
                   "auf Anfrage f\u00fcr Auditzwecke verf\u00fcgbar.")
    story.append(Spacer(1, SPACING_FINDING))


def build_supply_chain_page(story, styles, supply_chain_data, scan_meta):
    """Build supply chain summary page (standalone 1-pager for section 30 Abs. 2 Nr. 4 BSIG)."""
    story.append(PageBreak())
    story.append(Paragraph("Lieferketten-Zusammenfassung", styles["SectionTitle"]))
    story.append(Paragraph(
        "Nachweis gem\u00e4\u00df \u00a730 Abs. 2 Nr. 4 BSIG \u2014 Sicherheit der Lieferkette",
        styles["SubsectionTitle"],
    ))
    story.append(Spacer(1, SPACING_PARAGRAPH))

    # Risk box
    overall_rating = supply_chain_data.get("overall_rating", "MEDIUM")
    recommendation = supply_chain_data.get("recommendation", "")
    build_risk_box(story, "Gesamtbewertung f\u00fcr Auftraggeber", overall_rating, recommendation)
    story.append(Spacer(1, SPACING_FINDING))

    # Key metrics table
    header_style = ParagraphStyle("th", fontName=FONT_HEADING, fontSize=FONT_SIZE_TABLE_HEADER,
                                   leading=11, textColor=COLORS["white"], alignment=TA_CENTER)
    cell_label = ParagraphStyle("al", fontName=FONT_HEADING, fontSize=FONT_SIZE_TABLE_CELL,
                                 leading=11, textColor=COLORS["text"])
    cell_value = ParagraphStyle("av", fontName=FONT_BODY, fontSize=FONT_SIZE_TABLE_CELL,
                                 leading=11, textColor=COLORS["text"])

    header_row = [
        Paragraph("<b>Kennzahl</b>", header_style),
        Paragraph("<b>Wert</b>", header_style),
    ]

    data_rows = [
        [Paragraph("Gepr\u00fcfte Domain", cell_label),
         Paragraph(str(scan_meta.get("domain", "\u2014")), cell_value)],
        [Paragraph("Scan-Datum", cell_label),
         Paragraph(str(scan_meta.get("date", "\u2014")), cell_value)],
        [Paragraph("Gesamtrisiko", cell_label),
         Paragraph(overall_rating, cell_value)],
        [Paragraph("Kritische/Hohe Befunde", cell_label),
         Paragraph(str(supply_chain_data.get("key_findings_count", 0)), cell_value)],
        [Paragraph("Positive Befunde", cell_label),
         Paragraph(str(supply_chain_data.get("positive_count", 0)), cell_value)],
        [Paragraph("Methodik", cell_label),
         Paragraph("PTES / CVSS v3.1", cell_value)],
    ]

    col_widths = [55 * mm, 115 * mm]
    table = styled_table(header_row, data_rows, col_widths, styles)
    story.append(table)
    story.append(Spacer(1, SPACING_FINDING))

    # Note text
    story.append(Paragraph(
        "Vollst\u00e4ndige technische Details sind im Hauptbericht dokumentiert.",
        styles["BodyText2"],
    ))
    story.append(Spacer(1, SPACING_PARAGRAPH))

    # Signature line
    story.append(Spacer(1, SPACING_SECTION))
    sig_style = ParagraphStyle("sig", fontName=FONT_BODY, fontSize=8, leading=12,
                                textColor=COLORS["muted"])
    story.append(Paragraph("Best\u00e4tigung durch Auftraggeber:", sig_style))
    story.append(Spacer(1, 10 * mm))

    # Two signature blocks side by side
    sig_header = ParagraphStyle("sigh", fontName=FONT_HEADING, fontSize=7.5, leading=10,
                                 textColor=COLORS["muted"])
    sig_cell = ParagraphStyle("sigc", fontName=FONT_BODY, fontSize=8, leading=10,
                               textColor=COLORS["text"])
    sig_rows = [
        [Paragraph("<b>Datum / Unterschrift</b>", sig_header),
         Paragraph("<b>Name / Funktion</b>", sig_header)],
        [Paragraph("______________________________", sig_cell),
         Paragraph("______________________________", sig_cell)],
    ]
    sig_table = Table(sig_rows, colWidths=[85 * mm, 85 * mm])
    sig_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(sig_table)
    story.append(Spacer(1, SPACING_FINDING))

    # Footer
    story.append(HorizontalLine(170 * mm, COLORS["light_accent"], 0.5))
    story.append(Spacer(1, 3 * mm))
    footer_style = ParagraphStyle("scf", fontName=FONT_BODY, fontSize=7.5, leading=10,
                                   textColor=COLORS["muted"], alignment=TA_CENTER)
    story.append(Paragraph(
        "Erstellt mit VectiScan \u2014 Automated Security Assessment \u2014 vectigal.tech",
        footer_style,
    ))


# ============================================================================
# BSI TR-03116-4 TLS COMPLIANCE SECTION
# ============================================================================

# Row background colors for TR-03116-4 compliance table
_TR_ROW_FAIL = HexColor("#FEF2F2")   # Very light red
_TR_ROW_WARN = HexColor("#FFFBEB")   # Very light yellow
_TR_BADGE_PASS = HexColor("#22C55E")  # Green
_TR_BADGE_PARTIAL = HexColor("#EAB308")  # Yellow
_TR_BADGE_FAIL = HexColor("#EF4444")  # Red

_TR_STATUS_SYMBOLS = {
    "PASS": "\u2713",   # ✓
    "FAIL": "\u2717",   # ✗
    "WARN": "\u26A0",   # ⚠
    "N/A":  "\u2014",   # —
}

_TR_STATUS_COLORS = {
    "PASS": HexColor("#22C55E"),
    "FAIL": HexColor("#EF4444"),
    "WARN": HexColor("#EAB308"),
    "N/A":  HexColor("#94A3B8"),
}


class TRComplianceBadge(Flowable):
    """Badge showing TR-03116-4 compliance status for a host."""

    def __init__(self, status, host, score):
        Flowable.__init__(self)
        self.status = status
        self.host = host
        self.score = score
        self.width = 170 * mm
        self.height = 9 * mm

    def draw(self):
        badge_colors = {
            "PASS": (_TR_BADGE_PASS, "TR-KONFORM"),
            "PARTIAL": (_TR_BADGE_PARTIAL, "TEILWEISE KONFORM"),
            "FAIL": (_TR_BADGE_FAIL, "NICHT KONFORM"),
        }
        color, label = badge_colors.get(self.status, (_TR_BADGE_FAIL, "UNBEKANNT"))

        # Host name
        self.canv.setFillColor(COLORS["text"])
        self.canv.setFont(FONT_HEADING, 11)
        self.canv.drawString(0, 2 * mm, self.host)

        # Badge
        badge_x = 90 * mm
        badge_w = 38 * mm
        self.canv.setFillColor(color)
        self.canv.roundRect(badge_x, 0.5 * mm, badge_w, 7 * mm, 2 * mm, fill=1, stroke=0)
        self.canv.setFillColor(HexColor("#FFFFFF"))
        self.canv.setFont(FONT_HEADING, 8)
        self.canv.drawCentredString(badge_x + badge_w / 2, 2.5 * mm, label)

        # Score
        self.canv.setFillColor(COLORS["muted"])
        self.canv.setFont(FONT_BODY, 9)
        self.canv.drawString(132 * mm, 2.5 * mm, f"{self.score} Prüfpunkte bestanden")


def build_tr03116_section(story, styles, tr03116_data):
    """Build the BSI TR-03116-4 TLS compliance section in the PDF."""
    if not tr03116_data:
        return

    # Section header
    story.append(Paragraph(
        "BSI TR-03116-4 TLS-Compliance-Prüfung",
        styles["SectionTitle"],
    ))
    story.append(HorizontalLine(170 * mm, COLORS["accent"], 1))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        "Prüfung gemäß BSI TLS-Checkliste für Diensteanbieter (Stand 2023)",
        ParagraphStyle(
            "TRSubtitle",
            parent=styles["BodyText2"],
            fontSize=9,
            textColor=COLORS["muted"],
            spaceAfter=4 * mm,
        ),
    ))

    for host_result in tr03116_data:
        host = host_result.get("host", "")
        overall = host_result.get("overall_status", "FAIL")
        score = host_result.get("score", "0/0")

        # Host badge
        story.append(TRComplianceBadge(overall, host, score))
        story.append(Spacer(1, 3 * mm))

        sections = host_result.get("sections", {})
        for sec_id in ("2.1", "2.2", "2.3", "2.4", "2.5", "2.6"):
            section = sections.get(sec_id)
            if not section:
                continue

            sec_title = section.get("title", "")
            required = section.get("required", True)
            optional_hint = "" if required else " (Empfehlungen — optional)"

            # Section sub-header row style
            sub_style = ParagraphStyle(
                f"TRSec{sec_id}",
                parent=styles["BodyText2"],
                fontSize=8,
                fontName=FONT_HEADING,
                textColor=COLORS["text"],
            )
            check_style = ParagraphStyle(
                "TRCheck",
                parent=styles["BodyText2"],
                fontSize=8,
                textColor=COLORS["text"],
            )
            detail_style = ParagraphStyle(
                "TRDetail",
                parent=styles["BodyText2"],
                fontSize=7.5,
                textColor=COLORS["muted"],
            )
            status_style_pass = ParagraphStyle("TRPass", parent=check_style,
                                               textColor=_TR_STATUS_COLORS["PASS"])
            status_style_fail = ParagraphStyle("TRFail", parent=check_style,
                                               textColor=_TR_STATUS_COLORS["FAIL"])
            status_style_warn = ParagraphStyle("TRWarn", parent=check_style,
                                               textColor=_TR_STATUS_COLORS["WARN"])
            status_style_na = ParagraphStyle("TRNA", parent=check_style,
                                             textColor=_TR_STATUS_COLORS["N/A"])
            status_styles = {
                "PASS": status_style_pass,
                "FAIL": status_style_fail,
                "WARN": status_style_warn,
                "N/A": status_style_na,
            }

            # Build header row
            hdr_style = ParagraphStyle(
                "TRHdr",
                parent=styles["BodyText2"],
                fontSize=8,
                fontName=FONT_HEADING,
                textColor=HexColor("#FFFFFF"),
            )
            header_row = [
                Paragraph("#", hdr_style),
                Paragraph("Prüfpunkt", hdr_style),
                Paragraph("Status", hdr_style),
                Paragraph("Detail", hdr_style),
            ]

            # Build data rows
            data_rows = []
            # Section header row
            data_rows.append([
                Paragraph(sec_id, sub_style),
                Paragraph(f"<b>{sec_title}{optional_hint}</b>", sub_style),
                Paragraph("", sub_style),
                Paragraph("", sub_style),
            ])

            checks = section.get("checks", [])
            for c in checks:
                status = c.get("status", "N/A")
                symbol = _TR_STATUS_SYMBOLS.get(status, "—")
                s_style = status_styles.get(status, status_style_na)

                data_rows.append([
                    Paragraph(c.get("check_id", ""), check_style),
                    Paragraph(c.get("title", ""), check_style),
                    Paragraph(f"<b>{symbol}</b>", s_style),
                    Paragraph(c.get("detail", "")[:120], detail_style),
                ])

            col_widths = [14 * mm, 55 * mm, 12 * mm, 89 * mm]
            all_rows = [header_row] + data_rows
            table = Table(all_rows, colWidths=col_widths)

            # Build table style commands
            style_cmds = [
                # Header row
                ("BACKGROUND", (0, 0), (-1, 0), COLORS["primary"]),
                ("GRID", (0, 0), (-1, -1), 0.3, COLORS["light_accent"]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                # Section header row (row 1)
                ("BACKGROUND", (0, 1), (-1, 1), COLORS["bg_light"]),
                ("SPAN", (1, 1), (3, 1)),
            ]

            # Color rows based on check status
            for row_idx, c in enumerate(checks, start=2):
                status = c.get("status", "N/A")
                if status == "FAIL":
                    style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), _TR_ROW_FAIL))
                elif status == "WARN":
                    style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), _TR_ROW_WARN))

            table.setStyle(TableStyle(style_cmds))
            story.append(table)
            story.append(Spacer(1, 2 * mm))

        story.append(Spacer(1, 3 * mm))

    # Footnote
    footnote_style = ParagraphStyle(
        "TRFootnote",
        parent=styles["BodyText2"],
        fontSize=7,
        fontName=FONT_BODY,
        textColor=COLORS["muted"],
        italic=True,
        spaceAfter=SPACING_SECTION,
    )
    story.append(Paragraph(
        "<i>Diese Prüfung erfolgt automatisiert auf Basis externer TLS-Analyse "
        "(testssl.sh) und bildet die Abschnitte 2.1–2.6 der BSI TLS-Checkliste "
        "ab. Abschnitte 3 (S/MIME), 4 (SAML) und 5 (OpenPGP) der TR-03116-4 "
        "erfordern interne Konfigurationsprüfung und sind nicht Bestandteil "
        "dieser externen Analyse.</i>",
        footnote_style,
    ))


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
        - screenshots: list of dicts with label, paths
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
    doc._classification_label = meta.get("classification_label", "CLASSIFICATION: CONFIDENTIAL \u2014 AUTHORIZED RECIPIENTS ONLY")

    cover_frame = Frame(25 * mm, 20 * mm, WIDTH - 50 * mm, HEIGHT - 40 * mm, id="cover")
    normal_frame = Frame(20 * mm, 20 * mm, WIDTH - 40 * mm, HEIGHT - 40 * mm, id="normal")

    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[cover_frame], onPage=draw_cover),
        PageTemplate(id="normal", frames=[normal_frame], onPage=draw_normal),
    ])

    styles = create_styles()
    story = []
    nis2 = report_data.get("nis2")

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
        story.append(Spacer(1, SPACING_PARAGRAPH))

        for sub in es.get("subsections", []):
            story.append(Paragraph(sub["title"], styles["SubsectionTitle"]))
            for p in sub.get("paragraphs", []):
                story.append(Paragraph(p, styles["BodyText2"]))
            if sub.get("risk_box"):
                rb = sub["risk_box"]
                # If this subsection already has paragraphs, skip the risk_box
                # description to avoid duplicate text — show label+level only
                rb_desc = rb.get("description", "")
                if sub.get("paragraphs"):
                    rb_desc = ""
                build_risk_box(story, rb["label"], rb["level"], rb_desc)
                story.append(Spacer(1, SPACING_SUBSECTION))
            if sub.get("table"):
                t = sub["table"]
                story.append(styled_table(t["header"], t["rows"], t["widths"], styles))
                story.append(Spacer(1, SPACING_SUBSECTION))

        story.append(PageBreak())

    # --- NIS2 Compliance Summary (after Executive Summary) ---
    if nis2 and nis2.get("compliance_summary"):
        build_compliance_summary(story, styles, nis2["compliance_summary"])

    # --- Scope & Methodology ---
    scope = report_data.get("scope", {})
    if scope:
        sec_label = scope.get("section_label", "2&nbsp;&nbsp;&nbsp;Scope &amp; Methodology")
        story.append(Paragraph(sec_label, styles["SectionTitle"]))
        story.append(HorizontalLine(170 * mm, COLORS["accent"], 1))
        story.append(Spacer(1, SPACING_PARAGRAPH))

        for sub in scope.get("subsections", []):
            story.append(Paragraph(sub["title"], styles["SubsectionTitle"]))
            for p in sub.get("paragraphs", []):
                story.append(Paragraph(p, styles["BodyText2"]))
            if sub.get("table"):
                t = sub["table"]
                story.append(styled_table(t["header"], t["rows"], t["widths"], styles))
                story.append(Spacer(1, SPACING_PARAGRAPH))
            if sub.get("info_box"):
                build_info_box(story, sub["info_box"])
                story.append(Spacer(1, SPACING_PARAGRAPH))

        # --- Screenshots (Web-Oberflaechen) subsection ---
        screenshots = report_data.get("screenshots", [])
        if screenshots:
            build_screenshots_section(story, styles, screenshots)

        story.append(PageBreak())

    # --- Findings ---
    findings = report_data.get("findings", [])
    if findings:
        # Split into negative (non-INFO) and positive (INFO) findings
        negative_findings = [f for f in findings if not _is_positive_finding(f)]
        positive_findings = [f for f in findings if _is_positive_finding(f)]

        # Section heading kept with first finding via keepWithNext on the style
        sec_label = report_data.get("findings_section_label", "3&nbsp;&nbsp;&nbsp;Findings")
        story.append(Paragraph(sec_label, styles["SectionTitle"]))
        story.append(HorizontalLine(170 * mm, COLORS["accent"], 1))
        story.append(Spacer(1, SPACING_SUBSECTION))

        for f in negative_findings:
            build_finding(story, styles, f, compact=False)

        # Positive findings subsection
        if positive_findings:
            story.append(Spacer(1, SPACING_SECTION))
            story.append(Paragraph("Positive Befunde", styles["SubsectionTitle"]))
            story.append(Spacer(1, SPACING_PARAGRAPH))
            for f in positive_findings:
                build_finding(story, styles, f, compact=True)

    story.append(PageBreak())

    # --- BSI TR-03116-4 TLS Compliance (after Findings, before Recommendations) ---
    tr03116 = report_data.get("tr03116_compliance")
    if tr03116:
        build_tr03116_section(story, styles, tr03116)
        story.append(PageBreak())

    # --- Recommendations ---
    recs = report_data.get("recommendations", {})
    if recs:
        sec_label = recs.get("section_label", "4&nbsp;&nbsp;&nbsp;Recommendations")
        story.append(Paragraph(sec_label, styles["SectionTitle"]))
        story.append(HorizontalLine(170 * mm, COLORS["accent"], 1))
        story.append(Spacer(1, SPACING_PARAGRAPH))
        for p in recs.get("paragraphs", []):
            story.append(Paragraph(p, styles["BodyText2"]))
        story.append(Spacer(1, SPACING_PARAGRAPH))
        if recs.get("table"):
            t = recs["table"]
            story.append(styled_table(t["header"], t["rows"], t["widths"], styles))
        story.append(PageBreak())

    # --- NIS2 Audit Trail (after Recommendations, before Appendices) ---
    if nis2 and nis2.get("audit_trail"):
        build_audit_trail(story, styles, nis2["audit_trail"])

    # --- Appendices ---
    for appendix in report_data.get("appendices", []):
        story.append(Paragraph(appendix["title"], styles["SectionTitle"]))
        story.append(HorizontalLine(170 * mm, COLORS["accent"], 1))
        story.append(Spacer(1, SPACING_PARAGRAPH))
        if appendix.get("table"):
            t = appendix["table"]
            story.append(styled_table(t["header"], t["rows"], t["widths"], styles))
            story.append(Spacer(1, SPACING_SUBSECTION))
        if appendix.get("evidence"):
            story.append(Paragraph(appendix["evidence"], styles["Evidence"]))
            story.append(Spacer(1, SPACING_SUBSECTION))
        for p in appendix.get("paragraphs", []):
            story.append(Paragraph(p, styles["BodyText2"]))

    # --- NIS2 Supply Chain Page (before Disclaimer) ---
    if nis2 and nis2.get("supply_chain"):
        build_supply_chain_page(story, styles, nis2["supply_chain"], report_data.get("scan_meta", {}))

    # --- Disclaimer ---
    disclaimer = report_data.get("disclaimer")
    if disclaimer:
        story.append(Spacer(1, SPACING_SUBSECTION))
        # Build comprehensive disclaimer section with bold subsection titles
        story.append(Paragraph("Haftungsausschluss", styles["SectionTitle"]))
        story.append(HorizontalLine(170 * mm, COLORS["accent"], 1))
        story.append(Spacer(1, SPACING_PARAGRAPH))

        _disclaimer_paragraphs = [
            (
                "Geltungsbereich",
                "Dieser Bericht dokumentiert den Sicherheitsstatus der gepr\u00fcften Systeme "
                "ausschlie\u00dflich zum Zeitpunkt der Durchf\u00fchrung. Sicherheitsbewertungen sind "
                "Momentaufnahmen und verlieren mit der Zeit an Aussagekraft, da neue Schwachstellen "
                "entdeckt, Software aktualisiert oder Konfigurationen ver\u00e4ndert werden k\u00f6nnen."
            ),
            (
                "Keine Vollst\u00e4ndigkeitsgarantie",
                "Die Pr\u00fcfung wurde ausschlie\u00dflich von extern ohne Zugang zu internen Systemen, "
                "Quellcode oder Dokumentation durchgef\u00fchrt. Es besteht keine Garantie, dass "
                "s\u00e4mtliche vorhandenen Schwachstellen identifiziert wurden. Insbesondere k\u00f6nnen "
                "Schwachstellen existieren, die nur durch interne Pr\u00fcfungen, manuelle Code-Reviews "
                "oder Social-Engineering-Tests aufgedeckt werden k\u00f6nnen."
            ),
            (
                "Haftungsbegrenzung",
                "BS Consulting \u00fcbernimmt keine Haftung f\u00fcr Sch\u00e4den, die aus der Umsetzung "
                "oder Nicht-Umsetzung der in diesem Bericht enthaltenen Empfehlungen entstehen. "
                "Die Empfehlungen stellen keine rechtsverbindliche Beratung dar. F\u00fcr die Umsetzung "
                "von Ma\u00dfnahmen ist der Auftraggeber verantwortlich."
            ),
            (
                "Vertraulichkeit",
                "Dieser Bericht ist ausschlie\u00dflich f\u00fcr den Auftraggeber bestimmt und darf ohne "
                "schriftliche Genehmigung nicht an Dritte weitergegeben werden. Bei der Weitergabe an "
                "autorisierte Dritte (z.B. IT-Dienstleister, Versicherer) liegt die Verantwortung "
                "f\u00fcr die Wahrung der Vertraulichkeit beim Auftraggeber."
            ),
            (
                "Wiederholungspr\u00fcfung",
                "Es wird empfohlen, Sicherheitspr\u00fcfungen in regelm\u00e4\u00dfigen Abst\u00e4nden "
                "(mindestens alle 12 Monate) sowie nach wesentlichen \u00c4nderungen an der Infrastruktur "
                "zu wiederholen."
            ),
        ]

        for sub_title, sub_text in _disclaimer_paragraphs:
            story.append(Paragraph(
                f"<b>{sub_title}:</b> {sub_text}",
                styles["BodyText2"],
            ))
            story.append(Spacer(1, SPACING_PARAGRAPH))

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
            "header_left": "VECTISCAN \u2014 SECURITY ASSESSMENT",
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
            ("3.1", "EX-2026-001 \u2014 Example Finding", True),
            ("3.2", "EX-2026-002 \u2014 Positive Finding", True),
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
        "screenshots": [],
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
                "cvss_score": "\u2014",
                "cvss_vector": "\u2014",
                "cwe": "\u2014",
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
