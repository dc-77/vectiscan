"""V2 Renderer-Top-Level.

Pipeline:
   Cover -> Frontpage (Schicht 1) -> Strategy (Schicht 2) ->
   Findings (Schicht 3) -> Appendix.
"""
import os

from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, NextPageTemplate,
)
from reportlab.lib.units import mm

# WIDTH/HEIGHT werden in reporter.generate_report als A4-Tuple exportiert.
from reporter.generate_report import (
    create_styles,
    draw_cover,
    draw_normal,
    WIDTH,
    HEIGHT,
)
from reporter.pdf.v2.cover import build_cover_v2
from reporter.pdf.v2.layers.frontpage import build_layer1_frontpage
from reporter.pdf.v2.layers.strategy import build_layer2_strategy
from reporter.pdf.v2.layers.findings import build_layer3_findings
from reporter.pdf.v2.layers.appendix import build_appendix


def generate_report_v2(report_data, output_path):
    """Top-Level v2-Renderer.

    Args:
        report_data: Dict aus report_mapper.map_to_report_data(...)
            plus v2-Augmentierungen aus _augment_for_v2 (layer1, domain).
        output_path: Ziel-PDF-Pfad.
    """
    out_dir = os.path.dirname(output_path) or "."
    os.makedirs(out_dir, exist_ok=True)

    meta = report_data.get("meta", {}) or {}
    doc = BaseDocTemplate(
        output_path,
        pagesize=(WIDTH, HEIGHT),
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=22 * mm,
        bottomMargin=20 * mm,
        title=meta.get("title", "VectiScan Report"),
        author=meta.get("author", "VectiScan"),
    )
    doc._meta = meta
    doc._classification_label = meta.get(
        "classification_label",
        # Echte Umlaute + Em-Dash: der fruehere ASCII-Workaround war ein Symptom des
        # fehlenden Unicode-Fonts, der jetzt in branding.py eingebettet wird.
        "KLASSIFIZIERUNG: VERTRAULICH — NUR FÜR AUTORISIERTE EMPFÄNGER",
    )

    cover_frame = Frame(
        25 * mm, 20 * mm,
        WIDTH - 50 * mm, HEIGHT - 40 * mm,
        id="cover",
    )
    normal_frame = Frame(
        20 * mm, 20 * mm,
        WIDTH - 40 * mm, HEIGHT - 40 * mm,
        id="normal",
    )
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[cover_frame], onPage=draw_cover),
        PageTemplate(id="normal", frames=[normal_frame], onPage=draw_normal),
    ])

    styles = create_styles()
    story = []

    # Cover-Seite mit Cover-Template, ab Seite 2 normal-Template.
    # build_cover_v2 emittiert intern NextPageTemplate('normal') + PageBreak,
    # so dass alle Folge-Seiten das normal-Template nutzen.
    build_cover_v2(story, styles, report_data.get("cover", {}))
    build_layer1_frontpage(story, styles, report_data)
    build_layer2_strategy(story, styles, report_data)
    build_layer3_findings(story, styles, report_data)
    build_appendix(story, styles, report_data)

    doc.build(story)
