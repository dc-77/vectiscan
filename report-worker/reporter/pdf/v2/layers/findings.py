"""Schicht 3 -- Befund-Details (Doc 02 Seite 11+).

M3 Skelett: Stub-Implementierung. Echte Implementierung kommt in M5
(WAS / NACHWEIS / THREAT INTELLIGENCE / GESCHAEFTSAUSWIRKUNG /
EMPFEHLUNG / VERIFIKATION / INTERNE REFERENZ).
"""
from reportlab.platypus import Paragraph, Spacer, PageBreak
from reportlab.lib.units import mm


def build_layer3_findings(story, styles, data):
    section_style = styles.get("SectionTitle") or styles["BodyText"]
    body_style = styles.get("BodyText2") or styles["BodyText"]

    story.append(Paragraph(
        "<b>Schicht 3 -- Befund-Details</b>",
        section_style,
    ))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "(In M5 implementiert: Befund-Header + 7-Sektionen-Body.)",
        body_style,
    ))
    story.append(PageBreak())
