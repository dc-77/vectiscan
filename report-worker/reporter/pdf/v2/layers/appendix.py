"""Anhaenge A-F (Doc 02 Seite 14+).

M3 Skelett: Stub-Implementierung. Echte Implementierung kommt in M5/M6
(A Scope, B Methodik, C Tools+Versionen, D Glossar, E Manuelle Checks,
F Rohdaten).
"""
from reportlab.platypus import Paragraph, Spacer, PageBreak
from reportlab.lib.units import mm


def build_appendix(story, styles, data):
    section_style = styles.get("SectionTitle") or styles["BodyText"]
    body_style = styles.get("BodyText2") or styles["BodyText"]

    story.append(Paragraph(
        "<b>Anhaenge</b>",
        section_style,
    ))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "(In M5/M6 implementiert: A Scope, B Methodik, C Tools+Versionen, "
        "D Glossar, E Manuelle Checks, F Rohdaten.)",
        body_style,
    ))
    story.append(PageBreak())
