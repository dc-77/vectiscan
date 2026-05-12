"""V2 Cover: Klassifizierung sichtbar, Scope sichtbar, Risk-Indikator NICHT
auf dem Cover (Datenschutz beim Drucker-Postfach).
"""
from reportlab.platypus import Paragraph, Spacer, PageBreak
from reportlab.lib.units import mm

from reporter.pdf.branding import CLASSIFICATION_LABEL_DE


def build_cover_v2(story, styles, cover_data):
    cover_data = cover_data or {}
    title = cover_data.get("cover_title", "Sicherheitsbewertung")
    subtitle = cover_data.get(
        "cover_subtitle", "VECTISCAN AUTOMATED SECURITY ASSESSMENT"
    )
    body_style = styles.get("BodyText2") or styles["BodyText"]

    story.append(Spacer(1, 40 * mm))
    story.append(Paragraph(
        f"<font color='#0F172A' size='14'>{subtitle}</font>",
        body_style,
    ))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        f"<font color='#0F172A' size='28'><b>{title}</b></font>",
        body_style,
    ))
    story.append(Spacer(1, 12 * mm))

    # Cover-Meta: Domain, Hosts, Paket, Datum -- KEINE Risk-Stufe.
    rows = cover_data.get("cover_meta") or []
    for row in rows:
        if not row or len(row) < 2:
            continue
        label, value = row[0], row[1]
        label_str = str(label or "").lower()
        if label_str.startswith(("ergebnis", "risiko", "befunde")):
            continue  # NEW v2: Risk-Indikator nicht auf Cover
        story.append(Paragraph(
            f"<font size='10'><b>{label}</b> {value}</font>",
            body_style,
        ))
    story.append(Spacer(1, 18 * mm))
    story.append(Paragraph(
        f"<font color='#64748B' size='8'>{CLASSIFICATION_LABEL_DE}</font>",
        body_style,
    ))
    story.append(PageBreak())
