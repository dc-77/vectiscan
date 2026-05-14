"""V2 Cover: Klassifizierung sichtbar, Scope sichtbar, Risk-Indikator NICHT
auf dem Cover (Datenschutz beim Drucker-Postfach).
"""
from reportlab.platypus import Paragraph, Spacer, PageBreak, NextPageTemplate
from reportlab.lib.units import mm

from reporter.pdf.branding import CLASSIFICATION_LABEL_DE


def build_cover_v2(story, styles, cover_data):
    cover_data = cover_data or {}
    title = cover_data.get("cover_title", "Sicherheitsbewertung")
    subtitle = cover_data.get(
        "cover_subtitle", "VECTISCAN AUTOMATED SECURITY ASSESSMENT"
    )
    body_style = styles.get("BodyText2") or styles["BodyText"]

    # Hintergrund von draw_cover ist dunkel (#1a1a2e) — Texte MUESSEN hell sein.
    # Auch der klassifizierungs-Bar wird von draw_cover (page decoration)
    # selbst gerendert; wir bringen ihn NICHT zusaetzlich in der Story unter
    # (sonst doppelt: einmal Bar unten + einmal Text oben).
    LIGHT = "#FFFFFF"
    SUBTLE = "#94A3B8"

    story.append(Spacer(1, 40 * mm))
    story.append(Paragraph(
        f"<font color='{SUBTLE}' size='12'>{subtitle}</font>",
        body_style,
    ))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        f"<font color='{LIGHT}' size='28'><b>{title}</b></font>",
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
            f"<font color='{LIGHT}' size='10'><b>{label}</b> {value}</font>",
            body_style,
        ))
    # WICHTIG: NextPageTemplate VOR PageBreak — der PageBreak triggert den
    # Template-Wechsel beim Beginn der naechsten Seite.
    story.append(NextPageTemplate("normal"))
    story.append(PageBreak())
