"""Schicht 1 -- Seite 2 'Auf einen Blick' (Doc 02).

Konsumiert layer1_aggregator + business_context + compliance_indicators.
Wenn der Aggregator noch keine Daten geliefert hat (None), faellt die
Funktion auf einen Hinweis-Paragraph zurueck, damit Doppel-Render-Tests
nicht crashen.

Aufbau (nach Strang-B-Streichliste):
  1. Seitentitel "Auf einen Blick" (frueher Risiko-Ampel — B4 gestrichen)
  2. Gesamtbewertung
  3. Die drei wichtigsten Hebel (HebelBox-Flowable)
  4. Kontext-Kasten (Datenarten + Geschaeftsbezug, kompakt)
  (Compliance-Indikatoren — B4 gestrichen; risk_ampel/AmpelBar bleiben in
   Daten/Code, nur die Anzeige entfaellt.)

Bewusst KEINE CVSS-Zahlen, KEINE Befund-IDs, KEINE Stundenangaben.
Doc 02: "Diese Seite ist fuer die Entscheidung 'Muessen wir reagieren? Wie schnell?'"
"""
from __future__ import annotations

from reportlab.platypus import Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.lib.units import mm

from reporter.pdf.v2.flowables import AmpelBar, HebelBox


# ---- Compliance-Status -> Anzeige-Farbe (hex strings for Paragraph) ----
_STATUS_COLOR_HEX = {
    "Konform":         "#16A34A",
    "Teilerfuellt":    "#CA8A04",
    "Handlungsbedarf": "#DC2626",
}


def build_layer1_frontpage(story, styles, data):
    """Rendert Doc 02 Seite 2 'Auf einen Blick'."""
    layer1 = (data or {}).get("layer1") or None
    body_style = styles.get("BodyText2") or styles["BodyText"]
    section_style = styles.get("SectionTitle") or styles["BodyText"]
    subsec_style = styles.get("SubsectionTitle") or styles["BodyText"]
    domain = (data or {}).get("domain") or "(unbekannt)"

    if not layer1:
        story.append(Paragraph(
            "<b>AUF EINEN BLICK</b>", section_style,
        ))
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph(
            "(Layer-1-Aggregation nicht verfuegbar - Aggregator-Modul fehlt "
            "oder Findings sind leer.)",
            body_style,
        ))
        story.append(PageBreak())
        return

    # ---- 1. Seitentitel ---------------------------------------------
    # B4 (Strang B): Risiko-Ampel gestrichen — die Kategorien bekamen alle
    # denselben max(severity)-Wert (keine echte Pruefung gegen DSGVO Art. 32 /
    # BSI), der Text suggerierte eine Kontrolle, die es nicht gibt, und die Ampel
    # war in beiden Audit-Reports zeichengleich. layer1['risk_ampel'] + AmpelBar
    # bleiben in Daten/Code (Regel 1). Neutraler Seitentitel statt Ampel-Header.
    story.append(Paragraph(
        f"<b>AUF EINEN BLICK &middot; {domain}</b>",
        section_style,
    ))
    story.append(Spacer(1, 3 * mm))
    # for cat in layer1.get("risk_ampel", []) or []:
    #     story.append(AmpelBar(cat.get("label", ""), cat.get("level", "")))
    #     story.append(Spacer(1, 1.5 * mm))

    # ---- 2. Gesamtbewertung -----------------------------------------
    overall = (layer1.get("overall_level") or "MITTEL").upper()
    overall_color = {
        "HOCH":         "#DC2626",
        "MITTEL-HOCH":  "#F97316",
        "MITTEL":       "#EAB308",
        "NIEDRIG-MITTEL": "#84CC16",
        "NIEDRIG":      "#22C55E",
        "INFO":         "#94A3B8",
    }.get(overall, "#64748B")
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        f"<b>Gesamtbewertung:</b> <font color='{overall_color}'><b>{overall}</b></font>",
        body_style,
    ))

    # ---- 3. Die drei wichtigsten Hebel ------------------------------
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        "<b>DIE DREI WICHTIGSTEN HEBEL</b>",
        subsec_style,
    ))
    story.append(Spacer(1, 2 * mm))
    top_hebel = layer1.get("top_hebel") or []
    if not top_hebel:
        story.append(Paragraph(
            "Keine kombinierbaren Massnahmen identifiziert "
            "(siehe Massnahmenplan auf Seite 10).",
            body_style,
        ))
    else:
        for hebel in top_hebel[:3]:
            story.append(HebelBox(
                rank=hebel.get("rank", 0),
                title=hebel.get("title", ""),
                effect=hebel.get("effect", ""),
                finding_ids=hebel.get("finding_ids", []) or [],
            ))
            story.append(Spacer(1, 3 * mm))

    # ---- 4. Kontext fuer diesen Bericht -----------------------------
    scope = (data or {}).get("scope_meta") or {}
    hosts_count = scope.get("hosts_count", "?")
    subdomains_count = scope.get("subdomains_count", "?")
    scan_date = scope.get("scan_date", "?")
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        "<b>KONTEXT FUER DIESEN BERICHT</b>",
        subsec_style,
    ))
    story.append(Spacer(1, 2 * mm))
    # Regel 2 (Widerspruch C3): frueher stand hier "Geprueft wurde ... N aktive
    # Hosts" — das behauptete eine Vollpruefung, obwohl das neue Kapitel "Was
    # wurde geprueft — und was nicht" zeigt, dass ein Teil der identifizierten
    # Hosts nicht pruefbar war (KI-Skip/Redirect/Limit).  Neutral als
    # "identifizierte Hosts" formuliert + Querverweis auf das Abdeckungskapitel;
    # analog strategy.py (C3).
    story.append(Paragraph(
        f"Betrachtet wurde die externe Angriffsflaeche von <b>{domain}</b> "
        f"({hosts_count} identifizierte Hosts, {subdomains_count} bekannte "
        f"Subdomains), Scan-Datum <b>{scan_date}</b>. Welche dieser Hosts "
        f"tatsaechlich geprueft werden konnten, schluesselt das Kapitel "
        f"„Was wurde geprueft — und was nicht“ auf.",
        body_style,
    ))
    story.append(Paragraph(
        "Ein Innenangriff oder Mitarbeiter-Szenario ist nicht Teil dieser "
        "Pruefung; siehe Abschnitt 'Umfang' fuer eine vollstaendige Liste der "
        "Auslassungen.",
        body_style,
    ))

    # ---- 5. Compliance-Indikatoren ----------------------------------
    # B4 (Strang B): Renderer-Zweig gestrichen — die drei Compliance-Pillen
    # bekamen alle denselben max(severity)-Wert; es findet KEINE Pruefung gegen
    # DSGVO Art. 32 / BSI statt, der Text suggerierte eine Kontrolle, die es nicht
    # gibt. Daten (compliance_indicators) + build_compliance_indicators bleiben
    # (Regel 1); nur die Anzeige entfaellt.
    indicators = []  # B4: war (data or {}).get("compliance_indicators") or []
    if indicators:  # -> immer False: Render-Zweig deaktiviert (nicht geloescht)
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph(
            "<b>COMPLIANCE-INDIKATOREN</b>",
            subsec_style,
        ))
        story.append(Spacer(1, 2 * mm))
        rows = []
        for ind in indicators:
            label = ind.get("label", "")
            status = ind.get("status", "—")
            color_hex = _STATUS_COLOR_HEX.get(status, "#64748B")
            rows.append([
                Paragraph(f"&#8226; {label}", body_style),
                Paragraph(
                    f"<font color='{color_hex}'><b>{status}</b></font>",
                    body_style,
                ),
            ])
        tbl = Table(rows, colWidths=[110 * mm, 50 * mm])
        tbl.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 1),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ]))
        story.append(tbl)

    story.append(PageBreak())
