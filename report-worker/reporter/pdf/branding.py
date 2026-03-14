"""
VectiScan — PDF Report Branding
================================
Zentrale Branding-Konfiguration für alle PDF-Reports.
Farben abgeleitet von scan.vectigal.tech CI.

WEB-CI (Dark Theme):
  Hintergrund:  #0F172A (slate-900)
  Karten:       #1E293B (slate-800)
  Logo/Akzent:  #38BDF8 (sky-400, Cyan)
  CTA:          #EAB308 (yellow-500, Gold)
  Links:        #3B82F6 (blue-500)
  Text:         #FFFFFF / #94A3B8 (slate-400)

PDF-ADAPTION (weißes Papier):
  Das dunkle Navy wird für Header-Bars, Cover und Tabellen-Header verwendet.
  Cyan wird Akzentfarbe für Überschriften und Links.
  Gold wird für NIS2-Badge und Highlights verwendet.
  Body-Text bleibt dunkelgrau auf Weiß (Lesbarkeit).
"""

from reportlab.lib.colors import HexColor


# ============================================================================
# COMPANY INFO
# ============================================================================

COMPANY_NAME = "VectiScan"
COMPANY_TAGLINE = "Automated Security Assessment"
COMPANY_URL = "https://vectigal.tech"
COMPANY_LEGAL = "Vectigal GmbH"
CLASSIFICATION_LABEL_DE = "KLASSIFIZIERUNG: VERTRAULICH — NUR FÜR AUTORISIERTE EMPFÄNGER"
CLASSIFICATION_LABEL_EN = "CLASSIFICATION: CONFIDENTIAL — AUTHORIZED RECIPIENTS ONLY"

# Logo — auf None setzen solange kein Logo vorhanden, dann wird Text-Fallback genutzt
LOGO_PATH = None  # z.B. "reporter/pdf/assets/vectiscan-logo.png"


# ============================================================================
# COLOR SCHEME — VectiScan CI
# ============================================================================

COLORS = {
    # --- Primärfarben (aus Web-CI) ---
    "primary":      HexColor("#0F172A"),   # Dunkles Navy — Cover, Header-Bars, Tabellen-Header
    "secondary":    HexColor("#1E293B"),   # Dunkleres Blau-Grau — sekundäre Hintergründe
    "accent":       HexColor("#38BDF8"),   # Cyan/Sky — Überschriften, Links, Akzentlinien
    "highlight":    HexColor("#EAB308"),   # Gold/Amber — CTA, NIS2-Badge, Highlights

    # --- Text ---
    "text":         HexColor("#1E293B"),   # Dunkelgrau auf Weiß (Body-Text, gute Lesbarkeit)
    "text_light":   HexColor("#FFFFFF"),   # Weiß — Text auf dunklem Hintergrund
    "muted":        HexColor("#64748B"),   # Gedämpftes Grau — Footer, Labels, Nebentext

    # --- Hintergründe ---
    "bg_light":     HexColor("#F1F5F9"),   # Helles Blau-Grau — alternating table rows, Evidence-BG
    "bg_evidence":  HexColor("#F1F5F9"),   # Evidence-Blöcke Hintergrund
    "white":        HexColor("#FFFFFF"),   # Weiß

    # --- Linien & Borders ---
    "light_accent": HexColor("#CBD5E1"),   # Helles Grau — Tabellen-Borders, Divider
    "divider":      HexColor("#E2E8F0"),   # Sehr hell — subtile Trennlinien

    # --- Severity (CVSS) — branchenüblich, nicht ändern ---
    "critical":     HexColor("#DC2626"),   # Rot (red-600)
    "high":         HexColor("#EA580C"),   # Orange (orange-600)
    "medium":       HexColor("#CA8A04"),   # Gold/Gelb (yellow-600)
    "low":          HexColor("#16A34A"),   # Grün (green-600)
    "info":         HexColor("#2563EB"),   # Blau (blue-600)

    # --- NIS2-spezifisch ---
    "nis2_badge":   HexColor("#EAB308"),   # Gold — NIS2 Compliance Badge
    "nis2_covered": HexColor("#16A34A"),   # Grün — §30 abgedeckt
    "nis2_partial": HexColor("#CA8A04"),   # Gelb — teilweise abgedeckt
    "nis2_out":     HexColor("#94A3B8"),   # Grau — nicht im Scope

    # --- Cover-spezifisch ---
    "cover_bg":           HexColor("#0F172A"),   # Cover Hintergrund (= primary)
    "cover_accent_bar":   HexColor("#38BDF8"),   # Linker Akzentstreifen auf Cover (= accent)
    "cover_overlay":      HexColor("#1E293B"),   # Geometrisches Overlay (= secondary)
    "cover_meta_label":   HexColor("#94A3B8"),   # Metadaten-Labels auf Cover (slate-400)
    "cover_meta_value":   HexColor("#E2E8F0"),   # Metadaten-Werte auf Cover (slate-200)
    "cover_rule":         HexColor("#475569"),   # Horizontale Linie auf Cover (slate-600)
}


# ============================================================================
# SEVERITY MAPPING — Deutsch + Englisch
# ============================================================================

SEVERITY_COLORS = {
    "CRITICAL":     COLORS["critical"],
    "KRITISCH":     COLORS["critical"],
    "HIGH":         COLORS["high"],
    "HOCH":         COLORS["high"],
    "MEDIUM":       COLORS["medium"],
    "MITTEL":       COLORS["medium"],
    "LOW":          COLORS["low"],
    "NIEDRIG":      COLORS["low"],
    "INFO":         COLORS["info"],
    "INFORMATIONAL": COLORS["info"],
    "INFORMATIV":   COLORS["info"],
}


# ============================================================================
# PAKET-KONFIGURATION (für Cover-Badge)
# ============================================================================

PACKAGE_BADGES = {
    "basic": {
        "label": "BASIC",
        "color": COLORS["accent"],           # Cyan
        "text_color": COLORS["primary"],      # Dunkler Text auf Cyan
    },
    "professional": {
        "label": "PROFESSIONAL",
        "color": COLORS["accent"],            # Cyan
        "text_color": COLORS["primary"],
    },
    "nis2": {
        "label": "NIS2 COMPLIANCE",
        "color": COLORS["highlight"],         # Gold
        "text_color": COLORS["primary"],
    },
}


# ============================================================================
# TYPOGRAPHY
# ============================================================================

# ReportLab hat nur eingebaute Fonts (Helvetica, Courier, Times).
# Für Custom Fonts müssten TTF-Dateien registriert werden.
# Helvetica ist dem System-Sans (Inter/Geist) am nächsten.
FONT_BODY = "Helvetica"
FONT_HEADING = "Helvetica-Bold"
FONT_MONO = "Courier"

# Größen
FONT_SIZE_BODY = 9.5
FONT_SIZE_HEADING1 = 18
FONT_SIZE_HEADING2 = 13
FONT_SIZE_EVIDENCE = 7.5
FONT_SIZE_TABLE_HEADER = 8
FONT_SIZE_TABLE_CELL = 8
FONT_SIZE_FOOTER = 7
FONT_SIZE_COVER_TITLE = 28
FONT_SIZE_COVER_SUBTITLE = 14