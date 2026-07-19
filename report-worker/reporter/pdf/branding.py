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
from reportlab.lib.units import mm


# ============================================================================
# COMPANY INFO
# ============================================================================

COMPANY_NAME = "VectiScan"
COMPANY_TAGLINE = "Automated Security Assessment"
COMPANY_URL = "https://vectigal.tech"
COMPANY_LEGAL = "Vectigal GmbH"
CLASSIFICATION_LABEL_DE = "KLASSIFIZIERUNG: VERTRAULICH \u2014 NUR F\u00dcR AUTORISIERTE EMPF\u00c4NGER"
CLASSIFICATION_LABEL_EN = "CLASSIFICATION: CONFIDENTIAL \u2014 AUTHORIZED RECIPIENTS ONLY"

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
    # v2 package names
    "webcheck": {
        "label": "WEBCHECK",
        "color": COLORS["accent"],           # Cyan
        "text_color": COLORS["primary"],
    },
    "perimeter": {
        "label": "PERIMETERSCAN",
        "color": COLORS["accent"],           # Cyan
        "text_color": COLORS["primary"],
    },
    "compliance": {
        "label": "NIS2 COMPLIANCE",
        "color": COLORS["highlight"],        # Gold
        "text_color": COLORS["primary"],
    },
    "supplychain": {
        "label": "SUPPLY CHAIN",
        "color": COLORS["accent"],           # Cyan
        "text_color": COLORS["primary"],
    },
    "insurance": {
        "label": "INSURANCE REPORT",
        "color": COLORS["accent"],           # Cyan
        "text_color": COLORS["primary"],
    },
    "tlscompliance": {
        "label": "TLS COMPLIANCE",
        "color": COLORS["low"],              # Grün
        "text_color": COLORS["white"],
    },
    # Legacy aliases
    "basic": {
        "label": "WEBCHECK",
        "color": COLORS["accent"],
        "text_color": COLORS["primary"],
    },
    "professional": {
        "label": "PERIMETERSCAN",
        "color": COLORS["accent"],
        "text_color": COLORS["primary"],
    },
    "nis2": {
        "label": "NIS2 COMPLIANCE",
        "color": COLORS["highlight"],
        "text_color": COLORS["primary"],
    },
}


# ============================================================================
# TYPOGRAPHY
# ============================================================================

# Font-Strategie: Die eingebauten ReportLab-Type1-Fonts (Helvetica/Courier) decken
# nur WinAnsi/CP1252 ab. Umlaute (ä ö ü ß) rendern damit zwar korrekt, aber non-WinAnsi-
# Symbole wie ● ✓ ◐ ✗ → (Severity-Dots, Compliance-Haken, KI-Pfeile) fehlen und erscheinen
# als leere .notdef-Box — vom Kunden als „kaputte Umlaute/Sonderzeichen" gemeldet.
# Fix: DejaVu (volle Unicode-Abdeckung, frei lizenziert) einbetten. Die Debian-Pakete
# fonts-dejavu-core (Regular/Bold/Mono) + fonts-dejavu-extra (Oblique/BoldOblique/Mono-Bold)
# liefern die TTFs (Dockerfile) unter /usr/share/fonts/truetype/dejavu.
# ROBUST: es reicht die Regular-Datei — fehlende Varianten (z.B. wenn nur -core installiert
# ist oder beim lokalen Test) werden auf die naechstbeste vorhandene gemappt, sodass ALLE
# Font-Namen (VectiSans-Bold/-Oblique/…) immer gueltig registriert sind. Fehlt DejaVu ganz,
# fallen wir sauber auf Helvetica zurueck.
import os as _os
from reportlab.pdfbase import pdfmetrics as _pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont as _TTFont

_DEJAVU_DIR = _os.environ.get("VECTISCAN_FONT_DIR", "/usr/share/fonts/truetype/dejavu")


def _register_unicode_fonts() -> bool:
    """Registriert die DejaVu-Familie robust. Nur die Regular-Datei ist Pflicht; fehlende
    Bold/Oblique/Mono-Varianten werden auf die beste vorhandene Datei gemappt, damit jeder
    Font-Name gueltig ist. True = mind. Regular geladen, False = kein DejaVu -> Helvetica."""
    def _p(fn):
        return _os.path.join(_DEJAVU_DIR, fn)

    regular = _p("DejaVuSans.ttf")
    if not _os.path.exists(regular):
        return False
    try:
        _pdfmetrics.registerFont(_TTFont("VectiSans", regular))

        def _reg(name, fn, fallback):
            """Registriert name mit fn wenn vorhanden, sonst mit fallback-Pfad."""
            src = _p(fn) if _os.path.exists(_p(fn)) else fallback
            _pdfmetrics.registerFont(_TTFont(name, src))
            return src

        bold = _reg("VectiSans-Bold", "DejaVuSans-Bold.ttf", regular)
        _reg("VectiSans-Oblique", "DejaVuSans-Oblique.ttf", regular)
        _reg("VectiSans-BoldOblique", "DejaVuSans-BoldOblique.ttf", bold)
        _pdfmetrics.registerFontFamily(
            "VectiSans", normal="VectiSans", bold="VectiSans-Bold",
            italic="VectiSans-Oblique", boldItalic="VectiSans-BoldOblique",
        )

        mono = _p("DejaVuSansMono.ttf")
        mono_src = mono if _os.path.exists(mono) else regular
        _pdfmetrics.registerFont(_TTFont("VectiMono", mono_src))
        _reg("VectiMono-Bold", "DejaVuSansMono-Bold.ttf", mono_src if _os.path.exists(mono) else bold)
        _pdfmetrics.registerFontFamily(
            "VectiMono", normal="VectiMono", bold="VectiMono-Bold",
            italic="VectiMono", boldItalic="VectiMono-Bold",
        )
        return True
    except Exception:
        return False


UNICODE_FONTS_AVAILABLE = _register_unicode_fonts()

if UNICODE_FONTS_AVAILABLE:
    FONT_BODY = "VectiSans"
    FONT_HEADING = "VectiSans-Bold"
    FONT_ITALIC = "VectiSans-Oblique"
    FONT_MONO = "VectiMono"
else:
    # Fallback (kein DejaVu vorhanden): Built-in Type1. Umlaute ok, Symbole ●✓◐✗→ als Box.
    FONT_BODY = "Helvetica"
    FONT_HEADING = "Helvetica-Bold"
    FONT_ITALIC = "Helvetica-Oblique"
    FONT_MONO = "Courier"

# Größen
FONT_SIZE_BODY = 10.5
FONT_SIZE_HEADING1 = 18
FONT_SIZE_HEADING2 = 13
FONT_SIZE_EVIDENCE = 8.5
FONT_SIZE_TABLE_HEADER = 9
FONT_SIZE_TABLE_CELL = 9
FONT_SIZE_FOOTER = 7
FONT_SIZE_COVER_TITLE = 28
FONT_SIZE_COVER_SUBTITLE = 14


# ============================================================================
# SPACING — tunable whitespace constants
# ============================================================================

SPACING_SECTION = 8 * mm        # Between major sections (H1 → content)
SPACING_SUBSECTION = 5 * mm     # Between subsections (H2 → content)
SPACING_FINDING = 4 * mm        # After each finding block
SPACING_PARAGRAPH = 2 * mm      # Between paragraphs within a section
SPACING_COVER_ELEMENT = 6 * mm  # Between cover page elements

# Orphan control — minimum lines to keep with a heading before a page break
MIN_LINES_BEFORE_BREAK = 3