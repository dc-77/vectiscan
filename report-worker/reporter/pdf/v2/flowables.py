"""V2 Custom Flowables -- Doc 02 Visual-Elemente.

M3 Skelett: Diese Flowables rendern die neuen Visual-Komponenten der
3-Schichten-Architektur. Polish (Typo-Feintuning, Schatten, exakte
Abstaende) kommt in M4/M5.
"""
from __future__ import annotations

from reportlab.platypus import Flowable
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor

from reporter.pdf.branding import COLORS, FONT_BODY, FONT_HEADING, FONT_ITALIC


class AmpelBar(Flowable):
    """Risiko-Ampel-Bar pro Kategorie (Doc 02 Seite 2, "Auf einen Blick").

    Renders einen horizontalen Balken in 5-Schritten
    (HOCH/MITTEL-HOCH/MITTEL/NIEDRIG-MITTEL/NIEDRIG/INFO).
    """

    def __init__(self, label: str, level: str, width: float = 80 * mm):
        super().__init__()
        self.label = label
        self.level = (level or "").lower()
        self.width = width
        self.height = 6 * mm

    def wrap(self, *_args):
        return (self.width + 60 * mm, self.height)

    def draw(self):
        c = self.canv
        # Label links
        c.setFont(FONT_BODY, 9)
        c.setFillColor(COLORS["text"])
        c.drawString(0, 1 * mm, self.label)
        # Bar rechts
        bar_x = 60 * mm
        bar_y = 0
        c.setStrokeColor(COLORS["muted"])
        c.setFillColor(self._bar_color())
        c.rect(bar_x, bar_y, self._bar_width(), self.height - 2 * mm,
               stroke=1, fill=1)
        # Level-Text rechts vom Balken
        c.setFillColor(COLORS["text"])
        c.drawString(bar_x + self.width + 2 * mm, 1 * mm,
                     self.level.upper())

    def _bar_width(self) -> float:
        mapping = {
            "hoch": 1.0,
            "mittel-hoch": 0.8,
            "mittel": 0.6,
            "niedrig-mittel": 0.4,
            "niedrig": 0.2,
            "info": 0.1,
        }
        return self.width * mapping.get(self.level, 0.5)

    def _bar_color(self) -> HexColor:
        mapping = {
            "hoch": HexColor("#DC2626"),         # red-600
            "mittel-hoch": HexColor("#F97316"),  # orange-500
            "mittel": HexColor("#EAB308"),       # yellow-500
            "niedrig-mittel": HexColor("#84CC16"),
            "niedrig": HexColor("#22C55E"),      # green-500
            "info": COLORS["muted"],
        }
        return mapping.get(self.level, COLORS["muted"])


class HebelBox(Flowable):
    """Top-3-Hebel-Box (Doc 02 Seite 2): kombinierte Massnahme + adressierte Findings."""

    def __init__(self, rank: int, title: str, effect: str,
                 finding_ids: list[str], width: float = 170 * mm):
        super().__init__()
        self.rank = rank
        self.title = title or ""
        self.effect = effect or ""
        self.finding_ids = finding_ids or []
        self.width = width
        self.height = 18 * mm

    def wrap(self, *_args):
        return (self.width, self.height)

    def draw(self):
        c = self.canv
        c.setStrokeColor(COLORS["accent"])
        c.setFillColor(COLORS["bg_light"])
        c.rect(0, 0, self.width, self.height, stroke=1, fill=1)
        c.setFillColor(COLORS["text"])
        c.setFont(FONT_HEADING, 11)
        c.drawString(4 * mm, self.height - 5 * mm,
                     f"{self.rank}. {self.title[:80]}")
        c.setFont(FONT_BODY, 9)
        c.setFillColor(COLORS["muted"])
        c.drawString(4 * mm, self.height - 10 * mm,
                     f"-> {self.effect[:120]}")
        c.setFont(FONT_ITALIC, 8)
        c.drawString(4 * mm, 2 * mm,
                     "Adressiert: " + ", ".join(self.finding_ids[:5]))


class KategorieBlock(Flowable):
    """Befund-Landschaft-Block (Doc 02 Seite 8-9): Kategorie-Header + Befund-Liste."""

    def __init__(self, category_label: str, count: int, schwerpunkt: str,
                 finding_titles: list[tuple[str, str]],  # (id, title)
                 width: float = 170 * mm):
        super().__init__()
        self.category_label = category_label or ""
        self.count = count
        self.schwerpunkt = schwerpunkt or ""
        self.finding_titles = finding_titles or []
        self.width = width
        self.height = 8 * mm + 5 * mm * max(1, len(self.finding_titles))

    def wrap(self, *_args):
        return (self.width, self.height)

    def draw(self):
        c = self.canv
        c.setFillColor(COLORS["primary"])
        c.setFont(FONT_HEADING, 10)
        c.drawString(0, self.height - 5 * mm,
                     self.category_label.upper())
        c.setFont(FONT_BODY, 9)
        c.setFillColor(COLORS["muted"])
        c.drawString(0, self.height - 9 * mm,
                     f"{self.count} Befunde -- Schwerpunkt {self.schwerpunkt.upper()}")
        y = self.height - 13 * mm
        c.setFillColor(COLORS["text"])
        for fid, title in self.finding_titles[:8]:
            c.setFont(FONT_BODY, 9)
            c.drawString(4 * mm, y, f"- {title[:70]}  ({fid})")
            y -= 4 * mm


class PostureIndicator(Flowable):
    """Mini-Dashboard fuer Mail/Web/DNS/TLS (Doc 02 Seite 7).

    Pro Sub-Indikator eine farbige Pille (gruen=ok, rot=fail, gelb=warn) mit
    dem Sub-Label darin. Kein X/OK/! mehr — wirkt sonst wie eine kryptische
    Statuszeile.
    """

    def __init__(self, label: str, items: list[tuple[str, str]],  # (sub_label, status)
                 width: float = 170 * mm):
        super().__init__()
        self.label = label or ""
        self.items = items or []
        self.width = width
        self.height = 10 * mm

    def wrap(self, *_args):
        return (self.width, self.height)

    def draw(self):
        c = self.canv
        c.setFillColor(COLORS["text"])
        c.setFont(FONT_HEADING, 9)
        c.drawString(0, 3 * mm, f"{self.label}:")
        x = 60 * mm

        # Pillen-Farben pro Status — gefuellte Rechtecke mit Text drin.
        bg_colors = {
            "ok":   HexColor("#16A34A"),   # green-600
            "fail": HexColor("#DC2626"),   # red-600
            "warn": HexColor("#CA8A04"),   # yellow-600
        }
        for sub, status in self.items[:6]:
            status_lc = (status or "").lower()
            bg = bg_colors.get(status_lc, COLORS["muted"])
            # Symbol vor dem Sub-Label
            symbol = {"ok": "✓", "fail": "✗", "warn": "!"}.get(
                status_lc, "-")
            pill_text = f" {symbol} {sub} "
            text_w = c.stringWidth(pill_text, FONT_HEADING, 8.5)
            pill_w = text_w + 2 * mm
            pill_h = 5.5 * mm
            pill_y = 1.5 * mm
            # Gefuelltes Rounded-Rect als Hintergrund
            c.setFillColor(bg)
            c.setStrokeColor(bg)
            c.roundRect(x, pill_y, pill_w, pill_h, 1.5 * mm,
                        stroke=0, fill=1)
            # Text in weiss
            c.setFillColor(HexColor("#FFFFFF"))
            c.setFont(FONT_HEADING, 8.5)
            c.drawString(x + 1 * mm, pill_y + 1.5 * mm, pill_text.strip())
            x += pill_w + 2 * mm


class ServiceCard(Flowable):
    """Service-Karte mit Port-Chips pro Host (Doc 02 Seite 6-7)."""

    def __init__(self, host_label: str,
                 ports: list[tuple[int, str, str]],  # (port, service, risk_color)
                 width: float = 170 * mm):
        super().__init__()
        self.host_label = host_label or ""
        self.ports = ports or []
        self.width = width
        rows = max(1, (len(self.ports) + 5) // 6)
        self.height = 10 * mm + 8 * mm * rows

    def wrap(self, *_args):
        return (self.width, self.height)

    def draw(self):
        c = self.canv
        c.setFillColor(COLORS["text"])
        c.setFont(FONT_HEADING, 10)
        c.drawString(0, self.height - 4 * mm, self.host_label)
        x = 0
        y = self.height - 12 * mm
        for port, service, color in self.ports:
            chip_w = 26 * mm
            try:
                fill_color = HexColor(color) if color else COLORS["bg_light"]
            except Exception:
                fill_color = COLORS["bg_light"]
            c.setFillColor(fill_color)
            c.rect(x, y, chip_w, 6 * mm, stroke=1, fill=1)
            c.setFillColor(COLORS["text"])
            c.setFont(FONT_BODY, 8)
            service_label = (service or "")[:10]
            c.drawString(x + 1 * mm, y + 1.5 * mm, f"{port} {service_label}")
            x += chip_w + 2 * mm
            if x > self.width - chip_w:
                x = 0
                y -= 8 * mm


class FindingHeaderV2(Flowable):
    """Befund-Header mit Priority + Risk-Stufe (Doc 02 Seite 11+).

    Sektionen: WAS / NACHWEIS / THREAT INTELLIGENCE / GESCHAEFTSAUSWIRKUNG /
    EMPFEHLUNG / VERIFIKATION / INTERNE REFERENZ.
    Dieser Flowable rendert nur den Header -- der restliche Body kommt in M5
    als build_finding_v2.
    """

    def __init__(self, finding_id: str, title: str, priority: str, risk: str,
                 policy_id: str | None = None, width: float = 170 * mm):
        super().__init__()
        self.finding_id = finding_id or ""
        self.title = title or ""
        self.priority = priority or ""
        self.risk = risk or ""
        self.policy_id = policy_id
        self.width = width
        self.height = 16 * mm

    def wrap(self, *_args):
        return (self.width, self.height)

    def draw(self):
        c = self.canv
        c.setFillColor(COLORS["primary"])
        c.rect(0, 0, self.width, self.height, stroke=0, fill=1)
        c.setFillColor(COLORS["text_light"])
        c.setFont(FONT_HEADING, 11)
        c.drawString(4 * mm, self.height - 6 * mm,
                     f"{self.finding_id}   {self.title[:80]}")
        c.setFont(FONT_BODY, 9)
        c.drawString(4 * mm, 3 * mm,
                     f"Prioritaet: {self.priority}   |   Risiko: {self.risk}")
        if self.policy_id:
            c.drawRightString(self.width - 4 * mm, 3 * mm,
                              f"Policy {self.policy_id}")
