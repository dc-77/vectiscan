# -*- coding: utf-8 -*-
"""Renderer v3 (Session S4): Reportdaten aus ``reporter.v3`` als HTML und PDF.

Oeffentliche Schnittstelle:
    render_html(data, *, resolver=None, package=None) -> (html, variant, warnings)
    render_report_v3(data, output_path, *, resolver=None, package=None, ...) -> RenderResult

``render_html`` braucht kein WeasyPrint. Alles Fachliche (Paketvariante, Aufteilung von
Kapitel 6, Textlint, Prototyp-Treue) ist damit ohne Systemabhaengigkeiten pruefbar.
"""
from reporter.pdf.v3.context import (TOP_N_HAUPTTEIL, TOP_N_SCHWELLE, build_context,
                                     split_findings, urgency_counts, urgency_rank)
from reporter.pdf.v3.screenshots import (MinioScreenshots, ScreenshotResolver,
                                         no_screenshots)
from reporter.pdf.v3.variants import VARIANTS, Variant, variant_for

__all__ = [
    "MinioScreenshots", "RenderGateError", "RenderResult", "ScreenshotResolver",
    "TOP_N_HAUPTTEIL", "TOP_N_SCHWELLE", "VARIANTS", "Variant", "build_context",
    "no_screenshots", "render_html", "render_report_v3", "split_findings",
    "urgency_counts", "urgency_rank", "variant_for",
]

_AUS_RENDER = ("render_html", "render_report_v3", "RenderResult", "RenderGateError")


def __getattr__(name: str):
    """render.py zieht jinja2 und (fuer das PDF) weasyprint nach. Erst bei Bedarf."""
    if name in _AUS_RENDER:
        from reporter.pdf.v3 import render
        return getattr(render, name)
    raise AttributeError(name)
