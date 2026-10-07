# -*- coding: utf-8 -*-
"""Bildnachweise fuer Kapitel 3.4.

Die Reportdaten tragen nur den Schluessel (``architecture.screens[].key``, gefuellt aus
``facts.fqdns[].screenshot_key``), nicht die Bilddatei. Der Renderer loest ihn hier auf.

Eingebunden wird ueber WeasyPrints ``url_fetcher`` und ein eigenes URL-Schema, nicht
ueber temporaere Verzeichnisse und nicht ueber data-URIs: so bleibt das HTML klein und
diffbar, es gibt nichts aufzuraeumen, und derselbe HTML-String rendert mit und ohne
Bilder.
"""
from __future__ import annotations

import io
import os
from typing import Protocol

import structlog

log = structlog.get_logger()

SCHEME = "vectiscan-screenshot"
# Praefix je Feld wie in reporter/worker.py (Swarm, 06.10.2026).
BUCKET = f"{os.environ.get('MINIO_BUCKET_PREFIX', '')}scan-screenshots"

# Die Rasterzelle ist bei drei Spalten auf 174 mm Satzbreite rund 55 mm breit, also
# etwa 650 Pixel bei 300 dpi. Vierzehn ungeskalierte Vollbilder sind dekodiert leicht
# einige hundert Megabyte, der Container hat 1 GB.
MAX_WIDTH = 900


class ScreenshotResolver(Protocol):
    """Schluessel zu Bildbytes. ``None`` heisst: kein Bild, Platzhalter zeigen."""

    def __call__(self, key: str) -> bytes | None: ...


def no_screenshots(key: str) -> bytes | None:
    """Vorgabe-Resolver: es gibt keine Bilder (Golden-Laeufe, Tests)."""
    return None


# S7a Punkt 1: Golden-Laeufe ohne Bilder lassen Kapitel 3.4 weg, die Fuellpruefung sah den Umbruch
# um die Bilder deshalb nie (CA 19 in Produktion). Ein graues Bild im Seitenverhaeltnis der
# Aufnahmen (1440 x 900, auf MAX_WIDTH verkleinert) setzt Kapitel 3.4 so wie im echten Bericht.
PLACEHOLDER_SIZE = (MAX_WIDTH, round(MAX_WIDTH * 900 / 1440))
_PLACEHOLDER_PNG: bytes | None = None


def placeholder_screenshots(key: str) -> bytes | None:
    """Resolver fuer die Seitenerwartung mit Bildern: ein graues PNG je Schluessel."""
    global _PLACEHOLDER_PNG
    if not key:
        return None
    if _PLACEHOLDER_PNG is None:
        from PIL import Image
        buf = io.BytesIO()
        Image.new("RGB", PLACEHOLDER_SIZE, (226, 232, 240)).save(buf, format="PNG")
        _PLACEHOLDER_PNG = buf.getvalue()
    return _PLACEHOLDER_PNG


def downscale(data: bytes, max_width: int = MAX_WIDTH) -> bytes:
    """Auf Rasterbreite herunterrechnen, wenn Pillow da ist. Sonst unveraendert."""
    try:
        from PIL import Image
    except ImportError:
        return data
    try:
        with Image.open(io.BytesIO(data)) as img:
            if img.width <= max_width:
                return data
            height = max(1, round(img.height * max_width / img.width))
            small = img.convert("RGB").resize((max_width, height), Image.LANCZOS)
            buf = io.BytesIO()
            small.save(buf, format="JPEG", quality=82, optimize=True)
            return buf.getvalue()
    except Exception as exc:  # defektes Bild darf den Bericht nicht kippen
        log.warning("screenshot_downscale_failed", error=str(exc))
        return data


class MinioScreenshots:
    """Bilder aus MinIO, je Schluessel einmal geladen."""

    def __init__(self, client, bucket: str = BUCKET, *, max_width: int = MAX_WIDTH):
        self._client = client
        self._bucket = bucket
        self._max_width = max_width
        self._cache: dict[str, bytes | None] = {}

    def __call__(self, key: str) -> bytes | None:
        if key in self._cache:
            return self._cache[key]
        data: bytes | None = None
        response = None
        try:
            response = self._client.get_object(self._bucket, key)
            data = downscale(response.read(), self._max_width)
        except Exception as exc:
            log.warning("screenshot_fetch_failed", bucket=self._bucket, key=key,
                        error=str(exc))
            data = None
        finally:
            if response is not None:
                try:
                    response.close()
                    response.release_conn()
                except Exception:
                    pass
        self._cache[key] = data
        return data


def available(screens: list[dict], resolver: ScreenshotResolver) -> bool:
    """Liefert mindestens ein Eintrag Bytes?

    Ohne ein einziges Bild bleibt Kapitel 3.4 weg; ein Raster aus lauter Platzhaltern
    ergaebe eine halbleere Seite und damit einen Sparse-Treffer.
    """
    return any(resolver(sc.get("key") or sc.get("file") or "") for sc in screens)
