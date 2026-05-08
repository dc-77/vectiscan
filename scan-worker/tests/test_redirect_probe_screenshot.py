"""Tests fuer Screenshot-Pipeline (Per-VHost-Schema, viewport-only).

Mai 2026: full_page=True wurde wieder zu full_page=False zurueckgenommen
(Customer-Reports zeigten ueberlange Screenshots — gewuenscht ist nur die
erste Bildschirm-Ansicht). Pillow-Hoehencap entfaellt damit.

Deckt:
1. _take_screenshot ruft page.screenshot mit full_page=False + animations="disabled".
2. Filename-Konvention behaelt Punkte (Sanitizer ersetzt nur Slashes).
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock


def test_take_screenshot_uses_viewport_only(tmp_path: Path) -> None:
    """page.screenshot wird mit full_page=False (Viewport-Only) aufgerufen."""
    from scanner.tools.redirect_probe import _take_screenshot

    scan_dir = str(tmp_path)
    fake_page = MagicMock()

    result = _take_screenshot(fake_page, "www.example.com", scan_dir, "1.2.3.4")

    # Pfad zurueckgegeben
    assert result is not None
    assert result.endswith("screenshot_www.example.com.png")
    # Viewport-only + animations="disabled".
    fake_page.screenshot.assert_called_once()
    kwargs = fake_page.screenshot.call_args.kwargs
    assert kwargs.get("full_page") is False
    assert kwargs.get("animations") == "disabled"


def test_take_screenshot_keeps_dots_in_filename(tmp_path: Path) -> None:
    """Sanitizer behaelt Punkte (vorher: Punkte → Underscore)."""
    from scanner.tools.redirect_probe import _take_screenshot, _sanitize_vhost

    fake_page = MagicMock()
    result = _take_screenshot(fake_page, "shop.example.de", str(tmp_path), "5.6.7.8")

    assert result is not None
    # Punkte bleiben — neue Konvention
    assert "shop.example.de" in os.path.basename(result)

    # Sanitizer-Helper
    assert _sanitize_vhost("a/b\\c.example.com") == "a-b-c.example.com"
