"""Tests fuer F-PH1-003 Screenshot-Pipeline (full_page + Per-VHost-Schema).

Deckt:
1. _take_screenshot ruft page.screenshot mit full_page=True + animations="disabled".
2. Filename-Konvention behaelt Punkte (Sanitizer ersetzt nur Slashes).
3. _cap_screenshot_height resized PNGs >4096px Hoehe und laesst kleinere unveraendert.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest


def test_take_screenshot_uses_full_page(tmp_path: Path) -> None:
    """F-PH1-003: page.screenshot wird mit full_page=True aufgerufen."""
    from scanner.tools.redirect_probe import _take_screenshot

    scan_dir = str(tmp_path)
    fake_page = MagicMock()

    result = _take_screenshot(fake_page, "www.example.com", scan_dir, "1.2.3.4")

    # Pfad zurueckgegeben
    assert result is not None
    assert result.endswith("screenshot_www.example.com.png")
    # full_page + animations="disabled" — F-PH1-003 Kern.
    fake_page.screenshot.assert_called_once()
    kwargs = fake_page.screenshot.call_args.kwargs
    assert kwargs.get("full_page") is True
    assert kwargs.get("animations") == "disabled"


def test_take_screenshot_keeps_dots_in_filename(tmp_path: Path) -> None:
    """F-PH1-003: Sanitizer behaelt Punkte (vorher: Punkte → Underscore)."""
    from scanner.tools.redirect_probe import _take_screenshot, _sanitize_vhost

    fake_page = MagicMock()
    result = _take_screenshot(fake_page, "shop.example.de", str(tmp_path), "5.6.7.8")

    assert result is not None
    # Punkte bleiben — neue Konvention
    assert "shop.example.de" in os.path.basename(result)

    # Sanitizer-Helper
    assert _sanitize_vhost("a/b\\c.example.com") == "a-b-c.example.com"


def test_cap_screenshot_height_resizes_oversized(tmp_path: Path) -> None:
    """F-PH1-003: Pillow-Hoehencap auf 4096px bei extrem langen Screenshots."""
    pytest.importorskip("PIL")
    from PIL import Image as _PILImage  # type: ignore

    from scanner.tools.redirect_probe import _cap_screenshot_height

    # 200x6000 -> sollte auf 200*(4096/6000) x 4096 resized werden
    big_png = tmp_path / "big.png"
    img = _PILImage.new("RGB", (200, 6000), color=(255, 0, 0))
    img.save(big_png, format="PNG")

    _cap_screenshot_height(str(big_png), max_height=4096)

    with _PILImage.open(big_png) as out:
        assert out.size[1] == 4096
        # Aspect Ratio bewahrt: 200 * (4096/6000) ~ 136
        assert 130 <= out.size[0] <= 142


def test_cap_screenshot_height_skips_small(tmp_path: Path) -> None:
    """Kleine Screenshots bleiben unveraendert."""
    pytest.importorskip("PIL")
    from PIL import Image as _PILImage  # type: ignore

    from scanner.tools.redirect_probe import _cap_screenshot_height

    small = tmp_path / "small.png"
    img = _PILImage.new("RGB", (300, 800), color=(0, 255, 0))
    img.save(small, format="PNG")

    _cap_screenshot_height(str(small), max_height=4096)

    with _PILImage.open(small) as out:
        assert out.size == (300, 800)
