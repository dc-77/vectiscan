"""M6.1 -- Screenshot-Pipeline v2 Tests (Doc 01 Phase J).

Body-Hash-Dedup + Cap auf max 2 Screenshots + Caption-Aggregation fuer
Mehrfach-Vorkommen identischer Standard-Seiten.
"""
from __future__ import annotations

import pathlib

import pytest

from reporter.screenshot_pipeline import (
    DEFAULT_MAX_SCREENSHOTS, dedup_and_cap,
)


# ====================================================================
# Fixture-Helper: kleine PNGs unter tmp_path schreiben
# ====================================================================
# 1x1-PNG (rot)
_PNG_RED = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108020000"
    "00907753de0000000d4944415478da6364f8ff9f0100050001bd1a6a"
    "f10000000049454e44ae426082"
)
# 1x1-PNG (blau)
_PNG_BLUE = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108020000"
    "00907753de0000000d4944415478da63601800000001000005000178"
    "47b6520000000049454e44ae426082"
)
# 1x1-PNG (gruen)
_PNG_GREEN = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108020000"
    "00907753de0000000d4944415478da636060f8ff1f0000060300011a"
    "fce0700000000049454e44ae426082"
)


def _write_png(tmp_path: pathlib.Path, name: str, payload: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(payload)
    return str(path)


# ====================================================================
# Body-Hash-Dedup
# ====================================================================
class TestBodyHashDedup:
    def test_three_identical_screenshots_collapse_to_one(self, tmp_path):
        p1 = _write_png(tmp_path, "host_a.png", _PNG_RED)
        p2 = _write_png(tmp_path, "host_b.png", _PNG_RED)
        p3 = _write_png(tmp_path, "host_c.png", _PNG_RED)
        entries = [
            {"label": "a.example.de (Screenshot)", "paths": [p1]},
            {"label": "b.example.de (Screenshot)", "paths": [p2]},
            {"label": "c.example.de (Screenshot)", "paths": [p3]},
        ]
        out = dedup_and_cap(entries)
        assert len(out) == 1
        primary = out[0]
        # Erstes Vorkommen behaelt seinen Pfad
        assert primary["paths"] == [p1]
        # Dedup-Caption listet die anderen
        assert "caption_dedup" in primary
        assert "b.example.de" in primary["caption_dedup"]
        assert "c.example.de" in primary["caption_dedup"]
        assert primary["dedup_count"] == 3

    def test_distinct_screenshots_stay_separate(self, tmp_path):
        p1 = _write_png(tmp_path, "a.png", _PNG_RED)
        p2 = _write_png(tmp_path, "b.png", _PNG_BLUE)
        entries = [
            {"label": "a.example.de (Screenshot)", "paths": [p1]},
            {"label": "b.example.de (Screenshot)", "paths": [p2]},
        ]
        out = dedup_and_cap(entries)
        assert len(out) == 2
        # Keiner darf eine Dedup-Caption haben
        assert all("caption_dedup" not in e for e in out)

    def test_mixed_duplicates_and_uniques(self, tmp_path):
        red_a = _write_png(tmp_path, "red_a.png", _PNG_RED)
        red_b = _write_png(tmp_path, "red_b.png", _PNG_RED)
        blue = _write_png(tmp_path, "blue.png", _PNG_BLUE)
        green = _write_png(tmp_path, "green.png", _PNG_GREEN)
        entries = [
            {"label": "a.example.de (Screenshot)", "paths": [red_a]},
            {"label": "b.example.de (Screenshot)", "paths": [red_b]},
            {"label": "c.example.de (Screenshot)", "paths": [blue]},
            {"label": "d.example.de (Screenshot)", "paths": [green]},
        ]
        out = dedup_and_cap(entries, max_screenshots=10)
        # 3 distinkte Hashes
        assert len(out) == 3
        # Erste Gruppe ist die dedup'd
        assert out[0]["dedup_count"] == 2

    def test_dedup_with_more_than_three_groups_keeps_largest_first(self, tmp_path):
        red = _PNG_RED
        blue = _PNG_BLUE
        # 4x red, 1x blue
        paths_red = [
            _write_png(tmp_path, f"red_{i}.png", red) for i in range(4)
        ]
        path_blue = _write_png(tmp_path, "blue.png", blue)
        entries = [
            {"label": f"r{i}.example.de (Screenshot)", "paths": [p]}
            for i, p in enumerate(paths_red)
        ] + [
            {"label": "b.example.de (Screenshot)", "paths": [path_blue]},
        ]
        out = dedup_and_cap(entries, max_screenshots=10)
        assert len(out) == 2
        # Dedup-Gruppe (4er) zuerst
        assert out[0]["dedup_count"] == 4


# ====================================================================
# Cap auf max-2 (Default)
# ====================================================================
class TestMaxCap:
    def test_default_max_is_two(self):
        assert DEFAULT_MAX_SCREENSHOTS == 2

    def test_four_unique_screenshots_capped_to_two(self, tmp_path):
        files = [
            _write_png(tmp_path, "a.png", _PNG_RED),
            _write_png(tmp_path, "b.png", _PNG_BLUE),
            _write_png(tmp_path, "c.png", _PNG_GREEN),
            _write_png(tmp_path, "d.png", bytes.fromhex(  # 1x1-PNG schwarz
                "89504e470d0a1a0a0000000d49484452000000010000000108"
                "020000009077532000000010494441545478da636868f80f00"
                "0007030101fcbc3c3a0000000049454e44ae426082"
            )),
        ]
        entries = [
            {"label": f"h{i}.example.de (Screenshot)", "paths": [p]}
            for i, p in enumerate(files)
        ]
        out = dedup_and_cap(entries)
        assert len(out) == 2

    def test_custom_max(self, tmp_path):
        files = [
            _write_png(tmp_path, "a.png", _PNG_RED),
            _write_png(tmp_path, "b.png", _PNG_BLUE),
            _write_png(tmp_path, "c.png", _PNG_GREEN),
        ]
        entries = [
            {"label": f"h{i}.example.de (Screenshot)", "paths": [p]}
            for i, p in enumerate(files)
        ]
        out = dedup_and_cap(entries, max_screenshots=3)
        assert len(out) == 3


# ====================================================================
# Edge cases
# ====================================================================
class TestEdgeCases:
    def test_empty_input_returns_empty(self):
        assert dedup_and_cap([]) == []
        assert dedup_and_cap(None) == []  # type: ignore[arg-type]

    def test_missing_file_skipped(self, tmp_path):
        # Eine existierende Datei + eine nicht-existierende
        p_ok = _write_png(tmp_path, "ok.png", _PNG_RED)
        entries = [
            {"label": "ghost.example.de (Screenshot)", "paths": [
                str(tmp_path / "does_not_exist.png"),
            ]},
            {"label": "ok.example.de (Screenshot)", "paths": [p_ok]},
        ]
        out = dedup_and_cap(entries)
        assert len(out) == 1
        assert out[0]["paths"] == [p_ok]

    def test_entry_without_paths_skipped(self):
        out = dedup_and_cap([
            {"label": "no_path (Screenshot)"},
            {"label": "also_no_path (Screenshot)", "paths": []},
        ])
        assert out == []

    def test_preserves_caption_and_tech_chips(self, tmp_path):
        p = _write_png(tmp_path, "a.png", _PNG_RED)
        entries = [
            {
                "label": "a.example.de (Screenshot)",
                "paths": [p],
                "caption": "Live-Shop mit Bezahlfunktion",
                "tech_chips": ["WordPress 6.4", "WooCommerce"],
                "classification": "real_content",
            },
        ]
        out = dedup_and_cap(entries)
        assert len(out) == 1
        assert out[0]["caption"] == "Live-Shop mit Bezahlfunktion"
        assert out[0]["tech_chips"] == ["WordPress 6.4", "WooCommerce"]
        assert out[0]["classification"] == "real_content"


# ====================================================================
# Integration: v2-Augment ruft Pipeline
# ====================================================================
def test_augment_for_v2_populates_screenshots_v2(tmp_path):
    """_augment_for_v2 muss screenshots_v2 mit dedup'd Eintraegen befuellen."""
    from reporter.report_mapper import _augment_for_v2

    p_red = _write_png(tmp_path, "red.png", _PNG_RED)
    base = {
        "screenshots": [
            {"label": "a.example.de (Screenshot)", "paths": [p_red]},
            {"label": "b.example.de (Screenshot)", "paths": [p_red]},  # gleicher Hash via Pfad-Dedup
        ],
        "findings": [],
    }
    _augment_for_v2(
        base, {"findings": [], "additional_findings": []},
        host_inventory={"domain": "example.de", "hosts": []},
        package="perimeter",
        scan_meta={"domain": "example.de"},
    )
    assert "screenshots_v2" in base
    # Beide haben denselben Pfad -> beide hashen identisch -> 1 Eintrag
    assert len(base["screenshots_v2"]) == 1
