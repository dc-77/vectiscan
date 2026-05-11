"""Tests fuer F-PH1-003 Screenshot-Data im Report-Mapper.

Deckt:
1. Per-VHost-Schema (Liste von Dicts) wird akzeptiert.
2. Legacy-Schema (Liste von Pfaden) bleibt funktionsfaehig.
3. Cap auf MAX_SCREENSHOTS_PER_HOST_IN_PDF — verhindert PDF-Bloat.
4. Label fuer VHost-Schema enthaelt FQDN ("<vhost> (Screenshot)").
"""

from __future__ import annotations


def test_build_screenshot_data_per_vhost_schema() -> None:
    """F-PH1-003: Liste von Dicts {vhost,path} produziert pro VHost einen Entry."""
    from reporter.report_mapper import _build_screenshot_data

    inv = {"hosts": [{"ip": "1.2.3.4", "fqdns": ["a.example.com", "b.example.com"]}]}
    shots = {
        "1.2.3.4": [
            {"vhost": "a.example.com", "path": "/tmp/screenshot_a.example.com.png"},
            {"vhost": "b.example.com", "path": "/tmp/screenshot_b.example.com.png"},
        ],
    }
    entries = _build_screenshot_data(inv, shots)

    # 2 Entries — vorher 1 pro IP.
    assert len(entries) == 2
    labels = [e["label"] for e in entries]
    assert "a.example.com (Screenshot)" in labels
    assert "b.example.com (Screenshot)" in labels


def test_build_screenshot_data_legacy_path_list() -> None:
    """Legacy: Liste von Pfaden — extrahiert VHost aus Filename."""
    from reporter.report_mapper import _build_screenshot_data

    inv = {"hosts": [{"ip": "9.9.9.9", "fqdns": ["legacy.example.com"]}]}
    shots = {
        "9.9.9.9": ["/tmp/screenshot_legacy.example.com.png"],
    }
    entries = _build_screenshot_data(inv, shots)

    assert len(entries) == 1
    assert entries[0]["label"] == "legacy.example.com (Screenshot)"
    assert entries[0]["paths"] == ["/tmp/screenshot_legacy.example.com.png"]


def test_build_screenshot_data_caps_at_max_per_host() -> None:
    """F-PH1-003: nicht mehr als _MAX_SCREENSHOTS_PER_HOST_IN_PDF pro Host."""
    from reporter.report_mapper import (
        _MAX_SCREENSHOTS_PER_HOST_IN_PDF,
        _build_screenshot_data,
    )

    inv = {"hosts": [{"ip": "1.1.1.1", "fqdns": ["x.com"]}]}
    # 7 VHosts -> Cap auf 5
    items = [
        {"vhost": f"v{i}.example.com", "path": f"/tmp/shot{i}.png"}
        for i in range(7)
    ]
    entries = _build_screenshot_data(inv, {"1.1.1.1": items})

    assert len(entries) == _MAX_SCREENSHOTS_PER_HOST_IN_PDF
    # Erste 5 in Reihenfolge.
    assert entries[0]["label"] == "v0.example.com (Screenshot)"
    assert entries[4]["label"] == "v4.example.com (Screenshot)"


def test_build_screenshot_data_empty_returns_empty() -> None:
    """Leere host_screenshots produziert []."""
    from reporter.report_mapper import _build_screenshot_data

    assert _build_screenshot_data({"hosts": []}, None) == []
    assert _build_screenshot_data({"hosts": []}, {}) == []


# ---------------------------------------------------------------------------
# PR-F (Mai 2026): site_summary -> caption + tech_chips + skip_non_content
# ---------------------------------------------------------------------------

def test_build_screenshot_data_includes_site_summary_caption() -> None:
    """vhost.site_summary.description wird als ``caption`` im PDF-Entry uebernommen."""
    from reporter.report_mapper import _build_screenshot_data

    inv = {"hosts": [{
        "ip": "1.2.3.4",
        "fqdns": ["heuel.com"],
        "cms": "WordPress",
        "server": "Apache/2.4.62",
        "vhosts": [{
            "fqdn": "heuel.com",
            "is_primary": True,
            "site_summary": {
                "description": "WordPress 6.4 auf Apache 2.4.62 - Marketing-Webseite.",
                "classification": "web_content",
                "is_real_content": True,
                "confidence": 0.95,
            },
        }],
    }]}
    shots = {"1.2.3.4": [{"vhost": "heuel.com", "path": "/tmp/shot.png"}]}
    entries = _build_screenshot_data(inv, shots)

    assert len(entries) == 1
    assert entries[0]["caption"] == "WordPress 6.4 auf Apache 2.4.62 - Marketing-Webseite."
    assert entries[0]["classification"] == "web_content"
    assert "WordPress" in entries[0]["tech_chips"][0]


def test_build_screenshot_data_skips_non_content_by_default() -> None:
    """Parking/Error/Non-Web werden Default-maessig nicht ins PDF aufgenommen."""
    from reporter.report_mapper import _build_screenshot_data

    inv = {"hosts": [{
        "ip": "9.9.9.9",
        "fqdns": ["parked.example.com"],
        "vhosts": [{
            "fqdn": "parked.example.com",
            "site_summary": {
                "description": "Parking-Page - Domain ist nicht aktiv.",
                "classification": "parking",
                "is_real_content": False,
                "confidence": 1.0,
            },
        }],
    }]}
    shots = {"9.9.9.9": [{"vhost": "parked.example.com", "path": "/tmp/shot.png"}]}
    entries = _build_screenshot_data(inv, shots)

    assert entries == []


def test_build_screenshot_data_includes_non_content_when_flag_off() -> None:
    """skip_non_content=False (Admin-Mode) zeigt auch Parking/Error im PDF."""
    from reporter.report_mapper import _build_screenshot_data

    inv = {"hosts": [{
        "ip": "9.9.9.9",
        "fqdns": ["parked.example.com"],
        "vhosts": [{
            "fqdn": "parked.example.com",
            "site_summary": {
                "description": "Parking-Page.",
                "classification": "parking",
                "is_real_content": False,
                "confidence": 1.0,
            },
        }],
    }]}
    shots = {"9.9.9.9": [{"vhost": "parked.example.com", "path": "/tmp/shot.png"}]}
    entries = _build_screenshot_data(inv, shots, skip_non_content=False)

    assert len(entries) == 1
    assert entries[0]["caption"] == "Parking-Page."
    assert entries[0]["classification"] == "parking"


def test_build_screenshot_data_caption_truncated_to_200_chars() -> None:
    """Description ueber 200 Zeichen wird gekuerzt."""
    from reporter.report_mapper import _build_screenshot_data

    very_long = "X" * 300
    inv = {"hosts": [{
        "ip": "5.5.5.5",
        "fqdns": ["long.example.com"],
        "vhosts": [{
            "fqdn": "long.example.com",
            "site_summary": {
                "description": very_long,
                "classification": "web_content",
                "is_real_content": True,
                "confidence": 0.7,
            },
        }],
    }]}
    shots = {"5.5.5.5": [{"vhost": "long.example.com", "path": "/tmp/shot.png"}]}
    entries = _build_screenshot_data(inv, shots)

    assert len(entries[0]["caption"]) == 200


def test_build_screenshot_data_no_summary_still_works() -> None:
    """Order vor PR-E ohne site_summary auf vhosts: Entry hat keine caption."""
    from reporter.report_mapper import _build_screenshot_data

    inv = {"hosts": [{
        "ip": "1.1.1.1",
        "fqdns": ["old.example.com"],
        "vhosts": [{"fqdn": "old.example.com"}],
    }]}
    shots = {"1.1.1.1": [{"vhost": "old.example.com", "path": "/tmp/shot.png"}]}
    entries = _build_screenshot_data(inv, shots)

    assert len(entries) == 1
    assert "caption" not in entries[0]
    assert "classification" not in entries[0]
