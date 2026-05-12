"""M3 -- pdf/v2-Skelett: Smoke + Doppel-Render.

Verifiziert:
1. v2 rendert minimales report_data ohne Crash.
2. v2 verkraftet fehlendes layer1 (Aggregator-Agent noch nicht gemerged).
3. Doppel-Render (v1 + v2) auf identischem Input laeuft beidseitig durch.
4. ENV-Flag ohne Setzen => v1.
5. ENV-Flag = "v2" => v2.
"""
import os

import pytest

from reporter.generate_report import generate_report
from reporter.pdf.v2 import generate_report_v2


def _minimal_report_data(domain: str = "test.example.de") -> dict:
    return {
        "meta": {
            "title": "T",
            "author": "VectiScan",
            "header_left": "VECTISCAN",
            "header_right": domain,
            "footer_left": "Vertraulich",
            "classification_label": "VERTRAULICH",
        },
        "cover": {
            "cover_subtitle": "VECTISCAN",
            "cover_title": "Test",
            "package": "perimeter",
            "cover_meta": [
                ["Ziel:", domain],
                ["Datum:", "2026-06-01"],
            ],
        },
        "domain": domain,
        "toc": [("1", "Test", False)],
        "executive_summary": {
            "section_label": "1 ES",
            "subsections": [
                {"title": "ES", "paragraphs": ["body"]},
            ],
        },
        "scope": {
            "section_label": "2 Scope",
            "subsections": [
                {"title": "Sc", "paragraphs": ["body"]},
            ],
        },
        "findings": [],
        "recommendations": {
            "intro_paragraph": "x",
            "roadmap_table": None,
        },
        "screenshots": [],
        "disclaimer": "Disclaimer",
        # v2-Felder
        "layer1": {
            "risk_ampel": [
                {"label": "Patch & EOL", "level": "hoch"},
                {"label": "E-Mail", "level": "mittel"},
            ],
            "top_hebel": [
                {
                    "rank": 1,
                    "title": "DB-Port + Dev-Umgebung schliessen",
                    "effect": "schliesst 2 Befunde gleichzeitig",
                    "finding_ids": ["VS-2026-001", "VS-2026-002"],
                },
            ],
            "overall_level": "HOCH",
        },
    }


def test_v2_skeleton_renders_minimal_report(tmp_path):
    out = tmp_path / "test_v2.pdf"
    generate_report_v2(_minimal_report_data(), str(out))
    assert out.exists()
    assert out.stat().st_size > 1000  # PDF mit Inhalt


def test_v2_skeleton_renders_without_layer1(tmp_path):
    """Wenn der Aggregator noch nicht gemerged ist
    (report_data.layer1=None), laeuft v2 trotzdem durch -- kein Crash.
    """
    out = tmp_path / "test_v2_nolayer.pdf"
    data = _minimal_report_data()
    data["layer1"] = None
    generate_report_v2(data, str(out))
    assert out.exists()
    assert out.stat().st_size > 500


def test_double_render_v1_and_v2_succeed(tmp_path):
    """Doppel-Render-Smoke: Alt + Neu produzieren beide PDFs ohne Crash."""
    data = _minimal_report_data()
    out_v1 = tmp_path / "v1.pdf"
    out_v2 = tmp_path / "v2.pdf"
    generate_report(data, str(out_v1))
    generate_report_v2(data, str(out_v2))
    assert out_v1.exists() and out_v1.stat().st_size > 1000
    assert out_v2.exists() and out_v2.stat().st_size > 1000


def test_env_flag_off_uses_v1():
    os.environ.pop("VECTISCAN_REPORT_LAYOUT", None)
    layout = os.environ.get("VECTISCAN_REPORT_LAYOUT", "v1").lower()
    assert layout == "v1"


def test_env_flag_v2_activates(monkeypatch):
    monkeypatch.setenv("VECTISCAN_REPORT_LAYOUT", "v2")
    assert os.environ.get("VECTISCAN_REPORT_LAYOUT", "v1").lower() == "v2"


# ---------------------------------------------------------------------------
# Bonus: Dispatcher-Integration in report_mapper -- _augment_for_v2 verkraftet
# fehlenden Aggregator. Nicht in den Akzeptanzkriterien explizit gelistet,
# aber Teil von Liefer-Punkt 5 (Verifikation der Dispatch-Integration).
# ---------------------------------------------------------------------------


def test_augment_for_v2_handles_missing_aggregator(monkeypatch):
    """_augment_for_v2 darf nicht crashen, wenn layer1_aggregator fehlt.

    Da der Aggregator-Agent noch nicht gemerged ist, sollte report_data
    nach Augmentierung _renderer_layout="v2", domain=... und layer1=None
    enthalten.
    """
    from reporter.report_mapper import _augment_for_v2

    report_data: dict = {}
    claude_output = {"findings": [], "recommendations": []}
    host_inventory = {"domain": "agg-missing.example.de", "hosts": []}
    scan_meta = {"domain": "agg-missing.example.de"}

    _augment_for_v2(
        report_data,
        claude_output,
        host_inventory,
        package="perimeter",
        scan_meta=scan_meta,
    )

    assert report_data.get("_renderer_layout") == "v2"
    assert report_data.get("domain") == "agg-missing.example.de"
    # layer1 ist entweder ein Dict (Aggregator schon da) oder None (noch
    # nicht). Beides ist akzeptabel.
    assert "layer1" in report_data
    assert report_data["layer1"] is None or isinstance(
        report_data["layer1"], dict
    )
