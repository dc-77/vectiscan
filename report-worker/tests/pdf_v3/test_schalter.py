# -*- coding: utf-8 -*-
"""Der Schalter VECTISCAN_REPORT_LAYOUT und die Verkettung zum Datenmodell.

Der vollstaendige Auftragsweg braucht Datenbank, MinIO und Redis und wird hier nicht
nachgebaut. Geprueft wird, dass der Schalter den v3-Zweig waehlt, dass er die
Vorgabewerte nicht verschiebt und dass die Verkettung Fakten -> Katalog -> Reportdaten
aus einem Roh-Tar durchlaeuft.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from reporter.pdf.v3.pipeline import DEBUG_BUCKET, DEBUG_PREFIX, report_data_from_source
from reporter.v3.models import ReportData
from tests.pdf_v3.conftest import JUNKERWERK_MULTI, REPORT_WORKER

WORKER = (REPORT_WORKER / "reporter" / "worker.py").read_text(encoding="utf-8")
TAR = REPORT_WORKER / "tests" / "golden" / "tars" / f"{JUNKERWERK_MULTI}.tar.gz"
REPO = REPORT_WORKER.parent

# docker-compose.yml und .gitlab-ci.yml liegen im Repo-Wurzelverzeichnis. Der
# Docker-Build-Kontext des Workers ist report-worker/, im Abbild gibt es sie also
# nicht. Die beiden Tests pruefen das Zusammenspiel im Repo, nicht den Renderer, und
# werden dort uebersprungen (Lauf im Abbild: test-report-worker-pdf).
nur_im_repo = pytest.mark.skipif(not (REPO / "docker-compose.yml").exists(),
                                 reason="Repo-Wurzel fehlt (Lauf im Abbild)")


@nur_im_repo
def test_vorgabewerte_bleiben_wie_sie_waren():
    """v3 ist ein Opt-in. Code-Vorgabe v1, Compose-Vorgabe v2, beides unveraendert."""
    os.environ.pop("VECTISCAN_REPORT_LAYOUT", None)
    assert os.environ.get("VECTISCAN_REPORT_LAYOUT", "v1").lower() == "v1"
    compose = (REPO / "docker-compose.yml").read_text(encoding="utf-8")
    assert "VECTISCAN_REPORT_LAYOUT: ${VECTISCAN_REPORT_LAYOUT:-v2}" in compose


def test_worker_kennt_den_v3_zweig():
    assert 'if layout == "v3":' in WORKER
    assert 'elif layout == "v2":' in WORKER
    assert "render_report_v3" in WORKER
    assert "report_data_from_source" in WORKER


def test_worker_faellt_bei_v3_nicht_still_auf_v2_zurueck():
    """Ein v2-PDF im Bucket unter dem Etikett v3 waere schlimmer als ein Fehlschlag."""
    zweig = WORKER.split('if layout == "v3":')[1].split('elif layout == "v2":')[0]
    assert "try:" not in zweig
    assert "except" not in zweig


def test_worker_reicht_den_bildresolver_durch():
    zweig = WORKER.split('if layout == "v3":')[1].split('elif layout == "v2":')[0]
    assert "MinioScreenshots(minio_client)" in zweig
    assert "package=package" in zweig


@pytest.mark.parametrize("wert,zweig", [("v3", "v3"), ("v2", "v2"), ("", "v1")])
def test_schalterwerte(monkeypatch, wert, zweig):
    if wert:
        monkeypatch.setenv("VECTISCAN_REPORT_LAYOUT", wert)
    else:
        monkeypatch.delenv("VECTISCAN_REPORT_LAYOUT", raising=False)
    assert os.environ.get("VECTISCAN_REPORT_LAYOUT", "v1").lower() == zweig


@pytest.mark.skipif(not TAR.exists(), reason="Golden-Tar fehlt")
def test_verkettung_aus_dem_roh_tar():
    """Fakten, Katalog und Reportdaten aus dem Tar, wie der Worker es tut."""
    data = report_data_from_source(TAR, report_date="19.09.2026")
    assert isinstance(data, ReportData)
    assert data.findings
    assert data.meta.customer_short
    assert data.scope.hosts


@pytest.mark.skipif(not TAR.exists(), reason="Golden-Tar fehlt")
def test_ohne_werkzeuglaeufe_bleibt_der_werkzeuganhang_leer():
    """Datenfalle: ohne scan_results-Zeilen ist die Abdeckung unbekannt.

    Der Anhang "Eingesetzte Werkzeuge" fuellt sich nur aus der Abdeckung, und
    selfcheck.check_report_data verlangt ihn. Wer aus dem Tar allein rendert, bekommt
    deshalb einen Defekt gemeldet, statt eine stille Luecke. Worker und Ops-Job
    reichen die Zeilen durch (pipeline.tool_runs_from_db).
    """
    from reporter.v3.selfcheck import check_report_data

    data = report_data_from_source(TAR, report_date="19.09.2026")
    assert data.appendix.tools == []
    assert any("Werkzeug" in d for d in check_report_data(data))


def test_ablage_im_debug_bucket_statt_bei_den_berichten():
    """Der Ops-Job darf den Kundenbericht nicht ueberschreiben."""
    assert DEBUG_BUCKET == "scan-debug"
    assert DEBUG_PREFIX == "v3"


@nur_im_repo
def test_ops_job_ist_in_der_pipeline_hinterlegt():
    ci = (REPO / ".gitlab-ci.yml").read_text(encoding="utf-8")
    assert "ops-render-v3:" in ci
    assert "test-report-worker-pdf:" in ci
    assert "VECTISCAN_REQUIRE_WEASYPRINT" in ci
    # Der Abbild-Job muss den Marker abwaehlen, sonst faellt test_font_constants dort.
    assert "not reportlab_fallback" in ci


@nur_im_repo
def test_pdf_job_laeuft_genau_dort_wo_auch_gebaut_wird():
    """Sonst lehnt GitLab die ganze Pipeline ab.

    test-report-worker-pdf braucht das Abbild aus build-report-worker. Traegt der
    Testjob eine Regel, die der Buildjob nicht hat, entsteht eine Pipeline, in der
    das `needs` ins Leere zeigt, und GitLab weist sie komplett zurueck. Das hat den
    dokumentierten Ops-Weg (API-Pipeline auf einem Session-Branch, siehe
    ops-export-golden-tars) unbrauchbar gemacht.
    """
    import yaml

    ci = yaml.safe_load((REPO / ".gitlab-ci.yml").read_text(encoding="utf-8"))
    pdf = ci["test-report-worker-pdf"]
    assert pdf["needs"] == ["build-report-worker"]
    assert pdf["rules"] == ci[".build-base"]["rules"]
