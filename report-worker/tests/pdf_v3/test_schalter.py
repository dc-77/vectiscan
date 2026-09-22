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

from reporter import engine as E
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


def test_ohne_env_gilt_katalog_v3_und_strict(monkeypatch):
    """S6: Der Katalogweg ist die Vorgabe, nicht mehr ein Opt-in.

    Bis S6 stand hier das Gegenteil: Code-Vorgabe v1, Compose-Vorgabe v2, Gate
    warn. Wer eine dieser Zeilen aendert, aendert, was beim Kunden ankommt, und
    soll hier vorbeikommen.
    """
    for name in ("VECTISCAN_REPORT_ENGINE", "VECTISCAN_REPORT_LAYOUT",
                 "VECTISCAN_VALIDATION_LEVEL"):
        monkeypatch.delenv(name, raising=False)
    assert E.engine() == "catalog"
    assert E.layout() == "v3"
    assert E.validation_level() == "strict"
    assert E.resolve() == ("catalog", "v3")
    assert E.uses_catalog() is True


def test_legacy_bleibt_eine_release_lang_erreichbar(monkeypatch):
    monkeypatch.setenv("VECTISCAN_REPORT_ENGINE", "legacy")
    monkeypatch.setenv("VECTISCAN_REPORT_LAYOUT", "v2")
    assert E.resolve() == ("legacy", "v2")
    assert E.uses_catalog() is False
    # Der Weg aus S4 und S5 (alte Kette, v3-Renderer) bleibt fuer Vergleichslaeufe.
    monkeypatch.setenv("VECTISCAN_REPORT_LAYOUT", "v3")
    assert E.resolve() == ("legacy", "v3")


def test_katalog_mit_altem_renderer_faellt_laut(monkeypatch):
    """Der v2-Renderer liest das Datenmodell der alten Kette; unter catalog gibt es das nicht."""
    monkeypatch.setenv("VECTISCAN_REPORT_ENGINE", "catalog")
    for layout in ("v2", "v1"):
        monkeypatch.setenv("VECTISCAN_REPORT_LAYOUT", layout)
        with pytest.raises(E.EngineConfigError):
            E.resolve()


def test_tippfehler_ist_ein_fehler_kein_rueckfall(monkeypatch):
    monkeypatch.setenv("VECTISCAN_REPORT_ENGINE", "ctalog")
    with pytest.raises(E.EngineConfigError):
        E.engine()
    monkeypatch.setenv("VECTISCAN_REPORT_ENGINE", "catalog")
    monkeypatch.setenv("VECTISCAN_VALIDATION_LEVEL", "strikt")
    with pytest.raises(E.EngineConfigError):
        E.validation_level()


@nur_im_repo
def test_deploy_konfiguration_traegt_dieselben_vorgaben():
    compose = (REPO / "docker-compose.yml").read_text(encoding="utf-8")
    assert "VECTISCAN_REPORT_ENGINE: ${VECTISCAN_REPORT_ENGINE:-catalog}" in compose
    assert "VECTISCAN_REPORT_LAYOUT: ${VECTISCAN_REPORT_LAYOUT:-v3}" in compose
    assert "VECTISCAN_VALIDATION_LEVEL: ${VECTISCAN_VALIDATION_LEVEL:-strict}" in compose
    ci = (REPO / ".gitlab-ci.yml").read_text(encoding="utf-8")
    # Ohne die Zeilen im .env haengt die Produktion still am Compose-Default und
    # ein Rueckweg braucht eine Compose-Aenderung.
    assert "VECTISCAN_REPORT_ENGINE=${VECTISCAN_REPORT_ENGINE:-catalog}" in ci
    assert "VECTISCAN_REPORT_LAYOUT=${VECTISCAN_REPORT_LAYOUT:-v3}" in ci
    assert "VECTISCAN_VALIDATION_LEVEL=${VECTISCAN_VALIDATION_LEVEL:-strict}" in ci
    vorlage = (REPO / ".env.template").read_text(encoding="utf-8")
    assert "VECTISCAN_REPORT_ENGINE=catalog" in vorlage
    assert "VECTISCAN_VALIDATION_LEVEL=strict" in vorlage


@nur_im_repo
def test_die_alte_kette_laeuft_nicht_mehr_im_katalogweg():
    """Teil A Punkt 2: KI#5 und die Reparaturkette gehoeren in den legacy-Zweig."""
    assert "if not uses_legacy:" in WORKER
    # call_claude darf nur noch unter legacy erreichbar sein.
    vor_der_verzweigung = WORKER[:WORKER.index("if not uses_legacy:")]
    assert "call_claude(" not in vor_der_verzweigung


def test_worker_kennt_den_v3_zweig():
    assert 'if layout == "v3":' in WORKER
    assert 'elif layout == "v2":' in WORKER
    assert "render_report_v3" in WORKER
    # S5: Der Worker nimmt die Variante mit den Zwischenstaenden, weil das Gate
    # die Fakten und das Katalogergebnis braucht. Die Verkettung selbst bleibt
    # an einer Stelle; report_data_from_source ruft dieselbe Funktion.
    assert "report_bundle_from_source" in WORKER


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
    # S6: Der Marker reportlab_fallback ist weg, samt dem Test, den er abwaehlte.
    # Bleibt die Abwahl in der Pipeline stehen, laeuft pytest mit einem
    # unbekannten Marker und meldet nur eine Warnung.
    assert "reportlab_fallback" not in ci


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
