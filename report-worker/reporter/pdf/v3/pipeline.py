# -*- coding: utf-8 -*-
"""Vom Auftrag zu den Reportdaten.

Der Renderer bekommt ``ReportData`` aus ``reporter.v3``. Diese drei Zeilen Verkettung
brauchen zwei Aufrufer, den Worker und den Ops-Job, deshalb stehen sie hier und nicht
in beiden.

Der Umschalter ``VECTISCAN_REPORT_ENGINE`` und das Entfernen der alten Reparaturkette
sind Session S6; hier wird nur der v3-Strang bedient.
"""
from __future__ import annotations

import io
import os
from pathlib import Path
from typing import Any

import structlog

from reporter.v3.models import ReportData

log = structlog.get_logger()

RAWDATA_BUCKET = "scan-rawdata"
DEBUG_BUCKET = "scan-debug"
DEBUG_PREFIX = "v3"


def report_bundle_from_source(source: str | Path,
                              host_inventory: dict | None = None,
                              tech_profiles: list | None = None,
                              correlated_findings: list | None = None,
                              job_payload: dict | None = None, *,
                              tool_runs: Any = None,
                              orders_json: Any = None,
                              order: dict | None = None,
                              customer_context: dict | None = None,
                              report_version: str = "1.0",
                              report_date: str | None = None,
                              prose: Any = None) -> tuple[Any, Any, ReportData]:
    """Roh-Tar oder entpacktes Scan-Verzeichnis -> Fakten, Katalog, Reportdaten.

    Die ersten fuenf Parameter sind die Signatur von ``reporter.facts.build_facts``;
    der Worker hat sie alle schon zur Hand.

    Gibt alle drei Zwischenstaende zurueck, weil das Gate aus S5 die Fakten (fuer
    die Beobachtungen ohne Regel) und das Katalogergebnis (fuer deren Zahl)
    braucht. Wer nur die Reportdaten will, nimmt ``report_data_from_source``.
    """
    from reporter.catalog import evaluate
    from reporter.facts import build_facts
    from reporter.v3 import build_report_data

    facts = build_facts(str(source), host_inventory, tech_profiles,
                        correlated_findings, job_payload,
                        tool_runs=tool_runs, orders_json=orders_json, order=order)
    output = evaluate(facts)
    data = build_report_data(facts, output, order=order,
                             customer_context=customer_context,
                             report_version=report_version, report_date=report_date,
                             prose=prose)
    log.info("report_data_v3_built", order_id=facts.scan.order_id,
             findings=len(data.findings), positives=len(data.positives),
             warnings=len(facts.warnings))
    return facts, output, data


def report_data_from_source(*args: Any, **kwargs: Any) -> ReportData:
    """Nur die Reportdaten; Signatur wie ``report_bundle_from_source``."""
    return report_bundle_from_source(*args, **kwargs)[2]


def tool_runs_from_db(order_id: str) -> list[dict]:
    """Die ``scan_results``-Zeilen eines Auftrags.

    Ohne sie bleibt die Abdeckung ``unknown``, und damit bleibt der Anhang
    "Eingesetzte Werkzeuge" leer; ``selfcheck.check_report_data`` meldet das als
    Defekt. Der Worker reicht die Zeilen durch, der Ops-Job holt sie hier selbst.
    Faellt die Datenbank aus, bleibt es bei einer leeren Liste und der Selbstcheck
    zeigt die Luecke, statt sie zu verschweigen.
    """
    try:
        import psycopg2

        from reporter.worker import DATABASE_URL, _load_tool_runs
        with psycopg2.connect(DATABASE_URL) as conn:
            return _load_tool_runs(conn, order_id)
    except Exception as exc:
        log.warning("tool_runs_unavailable", order_id=order_id, error=str(exc))
        return []


def minio_client():
    """Derselbe Client wie im Worker, aus denselben Umgebungsvariablen."""
    from minio import Minio

    endpoint = f"{os.environ.get('MINIO_ENDPOINT', 'minio')}:{os.environ.get('MINIO_PORT', '9000')}"
    return Minio(endpoint,
                 access_key=os.environ.get("MINIO_ACCESS_KEY", "minioadmin"),
                 secret_key=os.environ.get("MINIO_SECRET_KEY", "minioadmin"),
                 secure=os.environ.get("MINIO_SECURE", "false").lower() == "true")


def fetch_rawdata(client, order_id: str, dest: Path) -> Path:
    """Roh-Tar eines Auftrags aus MinIO holen."""
    key = f"{order_id}.tar.gz"
    local = dest / key
    client.fget_object(RAWDATA_BUCKET, key, str(local))
    log.info("rawdata_downloaded", key=key, size=local.stat().st_size)
    return local


def facts_export_enabled() -> bool:
    """Schalter ``VECTISCAN_FACTS_EXPORT``. Ohne ihn aendert sich nichts."""
    return os.environ.get("VECTISCAN_FACTS_EXPORT", "").strip().lower() in ("1", "true", "ja", "yes")


def upload_facts_export(client, order_id: str, facts: Any, output: Any) -> list[str]:
    """``facts.json`` und das Katalogergebnis neben das Roh-Tar legen.

    Ziel ist ``scan-rawdata``, nicht der Auslieferungs-Bucket: die Dateien sind
    Arbeitsmaterial fuer Admin-Review, Fehlersuche und den Export in S7, kein
    Kundendokument. Sie liegen damit an derselben Stelle wie die Rohdaten, aus
    denen sie entstanden sind.

    Deterministisch geschrieben (``reporter.facts.serialize.dumps``), damit zwei
    Laeufe derselben Order byte-gleiche Dateien ergeben.
    """
    from reporter.facts.serialize import dumps

    if not client.bucket_exists(RAWDATA_BUCKET):
        client.make_bucket(RAWDATA_BUCKET)
    keys: list[str] = []
    for name, obj in (("facts.json", facts), ("catalog.json", output)):
        data = dumps(obj.to_dict()).encode("utf-8")
        key = f"{order_id}/{name}"
        client.put_object(RAWDATA_BUCKET, key, io.BytesIO(data), len(data),
                          content_type="application/json")
        log.info("facts_export_uploaded", bucket=RAWDATA_BUCKET, key=key, size=len(data))
        keys.append(f"{RAWDATA_BUCKET}/{key}")
    return keys


def export_facts_if_enabled(client, order_id: str, facts: Any, output: Any) -> list[str]:
    """Export nur mit Schalter, und nie auf Kosten des Berichts.

    Die Ausnahmebehandlung steht hier und nicht beim Aufrufer: der v3-Zweig im
    Worker soll ohne ``try`` auskommen, damit ein Fehler beim Rendern nicht
    versehentlich abgefangen wird und ein v2-PDF unter dem Etikett v3 landet
    (Waechtertest ``test_worker_faellt_bei_v3_nicht_still_auf_v2_zurueck``).
    """
    if not facts_export_enabled():
        return []
    try:
        return upload_facts_export(client, order_id, facts, output)
    except Exception as exc:
        log.warning("facts_export_failed", order_id=order_id, error=str(exc))
        return []


def upload_debug_pdf(client, order_id: str, pdf: Path, stamp: str) -> str:
    """PDF in den Debug-Bucket legen. Weder Auftrag noch Report werden angefasst."""
    if not client.bucket_exists(DEBUG_BUCKET):
        client.make_bucket(DEBUG_BUCKET)
    key = f"{DEBUG_PREFIX}/{order_id}-{stamp}.pdf"
    client.fput_object(DEBUG_BUCKET, key, str(pdf), content_type="application/pdf")
    log.info("pdf_v3_uploaded", bucket=DEBUG_BUCKET, key=key, size=pdf.stat().st_size)
    return f"{DEBUG_BUCKET}/{key}"
