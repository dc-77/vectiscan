"""Abo-Statusbericht (Issue #29, S6a).

Der Job-Typ `subscriptionId` ohne `orderId` hatte bis S6a keinen einzigen
Test und ist in Produktion nie durchgelaufen: sechsmal `HexColor()` um einen
Wert, der schon eine Farbe ist, dahinter MinIO ohne Port und Datenwerte, die
ungeschuetzt in ReportLab-Markup landeten. Diese Tests fahren den Job aus
einem Fixture-Abo bis zum PDF; die Datenbank ist ein In-Memory-Stub nach dem
Muster aus test_posture_aggregator.py, MinIO wird am Client abgefangen.
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pypdf import PdfReader

from reporter import status_report_generator as SRG

FIXTURE = Path(__file__).parent / "fixtures" / "status_report" / "abo.json"
SUB_ID = "5ab0c0de-0000-4000-8000-000000000029"


def _dates(obj):
    """ISO-Zeichenketten der *_at-Felder in datetime wandeln, wie psycopg2."""
    if isinstance(obj, list):
        return [_dates(x) for x in obj]
    if isinstance(obj, dict):
        return {k: (datetime.fromisoformat(v) if k.endswith("_at") and isinstance(v, str) else _dates(v))
                for k, v in obj.items()}
    return obj


def _abo() -> dict:
    return _dates(json.loads(FIXTURE.read_text(encoding="utf-8")))


class _FakeCursor:
    def __init__(self, store: dict, dict_rows: bool):
        self.store = store
        self.dict_rows = dict_rows
        self._rows: list = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql: str, params: tuple = ()):
        low = " ".join(sql.lower().split())
        self.store["sql"].append((low, params))
        abo = self.store["abo"]
        sub = abo["subscription"]
        if "select scan_interval, last_status_report_at from subscriptions" in low:
            self._rows = [(sub["scan_interval"], self.store["last_status_report_at"])] \
                if params[0] == sub["id"] else []
        elif "from subscriptions s join customers" in low:
            self._rows = [dict(sub)] if params[0] == sub["id"] else []
        elif "from subscription_posture" in low:
            self._rows = [dict(abo["posture"])] if abo["posture"] else []
        elif "from consolidated_findings" in low:
            self._rows = [dict(f) for f in abo["findings"]]
        elif "from posture_history" in low:
            self._rows = [dict(h) for h in abo["history"]]
        elif "from scan_targets" in low:
            self._rows = [{"canonical": t} for t in abo["targets"]]
        elif low.startswith("insert into subscription_status_reports"):
            self.store["inserted"].append(params)
            self._rows = []
        elif low.startswith("update subscriptions set last_status_report_at"):
            self.store["updated"].append(params)
            self._rows = []
        else:  # pragma: no cover - neue Abfrage ohne Stub
            raise AssertionError(f"unerwartete Abfrage: {low}")

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _FakeConn:
    def __init__(self, store: dict):
        self.store = store
        self.committed = False
        self.closed = False

    def cursor(self, cursor_factory=None):
        return _FakeCursor(self.store, dict_rows=cursor_factory is not None)

    def commit(self):
        self.committed = True

    def close(self):
        self.closed = True


@pytest.fixture
def store():
    return {"abo": _abo(), "sql": [], "inserted": [], "updated": [], "last_status_report_at": None}


@pytest.fixture
def minio():
    client = MagicMock()
    client.bucket_exists.return_value = True
    uploads: list[bytes] = []

    def _put(bucket, key, data, length, content_type):
        uploads.append(data.read())

    client.put_object.side_effect = _put
    client.uploads = uploads
    with patch("reporter.worker._get_minio_client", return_value=client):
        yield client


def _run(store, job: dict, **kw):
    conn = _FakeConn(store)
    with patch.object(SRG.psycopg2, "connect", return_value=conn):
        report_id = SRG.process_status_report_job(job, **kw)
    return report_id, conn


def _text(pdf: bytes) -> str:
    return "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(pdf)).pages)


def test_statusbericht_aus_fixture_abo_bis_zum_pdf(store, minio):
    report_id, conn = _run(store, {"subscriptionId": SUB_ID, "triggerReason": "on_demand"})

    assert report_id
    assert conn.committed and conn.closed
    # MinIO: derselbe Bucket wie die Auftragsberichte, Schluessel je Abo.
    bucket, key = minio.put_object.call_args.args[:2]
    assert bucket == "scan-reports"
    assert key == f"subscription-reports/{SUB_ID}/{report_id}.pdf"
    pdf = minio.uploads[0]
    assert pdf.startswith(b"%PDF-")

    text = _text(pdf)
    # Sonderzeichen erscheinen woertlich, statt den Parser zu brechen.
    assert "Müller & Söhne <Beispiel> GmbH" in text
    assert "Header <script> reflektiert & ungefiltert" in text
    assert "Nur über VPN & IP-Filter <intern> erreichbar" in text
    assert "Statusbericht" in text
    assert "Anlass: auf Anforderung" in text
    assert "Offene Befunde (3)" in text  # open und regressed
    assert "Behoben im Berichtszeitraum (1)" in text
    assert "Geprüft wurden 2 Ziele" in text
    for englisch in ("CRITICAL", "Executive Summary", "Geprueft", "Begruendung", "Trigger"):
        assert englisch not in text

    # DB: eine Zeile in subscription_status_reports, Zeitstempel am Abo.
    (params,) = store["inserted"]
    assert params[0] == report_id and params[1] == SUB_ID
    assert params[4] == "on_demand"
    assert params[5] == 72.4 and params[6:9] == (3, 2, 1)
    assert params[9] == key and params[10] == len(pdf)
    assert store["updated"] == [(SUB_ID,)]


def test_kein_gedankenstrich_und_echte_umlaute_in_festtexten(store, minio):
    _run(store, {"subscriptionId": SUB_ID})
    text = _text(minio.uploads[0])
    assert "—" not in text and "–" not in text
    assert "Begründung" in text


def test_pdf_kopie_fuer_das_artefakt(store, minio, tmp_path):
    out = tmp_path / "status.pdf"
    _run(store, {"subscriptionId": SUB_ID}, save_pdf_to=str(out))
    assert out.read_bytes() == minio.uploads[0]


def test_ohne_started_at_beginnt_der_zeitraum_mit_der_ersten_messung(store, minio):
    store["abo"]["subscription"]["started_at"] = None
    _run(store, {"subscriptionId": SUB_ID})
    (params,) = store["inserted"]
    assert params[2] == store["abo"]["history"][0]["snapshot_at"]


def test_ohne_started_at_und_ohne_messung_ist_der_zeitraum_der_stichtag(store, minio):
    store["abo"]["subscription"]["started_at"] = None
    store["abo"]["history"] = []
    _run(store, {"subscriptionId": SUB_ID, "periodEnd": "2026-09-23T10:00:00+00:00"})
    (params,) = store["inserted"]
    assert params[2] == params[3]


def test_ohne_posture_und_befunde(store, minio):
    store["abo"]["posture"] = None
    store["abo"]["findings"] = []
    store["abo"]["history"] = []
    report_id, _ = _run(store, {"subscriptionId": SUB_ID})
    assert report_id
    assert "Keine offenen Befunde" in _text(minio.uploads[0])


def test_unbekanntes_abo_erzeugt_nichts(store, minio):
    report_id, conn = _run(store, {"subscriptionId": "00000000-0000-4000-8000-000000000000"})
    assert report_id is None
    assert not store["inserted"] and not minio.put_object.called
    assert conn.closed


def test_planmaessig_und_faellig(store, minio):
    store["last_status_report_at"] = datetime.now(timezone.utc) - timedelta(days=31)
    report_id, _ = _run(store, {"subscriptionId": SUB_ID, "triggerReason": "scheduled"})
    assert report_id
    assert store["inserted"][0][4] == "scheduled"


def test_planmaessig_nicht_mehr_faellig_erzeugt_keinen_zweiten_bericht(store, minio):
    # Der Scheduler stellt jede Minute ein; waehrend ein langer Auftragsbericht
    # laeuft, stauen sich die Jobs. Nur der erste darf einen Bericht erzeugen.
    store["last_status_report_at"] = datetime.now(timezone.utc) - timedelta(minutes=2)
    report_id, _ = _run(store, {"subscriptionId": SUB_ID, "triggerReason": "scheduled"})
    assert report_id is None
    assert not store["inserted"] and not minio.put_object.called


def test_auf_anforderung_umgeht_die_faelligkeit(store, minio):
    store["last_status_report_at"] = datetime.now(timezone.utc) - timedelta(minutes=2)
    report_id, _ = _run(store, {"subscriptionId": SUB_ID, "triggerReason": "on_demand"})
    assert report_id


def test_minio_client_traegt_den_port():
    # Produktion setzt MINIO_ENDPOINT=minio und MINIO_PORT=9000 getrennt; der
    # alte Generator baute Minio("minio") und landete auf Port 80.
    from reporter import worker
    assert worker.MINIO_ENDPOINT.rsplit(":", 1)[-1].isdigit()
    client = MagicMock()
    client.bucket_exists.return_value = False
    with patch("reporter.worker._get_minio_client", return_value=client) as factory:
        key, size = SRG._upload_to_minio(b"%PDF-1.4 x", SUB_ID, "rid")
    factory.assert_called_once_with()
    client.make_bucket.assert_called_once_with("scan-reports")
    assert (key, size) == (f"subscription-reports/{SUB_ID}/rid.pdf", 10)


def test_worker_leitet_den_job_typ_an_den_generator():
    from reporter import worker
    with patch("reporter.status_report_generator.process_status_report_job",
               return_value="rid") as job, \
         patch("reporter.worker._get_db_connection") as db:
        worker.process_job({"subscriptionId": SUB_ID, "triggerReason": "scheduled"})
    job.assert_called_once_with({"subscriptionId": SUB_ID, "triggerReason": "scheduled"})
    db.assert_not_called()


def test_cli_schreibt_pdf_und_meldet_die_id(store, minio, tmp_path, capsys):
    out = tmp_path / "cli.pdf"
    conn = _FakeConn(store)
    with patch.object(SRG.psycopg2, "connect", return_value=conn):
        rc = SRG.main(["--subscription", SUB_ID, "--pdf", str(out)])
    assert rc == 0
    assert out.read_bytes().startswith(b"%PDF-")
    # structlog schreibt ebenfalls nach stdout; die ID ist die letzte Zeile.
    assert capsys.readouterr().out.strip().splitlines()[-1] == store["inserted"][0][0]


def test_farben_aus_branding_sind_schon_farben():
    # Die Ursache von #29 als Sperre: wer COLORS wieder in HexColor() wickelt,
    # faellt hier und nicht erst in Produktion.
    from reportlab.lib.colors import Color
    from reporter.pdf.branding import COLORS
    assert isinstance(COLORS["primary"], Color) and isinstance(COLORS["text"], Color)
    src = Path(SRG.__file__).read_text(encoding="utf-8")
    assert "HexColor(COLORS" not in src
