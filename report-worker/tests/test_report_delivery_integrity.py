"""VEC-486: Regressionstests fuer die Report-Auslieferung.

Deckt die drei Defekte ab, die zusammen abgeschnittene PDFs an Kunden
ausgeliefert haben:

1. `_assert_pdf_intact` — bis dahin pruefte NICHTS im Repo das Ende einer
   PDF-Datei (nur `%PDF` am Anfang oder `st_size > N`), sodass ein Torso ohne
   `startxref`/`%%EOF` bis in die Kunden-Mail durchlief.
2. MinIO-Key-Kollision — ein zweiter Lauf ohne Ausschluesse blieb auf
   `version=1` und ueberschrieb `{order_id}.pdf`, waehrend die bereits
   ausgelieferte reports-Zeile ihre alte `file_size_bytes` behielt.
3. `_normalize_excluded_ids` — die API stellt `[{finding_id, reason}]` ein,
   der Filter verglich gegen Finding-ID-Strings und traf daher nie.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from reporter.worker import (
    TruncatedPdfError,
    _assert_pdf_intact,
    _normalize_excluded_ids,
    _upload_report,
)


# --------------------------------------------------------------------------
# 1. PDF-Integritaet
# --------------------------------------------------------------------------

def _write_pdf(path: Path, *, body_kb: int = 40, tail: bytes = b"startxref\n123\n%%EOF\n") -> Path:
    path.write_bytes(b"%PDF-1.4\n" + (b"x" * (body_kb * 1024)) + b"\n" + tail)
    return path


class TestAssertPdfIntact:
    def test_accepts_complete_pdf(self, tmp_path: Path) -> None:
        pdf = _write_pdf(tmp_path / "ok.pdf")
        assert _assert_pdf_intact(pdf) == pdf.stat().st_size

    def test_rejects_missing_eof(self, tmp_path: Path) -> None:
        """Exakt der Prod-Fall: Datei endet mitten im Objekt-Stream."""
        pdf = _write_pdf(tmp_path / "cut.pdf", tail=b"")
        with pytest.raises(TruncatedPdfError, match="startxref"):
            _assert_pdf_intact(pdf)

    def test_rejects_startxref_without_eof(self, tmp_path: Path) -> None:
        pdf = _write_pdf(tmp_path / "half.pdf", tail=b"startxref\n123\n")
        with pytest.raises(TruncatedPdfError, match="%%EOF"):
            _assert_pdf_intact(pdf)

    def test_rejects_tiny_file(self, tmp_path: Path) -> None:
        pdf = tmp_path / "stub.pdf"
        pdf.write_bytes(b"%PDF-1.4\nstartxref\n0\n%%EOF\n")
        with pytest.raises(TruncatedPdfError, match="zu klein"):
            _assert_pdf_intact(pdf)

    def test_rejects_non_pdf(self, tmp_path: Path) -> None:
        junk = tmp_path / "junk.pdf"
        junk.write_bytes(b"<html>" + b"x" * (40 * 1024))
        with pytest.raises(TruncatedPdfError, match="PDF-Header"):
            _assert_pdf_intact(junk)


class TestUploadReport:
    def test_truncated_pdf_is_never_uploaded(self, tmp_path: Path) -> None:
        """Ein Torso darf MinIO gar nicht erst erreichen."""
        pdf = _write_pdf(tmp_path / "cut.pdf", tail=b"")
        client = MagicMock()
        client.bucket_exists.return_value = True

        with pytest.raises(TruncatedPdfError):
            _upload_report(client, pdf, "order.pdf")

        client.fput_object.assert_not_called()

    def test_returns_size_reported_by_minio(self, tmp_path: Path) -> None:
        """reports.file_size_bytes muss die Groesse des GESPEICHERTEN Objekts sein."""
        pdf = _write_pdf(tmp_path / "ok.pdf")
        client = MagicMock()
        client.bucket_exists.return_value = True
        client.stat_object.return_value = MagicMock(size=999_999)

        assert _upload_report(client, pdf, "order.pdf") == 999_999
        client.fput_object.assert_called_once()

    def test_falls_back_to_local_size_when_stat_fails(self, tmp_path: Path) -> None:
        pdf = _write_pdf(tmp_path / "ok.pdf")
        client = MagicMock()
        client.bucket_exists.return_value = True
        client.stat_object.side_effect = RuntimeError("minio down")

        assert _upload_report(client, pdf, "order.pdf") == pdf.stat().st_size


# --------------------------------------------------------------------------
# 2. Exclusion-Normalisierung
# --------------------------------------------------------------------------

class TestNormalizeExcludedIds:
    def test_api_object_payload(self) -> None:
        """Form, die api/src/routes/orders.ts:1643 und :1753 tatsaechlich senden."""
        raw = [
            {"finding_id": "VS-2026-004", "reason": "False Positive"},
            {"finding_id": "VS-2026-009", "reason": "akzeptiertes Risiko"},
        ]
        assert _normalize_excluded_ids(raw) == ["VS-2026-004", "VS-2026-009"]

    def test_legacy_string_payload(self) -> None:
        assert _normalize_excluded_ids(["VS-2026-001"]) == ["VS-2026-001"]

    def test_camel_case_and_id_keys(self) -> None:
        raw = [{"findingId": "VS-2026-002"}, {"id": "VS-2026-003"}]
        assert _normalize_excluded_ids(raw) == ["VS-2026-002", "VS-2026-003"]

    def test_empty_and_garbage(self) -> None:
        assert _normalize_excluded_ids([]) == []
        assert _normalize_excluded_ids(None) == []
        assert _normalize_excluded_ids([{"reason": "kein finding_id"}, 42, None]) == []

    def test_object_payload_actually_filters_findings(self) -> None:
        """Der Filter aus Schritt 5b muss mit dem normalisierten Ergebnis greifen.

        Vor VEC-486 lief `f["id"] not in excluded` gegen eine Liste von Dicts
        und war immer wahr — es wurde nie etwas ausgeschlossen.
        """
        findings = [{"id": "VS-2026-001"}, {"id": "VS-2026-004"}]
        raw = [{"finding_id": "VS-2026-004", "reason": "FP"}]

        naive = [f for f in findings if f["id"] not in raw]
        assert naive == findings, "Vorbedingung: der alte Vergleich filtert nichts"

        excluded = _normalize_excluded_ids(raw)
        assert [f for f in findings if f["id"] not in excluded] == [{"id": "VS-2026-001"}]


# --------------------------------------------------------------------------
# 3. MinIO-Key-Kollision (die eigentliche Ursache)
# --------------------------------------------------------------------------

class TestMinioKeyCollision:
    """Zwei Laeufe derselben Order duerfen niemals denselben MinIO-Key belegen.

    Prod-Fall: Der Scan erzeugt Report #1 (Status pending_review, Mail mit
    download_token raus), das Admin-Approve stellt einen zweiten Job mit
    `excludedFindings: []` ein. Weil die leere Liste falsy ist, blieb version=1
    und `{order_id}.pdf` wurde ueberschrieben — die bereits ausgelieferte
    reports-Zeile behielt ihre alte, kleinere file_size_bytes.
    """

    @staticmethod
    def _run(job_data: dict, max_version: int, tmp_path: Path) -> str:
        """Fuehrt process_job aus und gibt den benutzten MinIO-Key zurueck."""
        patches = {
            name: patch(f"reporter.worker.{name}")
            for name in (
                "_get_db_connection", "_get_minio_client", "_download_rawdata",
                "tarfile", "parse_scan_data", "call_claude", "map_to_report_data",
                "generate_report", "_upload_report", "_create_report_record",
                "_update_order_status", "shutil",
            )
        }
        started = {name: p.start() for name, p in patches.items()}
        try:
            from reporter.worker import process_job

            conn = MagicMock()
            started["_get_db_connection"].return_value = conn
            conn.cursor.return_value.__enter__.return_value.fetchone.return_value = (max_version,)

            started["_download_rawdata"].return_value = tmp_path / "rawdata.tar.gz"
            started["parse_scan_data"].return_value = {
                "host_inventory": {"domain": "beispiel.de", "hosts": [{"ip": "1.2.3.4"}]},
                "tech_profiles": [{"ip": "1.2.3.4"}],
                "consolidated_findings": "test findings",
            }
            started["call_claude"].return_value = {"overall_risk": "HIGH", "findings": []}
            started["map_to_report_data"].return_value = {"meta": {}, "findings": []}
            started["_upload_report"].return_value = 12345
            started["_create_report_record"].return_value = ("report-id", "token")

            def fake_generate(data, path):
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_bytes(b"fake-pdf")
            started["generate_report"].side_effect = fake_generate

            process_job(job_data)
            # _upload_report(minio_client, pdf_path, minio_path)
            return started["_upload_report"].call_args[0][2]
        finally:
            for p in patches.values():
                p.stop()

    def test_second_run_without_exclusions_uses_a_different_key(self, tmp_path: Path) -> None:
        order_id = "order-abc"
        base = {"orderId": order_id, "rawDataPath": f"{order_id}.tar.gz",
                "hostInventory": {"domain": "beispiel.de", "hosts": []}, "techProfiles": []}

        first = self._run({**base}, max_version=0, tmp_path=tmp_path)
        # Approve-Job: leere Exclusion-Liste — genau der Prod-Auslöser.
        second = self._run({**base, "excludedFindings": [], "approved": True},
                           max_version=1, tmp_path=tmp_path)

        assert first == f"{order_id}.pdf"
        assert second == f"{order_id}_v2.pdf"
        assert first != second, "zweiter Lauf darf den Key des ersten nicht ueberschreiben"
