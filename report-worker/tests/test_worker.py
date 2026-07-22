"""Unit tests for reporter.worker module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def test_reporter_package_imports() -> None:
    """Verify the reporter package can be imported."""
    import reporter
    assert reporter.__doc__ is not None


def test_worker_module_imports() -> None:
    """Verify reporter.worker module imports without errors."""
    from reporter import worker
    assert worker.__doc__ is not None


class TestProcessJob:
    """Tests for the process_job function."""

    @patch("reporter.worker._get_db_connection")
    @patch("reporter.worker._get_minio_client")
    @patch("reporter.worker._download_rawdata")
    @patch("reporter.worker.tarfile")
    @patch("reporter.worker.parse_scan_data")
    @patch("reporter.worker.call_claude")
    @patch("reporter.worker.map_to_report_data")
    @patch("reporter.worker.generate_report")
    @patch("reporter.worker._upload_report")
    @patch("reporter.worker._create_report_record")
    @patch("reporter.worker._update_order_status")
    @patch("reporter.worker.shutil")
    def test_process_job_success(
        self,
        mock_shutil,
        mock_update_status,
        mock_create_record,
        mock_upload,
        mock_gen_report,
        mock_map,
        mock_claude,
        mock_parse,
        mock_tarfile,
        mock_download,
        mock_minio,
        mock_db,
        tmp_path,
    ) -> None:
        from reporter.worker import process_job

        # Setup mocks
        mock_conn = MagicMock()
        mock_db.return_value = mock_conn
        # VEC-486: die Versions-Query (SELECT COALESCE(MAX(version), 0)) laeuft
        # jetzt bei JEDEM Lauf, nicht mehr nur bei gesetzten Exclusions.
        # Ohne echtes Ergebnis liefert der Cursor-Mock ein MagicMock und
        # `version + 1` waere kein int mehr.
        mock_conn.cursor.return_value.__enter__.return_value.fetchone.return_value = (0,)

        mock_download.return_value = tmp_path / "rawdata.tar.gz"

        mock_parse.return_value = {
            "host_inventory": {"domain": "beispiel.de", "hosts": [{"ip": "1.2.3.4"}]},
            "tech_profiles": [{"ip": "1.2.3.4"}],
            "consolidated_findings": "test findings",
        }
        mock_claude.return_value = {"overall_risk": "HIGH", "findings": []}
        mock_map.return_value = {"meta": {}, "findings": []}
        mock_upload.return_value = 12345
        mock_create_record.return_value = ("report-id-123", "token-456")

        # generate_report is mocked — create a fake PDF so pdf_path.stat() works
        def fake_generate(data, path):
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_bytes(b"fake-pdf")
        mock_gen_report.side_effect = fake_generate

        job_data = {
            "scanId": "scan-123",
            "rawDataPath": "scan-123.tar.gz",
            "hostInventory": {"domain": "beispiel.de", "hosts": []},
            "techProfiles": [],
        }

        process_job(job_data)

        # Verify key steps were called
        mock_parse.assert_called_once()
        mock_claude.assert_called_once()
        mock_map.assert_called_once()
        mock_gen_report.assert_called_once()
        mock_upload.assert_called_once()
        mock_create_record.assert_called_once()
        # First run (no excluded findings) → pending_review for admin approval
        mock_update_status.assert_called_with(mock_conn, "scan-123", "pending_review"
        )

    @patch("reporter.worker._get_db_connection")
    @patch("reporter.worker._get_minio_client")
    @patch("reporter.worker._download_rawdata")
    @patch("reporter.worker._update_order_status")
    @patch("reporter.worker.shutil")
    def test_process_job_failure_updates_status(
        self,
        mock_shutil,
        mock_update_status,
        mock_download,
        mock_minio,
        mock_db,
    ) -> None:
        from reporter.worker import process_job

        mock_conn = MagicMock()
        mock_db.return_value = mock_conn
        mock_download.side_effect = Exception("Download failed")

        job_data = {
            "scanId": "scan-fail",
            "rawDataPath": "scan-fail.tar.gz",
            "hostInventory": {},
            "techProfiles": [],
        }

        process_job(job_data)

        # Should have tried to set status to failed
        mock_update_status.assert_called_once()
        args = mock_update_status.call_args
        assert args[0][2] == "failed"  # status arg


# ---------------------------------------------------------------------------
# F-RPT-005 — QA severity-cap order tests
# ---------------------------------------------------------------------------


class TestQASeverityCapOrder:
    """F-RPT-005: severity_evidence-Cap soll erst nach der Determinismus-
    Pipeline laufen und nur SP-FALLBACK-Findings cappen.

    `run_qa_checks(apply_severity_cap=False)` ueberspringt den Cap-Check.
    Default (True) erhaelt das alte Verhalten fuer Tests/Calls die nicht
    migriert sind.
    """

    def test_qa_severity_cap_skipped_when_flag_false(self) -> None:
        """run_qa_checks(apply_severity_cap=False) ueberspringt severity_evidence."""
        from reporter.qa_check import run_qa_checks

        findings = [{
            "id": "f1",
            "severity": "HIGH",
            "title": "veraltete Software xyz",
            "cvss_score": "5.0",
            "cwe": "CWE-1104",
            "recommendation": "update auf aktuelle Version durchfuehren",
            "evidence": "",
            "cve": "",
        }]
        out = {"findings": findings, "positive_findings": []}
        run_qa_checks(out, package="webcheck", apply_severity_cap=False)
        assert findings[0]["severity"] == "HIGH", \
            "Cap haette nicht laufen sollen (apply_severity_cap=False)"

    def test_qa_severity_cap_runs_when_flag_true(self) -> None:
        """Default (oder True) belaesst altes Verhalten — Cap wird angewendet."""
        from reporter.qa_check import run_qa_checks

        findings = [{
            "id": "f1",
            "severity": "HIGH",
            "title": "veraltete Software xyz",
            "cvss_score": "5.0",
            "cwe": "CWE-1104",
            "recommendation": "update auf aktuelle Version durchfuehren",
            "evidence": "",
            "cve": "",
        }]
        out = {"findings": findings, "positive_findings": []}
        run_qa_checks(out, package="webcheck", apply_severity_cap=True)
        assert findings[0]["severity"] == "MEDIUM", \
            "Cap haette laufen sollen (apply_severity_cap=True, kein CVE)"

    def test_qa_severity_cap_default_is_true(self) -> None:
        """Backwards-compat: ohne explizite Flag-Angabe wird gecappt."""
        from reporter.qa_check import run_qa_checks

        findings = [{
            "id": "f1",
            "severity": "HIGH",
            "title": "veraltete Software xyz",
            "cvss_score": "5.0",
            "cwe": "CWE-1104",
            "recommendation": "update auf aktuelle Version durchfuehren",
            "evidence": "",
            "cve": "",
        }]
        out = {"findings": findings, "positive_findings": []}
        run_qa_checks(out, package="webcheck")
        assert findings[0]["severity"] == "MEDIUM", \
            "Default-Verhalten muss Cap anwenden (Flag default=True)"


class TestCreateReportRecordExpiry:
    """VEC-180 (CL-1/VEC-169): Jeder Report-Datensatz — auch anonyme
    WebCheck-Free-Reports — bekommt eine 30-Tage-TTL auf expires_at, damit der
    Download-Deeplink ablaeuft und der Copy-Claim "Link 30 Tage gueltig" stimmt.
    """

    def _mock_conn(self) -> MagicMock:
        conn = MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        # 1. fetchone(): validation_warnings-Spalten-Check -> existiert.
        # 2. fetchone(): RETURNING id des INSERT.
        cur.fetchone.side_effect = [(True,), ("report-id-xyz",)]
        return conn

    def _insert_params(self, conn: MagicMock) -> tuple:
        from reporter.worker import _create_report_record
        report_id, token = _create_report_record(
            conn, "order-webcheck-123", "scan-reports/r.pdf", 4242,
        )
        assert report_id == "report-id-xyz"
        assert token  # download_token (uuid) wird erzeugt
        cur = conn.cursor.return_value.__enter__.return_value
        insert_calls = [
            c for c in cur.execute.call_args_list
            if "INSERT INTO reports" in c.args[0]
        ]
        assert len(insert_calls) == 1, "genau ein Report-Insert erwartet"
        return insert_calls[0].args[1]

    def test_expires_at_is_set_30_days_out(self) -> None:
        from datetime import datetime, timezone, timedelta

        params = self._insert_params(self._mock_conn())
        # Param-Reihenfolge: order_id, bucket, minio_path, file_size,
        # download_token, expires_at, ...
        expires_at = params[5]
        assert isinstance(expires_at, datetime), "expires_at muss gesetzt sein (nicht NULL)"
        now = datetime.now(timezone.utc)
        delta = expires_at - now
        # ~30 Tage, grosszuegige Toleranz fuer Laufzeit/CI-Jitter.
        assert timedelta(days=29, hours=23) < delta < timedelta(days=30, minutes=5), \
            f"expires_at muss ~30 Tage in der Zukunft liegen, war {delta}"


class TestBuildFindingsDataGuardStats:
    """C1 (Phase 1): CVE-/Claims-Guard-Stats werden nach findings_data
    durchgereicht (Defekt 3: cve_guard_stats hatte repo-weit keinen Leser)."""

    def test_build_findings_data_carries_guard_stats(self) -> None:
        from reporter.worker import _build_findings_data

        claude_output = {
            "overall_risk": "medium",
            "overall_description": "d",
            "findings": [],
            "recommendations": [],
            "cve_guard_stats": {"removed_count": 1, "distinct_removed": ["CVE-2099-1"],
                                "allowlist_size": 5},
            "claims_guard_stats": {"removed_count": 1, "distinct_removed": ["CVE-2099-1"],
                                   "allowlist_size": 5, "mode": "enforce",
                                   "claims_checked": 3,
                                   "claims_unsupported": {"cve": ["CVE-2099-1"],
                                                          "version": [], "host": [],
                                                          "port": []},
                                   "fields_scanned": []},
        }
        data = _build_findings_data(claude_output, package="perimeter")
        assert data["cve_guard_stats"]["removed_count"] == 1
        assert data["claims_guard_stats"]["mode"] == "enforce"

    def test_build_findings_data_omits_guard_stats_when_absent(self) -> None:
        """Ohne Guard-Stats bleibt findings_data byte-identisch (keine Keys)."""
        from reporter.worker import _build_findings_data

        claude_output = {
            "overall_risk": "low", "overall_description": "d",
            "findings": [], "recommendations": [],
        }
        data = _build_findings_data(claude_output, package="webcheck")
        assert "cve_guard_stats" not in data
        assert "claims_guard_stats" not in data

    def test_build_findings_data_demojibakes_dashboard_text(self) -> None:
        """Dashboard-Umlaute (Juli 2026): mojibaked KI-Text (Ã¤) in findings_data
        wird fuer die Dashboard-Befundansicht zu echten Umlauten repariert."""
        from reporter.worker import _build_findings_data

        claude_output = {
            "overall_risk": "high",
            "overall_description": "Mehrere Systeme mit erhÃ¶htem Risiko.",
            "findings": [{
                "id": "VS-1", "severity": "HIGH",
                "title": "Exchange Server 2016 auf owa.example.de",
                "description": "regulÃ¤res End-of-Life am 14. MÃ¤rz erreicht.",
            }],
            "positive_findings": [{"title": "TLS ok",
                                   "description": "Gute AbwÃ¤rtskompatibilitÃ¤t."}],
        }
        data = _build_findings_data(claude_output, package="perimeter")
        desc = data["findings"][0]["description"]
        assert "reguläres" in desc and "März" in desc
        assert "Ã" not in desc
        assert "erhöhtem" in data["overall_description"]
        assert "Ã" not in data["positive_findings"][0]["description"]
