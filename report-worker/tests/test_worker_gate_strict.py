"""S0a/S5: Verhalten des Validation-Gates auf Level STRICT in worker.process_job.

Das Gate ist seit M2 implementiert (kein PDF, kein Upload), hatte aber keinen
Test. S0a hat das Verhalten festgeschrieben, S5 hat den Status geaendert: statt
'failed' geht die Order auf 'report_blocked' und die Defektliste liegt
strukturiert auf der Order, damit der Admin sie im Review sieht.

Aufbau wie tests/test_worker.py: alle Collaborators von reporter.worker
gepatcht, dann process_job() aufrufen und die Statusuebergaenge pruefen.
"""

from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from reporter.validation.gate import ValidationGate, ValidationLevel


# S6: Diese Datei prueft den alten Weg (KI#5, Reparaturkette, ReportLab). Seit der
# Umschaltung ist ``catalog`` mit Renderer v3 die Vorgabe; der alte Weg laeuft nur
# noch unter ``VECTISCAN_REPORT_ENGINE=legacy``.
@pytest.fixture(autouse=True)
def _legacy_engine(monkeypatch):
    monkeypatch.setenv("VECTISCAN_REPORT_ENGINE", "legacy")
    monkeypatch.setenv("VECTISCAN_REPORT_LAYOUT", "v1")

COLLABORATORS = (
    "_get_db_connection", "_get_minio_client", "_download_rawdata", "tarfile",
    "parse_scan_data", "call_claude", "map_to_report_data", "generate_report",
    "_upload_report", "_create_report_record", "_update_order_status", "shutil",
    "_store_report_defects",
)

JOB_DATA = {
    "scanId": "scan-strict-1",
    "rawDataPath": "scan-strict-1.tar.gz",
    "hostInventory": {"domain": "beispiel.de", "hosts": []},
    "techProfiles": [],
}


def _fake_gate(level: ValidationLevel, passed: bool) -> MagicMock:
    """ValidationGate-Ersatz mit fixem Ergebnis."""
    result = MagicMock()
    result.passed = passed
    result.errors = [] if passed else ["ids: Luecke zwischen VS-2026-003 und VS-2026-005"]
    result.warnings = []
    result.to_json.return_value = {"passed": passed, "errors": result.errors}

    gate = MagicMock()
    gate.level = level
    gate.run.return_value = result
    return gate


def _run_process_job(stack: ExitStack, tmp_path: Path, level: ValidationLevel):
    """Patcht alles weg, faehrt process_job und liefert die Mocks zurueck."""
    m = SimpleNamespace(**{
        name: stack.enter_context(patch(f"reporter.worker.{name}"))
        for name in COLLABORATORS
    })
    stack.enter_context(
        patch.object(ValidationGate, "from_env",
                     return_value=_fake_gate(level, passed=False))
    )

    conn = MagicMock()
    m._get_db_connection.return_value = conn
    conn.cursor.return_value.__enter__.return_value.fetchone.return_value = (0,)
    m._download_rawdata.return_value = tmp_path / "rawdata.tar.gz"
    m.parse_scan_data.return_value = {
        "host_inventory": {"domain": "beispiel.de", "hosts": [{"ip": "1.2.3.4"}]},
        "tech_profiles": [{"ip": "1.2.3.4"}],
        "consolidated_findings": "test findings",
    }
    m.call_claude.return_value = {"overall_risk": "HIGH", "findings": []}
    m.map_to_report_data.return_value = {"meta": {}, "findings": []}
    m._upload_report.return_value = 12345
    m._create_report_record.return_value = ("report-id-123", "token-456")

    def fake_generate(data, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(b"fake-pdf")

    m.generate_report.side_effect = fake_generate

    from reporter.worker import process_job

    process_job(dict(JOB_DATA))
    m.conn = conn
    return m


def test_strict_gate_failure_blocks_order(tmp_path) -> None:
    """Defekt unter STRICT: Order auf 'report_blocked', kein PDF, kein Upload."""
    with ExitStack() as stack:
        m = _run_process_job(stack, tmp_path, ValidationLevel.STRICT)

        # Status genau einmal gesetzt: der ValidationFailedError-Handler in
        # process_job darf die kuratierte Meldung nicht ueberschreiben.
        assert m._update_order_status.call_count == 1
        args, kwargs = m._update_order_status.call_args
        assert args[1] == "scan-strict-1"
        assert args[2] == "report_blocked"
        assert "Validation-Gate STRICT" in kwargs["error_message"]

        # Nichts wird ausgeliefert.
        m.generate_report.assert_not_called()
        m._upload_report.assert_not_called()
        m._create_report_record.assert_not_called()

        # S5: Die Defekte des alten Gates landen strukturiert auf der Order.
        payload = m._store_report_defects.call_args[0][2]
        assert payload["engine"] == "v2"
        assert payload["blocked_at"] is not None
        assert payload["counts"]["errors"] == 1
        assert payload["defects"][0]["engine"] == "v2"


def test_warn_gate_failure_still_delivers(tmp_path) -> None:
    """Derselbe Defekt unter WARN: Report wird gebaut, Order in den Review."""
    with ExitStack() as stack:
        m = _run_process_job(stack, tmp_path, ValidationLevel.WARN)

        m.generate_report.assert_called_once()
        m._upload_report.assert_called_once()
        m._update_order_status.assert_called_with(
            m.conn, "scan-strict-1", "pending_review"
        )
        # Auch ohne Blockade wird die Liste geschrieben, sonst sieht der Admin
        # im Review nicht, was der Lauf gefunden hat.
        payload = m._store_report_defects.call_args[0][2]
        assert payload["blocked_at"] is None
        assert payload["counts"]["errors"] == 1
