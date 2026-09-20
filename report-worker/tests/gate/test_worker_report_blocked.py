# -*- coding: utf-8 -*-
"""Statusuebergaenge des Gates in worker.process_job (S5).

Aufbau wie tests/test_worker_gate_strict.py: alle Collaborators gepatcht, dann
process_job() aufrufen und pruefen, was mit der Order passiert. Geprueft wird
hier der v3-Strang, also der Weg ueber selfcheck, die vier neuen Pruefungen und
die Render-Pruefungen.
"""
from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from reporter.gate.defects import Defect
from reporter.validation.gate import ValidationGate, ValidationLevel

COLLABORATORS = (
    "_get_db_connection", "_get_minio_client", "_download_rawdata", "tarfile",
    "parse_scan_data", "call_claude", "map_to_report_data", "generate_report",
    "_upload_report", "_create_report_record", "_update_order_status", "shutil",
    "_load_tool_runs", "_load_customer_context", "_store_customer_context",
    "_store_report_defects", "_research_customer_context",
)

JOB_DATA = {
    "scanId": "scan-v3-1",
    "rawDataPath": "scan-v3-1.tar.gz",
    "hostInventory": {"domain": "beispiel.de", "hosts": []},
    "techProfiles": [],
}


def _gate(level: ValidationLevel) -> MagicMock:
    """Das alte Gate meldet nichts; geprueft wird allein der v3-Strang."""
    result = MagicMock()
    result.passed = True
    result.errors = []
    result.warnings = []
    result.to_json.return_value = {"passed": True, "errors": []}

    gate = MagicMock()
    gate.level = level
    gate.run.return_value = result
    return gate


def _run(stack: ExitStack, tmp_path: Path, level: ValidationLevel,
         v3_defects: list, monkeypatch) -> SimpleNamespace:
    m = SimpleNamespace(**{
        name: stack.enter_context(patch(f"reporter.worker.{name}"))
        for name in COLLABORATORS
    })
    stack.enter_context(
        patch.object(ValidationGate, "from_env", return_value=_gate(level)))
    monkeypatch.setenv("VECTISCAN_REPORT_LAYOUT", "v3")

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
    m._load_tool_runs.return_value = []
    m._load_customer_context.return_value = {}
    m._research_customer_context.return_value = None

    # Der v3-Strang selbst wird gestellt: Datenmodell und Render kosten hier
    # nichts, geprueft werden die Statusuebergaenge.
    data = MagicMock()
    stack.enter_context(patch("reporter.pdf.v3.pipeline.report_bundle_from_source",
                              return_value=(MagicMock(), MagicMock(), data)))
    stack.enter_context(patch("reporter.v3.selfcheck.check_report_data_detailed",
                              return_value=[]))
    stack.enter_context(patch("reporter.gate.v3_checks.run_all",
                              return_value=list(v3_defects)))

    def fake_render(_data, path, **_kwargs):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(b"fake-pdf")
        return SimpleNamespace(pages=25, defects=[], warnings=[], sparse_pages=())

    stack.enter_context(patch("reporter.pdf.v3.render_report_v3", fake_render))

    from reporter.worker import process_job

    process_job(dict(JOB_DATA))
    m.conn = conn
    return m


def _fehler() -> Defect:
    return Defect(engine="v3", check="abdeckungskapitel_leer", severity="error",
                  message="Kapitel 2 nennt fuer keinen Host eine Abdeckung.")


def _warnung() -> Defect:
    return Defect(engine="v3", check="auftraggeber_fehlt", severity="warning",
                  message="Der Bericht nennt den Auftraggeber generisch.")


def test_defekt_unter_strict_blockiert_den_bericht(tmp_path, monkeypatch) -> None:
    with ExitStack() as stack:
        m = _run(stack, tmp_path, ValidationLevel.STRICT, [_fehler()], monkeypatch)

        assert m._update_order_status.call_count == 1
        args, kwargs = m._update_order_status.call_args
        assert args[2] == "report_blocked"
        assert "Bericht v3 blockiert" in kwargs["error_message"]

        # Nichts wird ausgeliefert.
        m._upload_report.assert_not_called()
        m._create_report_record.assert_not_called()

        # Die Defektliste liegt auf der Order, mit Zeitpunkt der Blockade.
        payload = m._store_report_defects.call_args[0][2]
        assert payload["engine"] == "v3"
        assert payload["blocked_at"] is not None
        assert payload["counts"]["errors"] == 1
        assert payload["defects"][0]["check"] == "abdeckungskapitel_leer"


def test_derselbe_defekt_unter_warn_liefert_aus(tmp_path, monkeypatch) -> None:
    with ExitStack() as stack:
        m = _run(stack, tmp_path, ValidationLevel.WARN, [_fehler()], monkeypatch)

        m._upload_report.assert_called_once()
        m._update_order_status.assert_called_with(m.conn, "scan-v3-1", "pending_review")

        payload = m._store_report_defects.call_args[0][2]
        assert payload["blocked_at"] is None
        assert payload["counts"]["errors"] == 1


def test_warnungen_blockieren_auch_unter_strict_nicht(tmp_path, monkeypatch) -> None:
    """Ein fehlender Firmenname haelt keinen Bericht auf."""
    with ExitStack() as stack:
        m = _run(stack, tmp_path, ValidationLevel.STRICT, [_warnung()], monkeypatch)

        m._upload_report.assert_called_once()
        payload = m._store_report_defects.call_args[0][2]
        assert payload["counts"] == {"errors": 0, "warnings": 1, "unprocessed": 0}


def test_ohne_defekte_wird_die_liste_trotzdem_geschrieben(tmp_path, monkeypatch) -> None:
    """Der Admin muss sehen koennen, dass ein Lauf sauber war."""
    with ExitStack() as stack:
        m = _run(stack, tmp_path, ValidationLevel.STRICT, [], monkeypatch)

        m._upload_report.assert_called_once()
        payload = m._store_report_defects.call_args[0][2]
        assert payload["defects"] == []
        assert payload["blocked_at"] is None


def test_kundenkontext_geht_in_den_bericht(tmp_path, monkeypatch) -> None:
    """Ohne diese Durchreichung nennt der Bericht nur "Auftraggeber" (offen aus S4)."""
    with ExitStack() as stack:
        m = _run(stack, tmp_path, ValidationLevel.WARN, [], monkeypatch)
        m._load_customer_context.assert_called_once()

    zweig = (Path("reporter") / "worker.py").read_text(encoding="utf-8")
    zweig = zweig.split('if layout == "v3":')[1].split('elif layout == "v2":')[0]
    assert "customer_context=customer_context" in zweig
