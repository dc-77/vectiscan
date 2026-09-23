# -*- coding: utf-8 -*-
"""Der Katalogweg fasst die alte Kette nicht mehr an (S6, Teil A Punkt 2).

Bis S6 lief ``call_claude`` mit der Reparaturkette bei jedem Auftrag durch,
auch wenn v3 renderte; das Ergebnis wurde danach verworfen und kostete rund
1,85 USD je Bericht. Die Module sind weiterhin importierbar, der Legacy-Weg
braucht sie. Was hier zaehlt, ist, dass sie unter ``engine=catalog`` nicht
aufgerufen werden.

Aufbau wie tests/gate/test_worker_report_blocked.py: alle Collaborators
gepatcht, dann ``process_job`` aufrufen.
"""
from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from reporter.v3.golden import build_golden_report_data

COLLABORATORS = (
    "_get_db_connection", "_get_minio_client", "_download_rawdata", "tarfile",
    "parse_scan_data", "call_claude", "map_to_report_data", "generate_report",
    "_upload_report", "_create_report_record", "_update_order_status", "shutil",
    "_load_tool_runs", "_load_customer_context", "_store_customer_context",
    "_store_report_defects", "_research_customer_context",
    "run_qa_checks", "apply_deterministic_pipeline", "_build_findings_data",
)

# Ein Golden-Auftrag mit Befunden; das Datenmodell ist echt, nur der Weg
# dorthin ist gestellt.
ORDER = "14272c00-1145-4675-9b4c-19ce2ead403b"

JOB_DATA = {
    "scanId": ORDER,
    "rawDataPath": f"{ORDER}.tar.gz",
    "hostInventory": {"domain": "beispiel.de", "hosts": []},
    "techProfiles": [],
}


def _lauf(stack: ExitStack, tmp_path: Path, monkeypatch, **job) -> SimpleNamespace:
    m = SimpleNamespace(**{
        name: stack.enter_context(patch(f"reporter.worker.{name}"))
        for name in COLLABORATORS
    })
    conn = MagicMock()
    m._get_db_connection.return_value = conn
    conn.cursor.return_value.__enter__.return_value.fetchone.return_value = (0,)
    m._download_rawdata.return_value = tmp_path / "rawdata.tar.gz"
    m.parse_scan_data.return_value = {
        "host_inventory": {"domain": "beispiel.de", "hosts": [{"ip": "1.2.3.4"}]},
        "tech_profiles": [{"ip": "1.2.3.4"}],
        "consolidated_findings": "test findings",
    }
    m._upload_report.return_value = 12345
    m._create_report_record.return_value = ("report-id-123", "token-456")
    m._load_tool_runs.return_value = []
    m._load_customer_context.return_value = {}
    m._research_customer_context.return_value = None

    daten = build_golden_report_data(ORDER)
    stack.enter_context(patch("reporter.pdf.v3.pipeline.report_bundle_from_source",
                              return_value=(MagicMock(), MagicMock(), daten)))
    stack.enter_context(patch("reporter.v3.selfcheck.check_report_data_detailed",
                              return_value=[]))
    stack.enter_context(patch("reporter.gate.v3_checks.run_all", return_value=[]))

    def fake_render(_data, path, **_kwargs):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(b"fake-pdf")
        return SimpleNamespace(pages=25, defects=[], warnings=[], sparse_pages=())

    stack.enter_context(patch("reporter.pdf.v3.render_report_v3", fake_render))

    from reporter.worker import process_job

    process_job({**JOB_DATA, **job})
    m.conn = conn
    m.daten = daten
    return m


def test_katalogweg_ruft_die_alte_kette_nicht_auf(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VECTISCAN_REPORT_ENGINE", raising=False)
    monkeypatch.delenv("VECTISCAN_REPORT_LAYOUT", raising=False)
    with ExitStack() as stack:
        m = _lauf(stack, tmp_path, monkeypatch)

    m.call_claude.assert_not_called()
    m.run_qa_checks.assert_not_called()
    m.apply_deterministic_pipeline.assert_not_called()
    m.map_to_report_data.assert_not_called()
    m.generate_report.assert_not_called()
    # Die Dashboard-Liste kommt aus den Katalogbefunden, nicht aus claude_output.
    m._build_findings_data.assert_not_called()


def test_dashboard_liste_und_versionen_kommen_aus_v3(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VECTISCAN_REPORT_ENGINE", raising=False)
    with ExitStack() as stack:
        m = _lauf(stack, tmp_path, monkeypatch)

    kwargs = m._create_report_record.call_args.kwargs
    args = m._create_report_record.call_args.args
    findings_data = args[4]
    assert findings_data["engine"] == "catalog"
    assert sum(findings_data["severity_counts"].values()) == len(m.daten.findings)
    assert "cvss_score" not in str(findings_data["findings"])[:4000]
    assert kwargs["policy_version"] == (
        f"Katalog {m.daten.meta.catalog_version} / "
        f"Fakten {m.daten.meta.facts_schema_version}")
    assert kwargs["policy_id_distinct"]
    # S6a: die Berichtsnummer vom Deckblatt geht in reports.report_number.
    assert kwargs["report_number"] == m.daten.meta.report_id
    assert kwargs["report_number"].startswith("VS-")


def test_legacy_ruft_die_alte_kette_weiterhin(tmp_path, monkeypatch) -> None:
    """Der Rueckweg muss funktionieren, solange er dokumentiert ist."""
    monkeypatch.setenv("VECTISCAN_REPORT_ENGINE", "legacy")
    monkeypatch.setenv("VECTISCAN_REPORT_LAYOUT", "v3")
    with ExitStack() as stack:
        m = _lauf(stack, tmp_path, monkeypatch)

    m.call_claude.assert_called_once()
    m.map_to_report_data.assert_called_once()
    m._build_findings_data.assert_called()


@pytest.mark.parametrize("approved,excluded,erwartet", [
    (False, [], "pending_review"),
    # Der Fall aus dem Sicherheitsnetz: eine Ausschlussliste ist keine Freigabe.
    (False, ["VS-2026-001"], "pending_review"),
    (True, [], "report_complete"),
    (True, ["VS-2026-001"], "report_complete"),
])
def test_nur_approved_liefert_aus(tmp_path, monkeypatch, approved, excluded,
                                  erwartet) -> None:
    monkeypatch.delenv("VECTISCAN_REPORT_ENGINE", raising=False)
    with ExitStack() as stack:
        m = _lauf(stack, tmp_path, monkeypatch,
                  approved=approved, excludedFindings=excluded)

    status = [c.args[2] for c in m._update_order_status.call_args_list]
    assert status[-1] == erwartet


@pytest.mark.parametrize("status,leert", [
    ("report_complete", True),
    ("pending_review", True),
    ("report_blocked", True),
    ("failed", True),
    ("scan_running", False),
])
def test_endstatus_raeumt_das_laufende_werkzeug_ab(status, leert) -> None:
    """Issue #25: progress.currentTool blieb nach dem Endstatus auf "uploading".

    Geschrieben wird das Feld sonst nur vom Scan-Worker
    (scan-worker/scanner/progress.py); der Report-Worker ist der Letzte, der die
    Order anfasst, und raeumt es deshalb hier ab.
    """
    from reporter.worker import _update_order_status

    conn = MagicMock()
    cur = conn.cursor.return_value.__enter__.return_value
    with patch("reporter.worker.redis"):
        _update_order_status(conn, "order-1", status)

    sql = cur.execute.call_args.args[0]
    assert ("current_tool = NULL" in sql) is leert, sql
    assert ("current_host = NULL" in sql) is leert, sql


def test_prosa_ki_laeuft_im_produktionspfad(tmp_path, monkeypatch) -> None:
    """S6: Der Worker reichte `prose` nie durch.

    `report_bundle_from_source` nimmt den Parameter seit S3, der Aufruf im
    Worker liess ihn weg. Die Prosa lief deshalb nur ueber die Ops-Wege, und
    jeder Bericht aus der Produktion stand allein auf Katalogtexten.
    Aufgefallen bei der Abnahme von S6, weil im Lauf kein `report_prose_cost`
    stand.
    """
    monkeypatch.delenv("VECTISCAN_REPORT_ENGINE", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    gesehen: dict = {}

    def fake_generate(payload, *, order_id=None, **kwargs):
        gesehen["order_id"] = order_id
        gesehen["payload"] = payload
        return {"overall_text": "Aus der Prosa-KI."}, {"total_cost_usd": 0.25}

    def fake_apply(data, fields, payload=None):
        gesehen["angewendet"] = sorted(fields)
        return []

    with ExitStack() as stack:
        stack.enter_context(patch("reporter.v3.prose.available", return_value=True))
        stack.enter_context(patch("reporter.v3.prose.generate", fake_generate))
        stack.enter_context(patch("reporter.v3.prose.apply_prose", fake_apply))
        _lauf(stack, tmp_path, monkeypatch)

    assert gesehen.get("angewendet") == ["overall_text"]
    assert gesehen.get("payload"), "die Prosa-KI bekam keine Reportdaten"


def test_ohne_schluessel_bleibt_der_katalogtext(tmp_path, monkeypatch) -> None:
    """Ein Lauf ohne KI-Schluessel liefert denselben Bericht ohne Prosa."""
    monkeypatch.delenv("VECTISCAN_REPORT_ENGINE", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with ExitStack() as stack:
        erzeugt = stack.enter_context(patch("reporter.v3.prose.generate"))
        _lauf(stack, tmp_path, monkeypatch)
    erzeugt.assert_not_called()


def test_ein_fehler_der_prosa_haelt_den_bericht_nicht_auf(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("VECTISCAN_REPORT_ENGINE", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    with ExitStack() as stack:
        stack.enter_context(patch("reporter.v3.prose.available", return_value=True))
        stack.enter_context(patch("reporter.v3.prose.generate",
                                  side_effect=RuntimeError("API weg")))
        m = _lauf(stack, tmp_path, monkeypatch)
    # Der Bericht entsteht trotzdem, nur mit den Katalogtexten.
    m._create_report_record.assert_called_once()
    assert [c.args[2] for c in m._update_order_status.call_args_list][-1] == "pending_review"
