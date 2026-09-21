# -*- coding: utf-8 -*-
"""Der Produktionspfad muss dieselben Fakten liefern wie der Tar-Pfad (S5b).

Bis S5b las ``worker._load_tool_runs`` weder ``created_at`` noch ``raw_output``.
Die Golden-Tests merkten davon nichts, weil sie ihre Zeilen aus dem
API-Schnappschuss beziehen. Gemessen an allen dreizehn Auftraegen fiel dadurch
die Zahl der ``ok``-Abdeckungszeilen im Produktionspfad auf null, und die
TLS-Protokolle fehlten.

Dieser Test schliesst die Luecke, ohne eine Datenbank zu brauchen: ein
Cursor-Doppel liefert die Werte des Schnappschusses in der Spaltenreihenfolge
des Produktions-SELECT, inklusive der Groessengrenze und der Sortierung.
``_load_tool_runs`` laeuft darueber, das Ergebnis geht durch ``build_facts`` und
wird mit den eingecheckten Golden-Facts verglichen.

Faellt dieser Test, wurde der SELECT wieder verengt.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from reporter.facts import build_facts
from reporter.facts.golden import (
    facts_path, golden_orders, results_path, tar_path, SNAPSHOT,
)
from reporter.facts.serialize import dumps, load_json
from reporter.worker import RAW_OUTPUT_MAX_BYTES, _load_tool_runs

# Spaltenreihenfolge von ``select_with_status`` in worker._load_tool_runs.
COLUMNS = ("hostIp", "phase", "toolName", "exitCode", "durationMs",
           "status", "skipReason", "createdAt", "rawOutput")

# Postgres sortiert ASC mit NULLS LAST; ein Sentinel oberhalb jedes echten
# Wertes bildet das nach, ohne dass ``None`` mit ``str`` verglichen wird.
_LAST = "￿"


def _snapshot_rows(order_id: str) -> list[dict[str, Any]]:
    data = json.loads(results_path(order_id).read_text(encoding="utf-8"))
    rows = data if isinstance(data, list) else data.get("data", {}).get("results", [])
    return [r for r in rows if isinstance(r, dict)]


def _order_by(row: dict[str, Any]) -> tuple:
    """ORDER BY phase, tool_name, host_ip, created_at, id mit NULLS LAST."""
    def txt(value: Any) -> str:
        return _LAST if value is None else str(value)
    phase = row.get("phase")
    return (phase if phase is not None else 1 << 30,
            txt(row.get("toolName")), txt(row.get("hostIp")),
            txt(row.get("createdAt")), txt(row.get("id")))


class _Cursor:
    """Gibt die Schnappschuss-Zeilen so zurueck, wie Postgres es taete."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows
        self._result: list[tuple] = []

    def __enter__(self) -> "_Cursor":
        return self

    def __exit__(self, *_exc: Any) -> bool:
        return False

    def execute(self, sql: str, params: tuple) -> None:
        limit, _order_id = params
        assert "created_at" in sql, "SELECT ohne created_at"
        assert "raw_output" in sql, "SELECT ohne raw_output"
        out = []
        for row in sorted(self._rows, key=_order_by):
            raw = row.get("rawOutput")
            size = None if raw is None else len(str(raw).encode("utf-8"))
            capped = raw if size is None or size <= limit else None
            out.append(tuple(row.get(c) for c in COLUMNS[:8]) + (capped, size))
        self._result = out

    def fetchall(self) -> list[tuple]:
        return self._result


class _Conn:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def cursor(self) -> _Cursor:
        return _Cursor(self._rows)

    def rollback(self) -> None:  # pragma: no cover - wird hier nie gebraucht
        raise AssertionError("Der Produktions-SELECT darf nicht scheitern")


def _ohne_zeilenherkunft(facts: dict) -> dict:
    """Die Herkunft der Zeilen darf abweichen, ihr Inhalt nicht.

    Der Golden-Pfad liest ``results.json`` und vermerkt Dateiname und Pruefsumme,
    der Produktionspfad bekommt die Zeilen aus der Datenbank. Verglichen werden
    die Fakten, nicht der Weg, auf dem sie hereinkamen.
    """
    kopie = json.loads(dumps(facts))
    gen = kopie.get("generator") or {}
    gen["inputs"] = [i for i in gen.get("inputs", []) if i.get("kind") != "tool_runs"]
    return kopie


def _cases() -> list[str]:
    return [o["order_id"] for o in golden_orders()
            if results_path(o["order_id"]) and facts_path(o["order_id"]).exists()]


@pytest.mark.parametrize("order_id", _cases())
def test_produktionspfad_liefert_dieselben_fakten(order_id: str) -> None:
    rows = _load_tool_runs(_Conn(_snapshot_rows(order_id)), order_id)
    assert rows, "keine Zeilen aus dem Produktions-SELECT"
    assert all(r.get("created_at") is not None for r in rows), \
        "created_at fehlt in mindestens einer Zeile"
    assert any(r.get("raw_output") for r in rows), \
        "raw_output fehlt in allen Zeilen"

    orders_json = SNAPSHOT / "orders.json"
    facts = build_facts(tar_path(order_id), tool_runs=rows,
                        orders_json=orders_json if orders_json.exists() else None)
    gebaut = facts.to_dict()
    erwartet = load_json(facts_path(order_id))
    arten = {i.get("kind") for i in (gebaut.get("generator") or {}).get("inputs", [])}
    assert "tool_runs" in arten, "die Zeilen stehen nicht in der Herkunft"
    assert dumps(_ohne_zeilenherkunft(gebaut)) == dumps(_ohne_zeilenherkunft(erwartet))


def test_groessengrenze_laesst_die_zeile_stehen() -> None:
    """Eine zu grosse Zeile wird weggelassen, nicht abgeschnitten."""
    rows = [{
        "hostIp": "192.0.2.1", "phase": 2, "toolName": "nuclei", "exitCode": 0,
        "durationMs": 10, "status": "ok", "skipReason": None,
        "createdAt": "2026-09-21T10:00:00Z", "id": "a",
        "rawOutput": "x" * (RAW_OUTPUT_MAX_BYTES + 1),
    }]
    geladen = _load_tool_runs(_Conn(rows), "order")
    assert geladen[0]["raw_output"] is None
    assert geladen[0]["raw_output_omitted"] is True


def test_normale_zeile_traegt_keinen_vermerk() -> None:
    rows = [{
        "hostIp": "192.0.2.1", "phase": 2, "toolName": "httpx", "exitCode": 0,
        "durationMs": 10, "status": "ok", "skipReason": None,
        "createdAt": "2026-09-21T10:00:00Z", "id": "a", "rawOutput": "{}",
    }]
    geladen = _load_tool_runs(_Conn(rows), "order")
    assert geladen[0]["raw_output"] == "{}"
    assert "raw_output_omitted" not in geladen[0]


def test_alte_konsumenten_sehen_ihre_schluessel() -> None:
    """``reporter/coverage.py`` liest nur die alten Schluessel (worker.py:1094)."""
    rows = [{
        "hostIp": "192.0.2.1", "phase": 1, "toolName": "nmap", "exitCode": 0,
        "durationMs": 10, "status": "ok", "skipReason": None,
        "createdAt": "2026-09-21T10:00:00Z", "id": "a", "rawOutput": "Nmap done",
    }]
    geladen = _load_tool_runs(_Conn(rows), "order")[0]
    for key in ("host_ip", "phase", "tool_name", "exit_code", "duration_ms",
                "status", "skip_reason"):
        assert key in geladen


def test_v2_kanal_bleibt_ohne_rohtext() -> None:
    """``scan_meta["toolRuns"]`` traegt weiter nur die sieben alten Felder.

    Der Rohtext waere dort pro Auftrag ein knappes Megabyte, das durch
    ``map_to_report_data`` liefe. Die Faktenschicht bekommt ihn direkt.
    """
    from reporter.worker import V2_TOOLRUN_KEYS, _ohne_rohtext

    rows = [{
        "hostIp": "192.0.2.1", "phase": 1, "toolName": "nmap", "exitCode": 0,
        "durationMs": 10, "status": "ok", "skipReason": None,
        "createdAt": "2026-09-21T10:00:00Z", "id": "a", "rawOutput": "x" * 5000,
    }]
    schlank = _ohne_rohtext(_load_tool_runs(_Conn(rows), "order"))
    assert set(schlank[0]) == set(V2_TOOLRUN_KEYS)
    assert "raw_output" not in schlank[0] and "created_at" not in schlank[0]
    assert schlank[0]["status"] == "ok" and schlank[0]["tool_name"] == "nmap"


def test_worker_reicht_dem_v2_kanal_die_schlanke_form() -> None:
    from pathlib import Path
    quelle = (Path(__file__).resolve().parents[1] / "reporter" / "worker.py").read_text(
        encoding="utf-8")
    assert '"toolRuns": _ohne_rohtext(tool_runs),' in quelle
    # und nur ein SELECT je Lauf
    assert quelle.count("_load_tool_runs(conn, order_id)") == 1
