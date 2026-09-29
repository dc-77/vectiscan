"""S6d (C4): testssl-Zeilen bekommen ihren Status aus der Ausgabe und einen Grund.

Datenbefund an den S6c-Probeauftraegen (DB 4394b0b7): testssl_21, _143, _465, _587,
_993 und _995 standen mit Exit 7 oder 8 auf ``failed``, obwohl der Lauf vollstaendig
war (testssl_587.json mit 235 Eintraegen, Protokollzeilen, Zertifikat, scanTime).
testssl meldet als Exit-Code die Zahl der Befunde. Umgekehrt trug ein wirklich
abgebrochener Lauf keinen Grund, und kaputte Ausgaben standen auf ``ok``.
"""

import json
from unittest.mock import patch

from scanner import phase2
from scanner.phase2 import evaluate_testssl_output


def _write(tmp_path, entries, name="testssl_587.json"):
    p = tmp_path / name
    p.write_text(json.dumps(entries), encoding="utf-8")
    return str(p)


_VOLLSTAENDIG = [
    {"id": "engine_problem", "severity": "WARN", "finding": "No engine or GOST support"},
    {"id": "service", "severity": "INFO", "finding": "SMTP"},
    {"id": "SSLv2", "severity": "OK", "finding": "not offered"},
    {"id": "TLS1", "severity": "LOW", "finding": "offered (deprecated)"},
    {"id": "TLS1_2", "severity": "OK", "finding": "offered"},
    {"id": "TLS1_3", "severity": "OK", "finding": "offered with final"},
    {"id": "cert_notAfter", "severity": "OK", "finding": "2026-12-01 10:00"},
    {"id": "scanTime", "severity": "INFO", "finding": "123"},
]


def test_exit_8_mit_vollstaendigem_json_ist_ok(tmp_path):
    path = _write(tmp_path, _VOLLSTAENDIG)
    status, reason, data = evaluate_testssl_output(path, 8)
    assert (status, reason) == ("ok", None)
    assert len(data) == len(_VOLLSTAENDIG)


def test_connection_refused_im_stderr_allein_entscheidet_nicht(tmp_path):
    """DB testssl_110: STDERR "Connection refused", Datei trotzdem vollstaendig."""
    path = _write(tmp_path, _VOLLSTAENDIG, "testssl_110.json")
    status, reason, _ = evaluate_testssl_output(
        path, 7, "--- STDERR ---\nConnection refused")
    assert (status, reason) == ("ok", None)


def test_scanproblem_connect_ist_tls_connect_refused(tmp_path):
    path = _write(tmp_path, [
        {"id": "scanProblem", "severity": "FATAL",
         "finding": "Can't connect to '88.99.35.112:110' Make sure a firewall is not between you"},
        {"id": "scanTime", "severity": "INFO", "finding": "3"},
    ], "testssl_110.json")
    assert evaluate_testssl_output(path, 246)[:2] == ("failed", "tls_connect_refused")


def test_kein_tls_auf_dem_port(tmp_path):
    path = _write(tmp_path, [
        {"id": "scanProblem", "severity": "FATAL",
         "finding": "188.40.3.130:21 doesn't seem to be a TLS/SSL enabled server"},
    ], "testssl_21.json")
    assert evaluate_testssl_output(path, 246)[:2] == ("failed", "no_tls_on_port")


def test_starttls_scheitert(tmp_path):
    path = _write(tmp_path, [
        {"id": "scanProblem", "severity": "FATAL",
         "finding": "STARTTLS handshake failed (code: 1)"},
    ], "testssl_587.json")
    assert evaluate_testssl_output(path, 250)[:2] == ("failed", "starttls_failed")


def test_unbekanntes_problem_behaelt_einen_grund(tmp_path):
    path = _write(tmp_path, [{"id": "scanProblem", "severity": "FATAL", "finding": "odd"}])
    assert evaluate_testssl_output(path, 245)[:2] == ("failed", "testssl_scan_problem")


def test_kaputte_ausgaben_sind_failed_mit_grund(tmp_path):
    assert evaluate_testssl_output(str(tmp_path / "fehlt.json"), 0)[:2] == (
        "failed", "no_output_file")
    leer = tmp_path / "leer.json"
    leer.write_text("", encoding="utf-8")
    assert evaluate_testssl_output(str(leer), 0)[:2] == ("failed", "no_output_file")
    kaputt = tmp_path / "kaputt.json"
    kaputt.write_text("[{", encoding="utf-8")
    assert evaluate_testssl_output(str(kaputt), 0)[:2] == ("failed", "invalid_json")
    banner = tmp_path / "banner.json"
    banner.write_text("Usage: testssl.sh [options] <URI>", encoding="utf-8")
    assert evaluate_testssl_output(str(banner), 0)[:2] == ("failed", "usage_banner")


def test_ohne_protokollzeilen_und_ohne_problem_entscheidet_der_exit_code(tmp_path):
    path = _write(tmp_path, [{"id": "scanTime", "severity": "INFO", "finding": "1"}])
    assert evaluate_testssl_output(path, 0)[:2] == ("ok", None)
    assert evaluate_testssl_output(path, 9)[:2] == ("failed", "incomplete_output")


def _run_once(tmp_path, entries, exit_code, tool_name="testssl_587"):
    """_run_testssl_once mit gestubtem run_tool: die Zeile entsteht ueber status_check."""
    out = tmp_path / f"{tool_name}.json"
    rows: list[tuple[str, str | None]] = []

    def fake_run_tool(**kwargs):
        out.write_text(json.dumps(entries), encoding="utf-8")
        verdict = kwargs["status_check"](exit_code, "")
        rows.append(verdict)
        return exit_code, 1000

    with patch.object(phase2, "run_tool", side_effect=fake_run_tool):
        data = phase2._run_testssl_once("mail.dortmund-beach.com", "88.99.35.112",
                                        str(out), "4394b0b7", tool_name=tool_name,
                                        port=587, starttls="smtp")
    return data, rows


def test_lauf_je_port_liefert_daten_trotz_befundzahl_im_exit_code(tmp_path):
    data, rows = _run_once(tmp_path, _VOLLSTAENDIG, 8)
    assert rows == [("ok", None)]
    assert data is not None and len(data) == len(_VOLLSTAENDIG)


def test_abgebrochener_lauf_je_port_ist_failed_mit_grund(tmp_path):
    data, rows = _run_once(tmp_path, [
        {"id": "scanProblem", "severity": "FATAL", "finding": "Can't connect to '88.99.35.112:587'"},
    ], 246)
    assert rows == [("failed", "tls_connect_refused")]
    assert data is None


def test_timeout_bleibt_failed_ohne_status_check(tmp_path):
    """Exit < 0 (Timeout, Ausnahme): run_tool schreibt die Zeile selbst."""
    out = tmp_path / "testssl_993.json"
    out.write_text(json.dumps(_VOLLSTAENDIG), encoding="utf-8")
    with patch.object(phase2, "run_tool", return_value=(-1, 300000)):
        assert phase2._run_testssl_once("x", "1.2.3.4", str(out), "o",
                                        tool_name="testssl_993", port=993) is None
