"""S0b: pluginId muss den Parser ueberleben.

Der Pruefkatalog aus S2 ordnet ZAP-Alerts ueber ihre pluginId zu (spec/06
Abschnitt 4: rund 150 Alert-Typen mit festen IDs). parse_zap_alerts_json
hat das Feld bisher verworfen, dem Reporter blieb nur der Anzeigename.
"""

from __future__ import annotations

import json

from reporter.parser import parse_zap_alerts_json

RAW_ALERTS = [
    {
        "pluginId": "40012",
        "alertRef": "40012-1",
        "name": "Cross Site Scripting (Reflected)",
        "risk": "High",
        "riskcode": "3",
        "confidence": "Medium",
        "sourceid": "1",
        "url": "http://target:8080/echo?q=test",
        "description": "Beschreibung",
        "solution": "Loesung",
        "evidence": "<script>",
        "param": "q",
        "method": "GET",
        "cweid": "79",
    },
    {
        "pluginId": "10054",
        "name": "Cookie without SameSite Attribute",
        "risk": "Low",
        "url": "http://target:8080/",
    },
]


def _write(tmp_path, payload):
    path = tmp_path / "zap_alerts.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_plugin_id_bleibt_erhalten(tmp_path):
    alerts = parse_zap_alerts_json(_write(tmp_path, RAW_ALERTS))
    by_name = {a["name"]: a for a in alerts}
    xss = by_name["Cross Site Scripting (Reflected)"]
    assert xss["pluginId"] == "40012"
    assert xss["alertRef"] == "40012-1"
    assert xss["riskcode"] == "3"
    assert xss["sourceid"] == "1"


def test_alert_ref_faellt_auf_plugin_id_zurueck(tmp_path):
    alerts = parse_zap_alerts_json(_write(tmp_path, RAW_ALERTS))
    cookie = [a for a in alerts if a["pluginId"] == "10054"][0]
    assert cookie["alertRef"] == "10054"


def test_bestehende_felder_unveraendert(tmp_path):
    alerts = parse_zap_alerts_json(_write(tmp_path, RAW_ALERTS))
    xss = [a for a in alerts if a["pluginId"] == "40012"][0]
    assert xss["severity"] == "high"
    assert xss["param"] == "q"
    assert xss["cweid"] == "79"


def test_alert_ohne_plugin_id_bleibt_lesbar(tmp_path):
    alerts = parse_zap_alerts_json(_write(tmp_path, [{"name": "X", "risk": "Low"}]))
    assert alerts[0]["pluginId"] == ""
    assert alerts[0]["alertRef"] == ""


def test_fehlende_datei_ergibt_leere_liste(tmp_path):
    assert parse_zap_alerts_json(str(tmp_path / "gibtsnicht.json")) == []
