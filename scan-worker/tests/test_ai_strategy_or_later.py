"""S6a2 (spec/09 Q11): KI #1 liest "or later" als Untergrenze.

Shodan meldet fuer PostgreSQL oft "9.6.0 or later". phase0a.build_passive_intel_for_ai
reicht das unveraendert als shodan_services weiter, und der Prompt stuft veraltete
Shodan-Versionen hoch. Ergebnis im Kasten Host-Strategie: "veraltete PostgreSQL 9.6".
Der Prompt haelt jetzt fest, dass eine Untergrenze keine Aussage ueber Aktualitaet
traegt. Der Rohwert bleibt im Prompt stehen; die KI sieht ihn und die Regel.
"""

from __future__ import annotations

from unittest.mock import patch

import scanner.ai_strategy as ai_s
from scanner.phase0a import build_passive_intel_for_ai

_KI1_RETURN = {
    "hosts": [{"ip": "116.202.77.64", "action": "scan", "priority": 1, "reasoning": "mock"}],
    "strategy_notes": "mock",
    "passive_intel_summary": "mock",
    "_raw": "{}",
    "_cost": {"total_cost_usd": 0.0},
}


def _inventory() -> dict:
    phase0a = {"shodan_hosts": {"116.202.77.64": {
        "ports": [3306, 5432],
        "services": [
            {"port": 5432, "product": "PostgreSQL", "version": "9.6.0 or later"},
            {"port": 3306, "product": "MariaDB", "version": "10.11.18-MariaDB-0+deb12u1"},
        ],
    }}}
    host = {"ip": "116.202.77.64", "fqdns": ["lumbeck-wolter.de", "www.lumbeck-wolter.de"],
            "web_probe": {"has_web": True, "status": 200},
            "passive_intel": build_passive_intel_for_ai(phase0a, "116.202.77.64")}
    return {"hosts": [host], "dns_findings": {}}


def test_system_prompt_nennt_or_later_als_untergrenze():
    prompt = ai_s.HOST_STRATEGY_SYSTEM
    assert '"or later"' in prompt and "Untergrenzen" in prompt
    assert "keine Aussage über Aktualität" in prompt
    assert "nicht als veraltet bezeichnen" in prompt
    # Die Regel steht bei der Hochstufung veralteter Shodan-Versionen, die sie begrenzt.
    regel = prompt.index("veralteten Service-Versionen aus Shodan")
    assert regel < prompt.index("Untergrenzen") < prompt.index("STANDARD-REGELN")


@patch("scanner.ai_strategy._call_haiku")
def test_erzeugter_prompt_traegt_regel_und_rohwert(mock_haiku):
    mock_haiku.return_value = dict(_KI1_RETURN)
    ai_s.plan_host_strategy(_inventory(), "lumbeck-wolter.de", "perimeter", order_id="")

    system, user = mock_haiku.call_args.args[:2]
    assert "Untergrenzen" in system
    assert "PostgreSQL 9.6.0 or later" in user


@patch("scanner.ai_strategy._call_haiku")
def test_prompt_aenderung_aendert_den_cache_schluessel(mock_haiku):
    """Der System-Prompt steckt im content_hash von KI #1; sonst liefert der Cache
    nach einer Prompt-Aenderung bis zu sieben Tage die alte Antwort."""
    mock_haiku.return_value = dict(_KI1_RETURN)
    ai_s.plan_host_strategy(_inventory(), "lumbeck-wolter.de", "perimeter", order_id="a")
    ai_s.plan_host_strategy(_inventory(), "lumbeck-wolter.de", "perimeter", order_id="b")
    with patch.object(ai_s, "HOST_STRATEGY_SYSTEM", ai_s.HOST_STRATEGY_SYSTEM + "\n- neue Regel"):
        ai_s.plan_host_strategy(_inventory(), "lumbeck-wolter.de", "perimeter", order_id="c")

    ch_a, ch_b, ch_c = (c.kwargs["content_hash"] for c in mock_haiku.call_args_list)
    assert ch_a == ch_b, "gleicher Prompt, gleiche Eingabe: gleicher Schluessel"
    assert ch_a != ch_c, "anderer System-Prompt: anderer Schluessel"
