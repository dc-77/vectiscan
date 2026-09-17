"""S0b: Active-Alerts duerfen nicht als passiv etikettiert werden.

Die Bereichsregel zaehlte 90000 bis 99999 pauschal zum passiven Scanner.
Dort liegen aber aktive Regeln, unter anderem Remote OS Command Injection
(90020) und XXE (90023). Genau diese Kategorien fordert KI #3 als "cmdi" und
"xxe" an. Ein Active-Scan-Treffer waere im Bericht als Beobachtung statt als
aktiver Nachweis erschienen.
"""

import pytest

from scanner.tools.zap_mapper import ZapAlertMapper, _is_passive


def _alert(plugin_id: int, name: str = "Befund") -> dict:
    return {
        "pluginId": str(plugin_id),
        "name": name,
        "risk": "High",
        "confidence": "Medium",
        "url": "https://example.com/echo?q=1",
        "description": "Beschreibung",
        "solution": "Loesung",
        "evidence": "<script>",
        "param": "q",
        "method": "GET",
        "cweid": "79",
    }


class TestPassivAktivTrennung:
    @pytest.mark.parametrize("plugin_id", [90019, 90020, 90021, 90023, 90024,
                                           90025, 90026, 90028, 90034])
    def test_aktive_9xxxx_regeln_sind_nicht_passiv(self, plugin_id):
        assert _is_passive(plugin_id) is False

    @pytest.mark.parametrize("plugin_id", [10010, 10054, 10038, 90001])
    def test_passive_regeln_bleiben_passiv(self, plugin_id):
        assert _is_passive(plugin_id) is True

    @pytest.mark.parametrize("plugin_id", [6, 40012, 40018, 40046])
    def test_klassische_aktive_regeln(self, plugin_id):
        assert _is_passive(plugin_id) is False


class TestMapping:
    def test_command_injection_wird_zap_active(self):
        findings = ZapAlertMapper().map_alerts(
            [_alert(90020, "Remote OS Command Injection")], "1.2.3.4", "example.com")
        assert findings
        assert findings[0]["tool"] == "zap_active"

    def test_reflektiertes_xss_wird_zap_active(self):
        findings = ZapAlertMapper().map_alerts(
            [_alert(40012, "Cross Site Scripting (Reflected)")], "1.2.3.4", "example.com")
        assert findings
        assert findings[0]["tool"] == "zap_active"

    def test_cookie_regel_bleibt_passiv(self):
        findings = ZapAlertMapper().map_alerts(
            [_alert(10054, "Cookie without SameSite Attribute")], "1.2.3.4", "example.com")
        assert findings
        assert findings[0]["tool"] == "zap_passive"
