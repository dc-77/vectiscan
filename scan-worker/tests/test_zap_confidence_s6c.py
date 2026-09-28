"""S6c/Q14, N2 (spec/09 Q14, spec/11 Teil 6): ZAP-Konfidenz, volle Alert-Liste,
Statuscode je Meldung.
"""

from unittest.mock import MagicMock, patch

from scanner import phase2
from scanner.tools.zap_client import ZapClient


def _alert(name, risk="Low", conf="Medium", url="https://x/", cwe="16", status=None):
    a = {"name": name, "risk": risk, "confidence": conf, "url": url, "cweid": cwe,
         "param": "", "sourceid": "3", "messageId": "1"}
    if status is not None:
        a["status"] = status
    return a


def test_alert_summary_nicht_auf_20_gekuerzt() -> None:
    """Mehr als 20 Meldungen bleiben vollstaendig mit Konfidenz (Q14)."""
    alerts = [_alert(f"Alert {i}", conf="Low" if i % 2 else "High") for i in range(35)]
    summary = phase2._build_zap_alert_summary(alerts, passive_count=35, active_count=0)
    assert summary["total_alerts"] == 35
    assert len(summary["top_alerts"]) == 35
    assert summary["truncated"] is False
    # Konfidenz je Meldung und Verteilung vorhanden.
    assert all("confidence" in a for a in summary["top_alerts"])
    assert summary["confidence_distribution"].get("Low", 0) > 0
    assert summary["confidence_distribution"].get("High", 0) > 0


def test_alert_summary_kuerzt_nur_bei_ueberlaenge() -> None:
    """Sehr viele Meldungen: Zeile wird gekuerzt und markiert, Vollsatz im Tar."""
    alerts = [_alert(f"Ein langer Meldungsname Nummer {i} mit Text",
                     url=f"https://host.example.com/pfad/{i}/lange/url/hier") for i in range(4000)]
    summary = phase2._build_zap_alert_summary(alerts, passive_count=4000, active_count=0)
    assert summary["total_alerts"] == 4000
    assert summary["truncated"] is True
    assert len(summary["top_alerts"]) < 4000


def test_alert_summary_traegt_statuscode() -> None:
    """N2: der Statuscode der Antwort steht je Meldung."""
    alerts = [_alert("HSTS nicht gesetzt", url="https://online.heuel.com/", status=429)]
    summary = phase2._build_zap_alert_summary(alerts, passive_count=1, active_count=0)
    assert summary["top_alerts"][0]["status"] == 429


def test_message_status_parst_antwortkopf() -> None:
    """zap_client.message_status liest den Statuscode aus dem responseHeader."""
    zc = ZapClient.__new__(ZapClient)
    with patch.object(ZapClient, "_get",
                      return_value={"message": {"responseHeader": "HTTP/1.1 429 Too Many Requests\r\nServer: Vercel"}}):
        assert zc.message_status("1") == 429
    with patch.object(ZapClient, "_get", return_value={"message": {"responseHeader": ""}}):
        assert zc.message_status("2") is None
