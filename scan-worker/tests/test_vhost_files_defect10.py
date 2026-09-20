"""Issue #10: headers.json und httpx.json wurden je VHost ueberschrieben.

Befund aus Session S1 (Golden-Tar 0bf16342, Host 217.243.248.28 mit mail.,
outlook., autodiscover.): run_header_check und run_httpx liefen je VHost,
schrieben aber immer denselben Dateinamen. Im Tar blieb nur der zuletzt
gepruefte VHost; die anderen existierten nur als scan_results-Zeile, httpx
nicht einmal das.

Seit S2b schreibt jeder VHost eine eigene Datei (headers_<slug>.json,
httpx_<slug>.json). Die alten Namen bleiben fuer den v2-Reporter und
tech_enricher erhalten und tragen ab jetzt deterministisch den primaeren
VHost statt des zuletzt geprueften.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from scanner.phase2 import vhost_slug


VHOSTS = ["mail.example.com", "outlook.example.com", "autodiscover.example.com"]


# ------------------------------------------------------------------- Slug

def test_slug_laesst_normalen_fqdn_unveraendert():
    assert vhost_slug("mail.junkerwerk.de") == "mail.junkerwerk.de"


def test_slug_entfernt_wildcard():
    """Zertifikatsnamen wie *.example.com sind keine zulaessigen Dateinamen."""
    slug = vhost_slug("*.example.com")
    assert "*" not in slug


def test_slug_kollidiert_nicht_bei_langen_namen():
    """Zwei FQDNs mit gleichem 80-Zeichen-Praefix muessen zwei Namen ergeben."""
    prefix = "a" * 80
    one = vhost_slug(prefix + "1.example.com")
    two = vhost_slug(prefix + "2.example.com")
    assert one != two
    assert len(one) <= 80 and len(two) <= 80


def test_slug_ist_ascii_und_dateinamensicher():
    for fqdn in ("*.example.com", "xn--bcher-kva.example.com", "a" * 120):
        slug = vhost_slug(fqdn)
        assert slug.isascii()
        assert not set(slug) & set('/\\:*?"<>| ')


# ------------------------------------------------- Dateiname je Werkzeug

def test_header_check_schreibt_benannte_datei(tmp_path):
    from scanner import phase2

    proc = MagicMock()
    proc.communicate.return_value = ("HTTP/2 200\r\nstrict-transport-security: max-age=63072000\r\n", "")
    proc.returncode = 0

    with patch("scanner.phase2.subprocess.Popen", return_value=proc):
        phase2.run_header_check("a.example.com", "1.2.3.4", str(tmp_path),
                                "order-1", filename="headers_a.example.com.json")

    target = tmp_path / "phase2" / "headers_a.example.com.json"
    assert target.is_file()
    assert json.loads(target.read_text())["url"] == "https://a.example.com"
    assert not (tmp_path / "phase2" / "headers.json").exists()


def test_header_check_default_bleibt_headers_json(tmp_path):
    """Ohne filename verhaelt sich die Funktion wie vorher."""
    from scanner import phase2

    proc = MagicMock()
    proc.communicate.return_value = ("HTTP/2 200\r\n", "")
    proc.returncode = 0

    with patch("scanner.phase2.subprocess.Popen", return_value=proc):
        phase2.run_header_check("a.example.com", "1.2.3.4", str(tmp_path), "order-1")

    assert (tmp_path / "phase2" / "headers.json").is_file()


def test_unerreichbarer_vhost_landet_in_der_vhost_datei(tmp_path):
    """A5-Regressionsschutz auf dem neuen Pfad: reachable:false statt 0/7."""
    from scanner import phase2

    proc = MagicMock()
    proc.communicate.return_value = ("", "")
    proc.returncode = 7

    with patch("scanner.phase2.subprocess.Popen", return_value=proc):
        result = phase2.run_header_check("b.example.com", "1.2.3.4", str(tmp_path),
                                         "order-1", filename="headers_b.example.com.json")

    data = json.loads((tmp_path / "phase2" / "headers_b.example.com.json").read_text())
    assert data["reachable"] is False
    assert result["reachable"] is False


def test_httpx_schreibt_benannte_datei(tmp_path):
    from scanner import phase2

    captured: dict = {}

    def fake_run_tool(**kwargs):
        captured["cmd"] = list(kwargs["cmd"])
        Path(kwargs["output_path"]).write_text(
            json.dumps({"input": "a.example.com", "status_code": 200}) + "\n",
            encoding="utf-8")
        return 0, 5

    with patch("scanner.phase2.run_tool", side_effect=fake_run_tool):
        out = phase2.run_httpx("a.example.com", "1.2.3.4", str(tmp_path), "order-1",
                               filename="httpx_a.example.com.json")

    assert (tmp_path / "phase2" / "httpx_a.example.com.json").is_file()
    assert out["status_code"] == 200
    # httpx schreibt selbst ueber -o; der Name muss dort ankommen.
    cmd = captured["cmd"]
    assert cmd[cmd.index("-o") + 1].endswith("/phase2/httpx_a.example.com.json")
    assert not (tmp_path / "phase2" / "httpx.json").exists()


# ------------------------------------------------- Zusammenspiel in phase2

def _mock_zap():
    zap = MagicMock()
    zap.health_check.return_value = True
    zap.get_version.return_value = "2.17.0"
    zap.create_context.return_value = 1
    zap.start_spider.return_value = 1
    zap.spider_status.return_value = 100
    zap.spider_results.return_value = ["https://mail.example.com/"]
    zap.ajax_spider_status.return_value = "stopped"
    zap.start_active_scan.return_value = 1
    zap.active_scan_status.return_value = 100
    zap.wait_for_passive_scan.return_value = True
    zap.get_alerts.return_value = []
    return zap


def _run_phase2(tmp_path, vhost_fqdns, fqdns=None):
    """run_phase2 mit echten Dateischreibern fuer headers/httpx."""
    from scanner.phase2 import run_phase2

    scan_dir = tmp_path / "scan"
    host_dir = scan_dir / "hosts" / "1.2.3.4"

    def fake_header_check(fqdn, ip, hdir, oid, filename=None):
        payload = {"url": f"https://{fqdn}", "reachable": True, "score": "3/7"}
        p = Path(hdir) / "phase2"
        p.mkdir(parents=True, exist_ok=True)
        (p / (filename or "headers.json")).write_text(json.dumps(payload))
        return payload

    def fake_httpx(fqdn, ip, hdir, oid, filename=None):
        line = {"input": fqdn, "status_code": 200}
        p = Path(hdir) / "phase2"
        p.mkdir(parents=True, exist_ok=True)
        (p / (filename or "httpx.json")).write_text(json.dumps(line) + "\n")
        return line

    tech_profile = {
        "fqdn": vhost_fqdns[0], "cms": None, "technologies": [],
        "has_web": True, "has_ssl": True, "open_ports": [80, 443],
    }
    config = {"package": "perimeter", "phase2_tools": ["headers", "httpx"]}

    with patch("scanner.tools.zap_client.ZapClient", return_value=_mock_zap()), \
            patch("scanner.phase2.publish_tool_output"), \
            patch("scanner.phase2.publish_event"), \
            patch("scanner.phase2._save_result"), \
            patch("scanner.phase2.record_tool_run"), \
            patch("scanner.phase2.run_header_check", side_effect=fake_header_check), \
            patch("scanner.phase2.run_httpx", side_effect=fake_httpx):
        result = run_phase2(
            "1.2.3.4", fqdns or vhost_fqdns, tech_profile,
            str(scan_dir), "order-1", MagicMock(), config,
            vhost_fqdns=vhost_fqdns,
        )
    return result, host_dir / "phase2"


def test_alle_vhosts_ueberleben_im_verzeichnis(tmp_path):
    """Der Defekt: vorher blieb nur der zuletzt gepruefte VHost uebrig."""
    _, phase2_dir = _run_phase2(tmp_path, VHOSTS)

    for vh in VHOSTS:
        assert (phase2_dir / f"headers_{vhost_slug(vh)}.json").is_file(), vh
        assert (phase2_dir / f"httpx_{vhost_slug(vh)}.json").is_file(), vh

    written = sorted(p.name for p in phase2_dir.glob("headers_*.json"))
    assert len(written) == len(VHOSTS)


def test_legacy_datei_traegt_den_primaeren_vhost(tmp_path):
    """headers.json ist nicht mehr "der letzte", sondern der primaere VHost."""
    # Reihenfolge so, dass der primaere VHost NICHT der letzte ist.
    reihenfolge = [VHOSTS[1], VHOSTS[2], VHOSTS[0]]
    _, phase2_dir = _run_phase2(tmp_path, reihenfolge, fqdns=[VHOSTS[0]])

    legacy = json.loads((phase2_dir / "headers.json").read_text())
    assert legacy["url"] == f"https://{VHOSTS[0]}"

    legacy_httpx = json.loads((phase2_dir / "httpx.json").read_text().strip())
    assert legacy_httpx["input"] == VHOSTS[0]


def test_legacy_datei_faellt_auf_ersten_vhost_zurueck(tmp_path):
    """Faellt der primaere FQDN aus der VHost-Liste, gilt der erste Eintrag."""
    _, phase2_dir = _run_phase2(tmp_path, [VHOSTS[1], VHOSTS[2]],
                                fqdns=["nicht-gespidert.example.com"])
    legacy = json.loads((phase2_dir / "headers.json").read_text())
    assert legacy["url"] == f"https://{VHOSTS[1]}"


def test_vhost_ergebnisse_bleiben_im_rueckgabewert(tmp_path):
    result, _ = _run_phase2(tmp_path, VHOSTS)
    vhost_results = result.get("vhost_results") or {}
    assert set(vhost_results) == set(VHOSTS)
    for vh in VHOSTS:
        assert vhost_results[vh]["headers"]["url"] == f"https://{vh}"
        assert vhost_results[vh]["httpx"]["input"] == vh
