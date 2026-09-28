"""S6c/Q1 (spec/09): Discovery-Parser, Wildcard-Skip und discovery_health-Luecke.

Fixtures aus der Scan-Runde vom 23.09.2026:
- lumbeck-wolter (c3d5724c) gobuster_dns Timeout-Teilausgabe: eset und ftp muessen
  ins Inventar, nicht als "name ip"-Zeile an dnsx.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

# Roh-Teilausgabe (gobuster -o-Datei) aus c3d5724c/results.json, gobuster_dns,
# status=timeout, skipReason=timeout_after_180s. Der Datei-Inhalt sind die
# Namen-mit-IP-Zeilen (ohne den TIMEOUT-Wrapper von run_tool).
LW_GOBUSTER_PARTIAL = (
    "autodiscover.lumbeck-wolter.de 52.98.241.168,52.97.135.104,52.98.171.232,"
    "52.98.179.72,2603:1026:c0d:c2f::8,2603:1026:c0d:1803::8\n"
    "eset.lumbeck-wolter.de 85.22.176.108\n"
    "ftp.lumbeck-wolter.de 217.160.231.158\n"
)


def _run_gobuster_with_file(tmp_path: Path, file_content: str) -> list[str]:
    from scanner import phase0

    scan_dir = str(tmp_path)
    (tmp_path / "phase0").mkdir(exist_ok=True)
    out = tmp_path / "phase0" / "gobuster_dns.txt"

    def fake_run_tool(**kwargs):
        out.write_text(file_content, encoding="utf-8")
        return (-1, 1000)  # Timeout-Sentinel

    with patch.object(phase0, "run_tool", side_effect=fake_run_tool), \
         patch.object(phase0, "publish_event"), \
         patch.object(phase0, "record_tool_run"):
        return phase0.run_gobuster_dns("lumbeck-wolter.de", scan_dir, "scan-1")


def test_parser_nimmt_nur_das_erste_feld(tmp_path: Path) -> None:
    """Der Name geht an dnsx, nicht "name ip" (Q1/R5, LW eset und ftp)."""
    names = _run_gobuster_with_file(tmp_path, LW_GOBUSTER_PARTIAL)
    assert "eset.lumbeck-wolter.de" in names
    assert "ftp.lumbeck-wolter.de" in names
    assert "autodiscover.lumbeck-wolter.de" in names
    # Keine IP im Namen, keine Leerzeichen-Zeile.
    assert all(" " not in n and "," not in n for n in names)
    assert all(not any(c.isdigit() for c in n.split(".")[-1]) for n in names)


def test_parser_ueberspringt_timeout_marker(tmp_path: Path) -> None:
    """Falls die Datei doch die run_tool-Wrappermarker traegt, werden sie ignoriert."""
    wrapped = ("TIMEOUT after 180s\n--- PARTIAL OUTPUT (246 chars) ---\n"
               + LW_GOBUSTER_PARTIAL)
    names = _run_gobuster_with_file(tmp_path, wrapped)
    assert "eset.lumbeck-wolter.de" in names
    assert not any(n.startswith("timeout") or n.startswith("---") for n in names)


def test_is_wildcard_dns_true_wenn_zufallslabel_aufloest() -> None:
    from scanner import phase0
    with patch.object(phase0, "_dns_label_resolves", return_value=True):
        assert phase0.is_wildcard_dns("dortmund-beach.com", probes=3) is True


def test_is_wildcard_dns_false_wenn_zufallslabel_nxdomain() -> None:
    from scanner import phase0
    with patch.object(phase0, "_dns_label_resolves", return_value=False):
        assert phase0.is_wildcard_dns("bergersysteme.com", probes=3) is False


def test_found_not_in_inventory_meldet_verlorene_namen() -> None:
    """Aufgeloeste Namen ohne Inventareintrag werden gemeldet (R5)."""
    from scanner.phase0 import _found_not_in_inventory

    dnsx = [
        {"host": "eset.lumbeck-wolter.de", "a": ["85.22.176.108"]},
        {"host": "ftp.lumbeck-wolter.de", "a": ["217.160.231.158"]},
        {"host": "www.lumbeck-wolter.de", "a": ["116.202.77.64"]},
    ]
    discovery_set = {"eset.lumbeck-wolter.de", "ftp.lumbeck-wolter.de", "www.lumbeck-wolter.de"}
    inventory = {"hosts": [{"ip": "116.202.77.64", "fqdns": ["www.lumbeck-wolter.de"]}],
                 "skipped_hosts": []}
    lost = _found_not_in_inventory(dnsx, discovery_set, inventory)
    assert lost == ["eset.lumbeck-wolter.de", "ftp.lumbeck-wolter.de"]


def test_found_not_in_inventory_ignoriert_unaufgeloeste() -> None:
    """Ein Name ohne A/AAAA (NXDOMAIN) ist kein Verlust, nur nicht existent."""
    from scanner.phase0 import _found_not_in_inventory

    dnsx = [{"host": "ghost.lumbeck-wolter.de", "a": []}]
    discovery_set = {"ghost.lumbeck-wolter.de"}
    inventory = {"hosts": [], "skipped_hosts": []}
    assert _found_not_in_inventory(dnsx, discovery_set, inventory) == []
