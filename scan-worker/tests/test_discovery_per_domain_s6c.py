"""S6c/7b, Q16 (spec/11): AXFR-Rohausgabe je Domain, Hostsuche je Zieldomain."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from scanner import phase0


def test_axfr_schreibt_rohdatei_ohne_nameserver(tmp_path: Path) -> None:
    """junkerwerk.hu ohne NS: trotzdem eine Rohdatei mit Grund (kein stiller Nichtlauf)."""
    (tmp_path / "phase0").mkdir()
    ns_empty = MagicMock()
    ns_empty.stdout = ""
    with patch("scanner.phase0.subprocess.run", return_value=ns_empty), \
         patch("scanner.phase0.publish_event"):
        phase0.run_zone_transfer("junkerwerk.hu", str(tmp_path), "o",
                                 filename="zone_transfer_junkerwerk.hu.txt")
    f = tmp_path / "phase0" / "zone_transfer_junkerwerk.hu.txt"
    assert f.exists()
    assert "keine Nameserver" in f.read_text()


def test_hostsuche_je_zieldomain_liefert_hosts(tmp_path: Path) -> None:
    """junkerwerk.hu bekommt eigene Hosts: die Enum-Namen der Zusatzdomain werden
    aufgeloest und ins Inventar aufgenommen (nicht nur DNS-/Mail-Eintraege)."""
    scan_dir = str(tmp_path / "scan")
    os.makedirs(scan_dir, exist_ok=True)
    dns_default = {"spf": None, "dmarc": None, "dkim": False, "mx": [], "ns": []}

    def fake_subfinder(domain, *a, **kw):
        if domain == "junkerwerk.hu":
            return ["archiv.junkerwerk.hu"]
        return []

    def fake_dnsx(subs, *a, **kw):
        return [{"host": s, "a": ["203.0.113.7"]} for s in subs if s == "archiv.junkerwerk.hu"]

    with patch("scanner.phase0.run_dnsx", side_effect=fake_dnsx), \
         patch("scanner.phase0.run_crtsh", return_value=[]), \
         patch("scanner.phase0.run_certspotter", return_value=[]), \
         patch("scanner.phase0.run_subfinder", side_effect=fake_subfinder), \
         patch("scanner.phase0.run_gobuster_dns", return_value=[]), \
         patch("scanner.phase0.is_wildcard_dns", return_value=False), \
         patch("scanner.phase0.collect_dns_records", return_value=dns_default), \
         patch("scanner.phase0.run_zone_transfer", return_value={"success": False, "data": {}}), \
         patch("scanner.phase0._probe_web_hosts", side_effect=lambda hosts, *a, **kw: hosts), \
         patch("scanner.phase0.socket.gethostbyaddr", side_effect=OSError), \
         patch("scanner.phase0.publish_event"):
        from scanner.packages import get_config
        inv = phase0.run_phase0("junkerwerk.de", scan_dir, "order-1",
                                get_config("perimeter"), extra_domains=["junkerwerk.hu"])

    all_fqdns = {f for h in inv.get("hosts", []) for f in h.get("fqdns", [])}
    assert "archiv.junkerwerk.hu" in all_fqdns
