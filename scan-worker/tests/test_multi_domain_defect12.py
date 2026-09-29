"""Issue #12: Multi-Target ohne DNS- und Passivlaeufe fuer die zweite Domain.

Befund aus Session S1 (Golden-Tar 0bf16342: junkerwerk.de + junkerwerk.hu):
worker reduzierte die Zielliste ueber derive_primary_domain auf eine Domain.
phase0/dns_records.json, phase0a/dns_security.json und die domainweiten
scan_results-Zeilen trugen nur das Primaerziel, und die Zeilen hatten kein
Domainfeld. Fuer junkerwerk.hu gab es weder SPF noch DMARC noch DNSSEC.

Entscheidung DC (19.09.2026): je weiterer Domain laufen DNS, Zonentransfer,
dns_security und WHOIS erneut. Kontingentpflichtige Quellen (Shodan,
SecurityTrails, VirusTotal) bleiben beim Primaerziel.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scanner.phase0a import DOMAIN_INTEL_TOOLS, domain_slug, run_domain_intel
from scanner.scope import MAX_EXTRA_DOMAINS, ScanTarget, derive_domains
from scanner.tools import domain_labeled_json


def _target(canonical: str, ttype: str = "fqdn_root", policy: str = "enumerate"):
    return ScanTarget(id=canonical, raw_input=canonical, canonical=canonical,
                      target_type=ttype, discovery_policy=policy, exclusions=[])


# ------------------------------------------------------------- Domainliste

def test_derive_domains_liefert_beide_domains():
    targets = [_target("junkerwerk.de"), _target("junkerwerk.hu")]
    assert derive_domains(targets) == ["junkerwerk.de", "junkerwerk.hu"]


def test_derive_domains_primaerziel_zuerst():
    """derive_primary_domain bevorzugt enumerate; die Liste beginnt damit."""
    targets = [_target("scoped.example", policy="scoped"),
               _target("enum.example", policy="enumerate")]
    assert derive_domains(targets)[0] == "enum.example"
    assert set(derive_domains(targets)) == {"scoped.example", "enum.example"}


def test_derive_domains_ignoriert_ip_und_cidr():
    targets = [_target("example.de"), _target("1.2.3.4", "ipv4", "ip_only"),
               _target("10.0.0.0/24", "cidr", "ip_only")]
    assert derive_domains(targets) == ["example.de"]


def test_derive_domains_dedupliziert():
    targets = [_target("example.de"), _target("example.de", "fqdn_specific")]
    assert derive_domains(targets) == ["example.de"]


# --------------------------------------------------------- Domain-Etikett

def test_domain_etikett_steht_vorn():
    """Vorn, damit es die 50k-Kappung ueberlebt."""
    raw = domain_labeled_json({"spf": "v=spf1 -all"}, "junkerwerk.hu")
    assert raw.startswith('{"_domain": "junkerwerk.hu"')
    assert json.loads(raw)["spf"] == "v=spf1 -all"


def test_domain_etikett_kollidiert_nicht_mit_nutzdaten():
    """securitytrails, otx, urlhaus und shodan_domain fuehren `domain` selbst."""
    raw = json.loads(domain_labeled_json({"domain": "nutzdaten"}, "etikett.de"))
    assert raw["_domain"] == "etikett.de"
    assert raw["domain"] == "nutzdaten"


def test_ohne_domain_bleibt_die_zeile_wie_bisher():
    assert domain_labeled_json({"a": 1}, None) == '{"a": 1}'


def test_domain_etikett_wird_gekappt():
    raw = domain_labeled_json({"gross": "x" * 200}, "example.de", limit=50)
    assert len(raw) == 50
    assert raw.startswith('{"_domain": "example.de"')


# ------------------------------------------------------- DNS je Domain

def test_dns_records_schreibt_datei_je_domain(tmp_path):
    from scanner import phase0

    (tmp_path / "phase0").mkdir(parents=True)
    proc = MagicMock()
    proc.stdout = ""
    proc.returncode = 0

    with patch("scanner.phase0.subprocess.run", return_value=proc), \
            patch("scanner.phase0.record_tool_run") as rec:
        phase0.collect_dns_records("junkerwerk.hu", str(tmp_path), "order-1",
                                   filename="dns_records_junkerwerk.hu.json",
                                   label_domain="junkerwerk.hu")

    assert (tmp_path / "phase0" / "dns_records_junkerwerk.hu.json").is_file()
    assert not (tmp_path / "phase0" / "dns_records.json").exists()
    raw = rec.call_args.kwargs["raw_output"]
    assert json.loads(raw)["_domain"] == "junkerwerk.hu"


def test_dns_records_default_bleibt_unveraendert(tmp_path):
    """Ohne die neuen Argumente verhaelt sich die Funktion wie vorher."""
    from scanner import phase0

    (tmp_path / "phase0").mkdir(parents=True)
    proc = MagicMock()
    proc.stdout = ""
    proc.returncode = 0

    with patch("scanner.phase0.subprocess.run", return_value=proc), \
            patch("scanner.phase0.record_tool_run") as rec:
        phase0.collect_dns_records("example.de", str(tmp_path), "order-1")

    assert (tmp_path / "phase0" / "dns_records.json").is_file()
    assert "_domain" not in json.loads(rec.call_args.kwargs["raw_output"])


# --------------------------------------------------------- run_domain_intel

def test_domain_intel_laeuft_nur_kostenfreie_quellen(tmp_path):
    """Kein Shodan, kein VirusTotal je Zusatzdomain. S6d (Issue #22, DC 29.09.2026):
    OTX und SecurityTrails laufen je Domain, SecurityTrails aber nur, wenn es im
    Paket steht (hier nicht)."""
    assert set(DOMAIN_INTEL_TOOLS) == {"whois", "dns_security", "otx", "securitytrails"}

    with patch("scanner.phase0a.WhoisClient") as whois_cls, \
            patch("scanner.phase0a.run_all_dns_security",
                  return_value={"dnssec": {"enabled": True}}), \
            patch("scanner.phase0a.ShodanClient") as shodan_cls, \
            patch("scanner.phase0a.SecurityTrailsClient") as st_cls, \
            patch("scanner.phase0a.VirusTotalClient") as vt_cls, \
            patch("scanner.phase0a.publish_event"), \
            patch("scanner.phase0a.record_tool_run"):
        whois_cls.return_value.lookup.return_value = {"registrar": "X"}
        run_domain_intel("junkerwerk.hu", str(tmp_path), "order-1",
                         {"package": "perimeter", "phase0a_tools": ["whois", "shodan"]})

    shodan_cls.assert_not_called()
    st_cls.assert_not_called()
    vt_cls.assert_not_called()


def test_domain_intel_schreibt_dateien_mit_suffix(tmp_path):
    with patch("scanner.phase0a.WhoisClient") as whois_cls, \
            patch("scanner.phase0a.run_all_dns_security",
                  return_value={"dnssec": {"enabled": True}}), \
            patch("scanner.phase0a.publish_event"), \
            patch("scanner.phase0a.record_tool_run"):
        whois_cls.return_value.lookup.return_value = {"registrar": "X"}
        out = run_domain_intel("junkerwerk.hu", str(tmp_path), "order-1",
                               {"package": "perimeter", "phase0a_tools": ["whois"]})

    p0a = tmp_path / "phase0a"
    assert (p0a / "whois_junkerwerk.hu.json").is_file()
    assert (p0a / "dns_security_junkerwerk.hu.json").is_file()
    # Die Dateien ohne Suffix gehoeren weiter dem Primaerziel.
    assert not (p0a / "whois.json").exists()
    assert not (p0a / "dns_security.json").exists()
    assert set(out) == {"whois", "dns_security"}


def test_domain_intel_zeilen_tragen_das_etikett(tmp_path):
    with patch("scanner.phase0a.WhoisClient") as whois_cls, \
            patch("scanner.phase0a.run_all_dns_security",
                  return_value={"dnssec": {"enabled": True}}), \
            patch("scanner.phase0a.publish_event"), \
            patch("scanner.phase0a.record_tool_run") as rec:
        whois_cls.return_value.lookup.return_value = {"registrar": "X"}
        run_domain_intel("junkerwerk.hu", str(tmp_path), "order-1",
                         {"package": "perimeter", "phase0a_tools": ["whois"]})

    tools = {c.args[3] for c in rec.call_args_list}
    assert tools == {"whois", "dns_security"}
    for call in rec.call_args_list:
        assert json.loads(call.kwargs["raw_output"])["_domain"] == "junkerwerk.hu"


def test_domain_intel_ueberlebt_einen_fehler(tmp_path):
    """Ein kaputter WHOIS-Server darf den Scan nicht kippen."""
    with patch("scanner.phase0a.WhoisClient") as whois_cls, \
            patch("scanner.phase0a.run_all_dns_security",
                  return_value={"dnssec": {"enabled": False}}), \
            patch("scanner.phase0a.publish_event"), \
            patch("scanner.phase0a.record_tool_run") as rec:
        whois_cls.return_value.lookup.side_effect = RuntimeError("timeout")
        out = run_domain_intel("junkerwerk.hu", str(tmp_path), "order-1",
                               {"package": "perimeter", "phase0a_tools": ["whois"]})

    assert "dns_security" in out
    stati = {(c.args[3], c.args[4]) for c in rec.call_args_list}
    assert ("whois", "failed") in stati
    assert ("dns_security", "ok") in stati


def test_domain_slug_ist_dateinamensicher():
    assert domain_slug("junkerwerk.hu") == "junkerwerk.hu"
    assert "/" not in domain_slug("a/b.example")
    assert domain_slug("") == "domain"


# --------------------------------------------------- run_phase0-Verdrahtung

def _run_phase0_with_extras(tmp_path, extras):
    """run_phase0 mit gemockten Discovery-Tools; liefert die beiden Mocks."""
    import os
    from scanner.packages import get_config
    from scanner.phase0 import run_phase0

    scan_dir = str(tmp_path / "scan")
    os.makedirs(scan_dir, exist_ok=True)
    dns_default = {"spf": None, "dmarc": None, "dkim": False, "mx": [], "ns": []}

    with patch("scanner.phase0.run_dnsx", return_value=[]), \
            patch("scanner.phase0.run_crtsh", return_value=[]), \
            patch("scanner.phase0.run_certspotter", return_value=[]), \
            patch("scanner.phase0.run_subfinder", return_value=[]), \
            patch("scanner.phase0.run_gobuster_dns", return_value=[]), \
            patch("scanner.phase0.is_wildcard_dns", return_value=False), \
            patch("scanner.phase0.collect_dns_records",
                  return_value=dns_default) as mock_dns, \
            patch("scanner.phase0.run_zone_transfer",
                  return_value={"success": False, "data": {}}) as mock_axfr:
        run_phase0("junkerwerk.de", scan_dir, "order-1", get_config("perimeter"),
                   extra_domains=extras)
    return mock_dns, mock_axfr


def test_phase0_sammelt_dns_fuer_jede_domain(tmp_path):
    """Der Defekt: nur die erste Domain bekam DNS-Fakten."""
    mock_dns, mock_axfr = _run_phase0_with_extras(tmp_path, ["junkerwerk.hu"])

    domains = [c.args[0] for c in mock_dns.call_args_list]
    assert domains == ["junkerwerk.de", "junkerwerk.hu"]

    zusatz = [c for c in mock_dns.call_args_list if c.args[0] == "junkerwerk.hu"][0]
    assert zusatz.kwargs["filename"] == "dns_records_junkerwerk.hu.json"
    assert zusatz.kwargs["label_domain"] == "junkerwerk.hu"

    # Das Primaerziel behaelt den alten Dateinamen und bekommt das Etikett.
    primaer = [c for c in mock_dns.call_args_list if c.args[0] == "junkerwerk.de"][0]
    assert primaer.kwargs.get("filename") is None
    assert primaer.kwargs["label_domain"] == "junkerwerk.de"

    axfr_domains = [c.args[0] for c in mock_axfr.call_args_list]
    assert axfr_domains == ["junkerwerk.de", "junkerwerk.hu"]


def test_phase0_ohne_zusatzdomains_unveraendert(tmp_path):
    mock_dns, mock_axfr = _run_phase0_with_extras(tmp_path, None)
    assert [c.args[0] for c in mock_dns.call_args_list] == ["junkerwerk.de"]
    assert [c.args[0] for c in mock_axfr.call_args_list] == ["junkerwerk.de"]


# ------------------------------------------------------------- Deckel

def test_deckel_ist_gesetzt():
    """Registries drosseln WHOIS; jede Order darf bis zu 10 Zeilen tragen."""
    assert MAX_EXTRA_DOMAINS == 5


# ----------------------------------- Nachweis-Scan 20.09.2026, zwei Befunde

def test_domain_intel_whois_ohne_daten_ist_failed(tmp_path):
    """S6c/#35 (spec/09 Teil 2 Punkt 21): ein whois-Abruf ohne Daten ist failed,
    nicht ok mit no_data. Frueher (S2b) stand er auf ok, weil "empty" still zu
    "failed" verbogen wurde; jetzt ist "failed" mit Grund whois_no_data explizit.
    dns_security ohne Treffer bleibt ok.
    """
    with patch("scanner.phase0a.WhoisClient") as whois_cls, \
            patch("scanner.phase0a.run_all_dns_security",
                  return_value={"dnssec": {"enabled": False}}), \
            patch("scanner.phase0a.publish_event"), \
            patch("scanner.phase0a.record_tool_run") as rec:
        whois_cls.return_value.lookup.return_value = None
        run_domain_intel("zweite.example", str(tmp_path), "order-1",
                         {"package": "perimeter", "phase0a_tools": ["whois"]})

    stati = {(c.args[3], c.args[4]) for c in rec.call_args_list}
    assert ("whois", "failed") in stati, stati
    assert ("whois", "ok") not in stati
    grund = [c.kwargs.get("reason") for c in rec.call_args_list
             if c.args[3] == "whois"][0]
    assert grund == "whois_no_data"


def test_status_wird_nicht_still_verbogen():
    """Sicherheitsnetz: nur Werte aus TOOL_RUN_STATUSES verwenden."""
    from scanner.phase0a import DOMAIN_INTEL_TOOLS  # noqa: F401
    from scanner.tools import TOOL_RUN_STATUSES
    assert "empty" not in TOOL_RUN_STATUSES


def test_domain_dateien_tragen_das_etikett(tmp_path):
    """Befund aus dem Nachweis-Scan: die Dateien mit Domain-Suffix trugen die
    Domain nur im Dateinamen. Die Zuordnung gehoert in den Inhalt, sonst ist
    die Datei nach einem Umbenennen nicht mehr zuzuordnen (gleiche Regel wie
    bei den VHost-Dateien, die ihren FQDN in url bzw. input tragen)."""
    with patch("scanner.phase0a.WhoisClient") as whois_cls, \
            patch("scanner.phase0a.run_all_dns_security",
                  return_value={"dnssec": {"dnssec_signed": False}}), \
            patch("scanner.phase0a.publish_event"), \
            patch("scanner.phase0a.record_tool_run"):
        whois_cls.return_value.lookup.return_value = {"registrar": "X"}
        run_domain_intel("zweite.example", str(tmp_path), "order-1",
                         {"package": "perimeter", "phase0a_tools": ["whois"]})

    p0a = tmp_path / "phase0a"
    for name in ("whois_zweite.example.json", "dns_security_zweite.example.json"):
        data = json.loads((p0a / name).read_text(encoding="utf-8"))
        assert data["_domain"] == "zweite.example", name
        # Das Etikett steht vorn, damit es eine Laengenkappung ueberlebt.
        assert next(iter(data)) == "_domain"


def test_dns_records_datei_traegt_das_etikett(tmp_path):
    from scanner import phase0

    (tmp_path / "phase0").mkdir(parents=True)
    proc = MagicMock()
    proc.stdout = ""
    proc.returncode = 0
    with patch("scanner.phase0.subprocess.run", return_value=proc), \
            patch("scanner.phase0.record_tool_run"):
        phase0.collect_dns_records("zweite.example", str(tmp_path), "order-1",
                                   filename="dns_records_zweite.example.json",
                                   label_domain="zweite.example")
    data = json.loads(
        (tmp_path / "phase0" / "dns_records_zweite.example.json").read_text(encoding="utf-8"))
    assert data["_domain"] == "zweite.example"
    assert "spf" in data


def test_dns_records_ohne_label_bleibt_ohne_etikett(tmp_path):
    from scanner import phase0

    (tmp_path / "phase0").mkdir(parents=True)
    proc = MagicMock()
    proc.stdout = ""
    proc.returncode = 0
    with patch("scanner.phase0.subprocess.run", return_value=proc), \
            patch("scanner.phase0.record_tool_run"):
        phase0.collect_dns_records("erste.example", str(tmp_path), "order-1")
    data = json.loads(
        (tmp_path / "phase0" / "dns_records.json").read_text(encoding="utf-8"))
    assert "_domain" not in data
