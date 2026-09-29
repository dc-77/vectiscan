"""S6d: Passivquellen je Domain (C1, Issue #22) und RDAP mit den Inventar-IPs (C6).

C1: Bei einem Mehrziel-Auftrag (Struktur wie f9a2a2f6: junkerwerk.de als Primaerziel,
junkerwerk.hu als weitere Domain) liefen OTX und SecurityTrails nur fuer das
Primaerziel. Entscheidung DC 29.09.2026: beide laufen je Domain, Dateien mit
Domain-Suffix und ``_domain`` als erstem Schluessel, Zeilen mit Etikett.

C6: rdap bekam nie eine IP. Der erste phase0a-Durchgang laeuft vor der Discovery
mit ``ips=[]`` und schrieb ``ok``/``no_ips``, der IP-Durchgang filterte auf shodan
und abuseipdb und schrieb fuer rdap ``not_in_package``. Dazu schrieb der
IP-Durchgang Doppelzeilen fuer alle uebrigen Werkzeuge und fuhr dns_security
erneut.
"""

import json
from unittest.mock import patch

from scanner.phase0a import (PHASE0A_IP_TOOLS, run_domain_intel, run_phase0a)

PERIMETER_TOOLS = ["whois", "shodan", "abuseipdb", "securitytrails", "urlhaus",
                   "greynoise", "otx", "virustotal", "rdap"]


def _collect(calls: list[dict]):
    def _rec(order_id, host_ip, phase, tool, status, **kw):
        calls.append({"tool": tool, "status": status, "reason": kw.get("reason"),
                      "raw": kw.get("raw_output")})
    return _rec


def _rows(calls: list[dict], tool: str) -> list[dict]:
    return [c for c in calls if c["tool"] == tool]


# ------------------------------------------------------------------ C1 (#22)

def _domain_intel(tmp_path, *, otx=None, st_available=True, st_data=None,
                  tools=("whois", "otx", "securitytrails")):
    calls: list[dict] = []
    st_data = st_data or {}
    with patch("scanner.phase0a.WhoisClient") as whois_cls, \
            patch("scanner.phase0a.OTXClient") as otx_cls, \
            patch("scanner.phase0a.SecurityTrailsClient") as st_cls, \
            patch("scanner.phase0a.ShodanClient") as shodan_cls, \
            patch("scanner.phase0a.VirusTotalClient") as vt_cls, \
            patch("scanner.phase0a.run_all_dns_security",
                  return_value={"dnssec": {"dnssec_signed": False}}), \
            patch("scanner.phase0a.publish_event"), \
            patch("scanner.phase0a.record_tool_run", side_effect=_collect(calls)):
        whois_cls.return_value.lookup.return_value = {"registrar": "X"}
        otx_cls.return_value.lookup_domain.return_value = otx
        st = st_cls.return_value
        st.available = st_available
        st.lookup_domain.return_value = st_data.get("domain")
        st.get_subdomains.return_value = st_data.get("subdomains", [])
        st.get_dns_history.return_value = st_data.get("dns_history", {})
        out = run_domain_intel("junkerwerk.hu", str(tmp_path), "f9a2a2f6",
                               {"package": "perimeter", "phase0a_tools": list(tools)})
    return out, calls, {"otx": otx_cls, "st": st_cls, "shodan": shodan_cls, "vt": vt_cls}


def test_otx_und_securitytrails_laufen_fuer_die_weitere_domain(tmp_path):
    otx = {"domain": "junkerwerk.hu", "pulse_count": 0, "pulses": []}
    st = {"domain": {"domain": "junkerwerk.hu", "a_records": ["188.40.3.130"]},
          "subdomains": ["mail.junkerwerk.hu"], "dns_history": {}}
    out, calls, mocks = _domain_intel(tmp_path, otx=otx, st_data=st)

    assert set(out) == {"whois", "dns_security", "otx", "securitytrails"}
    mocks["otx"].return_value.lookup_domain.assert_called_once_with("junkerwerk.hu")
    # Nur der Domainanteil: keine IP-Abfragen je weiterer Domain.
    mocks["otx"].return_value.lookup_ip.assert_not_called()
    mocks["shodan"].assert_not_called()
    mocks["vt"].assert_not_called()

    p0a = tmp_path / "phase0a"
    otx_file = json.loads((p0a / "otx_junkerwerk.hu.json").read_text(encoding="utf-8"))
    assert next(iter(otx_file)) == "_domain"
    assert otx_file["_domain"] == "junkerwerk.hu"
    assert otx_file["domain"]["pulse_count"] == 0
    st_file = json.loads((p0a / "securitytrails_junkerwerk.hu.json").read_text(encoding="utf-8"))
    assert next(iter(st_file)) == "_domain"
    assert st_file["subdomains"] == ["mail.junkerwerk.hu"]
    # Die Dateien ohne Suffix gehoeren weiter dem Primaerziel.
    assert not (p0a / "otx.json").exists()
    assert not (p0a / "securitytrails.json").exists()


def test_zeilen_der_weiteren_domain_tragen_das_etikett(tmp_path):
    otx = {"domain": "junkerwerk.hu", "pulse_count": 2, "pulses": []}
    st = {"domain": {"domain": "junkerwerk.hu"}, "subdomains": [], "dns_history": {}}
    _, calls, _ = _domain_intel(tmp_path, otx=otx, st_data=st)

    for tool in ("otx", "securitytrails"):
        rows = _rows(calls, tool)
        assert len(rows) == 1, (tool, rows)
        assert rows[0]["status"] == "ok"
        assert json.loads(rows[0]["raw"])["_domain"] == "junkerwerk.hu"


def test_otx_ohne_antwort_ist_failed(tmp_path):
    """OTX antwortet auch fuer unbekannte Domains mit pulse_count 0; None ist ein
    Transport- oder Lesefehler und damit failed (Regel aus S6c/#35)."""
    _, calls, _ = _domain_intel(tmp_path, otx=None, st_data={"subdomains": ["a.junkerwerk.hu"]})
    rows = _rows(calls, "otx")
    assert [(r["status"], r["reason"]) for r in rows] == [("failed", "otx_no_data")]
    assert not (tmp_path / "phase0a" / "otx_junkerwerk.hu.json").exists()


def test_securitytrails_ohne_daten_ist_failed(tmp_path):
    _, calls, _ = _domain_intel(tmp_path, otx={"pulse_count": 0}, st_data={})
    rows = _rows(calls, "securitytrails")
    assert [(r["status"], r["reason"]) for r in rows] == [("failed", "securitytrails_no_data")]
    assert not (tmp_path / "phase0a" / "securitytrails_junkerwerk.hu.json").exists()


def test_securitytrails_ohne_schluessel_ist_skipped(tmp_path):
    _, calls, mocks = _domain_intel(tmp_path, otx={"pulse_count": 0}, st_available=False)
    rows = _rows(calls, "securitytrails")
    assert [(r["status"], r["reason"]) for r in rows] == [("skipped", "no_api_key")]
    mocks["st"].return_value.lookup_domain.assert_not_called()


def test_quellen_ausserhalb_des_pakets_laufen_nicht(tmp_path):
    """WebCheck-artige Pakete ohne otx und securitytrails: nur whois und dns_security."""
    out, calls, mocks = _domain_intel(tmp_path, tools=("whois",))
    assert set(out) == {"whois", "dns_security"}
    mocks["otx"].assert_not_called()
    mocks["st"].assert_not_called()
    assert {c["tool"] for c in calls} == {"whois", "dns_security"}


def test_otx_primaerziel_ohne_antwort_ist_failed(tmp_path):
    """Dieselbe Regel im Primaerziel: vorher ok mit no_data."""
    calls: list[dict] = []
    with patch("scanner.phase0a.OTXClient") as otx_cls, \
            patch("scanner.phase0a.run_all_dns_security", return_value={}), \
            patch("scanner.phase0a.publish_event"), \
            patch("scanner.phase0a.record_tool_run", side_effect=_collect(calls)):
        otx_cls.return_value.lookup_domain.return_value = None
        run_phase0a("junkerwerk.de", [], str(tmp_path), "f9a2a2f6",
                    {"phase0a_tools": ["otx"], "package": "perimeter"})
    rows = _rows(calls, "otx")
    assert [(r["status"], r["reason"]) for r in rows] == [("failed", "otx_no_data")]


# ------------------------------------------------------------------ C6 (rdap)

_RDAP_HETZNER = {
    "ip": "188.40.3.130", "netblock_owner": "Hetzner Online GmbH", "netname": "HETZNER-fsn1-dc5",
    "handle": "HETZNER-fsn1-dc5", "country": "DE", "cidr": [{"v4prefix": "188.40.0.0", "length": 16}],
    "rir": "RIPE", "source": "RIR", "source_url": "https://rdap.db.ripe.net/ip/188.40.3.130",
}


def _perimeter_run(tmp_path, ips, calls, **kwargs):
    with patch("scanner.phase0a.WhoisClient") as whois_cls, \
            patch("scanner.phase0a.ShodanClient") as shodan_cls, \
            patch("scanner.phase0a.AbuseIPDBClient") as abuse_cls, \
            patch("scanner.phase0a.RDAPClient") as rdap_cls, \
            patch("scanner.phase0a.SecurityTrailsClient") as st_cls, \
            patch("scanner.phase0a.URLhausClient") as uh_cls, \
            patch("scanner.phase0a.GreyNoiseClient") as gn_cls, \
            patch("scanner.phase0a.OTXClient") as otx_cls, \
            patch("scanner.phase0a.VirusTotalClient") as vt_cls, \
            patch("scanner.phase0a.run_all_dns_security",
                  return_value={"dnssec": {"dnssec_signed": False}}) as dns_sec, \
            patch("scanner.phase0a.publish_event"), \
            patch("scanner.phase0a.record_tool_run", side_effect=_collect(calls)):
        whois_cls.return_value.lookup.return_value = {"registrar": "X"}
        shodan_cls.return_value.available = True
        shodan_cls.return_value.lookup_domain.return_value = {"subdomains": ["www"]}
        shodan_cls.return_value.lookup_host.return_value = {"ports": [443]}
        abuse_cls.return_value.available = True
        abuse_cls.return_value.check_ip.return_value = {"abuseConfidenceScore": 0}
        rdap_cls.return_value.lookup_ip.return_value = dict(_RDAP_HETZNER)
        st_cls.return_value.available = False
        uh_cls.return_value.lookup_host.return_value = {"query_status": "no_results"}
        uh_cls.return_value.is_compromised.return_value = False
        gn_cls.return_value.lookup_ip.return_value = None
        otx_cls.return_value.lookup_domain.return_value = {"pulse_count": 0}
        otx_cls.return_value.lookup_ip.return_value = None
        vt_cls.return_value.available = False
        tools = kwargs.pop("tools", PERIMETER_TOOLS)
        result = run_phase0a("junkerwerk.de", ips, str(tmp_path), "f9a2a2f6",
                             {"phase0a_tools": tools, "package": "perimeter"}, **kwargs)
    return result, rdap_cls, dns_sec


def test_erster_durchgang_stellt_rdap_zurueck(tmp_path):
    """Ohne IPs schreibt rdap keine no_ips-Zeile mehr, wenn ein IP-Durchgang folgt."""
    calls: list[dict] = []
    _, rdap_cls, _ = _perimeter_run(tmp_path, [], calls, defer_ip_tools=True)
    assert _rows(calls, "rdap") == []
    rdap_cls.return_value.lookup_ip.assert_not_called()


def test_ohne_zurueckstellen_bleibt_das_alte_verhalten(tmp_path):
    """Aufrufer ausserhalb des Workers (Tests, Einzelaufrufe) sehen weiter no_ips."""
    calls: list[dict] = []
    _perimeter_run(tmp_path, [], calls)
    assert [(r["status"], r["reason"]) for r in _rows(calls, "rdap")] == [("ok", "no_ips")]


def test_ip_durchgang_faehrt_rdap_mit_den_inventar_ips(tmp_path):
    calls: list[dict] = []
    ip_tools = [t for t in PERIMETER_TOOLS if t in PHASE0A_IP_TOOLS]
    assert "rdap" in ip_tools
    result, rdap_cls, dns_sec = _perimeter_run(
        tmp_path, ["188.40.3.130"], calls, tools=ip_tools, ip_pass=True)

    rdap_cls.return_value.lookup_ip.assert_called_once_with("188.40.3.130")
    rdap_file = json.loads((tmp_path / "phase0a" / "rdap.json").read_text(encoding="utf-8"))
    assert rdap_file["188.40.3.130"]["netblock_owner"] == "Hetzner Online GmbH"
    assert rdap_file["188.40.3.130"]["rir"] == "RIPE"
    assert result["rdap"]["188.40.3.130"]["source"] == "RIR"
    rows = _rows(calls, "rdap")
    assert [(r["status"], r["reason"]) for r in rows] == [("ok", None)]
    # rdap ist IP-bezogen und auftragsweit: kein Domain-Etikett in der Zeile.
    assert "_domain" not in json.loads(rows[0]["raw"])
    # dns_security lief im ersten Durchgang und wird nicht wiederholt.
    dns_sec.assert_not_called()


def test_ip_durchgang_schreibt_keine_doppelzeilen(tmp_path):
    """Die beiden Durchgaenge zusammen ergeben je Werkzeug hoechstens die Zeilen,
    die zu ihm gehoeren: keine zweite not_in_package-Zeile fuer die Domainquellen,
    keine zweite dns_security-Zeile."""
    calls: list[dict] = []
    _perimeter_run(tmp_path, [], calls, defer_ip_tools=True)
    ip_tools = [t for t in PERIMETER_TOOLS if t in PHASE0A_IP_TOOLS]
    _perimeter_run(tmp_path, ["188.40.3.130"], calls, tools=ip_tools, ip_pass=True)

    for tool in ("whois", "securitytrails", "urlhaus", "greynoise", "otx", "virustotal",
                 "dns_security", "rdap"):
        assert len(_rows(calls, tool)) == 1, (tool, _rows(calls, tool))
    assert not any(c["reason"] == "not_in_package" for c in calls)


def test_ip_durchgang_fuehrt_die_zusammenfassung_zusammen(tmp_path):
    calls: list[dict] = []
    _perimeter_run(tmp_path, [], calls, defer_ip_tools=True)
    first = json.loads((tmp_path / "phase0a" / "summary.json").read_text(encoding="utf-8"))
    assert "whois" in first and "rdap" not in first
    ip_tools = [t for t in PERIMETER_TOOLS if t in PHASE0A_IP_TOOLS]
    _perimeter_run(tmp_path, ["188.40.3.130"], calls, tools=ip_tools, ip_pass=True)
    merged = json.loads((tmp_path / "phase0a" / "summary.json").read_text(encoding="utf-8"))
    # Der erste Durchgang bleibt erhalten, der IP-Durchgang ergaenzt.
    assert merged["whois"] == {"registrar": "X"}
    assert merged["dns_security"] == {"dnssec": {"dnssec_signed": False}}
    assert merged["rdap"]["188.40.3.130"]["rir"] == "RIPE"
    assert merged["passive_subdomains"] == first["passive_subdomains"]


def test_worker_filtert_den_ip_durchgang_auf_die_ip_werkzeuge():
    """Verdrahtung in worker.py: der IP-Durchgang nimmt PHASE0A_IP_TOOLS inklusive
    rdap und markiert sich als ip_pass; der erste Durchgang stellt zurueck."""
    import inspect

    from scanner import worker
    src = inspect.getsource(worker)
    assert "PHASE0A_IP_TOOLS" in src
    assert "ip_pass=True" in src
    assert "defer_ip_tools=True" in src
    assert set(PHASE0A_IP_TOOLS) == {"shodan", "abuseipdb", "rdap"}
