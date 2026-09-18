"""S1: Abgleich der Extraktion mit der Referenz report-prototype/build/catalog_sim.py.

``extract_facts(order_dir)`` liest results.json und order.json, genau die Form des
API-Snapshots. Verglichen werden nur Kennzahlen aus ASCII-Feldern: offene Dienste je
Host, TLS-Zwang und STARTTLS je Dienst, SPF und DMARC. Bekannte Defekte der Referenz
(Schluessel ``shodan_host`` statt ``shodan_hosts``, ``timeout`` nicht als Coverage,
TLS-Zaehlung ohne fehlgeschlagene Laeufe) werden nicht verglichen.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

from reporter.facts.build import build_from_snapshot
from reporter.facts.golden import SNAPSHOT

CATALOG_SIM = Path(__file__).resolve().parents[2] / "report-prototype" / "build" / "catalog_sim.py"


@pytest.fixture(scope="module")
def catalog_sim():
    if not CATALOG_SIM.exists():
        pytest.skip("report-prototype/build/catalog_sim.py nicht im Checkout")
    spec = importlib.util.spec_from_file_location("catalog_sim_ref", CATALOG_SIM)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _orders() -> list[str]:
    out = []
    for name in sorted(os.listdir(SNAPSHOT)):
        d = SNAPSHOT / name
        if d.is_dir() and (d / "results.json").exists() and not name.startswith("d0000000"):
            out.append(name)
    return out


@pytest.mark.parametrize("order_id", [pytest.param(o, id=o[:8]) for o in _orders()])
def test_dienste_und_dns_wie_referenz(catalog_sim, order_id):
    ref = catalog_sim.extract_facts(str(SNAPSHOT / order_id))
    facts = build_from_snapshot(SNAPSHOT / order_id)

    ref_services = {(s["host"], s["port"]) for s in ref["services"]}
    our_services = {(s.host_ip, s.port) for s in facts.services if s.proto == "tcp"}
    assert our_services == ref_services

    ours = {(s.host_ip, s.port): s for s in facts.services}
    for s in ref["services"]:
        mine = ours[(s["host"], s["port"])]
        if s["tls"]:
            assert mine.tls_required is True, (order_id, s["host"], s["port"])
        if s["starttls"]:
            assert mine.starttls is True, (order_id, s["host"], s["port"])
        if s["caps"] and not s["starttls"] and ("STARTTLS" in s["caps"] or "STLS" in s["caps"]):
            raise AssertionError("Referenz inkonsistent")

    ref_spf = bool((ref.get("dns") or {}).get("spf"))
    our_spf = bool(facts.dns and facts.dns[0].spf)
    assert our_spf == ref_spf, order_id
    ref_dmarc = ((ref.get("dns") or {}).get("dmarc_policy") or {}).get("dmarc_present")
    if isinstance(ref_dmarc, bool) and facts.dns and facts.dns[0].dmarc is not None:
        assert facts.dns[0].dmarc.present == ref_dmarc, order_id

    ref_hosts_up = {ip for ip, up in (ref.get("hosts_up") or {}).items() if up}
    our_hosts_up = {h.ip for h in facts.hosts if h.nmap_state == "up"}
    assert ref_hosts_up <= our_hosts_up, order_id
