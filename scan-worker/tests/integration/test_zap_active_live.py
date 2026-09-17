"""S0b: Spider plus Active Scan gegen das eigene Testziel.

Abnahme aus report-prototype/spec/prompts/S0b.md Punkt 4: ein Lauf ueber
Spider und Active Scan muss mindestens einen Active-Alert liefern. Dazu der
Regressionstest fuer die Diagnose: laeuft der Active Scan gegen eine andere
Instanz als Kontext und Policy, muss der Fehler jetzt sagen, an welchem
Endpunkt er entstanden ist.

Voraussetzung: ZAP_IT=1 und docker-compose.zap-it.yml laeuft.
"""

from __future__ import annotations

import uuid

import pytest

from tests.integration.conftest import TARGET_URL, requires_zap_it

pytestmark = pytest.mark.integration

CATEGORIES = ["sqli", "xss", "lfi", "cmdi"]


def _spider(zap, context_name: str, url: str) -> list[str]:
    scan_id = zap.start_spider(url, context_name=context_name, max_depth=5)
    zap.poll_until_complete(
        lambda: zap.spider_status(scan_id),
        timeout=180, interval=3, stop_value=100, tool_name="zap_spider",
    )
    return zap.spider_results(scan_id)


@requires_zap_it
def test_spider_plus_active_scan_liefert_active_alert(zap_a):
    """Vollstaendige Kette auf einer Instanz: Kontext, Spider, Policy, Scan."""
    from scanner.tools.zap_mapper import ZapAlertMapper
    from scanner.zap_pool import build_context_name, build_policy_name

    order_id = uuid.uuid4().hex
    context_name = build_context_name(order_id, "10.0.0.1")
    policy_name = build_policy_name(order_id, "10.0.0.1")

    try:
        context_id = zap_a.create_context(context_name)
        zap_a.include_in_context(context_name, ".*target.*")

        urls = _spider(zap_a, context_name, TARGET_URL)
        assert urls, "Spider hat keine URL gefunden, Testziel nicht erreichbar?"

        enabled = zap_a.create_scan_policy(policy_name, CATEGORIES, "aggressive")
        assert enabled, "keine einzige Scan-Regel aktivierbar"

        scan_id = zap_a.start_active_scan(TARGET_URL, context_id=context_id,
                                          scan_policy=policy_name)
        completed = zap_a.poll_until_complete(
            lambda: zap_a.active_scan_status(scan_id),
            timeout=600, interval=5, stop_value=100, tool_name="zap_active",
        )
        assert completed, "Active Scan wurde nicht fertig"

        zap_a.wait_for_passive_scan(timeout=60)
        alerts = zap_a.get_alerts(base_url=TARGET_URL)
        assert alerts, "ZAP hat gar keine Alerts geliefert"

        findings = ZapAlertMapper().map_alerts(alerts, "10.0.0.1", "target")
        active = [f for f in findings if f.get("tool") == "zap_active"]
        assert active, (
            "kein Active-Alert. Alerts: "
            + ", ".join(sorted({str(a.get("name")) for a in alerts}))
        )
        assert all(a.get("pluginId") for a in alerts if a.get("name")), \
            "Alerts ohne pluginId, der Pruefkatalog kann sie nicht zuordnen"
    finally:
        zap_a.remove_scan_policy(policy_name)
        zap_a.remove_context(context_name)


@requires_zap_it
def test_policy_auf_anderer_instanz_nennt_den_endpunkt(zap_a, zap_b):
    """Regressionstest fuer die Diagnose.

    Genau dieser Fall lief 26-mal in Produktion: Policy auf einer Instanz,
    Active Scan auf einer anderen. Der Fehler muss jetzt Endpunkt und
    ZAP-Code tragen, sonst ist er wieder nicht zuordenbar.
    """
    from scanner.tools.zap_client import ZapError
    from scanner.zap_pool import build_context_name, build_policy_name

    order_id = uuid.uuid4().hex
    context_name = build_context_name(order_id, "10.0.0.2")
    policy_name = build_policy_name(order_id, "10.0.0.2")

    try:
        context_id = zap_a.create_context(context_name)
        zap_a.include_in_context(context_name, ".*target.*")
        _spider(zap_a, context_name, TARGET_URL)
        zap_a.create_scan_policy(policy_name, CATEGORIES, "standard")

        # Instanz B kennt weder Kontext noch Policy.
        with pytest.raises(ZapError) as excinfo:
            zap_b.start_active_scan(TARGET_URL, context_id=context_id,
                                    scan_policy=policy_name)
        err = excinfo.value
        assert err.endpoint == "/JSON/ascan/action/scan/"
        assert err.zap_code, "ZAP-Fehlercode fehlt, Diagnose waere wieder blind"
        assert policy_name in str(err) or str(context_id) in str(err)
    finally:
        zap_a.remove_scan_policy(policy_name)
        zap_a.remove_context(context_name)


@requires_zap_it
def test_create_scan_policy_ist_idempotent(zap_a):
    """Zweiter Aufruf mit gleichem Namen darf nicht scheitern."""
    from scanner.zap_pool import build_policy_name

    policy_name = build_policy_name(uuid.uuid4().hex, "10.0.0.3")
    try:
        first = zap_a.create_scan_policy(policy_name, CATEGORIES, "standard")
        second = zap_a.create_scan_policy(policy_name, CATEGORIES, "standard")
        assert first == second
        assert policy_name in zap_a.get_scan_policy_names()
    finally:
        zap_a.remove_scan_policy(policy_name)


@requires_zap_it
def test_angeforderte_scanner_ids_sind_im_image_vorhanden(zap_a):
    """Protokolliert, welche Kategorie-IDs dieses Image nicht kennt.

    Der Test schlaegt nicht fehl, wenn etwas fehlt: welche Regeln installiert
    sind, entscheidet das Image. Er macht die Luecke sichtbar, damit sie in
    die Abdeckung wandern kann statt den Scan zu kippen.
    """
    from scanner.tools.zap_client import ZapClient

    installed = zap_a.get_installed_scanner_ids()
    assert installed, "ascan/view/scanners lieferte nichts"

    missing = {}
    for category, ids in ZapClient.CATEGORY_SCANNER_IDS.items():
        gap = sorted(set(ids) - ZapClient.FORBIDDEN_SCANNERS - installed)
        if gap:
            missing[category] = gap
    print(f"ZAP {zap_a.get_version()}: nicht installierte Scanner-IDs: {missing or 'keine'}")

    enabled, dropped = zap_a.resolve_scanner_ids(CATEGORIES)
    assert enabled, f"keine der Kategorien {CATEGORIES} ist in diesem Image nutzbar"
