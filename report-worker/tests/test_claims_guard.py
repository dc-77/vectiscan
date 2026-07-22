"""Tests fuer reporter/claims_guard.py — CVE-/Claims-Guard (C1).

Deckt die drei belegten Defekte ab:
  1. Halluzinierte CVE in recommendations[].action (SonicWall-Fall).
  2. WordPress-Versionswarnung trotz Status "latest".
  3. Vollstaendige Feldabdeckung + Guard-Stats.
"""

from __future__ import annotations

import pytest

from reporter.claims_guard import (
    CLAIMS_VERSION_MARKER,
    apply_claims_guard,
    iter_text_cells,
)
from reporter.claims_inventory import EvidenceInventory, build_evidence_inventory
from reporter.cve_guard import UNVERIFIED_MARKER


@pytest.fixture(autouse=True)
def _default_enforce_mode(monkeypatch):
    """Standard-Modus enforce erzwingen (unabhaengig von der Umgebung)."""
    monkeypatch.setenv("VECTISCAN_CLAIMS_GUARD_MODE", "enforce")


# ---------------------------------------------------------------------------
# Defekt 1: Halluzinierte CVE in bisher ungeprueften Feldern
# ---------------------------------------------------------------------------

def test_hallucinated_cve_in_recommendation_action_replaced():
    """Der belegte SonicWall-Fall: CVE weg, Marker da, Massnahme erhalten."""
    out = {
        "findings": [],
        "recommendations": [{
            "timeframe": "Sofort",
            "action": "SonicWall VPN-Firmware aktualisieren (CVE-2024-40766 patchen)",
            "finding_refs": [],
            "effort": "1 h",
        }],
    }
    stats = apply_claims_guard(out, inventory=EvidenceInventory(), enrichment={})
    action = out["recommendations"][0]["action"]
    assert "CVE-2024-40766" not in action
    assert UNVERIFIED_MARKER in action
    # Vulnerability-Klasse / Massnahme bleibt erhalten
    assert "SonicWall VPN-Firmware aktualisieren" in action
    assert stats["removed_count"] == 1
    assert stats["distinct_removed"] == ["CVE-2024-40766"]


def test_cve_in_top_recommendations_action_scrubbed():
    """WebCheck-Pfad: top_recommendations[].action."""
    out = {"findings": [], "top_recommendations": [
        {"action": "Patch fuer CVE-2099-88888 einspielen", "timeframe": "Sofort"},
    ]}
    stats = apply_claims_guard(out, inventory=EvidenceInventory(), enrichment={})
    assert "CVE-2099-88888" not in out["top_recommendations"][0]["action"]
    assert stats["removed_count"] == 1


def test_cve_in_positive_findings_and_executive_summary_scrubbed():
    out = {
        "findings": [],
        "positive_findings": [{"title": "Gut", "description": "Kein CVE-2099-00007 hier"}],
        "executive_summary": "Zusammenfassung mit CVE-2099-00008.",
    }
    stats = apply_claims_guard(out, inventory=EvidenceInventory(), enrichment={})
    assert "CVE-2099-00007" not in out["positive_findings"][0]["description"]
    assert "CVE-2099-00008" not in out["executive_summary"]
    assert stats["removed_count"] == 2


def test_cve_in_insurance_questionnaire_detail_and_premium_actions_scrubbed():
    out = {
        "findings": [],
        "insurance_questionnaire": [
            {"question": "Q", "answer": "ja", "detail": "Betroffen: CVE-2099-00011"},
        ],
        "risk_score": {"score": 40, "premium_reduction_actions": [
            "Patch CVE-2099-00012", "Backup pruefen",
        ]},
    }
    stats = apply_claims_guard(out, inventory=EvidenceInventory(), enrichment={})
    assert "CVE-2099-00011" not in out["insurance_questionnaire"][0]["detail"]
    assert "CVE-2099-00012" not in out["risk_score"]["premium_reduction_actions"][0]
    assert stats["removed_count"] == 2


def test_cve_in_supply_chain_and_scope_note_scrubbed():
    out = {
        "findings": [],
        "nis2_compliance_summary": {"scope_note": "Umfang inkl. CVE-2099-00021"},
        "supply_chain_summary": {"recommendation": "Lieferant CVE-2099-00022 pruefen"},
        "supply_chain_attestation": {"recommendation": "Nachweis CVE-2099-00023"},
        "iso27001_mapping": {"scope_note": "A.12 CVE-2099-00024"},
    }
    stats = apply_claims_guard(out, inventory=EvidenceInventory(), enrichment={})
    assert "CVE-2099-00021" not in out["nis2_compliance_summary"]["scope_note"]
    assert "CVE-2099-00022" not in out["supply_chain_summary"]["recommendation"]
    assert "CVE-2099-00023" not in out["supply_chain_attestation"]["recommendation"]
    assert "CVE-2099-00024" not in out["iso27001_mapping"]["scope_note"]
    assert stats["removed_count"] == 4


# ---------------------------------------------------------------------------
# Feldabdeckung — parametrisiert ueber die TEXT_TARGETS-Registry
# ---------------------------------------------------------------------------

def _full_skeleton() -> dict:
    """claude_output mit JEDEM Freitextfeld als String (fuer Coverage-Test)."""
    return {
        "findings": [{
            "id": "VS-2026-001", "title": "t", "description": "d",
            "recommendation": "r", "impact": "i", "evidence": "e", "affected": "a",
        }],
        "additional_findings_summary": [{
            "id": "VS-2026-050", "title": "t", "description": "d",
            "recommendation": "r", "impact": "i", "evidence": "e", "affected": "a",
        }],
        "overall_description": "od",
        "recommendations": [{"action": "ra"}],
        "top_recommendations": [{"action": "ta"}],
        "positive_findings": [{"title": "pt", "description": "pd"}],
        "executive_summary": "es",
        "nis2_compliance_summary": {"scope_note": "nsn"},
        "supply_chain_summary": {"recommendation": "scr"},
        "supply_chain_attestation": {"recommendation": "scar"},
        "iso27001_mapping": {"scope_note": "isn"},
        "insurance_questionnaire": [{"detail": "iqd"}],
        "risk_score": {"premium_reduction_actions": ["pra"]},
    }


def test_all_text_targets_are_reached():
    """Injiziert in JEDES Registry-Feld eine Fake-CVE und beweist volle Abdeckung.

    Schuetzt gegen kuenftige Prompt-Erweiterungen ohne Guard-Update: sobald ein
    neues Feld in iter_text_cells landet, muss es hier erreicht werden.
    """
    out = _full_skeleton()
    cells = list(iter_text_cells(out))
    assert len(cells) >= 20, f"unerwartet wenige Zellen: {len(cells)}"
    for i, cell in enumerate(cells):
        cell.set(f"Text mit CVE-2099-{i:05d} Referenz.")

    stats = apply_claims_guard(out, inventory=EvidenceInventory(), enrichment={})

    # Jede injizierte CVE muss gestrichen worden sein.
    assert stats["removed_count"] == len(cells)
    # Kein einziges Fake-CVE-Token darf im Output ueberleben.
    import json
    dumped = json.dumps(out)
    assert "CVE-2099-" not in dumped


# ---------------------------------------------------------------------------
# Defekt 2: Versionsaussage widerlegt durch Tool-Status
# ---------------------------------------------------------------------------

def _wordpress_current_inventory():
    return build_evidence_inventory(
        {"host_inventory": {"hosts": []}, "tech_profiles": []},
        host_tool_data={"1.2.3.4": {"wpscan": {
            "wp_version": "6.7.1", "wp_version_status": "latest"}}},
    )


def test_version_claim_outdated_contradicted_by_latest_status():
    """KI: 'WordPress veraltet', Inventar: latest -> unsupported + entschaerft."""
    inv = _wordpress_current_inventory()
    assert inv.is_current("wordpress")
    out = {
        "findings": [],
        "recommendations": [{
            "action": "WordPress 6.7.1 ist veraltet und sollte aktualisiert werden.",
            "finding_refs": [],
        }],
    }
    stats = apply_claims_guard(out, inventory=inv, enrichment={})
    assert "wordpress" in stats["claims_unsupported"]["version"]
    action = out["recommendations"][0]["action"]
    # Massnahme/Produktname bleibt, Korrektur-Hinweis angehaengt (enforce).
    assert "WordPress" in action
    assert CLAIMS_VERSION_MARKER in action


def test_nginx_current_next_to_outdated_ciphers_is_not_flagged():
    """FP-Regression (Befund-Fix): 'aktueller Webserver' + 'veraltete Cipher-
    Suites' im selben Satz darf NICHT als Versionswiderspruch gewertet werden.

    nginx ist aktuell belegt (mit Version), aber im Satz steht KEINE
    nginx-Versionsnummer -> keine Attribution -> Text bleibt byte-identisch.
    """
    inv = EvidenceInventory()
    inv.version_status["nginx"] = "aktuell"
    inv.versions["nginx"] = {"1.24.0"}
    inv.product_terms["nginx"] = {"nginx"}
    assert inv.is_current("nginx")

    original = ("Der nginx-Webserver ist aktuell, unterstuetzt aber weiterhin "
                "veraltete Cipher-Suites.")
    out = {"findings": [], "recommendations": [{"action": original}]}
    stats = apply_claims_guard(out, inventory=inv, enrichment={})
    # Kein FP: Text unveraendert, nginx NICHT als unbelegt markiert.
    assert out["recommendations"][0]["action"] == original
    assert "nginx" not in stats["claims_unsupported"]["version"]


def test_first_token_alias_does_not_defuse_other_product():
    """Der Ersten-Token-Alias ('apache') darf im Version-Enforce-Pfad NICHT
    'Apache Tomcat ist veraltet' treffen, wenn nur 'Apache HTTP Server' aktuell
    belegt ist (voller Produktname als einziger Term)."""
    inv = EvidenceInventory()
    inv.version_status["apache http server"] = "aktuell"
    inv.versions["apache http server"] = {"2.4.62"}
    inv.product_terms["apache http server"] = {"apache http server", "apache"}
    assert inv.is_current("apache http server")

    original = "Apache Tomcat ist veraltet und sollte aktualisiert werden."
    out = {"findings": [], "recommendations": [{"action": original}]}
    stats = apply_claims_guard(out, inventory=inv, enrichment={})
    # Kein Alias-Treffer -> Text unveraendert, nichts markiert.
    assert out["recommendations"][0]["action"] == original
    assert stats["claims_unsupported"]["version"] == []


def test_real_contradiction_with_version_and_name_is_defused():
    """Gegenprobe (Attribution vollstaendig): Produkt-Voll-Name + belegte
    Versionsnummer + 'veraltet' im selben Satz, Inventar sagt latest -> wird
    entschaerft."""
    inv = _wordpress_current_inventory()
    assert inv.is_current("wordpress")
    original = "WordPress 6.7.1 ist veraltet und muss dringend erneuert werden."
    out = {"findings": [], "recommendations": [{"action": original}]}
    stats = apply_claims_guard(out, inventory=inv, enrichment={})
    action = out["recommendations"][0]["action"]
    assert "wordpress" in stats["claims_unsupported"]["version"]
    assert CLAIMS_VERSION_MARKER in action
    assert "WordPress" in action  # Produktname/Aussage bleibt erhalten


def test_version_claim_supported_by_eol_row_kept():
    """Gegenprobe: Inventar meldet EOL -> Aussage bleibt byte-identisch."""
    inv = build_evidence_inventory(
        {"host_inventory": {"hosts": []}, "tech_profiles": []},
        host_tool_data={"1.2.3.4": {"wpscan": {
            "wp_version": "5.2", "wp_version_status": "insecure"}}},
    )
    assert not inv.is_current("wordpress")
    original = "WordPress 5.2 ist veraltet und unsicher."
    out = {"findings": [], "recommendations": [{"action": original}]}
    stats = apply_claims_guard(out, inventory=inv, enrichment={})
    assert out["recommendations"][0]["action"] == original
    assert stats["claims_unsupported"]["version"] == []


def test_version_claim_only_counted_in_shadow_mode(monkeypatch):
    """Shadow-Modus: Versionsaussage wird gezaehlt, aber Text bleibt gleich."""
    monkeypatch.setenv("VECTISCAN_CLAIMS_GUARD_MODE", "shadow")
    inv = _wordpress_current_inventory()
    original = "WordPress 6.7.1 ist veraltet."
    out = {"findings": [], "recommendations": [{"action": original}]}
    stats = apply_claims_guard(out, inventory=inv, enrichment={})
    assert stats["mode"] == "shadow"
    assert "wordpress" in stats["claims_unsupported"]["version"]
    # Text unveraendert im Shadow-Modus
    assert out["recommendations"][0]["action"] == original


# ---------------------------------------------------------------------------
# Defekt-Klasse Host/Port: immer shadow
# ---------------------------------------------------------------------------

def test_unknown_host_and_port_only_counted():
    """Host/Port nicht im Inventar -> gezaehlt, Text byte-identisch (auch enforce)."""
    inv = build_evidence_inventory({
        "host_inventory": {"domain": "example.com",
                           "hosts": [{"ip": "1.2.3.4", "fqdns": ["example.com"]}]},
        "tech_profiles": [{"ip": "1.2.3.4", "open_ports": [443]}],
    })
    original = "Firewall vor Port 3389 setzen und fremd.example.org sperren."
    out = {"findings": [], "recommendations": [{"action": original}]}
    stats = apply_claims_guard(out, inventory=inv, enrichment={})
    assert out["recommendations"][0]["action"] == original  # unveraendert
    assert "3389" in stats["claims_unsupported"]["port"]
    assert "fremd.example.org" in stats["claims_unsupported"]["host"]


def test_known_port_and_host_not_flagged():
    inv = build_evidence_inventory({
        "host_inventory": {"domain": "example.com",
                           "hosts": [{"ip": "1.2.3.4", "fqdns": ["example.com"]}]},
        "tech_profiles": [{"ip": "1.2.3.4", "open_ports": [443]}],
    })
    out = {"findings": [], "recommendations": [
        {"action": "Port 443 auf TLS 1.3 beschraenken (example.com)."}]}
    stats = apply_claims_guard(out, inventory=inv, enrichment={})
    assert "443" not in stats["claims_unsupported"]["port"]
    assert "example.com" not in stats["claims_unsupported"]["host"]


# ---------------------------------------------------------------------------
# Fail-open + Rueckwaertskompatibilitaet
# ---------------------------------------------------------------------------

def test_empty_inventory_is_noop():
    """Leeres Inventar -> keine Version/Host/Port-Aenderung (Fail-open)."""
    original = "WordPress 6.7.1 ist veraltet, Port 3389 offen auf fremd.example.org."
    out = {"findings": [], "recommendations": [{"action": original}]}
    inv = EvidenceInventory()
    assert inv.is_empty()
    stats = apply_claims_guard(out, inventory=inv, enrichment={})
    assert out["recommendations"][0]["action"] == original
    assert stats["claims_unsupported"]["version"] == []
    assert stats["claims_unsupported"]["host"] == []
    assert stats["claims_unsupported"]["port"] == []


def test_stats_backwards_compatible_keys():
    out = {"findings": [{"id": "X", "title": "CVE-2099-33333"}]}
    stats = apply_claims_guard(out, inventory=EvidenceInventory(), enrichment={})
    for key in ("removed_count", "distinct_removed", "allowlist_size"):
        assert key in stats
    assert stats["removed_count"] == 1
    assert stats["distinct_removed"] == ["CVE-2099-33333"]
    assert isinstance(stats["allowlist_size"], int)


def test_verified_cve_kept_across_all_fields():
    """Belegte CVE bleibt auch in den neuen Feldern erhalten."""
    enrichment = {"CVE-2024-6387": {"nvd": {"cve_id": "CVE-2024-6387"}}}
    out = {"findings": [], "recommendations": [
        {"action": "Patch fuer CVE-2024-6387 (regreSSHion) einspielen."}]}
    stats = apply_claims_guard(out, inventory=EvidenceInventory(), enrichment=enrichment)
    assert "CVE-2024-6387" in out["recommendations"][0]["action"]
    assert stats["removed_count"] == 0


def test_never_raises_on_garbage_output():
    """Fail-open: kaputtes claude_output darf keine Exception werfen."""
    for bad in ({"findings": None}, {"recommendations": "nope"},
                {"risk_score": {"premium_reduction_actions": [None, 5]}}):
        stats = apply_claims_guard(bad, inventory=EvidenceInventory(), enrichment={})
        assert "removed_count" in stats
