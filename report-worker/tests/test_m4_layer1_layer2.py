"""M4 -- Schicht 1 + 2 Render-Tests.

Pruefen die vier parallelen Tracks 4a/4b/4c/4d:

  - 4a: Cover v2 + Frontpage 'Auf einen Blick'
  - 4b: business_context-Modul + Render
  - 4c: Umfang + Methodik (scope_meta + methodology_stats)
  - 4d: Architektur (Tech-Tabelle, Service-Cards, Posture, Befund-Landschaft)

Verifikation (Master-Plan): Doppel-Render gegen replay_secumetrix_like.json
+ synthetisches trunk/heuel-Fixture, plus die einzelnen Aggregatoren.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from reporter.business_context import (
    INDUSTRY_CLUSTERS, GENERIC_CLUSTER, build_business_context,
)
from reporter.posture_v2 import build_posture_indicators
from reporter.befund_landschaft import (
    CATEGORIES, build_befund_landschaft, build_service_cards,
)
from reporter.v2_data import (
    build_scope_meta, build_methodology_stats,
    build_compliance_indicators, build_tech_table_v2,
)
from reporter.layer1_aggregator import build_layer1
from reporter.pdf.v2 import generate_report_v2


FIXTURE_DIR = (
    pathlib.Path(__file__).parent.parent
    / "reporter" / "validation" / "tests" / "fixtures"
)
SECUMETRIX_FX = FIXTURE_DIR / "replay_secumetrix_like.json"
TRUNK_FX = FIXTURE_DIR / "replay_trunk_heuel_like.json"


def _load(p: pathlib.Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


# ====================================================================
# 4a -- Compliance-Indikatoren + Frontpage-Daten
# ====================================================================
class TestTrack4aFrontpage:
    def test_compliance_indicators_critical_findings_yield_handlungsbedarf(self):
        co = _load(TRUNK_FX)  # hat ein CRITICAL
        bc = build_business_context({"domain": "trunk-immobilien.de"}, {}, co)
        inds = build_compliance_indicators(co, bc)
        assert len(inds) == 3
        for ind in inds:
            assert ind["status"] == "Handlungsbedarf"

    def test_compliance_indicators_empty_yields_konform(self):
        inds = build_compliance_indicators({"findings": []}, GENERIC_CLUSTER)
        for ind in inds:
            assert ind["status"] == "Konform"

    def test_compliance_indicators_medium_only_yields_teilerfuellt(self):
        co = {"findings": [{"severity": "MEDIUM"}, {"severity": "LOW"}]}
        inds = build_compliance_indicators(co, GENERIC_CLUSTER)
        for ind in inds:
            assert ind["status"] == "Teilerfuellt"

    def test_compliance_indicators_include_business_cluster_label(self):
        bc = INDUSTRY_CLUSTERS["real_estate"]
        co = {"findings": []}
        inds = build_compliance_indicators(co, {"cluster_label": bc["label"]})
        labels = " ".join(i["label"] for i in inds)
        assert "Immobilien" in labels


# ====================================================================
# 4b -- business_context
# ====================================================================
class TestTrack4bBusinessContext:
    def test_override_wins(self):
        out = build_business_context(
            {"industry_vertical": "healthcare"}, {}, {},
        )
        assert out["cluster_key"] == "healthcare"
        assert out["source"] == "override"
        assert "Patient" in " ".join(out["data_kinds"])

    def test_unknown_override_falls_back_to_generic(self):
        out = build_business_context(
            {"industry_vertical": "asdfgh"}, {}, {},
        )
        assert out["cluster_key"] == "generic"
        assert out["source"] == "generic"

    def test_tech_heuristic_detects_ecommerce(self):
        scan_meta = {
            "techProfiles": [
                {"cms": "WooCommerce", "technologies": [{"name": "Shopware 6"}]},
            ],
        }
        out = build_business_context(scan_meta, {}, {})
        assert out["cluster_key"] == "ecommerce"
        assert out["source"] == "tech_heuristic"

    def test_domain_heuristic_detects_legal(self):
        out = build_business_context(
            {"domain": "kanzlei-mueller.de"}, {}, {},
        )
        assert out["cluster_key"] == "legal_services"
        assert out["source"] == "domain_heuristic"

    def test_observed_apps_added_to_data_kinds(self):
        scan_meta = {
            "industry_vertical": "real_estate",
            "techProfiles": [
                {"cms": "WordPress", "technologies": [
                    {"name": "Contact Form 7"},
                ]},
            ],
        }
        out = build_business_context(scan_meta, {}, {})
        # Cluster-Default + beobachtete Datenarten
        joined = " ".join(out["data_kinds"]).lower()
        assert "kontaktanfragen" in joined
        assert "kyc" in joined or "kunden" in joined

    def test_generic_fallback_when_nothing_matches(self):
        out = build_business_context({}, {}, {})
        assert out["cluster_key"] == "generic"
        # Generic ist explizit datenarten-fokussiert, kein Marketing-Sprech
        assert "DSGVO" in out["narrative"]


# ====================================================================
# 4c -- Scope-Meta + Methodology-Stats
# ====================================================================
class TestTrack4cScopeMethodology:
    def test_scope_meta_extracts_hosts_and_subdomains(self):
        host_inv = {
            "domain": "example.de",
            "hosts": [
                {"ip": "1.1.1.1", "fqdns": ["www.example.de", "shop.example.de"]},
                {"ip": "2.2.2.2", "fqdns": ["dev.example.de"]},
            ],
        }
        scan_meta = {"domain": "example.de", "startedAt": "2026-05-13T08:00:00"}
        out = build_scope_meta(scan_meta, host_inv, {})
        assert out["hosts_count"] == 2
        assert out["subdomains_count"] == 3
        assert out["scan_date"] == "2026-05-13"

    def test_scope_meta_lists_default_out_of_scope(self):
        out = build_scope_meta({}, {}, {})
        assert "interne Netzsegmente" in out["out_of_scope"]
        assert "Social-Engineering-Versuche" in out["out_of_scope"]

    def test_methodology_filter_rate(self):
        co = {
            "findings": [{"id": "VS-1"}, {"id": "VS-2"}],
            "additional_findings": [{"finding_id": "x"}, {"finding_id": "y"}],
        }
        out = build_methodology_stats({}, co)
        assert out["selected_count"] == 2
        assert out["filtered_count"] == 2
        assert out["filter_rate_pct"] == 50.0

    def test_methodology_ai_models_concrete_named(self):
        # Doc 02-Anforderung: KI konkret benannt (kein Buzzword)
        out = build_methodology_stats({}, {"findings": []})
        names = [m["name"] for m in out["ai_models"]]
        assert any("Sonnet" in n for n in names)
        assert any("Haiku" in n for n in names)
        assert any("Severity-Policy" in n for n in names)
        # Auch model_id sichtbar fuer Audit
        ids = [m["model_id"] for m in out["ai_models"]]
        assert any("sonnet" in i.lower() for i in ids)

    def test_methodology_has_four_phases(self):
        out = build_methodology_stats({}, {"findings": []})
        phases = out["phases"]
        assert len(phases) == 4
        names = " ".join(p["name"] for p in phases)
        assert "Phase 0" in names
        assert "Phase 3" in names

    def test_policy_version_taken_from_env(self, monkeypatch):
        monkeypatch.setenv("VECTISCAN_POLICY_VERSION", "2026-99-99.9")
        out = build_methodology_stats({}, {"findings": []})
        assert out["policy_version"] == "2026-99-99.9"


# ====================================================================
# 4d -- Tech-Table v2 / Service-Cards / Posture / Befund-Landschaft
# ====================================================================
class TestTrack4dArchitektur:
    def test_befund_landschaft_categorizes_secumetrix(self):
        co = _load(SECUMETRIX_FX)
        out = build_befund_landschaft(co["findings"])
        # Mindestens 2 Kategorien sollten vorkommen (RDP + Info-Disclosure
        # + Mail im Fixture)
        cat_keys = [c["key"] for c in out["categories"]]
        assert "exposed_services" in cat_keys
        assert "info_disclosure" in cat_keys
        # Mail-Auth in dem Fixture
        assert "mail_authenticity" in cat_keys
        # Total deckt die Anzahl der Findings ab (minus positive)
        assert out["total_count"] == len(co["findings"])

    def test_befund_landschaft_schwerpunkt_picks_highest_severity(self):
        co = {
            "findings": [
                {"severity": "CRITICAL", "policy_id": "SP-DB-001", "title": "A"},
                {"severity": "LOW", "policy_id": "SP-DB-002", "title": "B"},
            ],
        }
        out = build_befund_landschaft(co["findings"])
        cat = next(c for c in out["categories"] if c["key"] == "exposed_services")
        assert cat["schwerpunkt"] == "kritisch"

    def test_service_cards_rank_red_ports_first(self):
        host_inv = {
            "hosts": [{"ip": "1.2.3.4", "fqdns": ["test.example.de"]}],
        }
        profiles = [{
            "ip": "1.2.3.4",
            "nmap": {
                "open_ports": [
                    {"port": 80, "service": "http"},
                    {"port": 3306, "service": "mysql"},
                    {"port": 443, "service": "https"},
                    {"port": 21, "service": "ftp"},
                ],
            },
        }]
        cards = build_service_cards(host_inv, profiles)
        assert len(cards) == 1
        ports_in_order = [p[0] for p in cards[0]["ports"]]
        # 3306 (rot) muss vor 21 (orange) vor 80/443 (gruen) stehen
        assert ports_in_order[0] == 3306
        # 21 ist klartext = orange, muss vor gruenen Ports kommen
        assert ports_in_order.index(21) < ports_in_order.index(443)

    def test_service_card_colors_match_risk(self):
        host_inv = {"hosts": [{"ip": "1.2.3.4", "fqdns": []}]}
        profiles = [{
            "ip": "1.2.3.4",
            "nmap": {"open_ports": [{"port": 3306}, {"port": 21}, {"port": 443}]},
        }]
        cards = build_service_cards(host_inv, profiles)
        port_colors = {p[0]: p[2] for p in cards[0]["ports"]}
        assert port_colors[3306] == "#DC2626"  # red
        assert port_colors[21] == "#F97316"   # orange
        assert port_colors[443] == "#22C55E"  # green

    def test_service_cards_accept_prod_flat_int_format(self):
        """Prod-Format: scan-worker/phase1.py speichert open_ports als list[int]
        TOP-LEVEL im tech_profile.json (nicht unter nmap.open_ports)."""
        host_inv = {"hosts": [{"ip": "5.199.141.24", "fqdns": ["heuel.com"]}]}
        profiles = [{
            "ip": "5.199.141.24",
            "open_ports": [21, 22, 80, 443, 3306, 3389],  # FLAT LIST OF INT
        }]
        cards = build_service_cards(host_inv, profiles)
        assert len(cards) == 1
        ports_in_order = [p[0] for p in cards[0]["ports"]]
        # Alle 6 Ports muessen erkannt werden
        assert set(ports_in_order) == {21, 22, 80, 443, 3306, 3389}
        # Red-First-Sort: 3306, 3389 zuerst (red), dann 21, 80 (orange),
        # dann 22, 443 (gruen)
        assert ports_in_order[0] in (3306, 3389)
        assert ports_in_order[1] in (3306, 3389)

    def test_service_cards_prefer_services_when_available(self):
        """Wenn tech_profile['services'] vorhanden ist, sollte der Service-
        Name daraus gezogen werden (statt nur die Port-Map)."""
        host_inv = {"hosts": [{"ip": "1.2.3.4", "fqdns": []}]}
        profiles = [{
            "ip": "1.2.3.4",
            "services": [
                {"port": 8443, "name": "https-alt", "product": "nginx"},
            ],
        }]
        cards = build_service_cards(host_inv, profiles)
        assert len(cards) == 1
        # 8443 ist nicht in SERVICE_LABELS -> Fallback nutzt service-Name
        port_8443 = next((p for p in cards[0]["ports"] if p[0] == 8443), None)
        assert port_8443 is not None

    def test_posture_email_fail_when_dkim_missing(self):
        co = {
            "findings": [
                {
                    "policy_id": "SP-DNS-002",
                    "finding_type": "mail_security_missing_dkim",
                    "title": "DKIM-Record fehlt",
                },
            ],
        }
        ind = build_posture_indicators(co)
        email = next(i for i in ind if i["key"] == "email")
        statuses = dict(email["items"])
        assert statuses["DKIM"] == "fail"
        # SPF/DMARC default ok wenn nichts erwaehnt
        assert statuses["SPF"] == "ok"

    def test_posture_web_fail_when_hsts_missing(self):
        co = {
            "findings": [
                {
                    "policy_id": "SP-HDR-001",
                    "finding_type": "header_missing_hsts",
                    "title": "HSTS-Header fehlt",
                },
            ],
        }
        ind = build_posture_indicators(co)
        web = next(i for i in ind if i["key"] == "web")
        statuses = dict(web["items"])
        assert statuses["HSTS"] == "fail"

    def test_posture_tls_reads_tr03116_overall(self):
        ind = build_posture_indicators(
            {"findings": []},
            tr03116_results=[{"overall_status": "FAIL"}],
        )
        tls = next(i for i in ind if i["key"] == "tls")
        statuses = dict(tls["items"])
        assert statuses["TR-03116"] == "fail"

    def test_tech_table_v2_skips_hosts_without_profile(self):
        host_inv = {
            "hosts": [
                {"ip": "1.1.1.1", "fqdns": ["a"]},
                {"ip": "2.2.2.2", "fqdns": ["b"]},
            ],
        }
        # Nur 1.1.1.1 hat Profile
        profiles = [{"ip": "1.1.1.1", "server": "nginx/1.24.0"}]
        out = build_tech_table_v2(host_inv, profiles)
        assert len(out) == 1
        assert out[0]["ip"] == "1.1.1.1"


# ====================================================================
# DOPPEL-RENDER: synthetische Fixtures gegen v1 + v2
# ====================================================================
def _build_full_report_data(fixture_path: pathlib.Path, domain: str) -> dict:
    """Wrappt ein Fixture in eine vollstaendige v2-augmentierte report_data."""
    from reporter.report_mapper import _augment_for_v2

    co = _load(fixture_path)
    host_inventory = {
        "domain": domain,
        "hosts": [
            {"ip": "5.199.141.24", "fqdns": [domain, f"www.{domain}"]},
            {"ip": "45.157.234.103", "fqdns": [f"mail.{domain}"]},
        ],
    }
    scan_meta = {
        "domain": domain,
        "orderId": "test-m4",
        "startedAt": "2026-05-13T08:00:00",
        "completedAt": "2026-05-13T09:30:00",
        "package": "perimeter",
        "techProfiles": [
            {
                "ip": "5.199.141.24",
                "cms": "WordPress",
                "cms_version": "6.4.2",
                "server": "Apache/2.4.49",
                "technologies": [
                    {"name": "PHP", "version": "7.4.30"},
                    {"name": "OpenSSH", "version": "7.4"},
                ],
                "nmap": {
                    "open_ports": [
                        {"port": 21, "service": "ftp"},
                        {"port": 22, "service": "ssh"},
                        {"port": 80, "service": "http"},
                        {"port": 443, "service": "https"},
                        {"port": 3306, "service": "mysql"},
                    ],
                },
            },
            {
                "ip": "45.157.234.103",
                "nmap": {
                    "open_ports": [
                        {"port": 25, "service": "smtp"},
                        {"port": 587, "service": "smtps"},
                        {"port": 3389, "service": "rdp"},
                    ],
                },
            },
        ],
    }
    base = {
        "meta": {
            "title": f"M4 Doppel-Render {domain}",
            "author": "VectiScan",
            "header_left": "VECTISCAN", "header_right": domain,
            "footer_left": "Vertraulich", "classification_label": "VERTRAULICH",
        },
        "cover": {
            "cover_subtitle": "VECTISCAN",
            "cover_title": f"Sicherheitsbewertung {domain}",
            "package": "perimeter",
            "cover_meta": [
                ["Ziel:", f"{domain} (2 Hosts)"],
                ["Datum:", "2026-05-13"],
                ["Paket:", "Perimeter"],
            ],
        },
        "domain": domain,
        "toc": [("1", "Befunde", False)],
        "executive_summary": {
            "section_label": "1 ES",
            "subsections": [{"title": "Zusammenfassung",
                             "paragraphs": ["Mehrere kritische Befunde."]}],
        },
        "scope": {
            "section_label": "2 Scope",
            "subsections": [{"title": "Pruefungsumfang",
                             "paragraphs": [domain]}],
        },
        "findings": [
            {"id": f.get("id"), "external_id": f.get("id"),
             "policy_id": f.get("policy_id", ""),
             "title": f.get("title", ""), "severity": f.get("severity"),
             "cvss_score": f.get("cvss_score"),
             "cvss_vector": f.get("cvss_vector", "—"),
             "cwe": f.get("cwe", "—"),
             "affected": f.get("affected", ""),
             "description": f.get("description", ""),
             "evidence": str(f.get("evidence", "—")),
             "impact": f.get("impact", ""),
             "recommendation": f.get("recommendation", ""),
             "scale": f.get("scale", "cvss"),
             "hygiene_level": f.get("hygiene_level"),
             "label_description": "Beschreibung",
             "label_evidence": "Nachweis",
             "label_impact": "Auswirkung",
             "label_recommendation": "Empfehlung"}
            for f in co.get("findings", [])
        ],
        "recommendations": {"intro_paragraph": "x", "roadmap_table": None},
        "screenshots": [],
        "disclaimer": "Disclaimer",
    }
    _augment_for_v2(base, co, host_inventory, "perimeter", scan_meta)
    return base


class TestDoppelRender:
    def test_secumetrix_v2_full_render(self, tmp_path):
        """v2 rendert die secumetrix-Fixture mit voller M4-Augmentierung."""
        data = _build_full_report_data(SECUMETRIX_FX, "secumetrix.de")
        out = tmp_path / "secumetrix_v2_m4.pdf"
        generate_report_v2(data, str(out))
        assert out.exists()
        assert out.stat().st_size > 6000
        # Augmentierungs-Marker im Daten-Objekt
        assert data["_renderer_layout"] == "v2"
        assert data.get("business_context") is not None
        assert data.get("scope_meta") is not None
        assert data.get("methodology_stats") is not None
        assert data.get("compliance_indicators") is not None
        assert data.get("posture_indicators") is not None
        assert data.get("befund_landschaft") is not None

    def test_trunk_heuel_v2_full_render(self, tmp_path):
        """v2 rendert die trunk-Fixture mit voller M4-Augmentierung."""
        data = _build_full_report_data(TRUNK_FX, "trunk-immobilien.de")
        out = tmp_path / "trunk_v2_m4.pdf"
        generate_report_v2(data, str(out))
        assert out.exists()
        assert out.stat().st_size > 6000
        # Domain-Heuristik laeuft bei "trunk-immobilien" auf real_estate
        bc = data.get("business_context")
        assert bc is not None
        assert bc["cluster_key"] == "real_estate"
        # CRITICAL-Finding fuehrt zu Handlungsbedarf
        inds = data.get("compliance_indicators") or []
        assert all(i["status"] == "Handlungsbedarf" for i in inds)

    def test_both_fixtures_yield_befund_landschaft(self, tmp_path):
        for fx, dom in ((SECUMETRIX_FX, "secumetrix.de"),
                        (TRUNK_FX, "trunk-immobilien.de")):
            data = _build_full_report_data(fx, dom)
            landschaft = data.get("befund_landschaft") or {}
            assert landschaft.get("total_count", 0) > 0
            assert landschaft.get("categories")
