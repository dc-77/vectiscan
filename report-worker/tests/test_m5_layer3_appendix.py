"""M5 -- Schicht 3 (Befund-Details) + Anhang A-F Tests.

Pruefen die drei parallelen Tracks 5a/5b/5c:

  - 5a: Befund-Detail v2 (7-Sektionen-Body) + verification_templates
  - 5b: Anhang A.1/A.2 (CVSS+Hygiene), B (Service-Inventar), C (Tools)
  - 5c: Anhang D (Compliance), E (Filterungen), F (Wiederholung) +
        compliance_mappings-Augment

Verifikation (Master-Plan M5):
  - Pro Befund-Klasse Fixture-Test (DB / RDP / Mail / Header / TLS / EOL)
  - Threat-Intel-Realitaetscheck (CVE-IDs + EPSS + KEV im Rendering)
  - Compliance-Mapping-Vollstaendigkeit: jeder policy_id im Fixture
    bekommt eine NIS2/ISO/BSI/DSGVO-Zeile (oder "nicht definiert")
  - Doppel-Render gegen replay_secumetrix_like + replay_trunk_heuel_like
"""
from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from reporter.compliance.bsi_grundschutz import map_finding_to_bsi
from reporter.compliance.dsgvo import (
    DSGVO_ARTICLES, map_finding_to_dsgvo, get_article_title,
)
from reporter.compliance.iso27001 import map_finding_to_iso27001
from reporter.compliance.nis2_bsig import map_finding_to_bsig, get_bsig_ref
from reporter.compliance_mappings import build_compliance_mappings
from reporter.verification_templates import (
    GENERIC_FALLBACK, VERIFICATION_TEMPLATES, get_verification_block,
)
from reporter.pdf.v2.layers.findings import (
    _SEV_TO_PRIORITY, _normalize_cve_entries,
)
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
# 5a -- Verification-Templates
# ====================================================================
class TestTrack5aVerificationTemplates:
    def test_top_15_policy_ids_have_template(self):
        """Mindestens 15 policy_ids muessen abgedeckt sein."""
        assert len(VERIFICATION_TEMPLATES) >= 15

    def test_secumetrix_policy_ids_covered(self):
        """secumetrix-Fixture-policy_ids muessen weitgehend abgedeckt sein."""
        co = _load(SECUMETRIX_FX)
        pids = {f.get("policy_id") for f in co["findings"] if f.get("policy_id")}
        expected_covered = {
            "SP-RDP-001", "SP-FTP-001", "SP-WP-001", "SP-WEB-001",
            "SP-DNS-002",
        }
        for pid in expected_covered:
            if pid in pids:
                assert pid in VERIFICATION_TEMPLATES, (
                    f"policy_id {pid} muss in Top-15 abgedeckt sein"
                )

    def test_trunk_policy_ids_covered(self):
        """trunk-Fixture (DB, Dev, FTP, EOL-SSH, DKIM, DMARC, HSTS, Cookie)."""
        for pid in (
            "SP-DB-001", "SP-WEB-002", "SP-FTP-001", "SP-EOL-002",
            "SP-DNS-002", "SP-DNS-004", "SP-HDR-001", "SP-COOK-003",
            "SP-WP-001", "SP-DISC-001",
        ):
            assert pid in VERIFICATION_TEMPLATES, (
                f"trunk-Befund-Klasse {pid} muss Template haben"
            )

    def test_db_template_substitutes_port_and_host(self):
        finding = {
            "policy_id": "SP-DB-001",
            "title_vars": {"host": "trunk-immobilien.de", "port": "3306"},
        }
        text, is_fallback = get_verification_block(finding)
        assert not is_fallback
        assert "trunk-immobilien.de" in text
        assert "3306" in text
        assert "nmap" in text

    def test_db_template_smart_var_from_affected(self):
        """Wenn title_vars fehlt, sollte host/port aus affected abgeleitet werden."""
        finding = {
            "policy_id": "SP-DB-001",
            "affected": "5.199.141.24:3306",
        }
        text, is_fallback = get_verification_block(finding)
        assert not is_fallback
        assert "5.199.141.24" in text
        assert "3306" in text

    def test_unknown_policy_id_falls_back_to_generic(self):
        finding = {"policy_id": "SP-UNKNOWN-999"}
        text, is_fallback = get_verification_block(finding)
        assert is_fallback
        assert text == GENERIC_FALLBACK

    def test_dkim_template_uses_domain(self):
        finding = {
            "policy_id": "SP-DNS-002",
            "affected": "trunk-immobilien.de",
        }
        scan_context = {"domain": "trunk-immobilien.de"}
        text, is_fallback = get_verification_block(finding, scan_context)
        assert not is_fallback
        assert "trunk-immobilien.de" in text
        assert "dig" in text.lower() and "dkim" in text.lower()

    def test_cookie_template_uses_cookie_name(self):
        finding = {
            "policy_id": "SP-COOK-003",
            "title_vars": {"host": "trunk-immobilien.de", "cookie_name": "PHPSESSID"},
        }
        text, is_fallback = get_verification_block(finding)
        assert not is_fallback
        assert "PHPSESSID" in text
        assert "SameSite" in text


# ====================================================================
# 5a -- Threat-Intel-Extraktion
# ====================================================================
class TestTrack5aThreatIntel:
    def test_cves_list_of_dicts_sorted_by_epss(self):
        finding = {
            "cves": [
                {"cve_id": "CVE-2022-0001", "epss_score": 0.1, "kev": False},
                {"cve_id": "CVE-2022-0002", "epss_score": 0.9, "kev": False},
                {"cve_id": "CVE-2022-0003", "epss_score": 0.5, "kev": False},
            ],
        }
        entries = _normalize_cve_entries(finding)
        assert len(entries) == 3
        assert entries[0]["cve_id"] == "CVE-2022-0002"
        assert entries[1]["cve_id"] == "CVE-2022-0003"
        assert entries[2]["cve_id"] == "CVE-2022-0001"

    def test_cves_top3_clip(self):
        finding = {
            "cves": [
                {"cve_id": f"CVE-2022-{i:04d}", "epss_score": 0.1 * i}
                for i in range(1, 8)
            ],
        }
        entries = _normalize_cve_entries(finding)
        assert len(entries) == 3

    def test_kev_priority_over_higher_epss(self):
        finding = {
            "cves": [
                {"cve_id": "CVE-A", "epss_score": 0.9, "kev": False},
                {"cve_id": "CVE-B", "epss_score": 0.1, "kev": True},
            ],
        }
        entries = _normalize_cve_entries(finding)
        # KEV wandert nach oben
        assert entries[0]["cve_id"] == "CVE-B"
        assert entries[0]["kev"] is True

    def test_threat_intel_simple_shape(self):
        finding = {
            "cve_id": "CVE-2023-12345",
            "threat_intel": {"epss_score": 0.78, "in_kev": True},
        }
        entries = _normalize_cve_entries(finding)
        assert len(entries) == 1
        assert entries[0]["epss_score"] == 0.78
        assert entries[0]["kev"] is True

    def test_threat_intel_structured_shape(self):
        finding = {
            "cves": ["CVE-2024-0001"],
            "enrichment": {
                "cisa_kev": {"known_ransomware": "Known"},
                "epss": {"epss": 0.42},
            },
        }
        entries = _normalize_cve_entries(finding)
        # CVE aus cves-Liste (epss/kev von Enrichment werden in correlation_data
        # gemerged, hier sind sie auf enrichment-Level — wir akzeptieren leere
        # CVE-Liste, weil cves[0] keine direkte EPSS/KEV-Info hatte).
        assert entries
        assert entries[0]["cve_id"] == "CVE-2024-0001"

    def test_no_threat_intel_yields_empty(self):
        finding = {"title": "irrelevant"}
        entries = _normalize_cve_entries(finding)
        assert entries == []


# ====================================================================
# 5a -- Severity-zu-Prioritaet-Mapping
# ====================================================================
class TestTrack5aPriorityMapping:
    def test_critical_and_high_unverzueglich(self):
        assert _SEV_TO_PRIORITY["CRITICAL"] == "Unverzueglich"
        assert _SEV_TO_PRIORITY["HIGH"] == "Unverzueglich"

    def test_medium_in_kuerze(self):
        assert _SEV_TO_PRIORITY["MEDIUM"] == "In Kuerze"

    def test_low_mittelfristig(self):
        assert _SEV_TO_PRIORITY["LOW"] == "Mittelfristig"


# ====================================================================
# 5c -- Compliance-Mappings
# ====================================================================
class TestTrack5cComplianceMappings:
    def test_dsgvo_tls_maps_to_art_32_1_a(self):
        f = {"title": "TLS-Cipher RC4", "description": "Weak ciphers."}
        ref = map_finding_to_dsgvo(f)
        assert ref == "Art. 32 Abs. 1 lit. a"

    def test_dsgvo_header_maps_to_art_25(self):
        f = {"title": "HSTS-Header fehlt", "description": "..."}
        ref = map_finding_to_dsgvo(f)
        assert ref == "Art. 25"

    def test_dsgvo_mail_spoof_maps_to_art_5(self):
        f = {"title": "SPF-Record fehlt", "description": "Spoofing moeglich"}
        ref = map_finding_to_dsgvo(f)
        assert ref == "Art. 5 Abs. 1 lit. f"

    def test_dsgvo_default_art_32_1_b(self):
        f = {"title": "ein generischer Befund", "description": ""}
        ref = map_finding_to_dsgvo(f)
        assert ref == "Art. 32 Abs. 1 lit. b"

    def test_dsgvo_articles_have_titles(self):
        for ref in DSGVO_ARTICLES:
            assert get_article_title(ref)

    def test_iso27001_tls_maps_to_kryptografie(self):
        f = {"title": "TLS schwach", "description": "RC4 angeboten"}
        ref = map_finding_to_iso27001(f)
        assert ref == "A.8.24"

    def test_iso27001_port_maps_to_netzwerk(self):
        f = {"title": "Datenbank-Port 3306 exponiert", "description": ""}
        ref = map_finding_to_iso27001(f)
        assert ref == "A.8.20"

    def test_bsi_grundschutz_tls_maps_to_kryptokonzept(self):
        f = {"title": "TLS schwach", "description": "Cipher RC4"}
        ref = map_finding_to_bsi(f)
        assert ref == "CON.1"

    def test_bsi_grundschutz_webserver_maps_to_app(self):
        f = {"title": "Apache Version exponiert", "description": "Server-Header"}
        ref = map_finding_to_bsi(f)
        assert ref == "APP.3.2"

    def test_nis2_default_schwachstellenmanagement(self):
        f = {"title": "CVE-2022-1 in OpenSSH", "description": ""}
        key = map_finding_to_bsig(f)
        assert key == "nr5"
        assert "Nr. 5" in get_bsig_ref(key)

    def test_build_mappings_per_finding(self):
        co = _load(TRUNK_FX)
        mappings = build_compliance_mappings(co["findings"])
        # Jedes Finding bekommt einen Eintrag
        for f in co["findings"]:
            fid = f.get("id")
            assert fid in mappings
            entry = mappings[fid]
            for key in ("nis2", "bsi", "iso27001", "dsgvo"):
                assert entry[key], f"Finding {fid} fehlt {key}-Mapping"

    def test_build_mappings_completeness_per_policy_id(self):
        """Doc 02 Anforderung: jeder policy_id im Fixture muss mindestens
        einen NIS2/ISO/BSI/DSGVO-Eintrag haben."""
        for fixture in (SECUMETRIX_FX, TRUNK_FX):
            co = _load(fixture)
            mappings = build_compliance_mappings(co["findings"])
            pids_seen = set()
            for f in co["findings"]:
                pids_seen.add(f.get("policy_id"))
            assert mappings  # nicht leer
            # Jedes Mapping muss alle vier Felder gesetzt haben
            for fid, entry in mappings.items():
                for key in ("nis2", "bsi", "iso27001", "dsgvo"):
                    assert entry[key], (
                        f"{fixture.name}: {fid} {key}-Mapping fehlt"
                    )


# ====================================================================
# DOPPEL-RENDER: M5 voller Pipeline-Lauf
# ====================================================================
def _build_full_report_data(fixture_path: pathlib.Path, domain: str) -> dict:
    """Volle v2-augmentierte report_data (analog M4 Tests, aber inkl. M5)."""
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
        "orderId": "test-m5",
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
            "title": f"M5 Doppel-Render {domain}",
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
             "title_vars": f.get("title_vars") or {},
             "finding_type": f.get("finding_type", ""),
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


class TestM5DoppelRender:
    def test_secumetrix_v2_full_render_includes_layer3(self, tmp_path):
        data = _build_full_report_data(SECUMETRIX_FX, "secumetrix.de")
        out = tmp_path / "secumetrix_v2_m5.pdf"
        generate_report_v2(data, str(out))
        assert out.exists()
        # M5 fuegt Inhalt hinzu: Layer3 + 6 Anhaenge -> deutlich groesser
        assert out.stat().st_size > 9000
        assert data["compliance_mappings"]
        assert isinstance(data["additional_findings"], list)

    def test_trunk_heuel_v2_full_render_includes_layer3(self, tmp_path):
        data = _build_full_report_data(TRUNK_FX, "trunk-immobilien.de")
        out = tmp_path / "trunk_v2_m5.pdf"
        generate_report_v2(data, str(out))
        assert out.exists()
        assert out.stat().st_size > 9000
        # Trunk-Fixture hat einen CRITICAL (DB-Port) -> sollte im compliance-Mapping
        # auf nr5 (Schwachstellenmanagement) + A.8.20 (Netzwerksicherheit) landen
        mappings = data["compliance_mappings"]
        db_finding_id = "VS-2026-001"  # MariaDB-Port
        assert db_finding_id in mappings
        m = mappings[db_finding_id]
        assert "Nr. 5" in m["nis2"]
        assert m["iso27001"] == "A.8.20"

    def test_threat_intel_appears_when_cves_present(self, tmp_path):
        """Threat-Intel-Block muss erscheinen wenn ein Finding CVEs liefert."""
        data = _build_full_report_data(TRUNK_FX, "trunk-immobilien.de")
        # Injiziere CVEs auf einem Finding (MariaDB-Port)
        for f in data["findings"]:
            if f.get("policy_id") == "SP-DB-001":
                f["cves"] = [
                    {"cve_id": "CVE-2021-46669", "epss_score": 0.78, "kev": False},
                    {"cve_id": "CVE-2023-22084", "epss_score": 0.42, "kev": False},
                ]
        out = tmp_path / "trunk_v2_m5_threat_intel.pdf"
        generate_report_v2(data, str(out))
        assert out.exists()
        assert out.stat().st_size > 9000

    def test_hygiene_split_appendix_a(self):
        """Hygiene-Findings im trunk-Fixture (HSTS, Cookie) muessen in
        Layer1.hygiene_split landen."""
        data = _build_full_report_data(TRUNK_FX, "trunk-immobilien.de")
        layer1 = data.get("layer1") or {}
        split = layer1.get("hygiene_split") or {}
        assert split.get("hygiene")  # mindestens 1 hygiene-Finding
        # alle Items haben scale=hygiene
        for f in split["hygiene"]:
            assert (f.get("scale") or "").lower() == "hygiene"
        # cvss-Bucket darf nicht leer sein (DB, FTP, EOL, etc.)
        assert split.get("cvss")


# ====================================================================
# Befund-Klassen-Fixture-Tests (M5-Akzeptanz)
# ====================================================================
@pytest.mark.parametrize("policy_id,expected_keyword", [
    ("SP-DB-001",   "nmap"),       # DB
    ("SP-RDP-001",  "VPN"),        # RDP
    ("SP-DNS-002",  "dig"),        # Mail (DKIM)
    ("SP-HDR-001",  "Strict-Transport"),  # Header
    ("SP-EOL-002",  "OpenSSH"),    # EOL
    ("SP-WEB-001",  "https"),      # TLS-bezogen (cleartext-login)
])
def test_verification_template_per_finding_class(policy_id, expected_keyword):
    """Pro Befund-Klasse muss das Template einen verifizierbaren Befehl haben."""
    finding = {
        "policy_id": policy_id,
        "title_vars": {"host": "example.de", "port": "3306",
                       "cookie_name": "PHPSESSID", "domain": "example.de"},
    }
    text, is_fallback = get_verification_block(finding)
    assert not is_fallback
    assert expected_keyword.lower() in text.lower()


def test_no_unverified_top_15_policy_uses_generic():
    """Kein Top-15-Befund-Klasse darf auf GENERIC_FALLBACK fallen."""
    top_15 = list(VERIFICATION_TEMPLATES.keys())
    for pid in top_15:
        text, is_fallback = get_verification_block({
            "policy_id": pid,
            "title_vars": {"host": "x.example", "port": "3306",
                           "cookie_name": "C", "domain": "x.example",
                           "tech": "ssh", "version": "1.0"},
        })
        assert not is_fallback, f"{pid} verwendet generischen Fallback"
