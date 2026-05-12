"""M2 Track 2d — Severity-Policy v2 + neue Regeln.

Pruft:
- POLICY_VERSION bump auf 2026-06-01.1
- SP-RDP-001/002/003 (RDP-Exposure neu)
- SP-DB-001 mit C:H/I:H/A:H + SP-DB-002 (EOL) + SP-DB-003 (multi-host)
- SP-EOL-005 (EOL + internet-facing + tech_critical)
- Neue Context-Flags: count_hosts_gt_one, is_eol, is_internet_facing,
  tech_critical
"""
from reporter.severity_policy import (
    apply_policy,
    extract_context_flags,
    POLICY_VERSION,
)


def test_policy_version_bumped():
    assert POLICY_VERSION == "2026-06-01.1"


def test_rdp_default_is_high_8_1():
    findings = [{
        "id": "VS-001",
        "finding_type": "rdp_exposed",
        "affected": "1.2.3.4",
        "evidence": {},
    }]
    apply_policy(findings, scan_context={})
    f = findings[0]
    assert f.get("policy_id") == "SP-RDP-001"
    assert f.get("severity", "").lower() == "high"
    # CVSS bleibt vom Vektor abhaengig - 8.1 nach Track 2a
    assert "C:H" in (f.get("cvss_vector") or "")


def test_rdp_multi_host_critical():
    findings = [{
        "id": "VS-002",
        "finding_type": "rdp_exposed",
        "affected": "1.2.3.4, 5.6.7.8",
        "affected_hosts": ["1.2.3.4", "5.6.7.8"],
        "evidence": {},
    }]
    apply_policy(findings, scan_context={})
    f = findings[0]
    assert f.get("policy_id") == "SP-RDP-002"


def test_rdp_eol_critical():
    findings = [{
        "id": "VS-RDP-EOL",
        "finding_type": "rdp_exposed",
        "affected": "1.2.3.4",
        "evidence": {"is_eol": True},
    }]
    apply_policy(findings, scan_context={})
    f = findings[0]
    assert f.get("policy_id") == "SP-RDP-003"
    assert f.get("severity", "").lower() == "critical"


def test_db_eol_is_critical():
    findings = [{
        "id": "VS-003",
        "finding_type": "database_port_exposed",
        "affected": "1.2.3.4",
        "evidence": {"is_eol": True, "tech": "mariadb"},
    }]
    apply_policy(findings, scan_context={})
    f = findings[0]
    assert f.get("policy_id") == "SP-DB-002"
    assert f.get("severity", "").lower() == "critical"


def test_db_default_impact_chi_i_a():
    findings = [{
        "id": "VS-004",
        "finding_type": "database_port_exposed",
        "affected": "1.2.3.4",
        "evidence": {"tech": "postgres"},
    }]
    apply_policy(findings, scan_context={})
    f = findings[0]
    v = f.get("cvss_vector") or ""
    assert "C:H" in v
    assert "I:H" in v
    assert "A:H" in v


def test_db_multi_host_critical():
    findings = [{
        "id": "VS-DB-MH",
        "finding_type": "database_port_exposed",
        "affected": "1.2.3.4, 5.6.7.8",
        "affected_hosts": ["1.2.3.4", "5.6.7.8"],
        "evidence": {"tech": "mysql"},
    }]
    apply_policy(findings, scan_context={})
    f = findings[0]
    assert f.get("policy_id") == "SP-DB-003"
    assert f.get("severity", "").lower() == "critical"


def test_context_flag_is_eol_from_tech_profiles():
    f = {
        "id": "VS-X",
        "finding_type": "database_port_exposed",
        "affected": "1.2.3.4:3306",
        "evidence": {},
    }
    sc = {
        "tech_profiles": [{
            "ip": "1.2.3.4",
            "tech_rows": [{"name": "mariadb", "version": "5.5",
                           "patch_status": "eol"}],
        }],
    }
    flags = extract_context_flags(f, sc)
    assert flags.get("is_eol") is True


def test_context_flag_count_hosts_gt_one():
    f = {
        "id": "VS-CH",
        "finding_type": "rdp_exposed",
        "affected": "10.0.0.1, 10.0.0.2, 10.0.0.3",
        "affected_hosts": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        "evidence": {},
    }
    flags = extract_context_flags(f, {})
    assert flags.get("count_hosts_gt_one") is True


def test_context_flag_count_hosts_single():
    f = {
        "id": "VS-CH-1",
        "finding_type": "rdp_exposed",
        "affected": "10.0.0.1",
        "affected_hosts": ["10.0.0.1"],
        "evidence": {},
    }
    flags = extract_context_flags(f, {})
    assert "count_hosts_gt_one" not in flags or not flags["count_hosts_gt_one"]


def test_context_flag_is_internet_facing_default_true():
    f = {
        "id": "VS-IF",
        "finding_type": "software_eol",
        "affected": "exchange.example.com",
        "evidence": {},
    }
    flags = extract_context_flags(f, {})
    assert flags.get("is_internet_facing") is True


def test_context_flag_is_internet_facing_explicit_false():
    f = {
        "id": "VS-IF-NO",
        "finding_type": "software_eol",
        "affected": "internal-host",
        "evidence": {"is_internet_facing": False},
    }
    flags = extract_context_flags(f, {})
    assert flags.get("is_internet_facing") is False


def test_context_flag_tech_critical_db():
    f = {
        "id": "VS-TC",
        "finding_type": "software_eol",
        "affected": "1.2.3.4",
        "evidence": {"tech": "mariadb 5.5"},
    }
    flags = extract_context_flags(f, {})
    assert flags.get("tech_critical") is True


def test_context_flag_tech_critical_negative():
    f = {
        "id": "VS-TC-NO",
        "finding_type": "software_eol",
        "affected": "1.2.3.4",
        "evidence": {"tech": "phpmyadmin"},
    }
    flags = extract_context_flags(f, {})
    # phpmyadmin matched nicht die Critical-Liste exakt
    assert flags.get("tech_critical") is not True


def test_eol_internet_facing_critical_db():
    """E2E: EOL-Software-Finding mit DB-Tech -> SP-EOL-005 CRITICAL."""
    findings = [{
        "id": "VS-EOL-DB",
        "finding_type": "software_eol",
        "affected": "1.2.3.4",
        "evidence": {"tech": "mariadb 5.5"},
    }]
    apply_policy(findings, scan_context={})
    f = findings[0]
    assert f.get("policy_id") == "SP-EOL-005"
    assert f.get("severity", "").lower() == "critical"
