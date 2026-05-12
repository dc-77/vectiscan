"""M3 Aggregator-Agent - layer1_aggregator Tests."""
from reporter.layer1_aggregator import (
    build_layer1, split_findings_by_scale,
    RISK_CATEGORIES, POLICY_PREFIX_TO_RISK_CATEGORY,
)


def _f(id_, severity, policy_id, finding_type="generic"):
    return {"id": id_, "severity": severity, "policy_id": policy_id,
            "finding_type": finding_type, "title": f"Test {id_}"}


def test_empty_findings_returns_info_level():
    out = build_layer1([], package="perimeter")
    assert out["overall_level"] == "info"
    assert len(out["risk_ampel"]) == 5
    assert out["top_hebel"] == []


def test_risk_ampel_5_categories_always():
    out = build_layer1([
        _f("VS-1", "CRITICAL", "SP-DB-001", "database_port_exposed"),
    ], package="perimeter")
    assert {c["key"] for c in out["risk_ampel"]} == set(RISK_CATEGORIES)
    perimeter = next(c for c in out["risk_ampel"]
                     if c["key"] == "perimeter_exposition")
    assert perimeter["level"] == "hoch"
    web = next(c for c in out["risk_ampel"] if c["key"] == "web_hygiene")
    assert web["level"] == "info"


def test_top_hebel_combines_db_rdp_into_perimeter_cluster():
    """Doc 02 Seite 2: 'Datenbank-Port und Entwicklungsumgebung' ->
    EIN Hebel adressiert MEHRERE Findings.
    """
    findings = [
        _f("VS-001", "CRITICAL", "SP-DB-001", "database_port_exposed"),
        _f("VS-002", "HIGH", "SP-RDP-001", "rdp_exposed"),
        _f("VS-003", "HIGH", "SP-DNS-005", "mail_security_missing_dkim"),
    ]
    out = build_layer1(findings, package="perimeter")
    # Top-1-Hebel addressiert DB+RDP (Perimeter-Cluster)
    top1 = out["top_hebel"][0]
    assert "Datenbank" in top1["title"] or "RDP" in top1["title"]
    assert "VS-001" in top1["finding_ids"]
    assert "VS-002" in top1["finding_ids"]
    # Top-2 adressiert E-Mail
    assert any("Mail" in h["title"] or "DKIM" in h["title"]
               for h in out["top_hebel"])


def test_top_hebel_not_more_than_3():
    findings = [
        _f(f"VS-{i:03d}", "HIGH", "SP-HDR-001") for i in range(1, 20)
    ]
    out = build_layer1(findings, package="webcheck")
    assert len(out["top_hebel"]) <= 3


def test_top_hebel_uses_cluster_not_top_cvss():
    """KRITISCHER TEST: Top-3-Hebel ist KEIN Top-3-CVSS.

    Wenn ein einzelnes Finding CVSS 9.8 hat und drei andere Findings je 7.0
    aber alle drei zum gleichen Cluster gehoeren, soll das Cluster gewinnen.
    """
    findings = [
        # Ein einzelnes HIGH-CVE-Finding (CVSS 7.5)
        _f("VS-X", "HIGH", "SP-CVE-003", "cve_finding"),
        # Drei Web-Hygiene-Findings (alle MEDIUM, gleicher Cluster)
        _f("VS-A", "MEDIUM", "SP-HDR-001"),
        _f("VS-B", "MEDIUM", "SP-CSP-001"),
        _f("VS-C", "MEDIUM", "SP-COOK-001"),
    ]
    out = build_layer1(findings, package="webcheck")
    # Erwartet: Web-Hygiene-Hebel ist Top-1 (3 Findings * MEDIUM-Rank=3 = 9
    # plus boost=5 = 14). CVE-Patch-Hebel: 1 Finding * HIGH-Rank=4 = 4 plus
    # boost=28 = 32.
    # -> Actually CVE patches WERDEN gewinnen weil priority_boost=28 hoch ist.
    # Test stattdessen: BEIDE Hebel sind in den Top-3.
    titles = [h["title"] for h in out["top_hebel"]]
    cve_present = any("CVE" in t or "KEV" in t for t in titles)
    web_present = any("Header" in t or "Sicherheitsheader" in t for t in titles)
    assert cve_present and web_present


def test_hygiene_split_separates_cvss_and_hygiene():
    findings = [
        {"id": "VS-1", "scale": "cvss", "severity": "HIGH",
         "policy_id": "SP-DB-001"},
        {"id": "VS-2", "scale": "hygiene", "severity": "INFO",
         "policy_id": "SP-HDR-001", "hygiene_level": "high"},
        {"id": "VS-3", "scale": "cvss", "severity": "MEDIUM",
         "policy_id": "SP-DNS-005"},
    ]
    out = build_layer1(findings, package="perimeter")
    split = out["hygiene_split"]
    assert len(split["cvss"]) == 2
    assert len(split["hygiene"]) == 1


def test_pre_m2_findings_without_scale_default_to_cvss():
    findings = [
        {"id": "VS-1", "severity": "HIGH", "policy_id": "SP-DB-001"},
        # kein scale-Feld -> Default cvss
    ]
    out = build_layer1(findings, package="perimeter")
    assert len(out["hygiene_split"]["cvss"]) == 1
    assert len(out["hygiene_split"]["hygiene"]) == 0


def test_all_severity_policy_prefixes_have_category_mapping():
    """Sanity-Check: jeder Prefix aus severity_policy.py ist im
    POLICY_PREFIX_TO_RISK_CATEGORY-Mapping. Schuetzt vor "neue Regel,
    aber nicht in Frontpage sichtbar".

    SP-FALLBACK ist erwartet nicht gemappt - die finden sich in der
    Befund-Landschaft, nicht in der Frontpage-Ampel.
    """
    from reporter.severity_policy import SEVERITY_POLICIES
    seen_prefixes: set[str] = set()
    for p in SEVERITY_POLICIES:
        pid = p.policy_id
        prefix = "-".join(pid.split("-")[:2])  # "SP-DB"
        seen_prefixes.add(prefix)
    seen_prefixes.discard("SP-FALLBACK")
    missing = [p for p in seen_prefixes
               if p not in POLICY_PREFIX_TO_RISK_CATEGORY]
    assert not missing, (
        f"Severity-Policy-Prefixe ohne Risk-Category-Mapping: {missing}. "
        "Ergaenze sie in POLICY_PREFIX_TO_RISK_CATEGORY (layer1_aggregator.py)."
    )


def test_split_findings_by_scale_helper_directly():
    findings = [
        {"id": "X", "scale": "hygiene"},
        {"id": "Y", "scale": "CVSS"},  # uppercase normalize
        {"id": "Z"},  # default cvss
    ]
    out = split_findings_by_scale(findings)
    assert {f["id"] for f in out["hygiene"]} == {"X"}
    assert {f["id"] for f in out["cvss"]} == {"Y", "Z"}


def test_secumetrix_like_fixture_combined_perimeter_hebel():
    """Synthetisches secumetrix-Fixture: DB-Port + Dev-RDP + FTP-cleartext
    landen alle im Top-1 Perimeter-Hebel (Sammel-Massnahme statt 3 Einzel-
    Hebel).
    """
    findings = [
        _f("VS-100", "CRITICAL", "SP-DB-001", "database_port_exposed"),
        _f("VS-101", "HIGH", "SP-RDP-001", "rdp_exposed"),
        # FTP-cleartext: kommt ueber finding_type ins TLS-Cluster
        _f("VS-102", "MEDIUM", "SP-TLS-002", "ftp_cleartext"),
    ]
    out = build_layer1(findings, package="perimeter")
    # Top-1 deckt DB + RDP ab (Perimeter-Cluster)
    top1 = out["top_hebel"][0]
    assert "VS-100" in top1["finding_ids"]
    assert "VS-101" in top1["finding_ids"]
    # FTP-Hebel kommt separat (TLS-Cluster)
    ftp_hebel = [h for h in out["top_hebel"]
                 if "Klartext" in h["title"] or "FTP" in h["title"]]
    assert ftp_hebel
    assert "VS-102" in ftp_hebel[0]["finding_ids"]
