"""Tests for SP-URLHAUS-001 (F-P0A-003).

Validates that the URLhaus Compromise-Detection-Policy is wired into the
severity-policy registry and produces deterministic CRITICAL severities,
with the expected CVSS, rationale and references.
"""

from reporter.severity_policy import (
    POLICY_VERSION,
    SEVERITY_POLICIES,
    Severity,
    apply_policy,
    lookup_policy,
)
from reporter.business_impact import POLICY_ID_TO_CATEGORIES
from reporter.title_policy import TITLE_TEMPLATES
from reporter.ai_finding_type_fallback import FINDING_TYPE_CATALOG
from reporter.finding_type_mapper import map_finding_type


def test_policy_version_bumped():
    """POLICY_VERSION must be at least 2026-05-10.1 once F-P0A-003 lands."""
    assert POLICY_VERSION >= "2026-05-10.1"


def test_sp_urlhaus_001_in_registry():
    ids = [p.policy_id for p in SEVERITY_POLICIES]
    assert "SP-URLHAUS-001" in ids


def test_sp_urlhaus_001_lookup_critical():
    policy = lookup_policy("urlhaus_compromise_detected", {})
    assert policy is not None
    assert policy.policy_id == "SP-URLHAUS-001"
    assert policy.final_severity == Severity.CRITICAL
    assert policy.cvss_score == 10.0
    assert "URLhaus" in policy.references


def test_sp_urlhaus_001_business_impact_categories():
    assert POLICY_ID_TO_CATEGORIES["SP-URLHAUS-001"] == {
        "data_exposure", "access_control",
    }


def test_sp_urlhaus_001_title_template_present():
    assert "SP-URLHAUS-001" in TITLE_TEMPLATES
    template = TITLE_TEMPLATES["SP-URLHAUS-001"]
    assert "{host}" in template


def test_finding_type_catalog_has_urlhaus_entry():
    assert "urlhaus_compromise_detected" in FINDING_TYPE_CATALOG


def test_finding_type_mapper_recognises_urlhaus_text():
    finding = {
        "title": "Host bei URLhaus als kompromittiert gelistet",
        "description": "URLhaus listet 3 aktive Malware-Distribution-URLs",
    }
    assert map_finding_type(finding) == "urlhaus_compromise_detected"


def test_finding_type_mapper_does_not_misclassify_ftp_cleartext_as_urlhaus():
    """Regression M6.18: das Pattern '(?:host|domain).*kompromit' war zu
    greedy und matchte greedy bis 'kompromittiertes Zwischennetz' im
    Impact-Text. Damit wurde der echte FTP-Befund als URLhaus klassifiziert.
    """
    ftp = {
        "title": "FTP-Dienst (Port 21) im Klartext exponiert auf 20.79.218.75",
        "description": (
            "Auf dem Host 20.79.218.75, der die EDI- und Mail-"
            "Webschnittstellen bedient, ist Port 21 (FTP) oeffentlich "
            "erreichbar."
        ),
        "impact": (
            "Ein Angreifer mit Netzwerkzugriff (z.B. im selben WLAN oder "
            "ueber ein kompromittiertes Zwischennetz) kann FTP-Anmeldedaten "
            "mitlesen."
        ),
    }
    result = map_finding_type(ftp)
    assert result != "urlhaus_compromise_detected", (
        f"FTP-Cleartext-Befund wurde faelschlich als URLhaus klassifiziert: {result}"
    )


def test_finding_type_mapper_recognises_host_kompromittiert_direct():
    """Engerer Pattern-Match: 'Host wird aktiv kompromittiert' direkt
    benannt soll weiterhin urlhaus_compromise_detected matchen."""
    finding = {
        "title": "Host wird aktiv kompromittiert",
        "description": "Beobachtet C2-Verkehr von 192.0.2.1",
    }
    assert map_finding_type(finding) == "urlhaus_compromise_detected"


def test_apply_policy_sets_critical_severity_for_urlhaus_finding():
    findings = [{
        "finding_type": "urlhaus_compromise_detected",
        "title": "Compromise on bad.example.com",
        "description": "Host bei URLhaus aktiv gelistet",
        "severity": "high",      # Tool-Severity wird ueberschrieben
        "tool_source": "phase0a",
    }]
    apply_policy(findings, scan_context={})
    assert findings[0]["severity"] == "critical"
    assert findings[0]["policy_id"] == "SP-URLHAUS-001"
    assert findings[0]["cvss_score"] == 10.0
    prov = findings[0]["severity_provenance"]
    assert prov["policy_id"] == "SP-URLHAUS-001"
    assert prov["policy_decision"] == "critical"
    assert "URLhaus" in str(prov["rule_references"])
