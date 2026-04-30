"""Deterministische, auditierbare Severity-Vergabe.

Spec: docs/deterministic/02-severity-policy.md

Vorgesehener Aufruf-Punkt:
    findings = severity_policy.apply_policy(findings, scan_context)
in report-worker/reporter/worker.py NACH der Phase-3-Korrelation und
VOR business_impact.recompute().

POLICY_VERSION wird in DB-Spalte reports.policy_version festgehalten und
bei Cache-Invalidierung im AI-Cache verwendet.
"""

from __future__ import annotations

import logging
import os
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

# ====================================================================
# POLICY VERSION
# ====================================================================
# Bei jeder Aenderung der Regeln HIER hochziehen. Wird im AI-Cache-Key
# eingebaut, damit Cache nach Policy-Update automatisch invalidiert.
POLICY_VERSION = os.environ.get("VECTISCAN_POLICY_VERSION", "2026-04-30.1")


# ====================================================================
# ENUMS
# ====================================================================
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_cvss(cls, cvss: float) -> "Severity":
        """CVSS 3.1 to severity mapping (NIST/FIRST.org)."""
        if cvss >= 9.0:
            return cls.CRITICAL
        if cvss >= 7.0:
            return cls.HIGH
        if cvss >= 4.0:
            return cls.MEDIUM
        if cvss >= 0.1:
            return cls.LOW
        return cls.INFO

    def rank(self) -> int:
        """For sorting: higher = more severe."""
        return {
            "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
        }[self.value]


# CVSS-Range pro Severity zur Cap-Logik (untere und obere Schranke).
SEVERITY_CVSS_RANGE: dict[Severity, tuple[float, float]] = {
    Severity.CRITICAL: (9.0, 10.0),
    Severity.HIGH:     (7.0, 8.9),
    Severity.MEDIUM:   (4.0, 6.9),
    Severity.LOW:      (0.1, 3.9),
    Severity.INFO:     (0.0, 0.0),
}


# ====================================================================
# SCHEMA
# ====================================================================
class SeverityPolicy(BaseModel):
    """Eine einzelne Policy-Regel.

    matches_when ist ein Dict mit context-flag-Bedingungen, die ALLE
    erfuellt sein muessen. Ein leeres Dict bedeutet "matcht immer".
    Stringwerte werden als exact-match interpretiert. Bool-Werte ebenfalls.
    Listen-Werte als "value IN list".
    """
    policy_id: str = Field(..., pattern=r"^SP-[A-Z]+-\d{3}$")
    finding_type: str
    matches_when: dict[str, Any] = Field(default_factory=dict)
    final_severity: Severity
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    rationale: str
    references: list[str] = Field(default_factory=list)
    overrides_tool_severity: bool = True

    @field_validator("policy_id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        return v


class SeverityProvenance(BaseModel):
    """Wird auf jedes Finding gehaengt fuer Audit-Trail."""
    policy_id: str
    policy_decision: Severity
    policy_version: str = POLICY_VERSION
    tool_severities: dict[str, str] = Field(default_factory=dict)
    context_flags: dict[str, Any] = Field(default_factory=dict)
    rationale: str
    rule_references: list[str] = Field(default_factory=list)


# ====================================================================
# REGEL-REGISTRY (40 Regeln, kalibriert gegen Rapid7/Acunetix-Baseline)
# ====================================================================
SEVERITY_POLICIES: list[SeverityPolicy] = [
    # ----------------------------------------------------------------
    # HEADER (SP-HDR-*)
    # ----------------------------------------------------------------
    SeverityPolicy(
        policy_id="SP-HDR-001",
        finding_type="hsts_missing",
        matches_when={"is_session_path": False},
        final_severity=Severity.INFO,
        cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
        cvss_score=0.0,
        rationale="Statische Seite ohne Session - HSTS-Fehlen ist Hardening-Issue, kein praktisches Risiko",
        references=["CWE-523", "OWASP2025-A02"],
    ),
    SeverityPolicy(
        policy_id="SP-HDR-002",
        finding_type="hsts_missing",
        matches_when={"is_session_path": True},
        final_severity=Severity.LOW,
        cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        cvss_score=2.6,
        rationale="Session-bearing path ohne HSTS - SSL-Stripping-Risiko bei MitM",
        references=["CWE-523", "OWASP2025-A02", "OWASP2021-A05"],
    ),
    SeverityPolicy(
        policy_id="SP-HDR-003",
        finding_type="hsts_no_includesubdomains",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="HSTS aktiviert aber Subdomains nicht eingeschlossen - Hardening",
        references=["CWE-523"],
    ),
    SeverityPolicy(
        policy_id="SP-HDR-004",
        finding_type="hsts_short_maxage",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="HSTS max-age < 6 Monate - Best-Practice-Verstoss ohne praktisches Risiko",
        references=["CWE-523"],
    ),
    SeverityPolicy(
        policy_id="SP-HDR-005",
        finding_type="xcto_missing",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="X-Content-Type-Options fehlt - MIME-Sniffing-Risiko nur in alten Browsern",
        references=["CWE-693", "OWASP2025-A06"],
    ),
    SeverityPolicy(
        policy_id="SP-HDR-006",
        finding_type="xfo_missing",
        matches_when={"is_session_path": False},
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="Clickjacking-Schutz fehlt, aber keine Session-Pages - theoretisches Risiko",
        references=["CWE-1021"],
    ),
    SeverityPolicy(
        policy_id="SP-HDR-007",
        finding_type="xfo_missing",
        matches_when={"is_session_path": True},
        final_severity=Severity.LOW,
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        cvss_score=3.1,
        rationale="Clickjacking-Schutz fehlt auf Session-Path - UI-Redress-Risiko",
        references=["CWE-1021", "OWASP2025-A06"],
    ),
    SeverityPolicy(
        policy_id="SP-HDR-008",
        finding_type="referrer_policy_missing",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="Privacy-Hardening - kein direktes Sicherheitsrisiko",
        references=["CWE-200"],
    ),
    SeverityPolicy(
        policy_id="SP-HDR-009",
        finding_type="permissions_policy_missing",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="Browser-Feature-Policy nicht restriktiv gesetzt - Hardening",
        references=["CWE-693"],
    ),

    # ----------------------------------------------------------------
    # CONTENT SECURITY POLICY (SP-CSP-*)
    # ----------------------------------------------------------------
    SeverityPolicy(
        policy_id="SP-CSP-001",
        finding_type="csp_missing",
        matches_when={"inline_scripts": False, "form_present": False},
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="Statische Seite ohne inline-Scripts oder Forms - kein praktisches XSS-Risiko",
        references=["CWE-693", "OWASP2025-A05"],
    ),
    SeverityPolicy(
        policy_id="SP-CSP-002",
        finding_type="csp_missing",
        matches_when={"form_present": True},
        final_severity=Severity.LOW,
        cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=3.8,
        rationale="Form-Page ohne CSP - wenn XSS-Luecke existiert, fehlt zusaetzliche Schutzschicht",
        references=["CWE-693", "OWASP2025-A05", "OWASP2021-A05"],
    ),
    SeverityPolicy(
        policy_id="SP-CSP-003",
        finding_type="csp_unsafe_inline",
        matches_when={"form_present": True},
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=5.4,
        rationale="CSP erlaubt unsafe-inline auf Form-Page - schwaecht XSS-Schutz signifikant",
        references=["CWE-693", "OWASP2025-A05"],
    ),
    SeverityPolicy(
        policy_id="SP-CSP-004",
        finding_type="csp_unsafe_eval",
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=5.4,
        rationale="CSP erlaubt unsafe-eval - eval()-basierte XSS moeglich",
        references=["CWE-95", "OWASP2025-A05"],
    ),
    SeverityPolicy(
        policy_id="SP-CSP-005",
        finding_type="csp_wildcard_source",
        final_severity=Severity.LOW,
        cvss_score=3.1,
        rationale="Wildcard `*` in CSP source-list schwaecht Whitelisting",
        references=["CWE-693"],
    ),

    # ----------------------------------------------------------------
    # COOKIES (SP-COOK-*)
    # ----------------------------------------------------------------
    SeverityPolicy(
        policy_id="SP-COOK-001",
        finding_type="cookie_no_secure",
        matches_when={"cookie_session": True, "https_in_use": True},
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=5.9,
        rationale="Session-Cookie ohne Secure-Flag auf HTTPS-Site - ueber HTTP uebertragbar",
        references=["CWE-614", "OWASP2025-A02"],
    ),
    SeverityPolicy(
        policy_id="SP-COOK-002",
        finding_type="cookie_no_httponly",
        matches_when={"cookie_session": True},
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
        cvss_score=5.7,
        rationale="Session-Cookie ohne HttpOnly - XSS kann Session-Token lesen",
        references=["CWE-1004", "OWASP2025-A07"],
    ),
    SeverityPolicy(
        policy_id="SP-COOK-003",
        finding_type="cookie_no_samesite",
        matches_when={"cookie_session": True},
        final_severity=Severity.LOW,
        cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
        cvss_score=2.6,
        rationale="Session-Cookie ohne SameSite - CSRF-Mitigation-Layer fehlt",
        references=["CWE-352", "CWE-1275", "OWASP2025-A01"],
    ),
    SeverityPolicy(
        policy_id="SP-COOK-004",
        finding_type="cookie_no_secure",
        matches_when={"cookie_session": False},
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="Tracking-Cookie ohne Secure - kein Auth-Risiko",
        references=["CWE-614"],
    ),
    SeverityPolicy(
        policy_id="SP-COOK-005",
        finding_type="cookie_no_samesite",
        matches_when={"cookie_session": False},
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="Tracking-Cookie ohne SameSite - kein State-Change-Vektor",
        references=["CWE-1275"],
    ),

    # ----------------------------------------------------------------
    # CSRF (SP-CSRF-*)
    # ----------------------------------------------------------------
    SeverityPolicy(
        policy_id="SP-CSRF-001",
        finding_type="csrf_token_missing",
        matches_when={"state_change": False},
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="Form ist GET-only oder ohne State-Change - kein CSRF-Vektor",
        references=["CWE-352"],
    ),
    SeverityPolicy(
        policy_id="SP-CSRF-002",
        finding_type="csrf_token_missing",
        matches_when={"state_change": True, "auth_present": False},
        final_severity=Severity.LOW,
        cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
        cvss_score=2.6,
        rationale="State-Change ohne Auth - CSRF moeglich, aber Schaden begrenzt",
        references=["CWE-352", "OWASP2025-A01"],
    ),
    SeverityPolicy(
        policy_id="SP-CSRF-003",
        finding_type="csrf_token_missing",
        matches_when={"state_change": True, "auth_present": True},
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:H/A:N",
        cvss_score=5.4,
        rationale="Authenticated state-change ohne CSRF-Token - Account-Takeover-Risiko",
        references=["CWE-352", "OWASP2025-A01"],
    ),

    # ----------------------------------------------------------------
    # INFORMATION DISCLOSURE (SP-DISC-*)
    # ----------------------------------------------------------------
    SeverityPolicy(
        policy_id="SP-DISC-001",
        finding_type="server_banner_with_version",
        final_severity=Severity.LOW,
        cvss_score=2.0,
        rationale="Server-Banner verraet Version - Recon-Vorteil fuer Angreifer",
        references=["CWE-200", "CWE-497"],
    ),
    SeverityPolicy(
        policy_id="SP-DISC-002",
        finding_type="server_banner_no_version",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="Server-Banner ohne Version - generische Information",
        references=["CWE-200"],
    ),
    SeverityPolicy(
        policy_id="SP-DISC-003",
        finding_type="nginx_status_endpoint_open",
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=5.3,
        rationale="Internal-Stats-Endpoint oeffentlich - Internals leaken",
        references=["CWE-200", "CWE-538"],
    ),
    SeverityPolicy(
        policy_id="SP-DISC-004",
        finding_type="phpinfo_exposed",
        final_severity=Severity.HIGH,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=7.5,
        rationale="phpinfo() exposed - komplette Server-Konfiguration, Pfade, Versionen",
        references=["CWE-200", "CWE-497", "OWASP2025-A05"],
    ),
    SeverityPolicy(
        policy_id="SP-DISC-005",
        finding_type="directory_listing_enabled",
        final_severity=Severity.LOW,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=3.7,
        rationale="Directory-Listing aktiv - File-Discovery erleichtert",
        references=["CWE-548"],
    ),
    SeverityPolicy(
        policy_id="SP-DISC-006",
        finding_type="error_message_with_stack",
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=5.3,
        rationale="Stack-Traces in Fehlerseiten - Pfade, Versionen, Lib-Names leaken",
        references=["CWE-209", "CWE-497"],
    ),
    SeverityPolicy(
        policy_id="SP-DISC-007",
        finding_type="git_directory_exposed",
        final_severity=Severity.HIGH,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=7.5,
        rationale=".git/-Verzeichnis oeffentlich - Source-Code-Leak moeglich",
        references=["CWE-538", "OWASP2025-A05"],
    ),
    SeverityPolicy(
        policy_id="SP-DISC-008",
        finding_type="env_file_exposed",
        final_severity=Severity.CRITICAL,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=9.8,
        rationale=".env-Datei oeffentlich - API-Keys, DB-Credentials, Secrets exposed",
        references=["CWE-538", "CWE-200", "OWASP2025-A05"],
    ),

    # ----------------------------------------------------------------
    # TLS (SP-TLS-*)
    # ----------------------------------------------------------------
    SeverityPolicy(
        policy_id="SP-TLS-001",
        finding_type="tls_below_tr03116_minimum",
        final_severity=Severity.HIGH,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=7.4,
        rationale="TLS-Version unter BSI TR-03116-4 Minimum - Compliance-Verstoss",
        references=["BSI-TR-03116-4", "CWE-326"],
    ),
    SeverityPolicy(
        policy_id="SP-TLS-002",
        finding_type="tls_weak_cipher_suites",
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=5.9,
        rationale="Schwache Cipher-Suiten verfuegbar - Man-in-the-Middle-Angriffe moeglich",
        references=["CWE-327", "CWE-326"],
    ),
    SeverityPolicy(
        policy_id="SP-TLS-003",
        finding_type="tls_no_pfs",
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=5.9,
        rationale="Perfect Forward Secrecy fehlt - bei Key-Compromise ist alle Historie lesbar",
        references=["CWE-310"],
    ),
    SeverityPolicy(
        policy_id="SP-TLS-004",
        finding_type="tls_certificate_expired",
        final_severity=Severity.HIGH,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        cvss_score=7.5,
        rationale="TLS-Zertifikat abgelaufen - Browser-Warnung, User akzeptieren = MitM",
        references=["CWE-298", "CWE-295"],
    ),
    SeverityPolicy(
        policy_id="SP-TLS-005",
        finding_type="tls_certificate_expiring_30d",
        final_severity=Severity.LOW,
        cvss_score=2.0,
        rationale="TLS-Zertifikat laeuft in <30 Tagen ab - Erneuerung erforderlich",
        references=["CWE-298"],
    ),
    SeverityPolicy(
        policy_id="SP-TLS-006",
        finding_type="tls_self_signed",
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
        cvss_score=5.7,
        rationale="Self-signed Zertifikat in oeffentlicher PKI - keine Vertrauenskette",
        references=["CWE-295", "CWE-296"],
    ),
    SeverityPolicy(
        policy_id="SP-TLS-007",
        finding_type="hsts_preload_missing",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="HSTS-Preload-List-Eintrag fehlt - Hardening, kein direktes Risiko",
        references=["CWE-523"],
    ),

    # ----------------------------------------------------------------
    # DNS / MAIL (SP-DNS-*)
    # ----------------------------------------------------------------
    SeverityPolicy(
        policy_id="SP-DNS-001",
        finding_type="dnssec_missing",
        final_severity=Severity.LOW,
        cvss_score=3.1,
        rationale="DNSSEC nicht aktiviert - DNS-Spoofing-Risiko",
        references=["CWE-345", "CWE-290"],
    ),
    SeverityPolicy(
        policy_id="SP-DNS-002",
        finding_type="dnssec_chain_broken",
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        cvss_score=5.9,
        rationale="DNSSEC aktiviert aber Chain-of-Trust gebrochen - false sense of security",
        references=["CWE-345"],
    ),
    SeverityPolicy(
        policy_id="SP-DNS-003",
        finding_type="caa_missing",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="CAA-Record fehlt - kein autorisierter CA festgelegt",
        references=["CWE-295"],
    ),
    SeverityPolicy(
        policy_id="SP-DNS-004",
        finding_type="spf_missing",
        matches_when={"mx_present": True},
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        cvss_score=4.7,
        rationale="SPF fehlt fuer Mail-Domain - Spoofing-Schutz fehlt",
        references=["CWE-290"],
    ),
    SeverityPolicy(
        policy_id="SP-DNS-005",
        finding_type="spf_softfail",
        final_severity=Severity.LOW,
        cvss_score=3.1,
        rationale="SPF mit ~all (softfail) statt -all (hardfail) - schwacher Schutz",
        references=["CWE-290"],
    ),
    SeverityPolicy(
        policy_id="SP-DNS-006",
        finding_type="dmarc_missing",
        matches_when={"mx_present": True},
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        cvss_score=4.7,
        rationale="DMARC fehlt fuer Mail-Domain - Phishing-Schutz fehlt",
        references=["CWE-290"],
    ),
    SeverityPolicy(
        policy_id="SP-DNS-007",
        finding_type="dmarc_p_none",
        final_severity=Severity.LOW,
        cvss_score=3.1,
        rationale="DMARC mit p=none - nur Monitoring, keine Durchsetzung",
        references=["CWE-290"],
    ),
    SeverityPolicy(
        policy_id="SP-DNS-008",
        finding_type="dkim_missing",
        matches_when={"mx_present": True},
        final_severity=Severity.LOW,
        cvss_score=3.1,
        rationale="DKIM-Signierung fehlt - Mail-Authentifizierung schwaecher",
        references=["CWE-290"],
    ),
    SeverityPolicy(
        policy_id="SP-DNS-009",
        finding_type="mta_sts_missing",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="MTA-STS-Policy fehlt - Mail-TLS-Hardening optional",
        references=["RFC-8461"],
    ),

    # ----------------------------------------------------------------
    # CVE-DRIVEN (SP-CVE-*)
    # SP-CVE-004 ist KEINE statische Regel — siehe apply_policy_for_cve().
    # ----------------------------------------------------------------
    SeverityPolicy(
        policy_id="SP-CVE-001",
        finding_type="cve_finding",
        matches_when={"cve_in_kev": True},
        final_severity=Severity.CRITICAL,
        rationale="CVE in CISA Known Exploited Vulnerabilities - aktive Ausnutzung beobachtet",
        references=["CISA-KEV"],
    ),
    SeverityPolicy(
        policy_id="SP-CVE-002",
        finding_type="cve_finding",
        matches_when={"cve_ransomware": True},
        final_severity=Severity.CRITICAL,
        rationale="CVE mit Ransomware-Verbindung - hoechstes Risiko fuer KMU",
        references=["CISA-KEV-Ransomware"],
    ),
    SeverityPolicy(
        policy_id="SP-CVE-003",
        finding_type="cve_finding",
        matches_when={"cve_epss_high": True},
        final_severity=Severity.HIGH,
        rationale="CVE mit hoher Exploit-Wahrscheinlichkeit (EPSS > 0.5)",
        references=["EPSS"],
    ),

    # ----------------------------------------------------------------
    # EOL SOFTWARE (SP-EOL-*)
    # ----------------------------------------------------------------
    SeverityPolicy(
        policy_id="SP-EOL-001",
        finding_type="software_eol",
        matches_when={"tech": "exchange"},
        final_severity=Severity.HIGH,
        # CVSS bewusst innerhalb HIGH-Range (7.0-8.9) — bei aktiv exploitierten
        # Exchange-CVEs hebt SP-CVE-001 (KEV) zusaetzlich auf CRITICAL.
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=8.2,
        rationale="Exchange EOL - ProxyLogon/ProxyShell-Vulnerability-Klasse",
        references=["CWE-1104", "CISA-KEV"],
    ),
    SeverityPolicy(
        policy_id="SP-EOL-002",
        finding_type="software_eol",
        matches_when={"tech": ["php", "nodejs", "python"]},
        final_severity=Severity.MEDIUM,
        cvss_score=5.3,
        rationale="EOL-Runtime - keine Security-Patches mehr",
        references=["CWE-1104"],
    ),
    SeverityPolicy(
        policy_id="SP-EOL-003",
        finding_type="software_eol",
        matches_when={"tech": ["nginx", "apache", "iis"]},
        final_severity=Severity.MEDIUM,
        cvss_score=5.3,
        rationale="EOL-Webserver - Bekannte CVE-Klassen ohne Patch",
        references=["CWE-1104"],
    ),
    SeverityPolicy(
        policy_id="SP-EOL-004",
        finding_type="software_eol",
        matches_when={"tech": "wordpress", "major_version_behind": True},
        final_severity=Severity.HIGH,
        cvss_score=7.5,
        rationale="WordPress mehrere Major-Versionen hinter Aktuell - bekannte RCE-Pfade",
        references=["CWE-1104"],
    ),
]


# ====================================================================
# CONTEXT-FLAG-EXTRAKTION
# ====================================================================
SESSION_PATH_PATTERNS = (
    "/login", "/logout", "/account", "/admin",
    "/cart", "/checkout", "/profile", "/dashboard",
    "/auth", "/oauth", "/sso", "/portal",
)

SESSION_COOKIE_NAMES = {
    "phpsessid", "jsessionid", "asp.net_sessionid", "sessionid",
    "session", "auth", "token", "sid", "connect.sid",
}

MANAGEMENT_PORTS = {22, 3389, 5900, 8080, 8443, 10000}


def extract_context_flags(finding: dict, scan_context: dict) -> dict[str, Any]:
    """Aus Tool-Outputs deterministisch Context-Flags ableiten.

    finding: dict aus Phase 3 mit u.a. `url` (oder `fqdn`), `evidence`, `tool_source`
    scan_context: dict mit globalen Scan-Daten:
        - host_inventory
        - tech_profiles
        - dns_records (mx_present, dnssec, ...)
        - enrichment[cve_id] = {nvd, epss, cisa_kev}

    Wenn ein Flag nicht ableitbar ist, weglassen statt raten — die Policy
    faellt dann auf die generischere Regel zurueck.
    """
    flags: dict[str, Any] = {}

    # ── URL-/Path-basierte Flags ─────────────────────────
    url = (finding.get("url") or finding.get("affected") or
           finding.get("fqdn") or "").lower()
    flags["is_session_path"] = any(p in url for p in SESSION_PATH_PATTERNS)
    flags["https_in_use"] = url.startswith("https://") or url.startswith("https:") \
        or scan_context.get("https_default", True)

    # ── Evidence-basierte Flags (ZAP, Spider, Cookies) ───
    evidence = finding.get("evidence") or {}
    if isinstance(evidence, str):
        evidence = {}  # Tool gab Evidence als String, keine Felder ableitbar

    flags["form_present"] = bool(evidence.get("forms_on_page")
                                 or evidence.get("form_present"))
    flags["inline_scripts"] = bool(evidence.get("has_inline_scripts")
                                   or evidence.get("inline_scripts"))

    # Cookie-Session-Heuristik
    cookie_info = evidence.get("cookie") or {}
    cookie_name = (cookie_info.get("name") or "").lower()
    flags["cookie_session"] = (
        bool(cookie_info.get("session_cookie"))
        or any(name in cookie_name for name in SESSION_COOKIE_NAMES)
    )

    # State-Change ueber HTTP-Methode
    method = (evidence.get("http_method") or evidence.get("method") or "GET").upper()
    flags["state_change"] = method in {"POST", "PUT", "DELETE", "PATCH"}

    flags["auth_present"] = bool(evidence.get("login_form_detected")
                                 or evidence.get("auth_present"))

    # ── DNS / MX (aus scan_context oder finding-eigenem dns-Block) ─
    dns_records = scan_context.get("dns_records") or finding.get("dns_records") or {}
    flags["mx_present"] = bool(dns_records.get("mx") or dns_records.get("mx_records"))

    # ── Threat-Intel (aus enrichment) ────────────────────
    # Unterstuetzt zwei Shapes:
    #  a) Einfach (Test-/Adhoc-Daten):
    #     finding.threat_intel = {"in_kev": True, "epss_score": 0.7,
    #                             "kev_ransomware": True}
    #  b) Strukturiert (real aus Phase 3 / NVD-Enrichment):
    #     finding.enrichment = {"cisa_kev": {...}, "epss": {"epss": 0.7}}
    threat_intel = (
        finding.get("threat_intel")
        or finding.get("enrichment")
        or {}
    )
    cve_id = finding.get("cve_id") or (
        finding.get("primary", {}).get("cve_id")
        if isinstance(finding.get("primary"), dict) else None
    )
    cve_data = threat_intel if isinstance(threat_intel, dict) else {}
    if cve_id and isinstance(scan_context.get("enrichment"), dict):
        cve_data = scan_context["enrichment"].get(cve_id) or cve_data

    # KEV-Detection: simple-shape ODER structured-shape
    kev_simple = bool(cve_data.get("in_kev") or cve_data.get("kev_in"))
    kev_struct = cve_data.get("cisa_kev") or cve_data.get("kev")
    kev_struct_truthy = False
    if isinstance(kev_struct, dict) and kev_struct:
        kev_struct_truthy = True
    elif kev_struct is True:
        kev_struct_truthy = True
    flags["cve_in_kev"] = kev_simple or kev_struct_truthy

    # Ransomware-Flag
    rans_simple = bool(cve_data.get("kev_ransomware") or cve_data.get("ransomware"))
    rans_struct = False
    if isinstance(kev_struct, dict):
        rans_field = (
            kev_struct.get("known_ransomware")
            or kev_struct.get("knownRansomwareCampaignUse")
            or ""
        )
        rans_struct = str(rans_field).lower() == "known"
    flags["cve_ransomware"] = rans_simple or rans_struct

    # EPSS-Score: simple-shape ODER structured-shape
    epss_score: float = 0.0
    epss_simple = cve_data.get("epss_score")
    if isinstance(epss_simple, (int, float)):
        epss_score = float(epss_simple)
    else:
        epss_data = cve_data.get("epss")
        if isinstance(epss_data, dict):
            try:
                epss_score = float(epss_data.get("epss") or 0.0)
            except (ValueError, TypeError):
                epss_score = 0.0
        elif isinstance(epss_data, (int, float)):
            epss_score = float(epss_data)
    flags["cve_epss_high"] = epss_score > 0.5

    # ── Tech / Version (aus tech_profiles oder primary tech) ──────
    tech_profiles = scan_context.get("tech_profiles") or []
    host = finding.get("host") or finding.get("host_ip") or finding.get("ip", "")
    primary_tech = ""
    major_version_behind = False
    for tp in tech_profiles:
        if tp.get("ip") == host or host in (tp.get("fqdns") or []):
            primary_tech = (tp.get("primary_tech") or tp.get("cms")
                            or tp.get("server") or "").lower()
            major_version_behind = bool(tp.get("major_version_behind"))
            break
    if primary_tech:
        flags["tech"] = primary_tech
    if major_version_behind:
        flags["major_version_behind"] = True

    # ── Port-Klassifikation ───────────────────────────────
    port = finding.get("port")
    if port is not None:
        try:
            flags["port_management"] = int(port) in MANAGEMENT_PORTS
        except (ValueError, TypeError):
            pass

    return flags


# ====================================================================
# POLICY LOOKUP
# ====================================================================
def _matches_context(policy: SeverityPolicy, flags: dict[str, Any]) -> bool:
    """Prueft ob alle policy.matches_when-Bedingungen in flags erfuellt sind."""
    for key, expected in policy.matches_when.items():
        if key not in flags:
            return False
        actual = flags[key]
        if isinstance(expected, list):
            if actual not in expected:
                return False
        else:
            if actual != expected:
                return False
    return True


def lookup_policy(finding_type: str,
                  context_flags: dict[str, Any]) -> Optional[SeverityPolicy]:
    """Findet die spezifischste Policy fuer einen Finding-Typ.

    Spezifitaet = Anzahl matchender context_flags.
    Tiebreaker: policy_id alphabetisch (deterministisch).
    """
    candidates = [p for p in SEVERITY_POLICIES if p.finding_type == finding_type]
    matching = [p for p in candidates if _matches_context(p, context_flags)]

    if not matching:
        return None

    matching.sort(key=lambda p: (-len(p.matches_when), p.policy_id))
    return matching[0]


# ====================================================================
# CVE-FALLBACK (SP-CVE-004)
# ====================================================================
def apply_policy_for_cve(finding: dict,
                         context_flags: dict[str, Any]) -> Optional[SeverityPolicy]:
    """CVE-Findings durchlaufen erst SP-CVE-001..003.

    Wenn keine matched, fallback: CVSS-> Severity (SP-CVE-004 dynamisch).
    """
    static = lookup_policy("cve_finding", context_flags)
    if static is not None:
        return static

    cvss = finding.get("cvss_score") or 0.0
    try:
        cvss = float(cvss)
    except (ValueError, TypeError):
        cvss = 0.0
    return SeverityPolicy(
        policy_id="SP-CVE-004",
        finding_type="cve_finding",
        final_severity=Severity.from_cvss(cvss),
        cvss_score=cvss,
        rationale=f"CVE-Standard-Mapping aus NVD-CVSS {cvss}",
        references=["NVD"],
    )


# ====================================================================
# CVSS-Cap an Policy-Severity
# ====================================================================
def _cap_cvss_to_severity(cvss: Optional[float], severity: Severity) -> Optional[float]:
    """Cap CVSS-Score in den Wertebereich der Policy-Severity.

    Aufgehoben wird der Score nicht (nie nach oben gepushtes CVSS), aber
    nach unten gedeckelt wenn Tool/NVD-Score ueber dem Severity-Bucket liegt.
    """
    if cvss is None:
        return None
    lo, hi = SEVERITY_CVSS_RANGE[severity]
    if cvss > hi:
        return hi
    if cvss < lo and severity != Severity.INFO:
        return lo
    return cvss


# ====================================================================
# HAUPT-FUNKTION
# ====================================================================
def apply_policy(findings: list[dict], scan_context: dict) -> list[dict]:
    """Wendet Policies auf alle Findings an.

    Modifiziert Findings IN-PLACE: setzt severity, policy_id, severity_provenance,
    capped cvss_score/cvss_vector wo Policy ein eigenes vorgibt.

    Returns: dieselbe Liste, mutiert.
    """
    fallback_count = 0
    miss_types: dict[str, int] = {}

    for finding in findings:
        finding_type = finding.get("finding_type") or finding.get("type")
        flags = extract_context_flags(finding, scan_context)

        # Original-Severity vor Override sichern
        original_severity = (finding.get("severity") or "info").lower()
        finding.setdefault("_original_severity", original_severity)

        if not finding_type:
            logger.warning("Finding without finding_type: %s",
                           finding.get("title", "<unknown>"))
            policy = None
            finding_type_for_log = "<unmapped>"
        elif finding_type == "cve_finding":
            policy = apply_policy_for_cve(finding, flags)
            finding_type_for_log = finding_type
        else:
            policy = lookup_policy(finding_type, flags)
            finding_type_for_log = finding_type

        if policy is None:
            fallback_count += 1
            miss_types[finding_type_for_log] = miss_types.get(finding_type_for_log, 0) + 1

            try:
                tool_severity = Severity(original_severity)
            except ValueError:
                tool_severity = Severity.INFO

            finding["severity"] = tool_severity.value
            finding["policy_id"] = "SP-FALLBACK"
            finding["severity_provenance"] = SeverityProvenance(
                policy_id="SP-FALLBACK",
                policy_decision=tool_severity,
                tool_severities={
                    finding.get("tool_source", "unknown"): original_severity,
                },
                context_flags=flags,
                rationale=(
                    f"Keine Policy-Regel fuer finding_type='{finding_type_for_log}' "
                    f"- Tool-Severity uebernommen"
                ),
                rule_references=[],
            ).model_dump(mode="json")
            continue

        # Policy gefunden - Severity ueberschreiben
        finding["severity"] = policy.final_severity.value
        finding["policy_id"] = policy.policy_id

        # CVSS aus Policy uebernehmen wenn verfuegbar; sonst capping
        if policy.cvss_score is not None:
            finding["cvss_score"] = policy.cvss_score
        else:
            existing = finding.get("cvss_score")
            try:
                existing_f = float(existing) if existing is not None else None
            except (ValueError, TypeError):
                existing_f = None
            capped = _cap_cvss_to_severity(existing_f, policy.final_severity)
            if capped is not None:
                finding["cvss_score"] = capped
        if policy.cvss_vector is not None:
            finding["cvss_vector"] = policy.cvss_vector

        finding["severity_provenance"] = SeverityProvenance(
            policy_id=policy.policy_id,
            policy_decision=policy.final_severity,
            tool_severities={
                finding.get("tool_source", "unknown"): original_severity,
            },
            context_flags=flags,
            rationale=policy.rationale,
            rule_references=policy.references,
        ).model_dump(mode="json")

    if fallback_count > 0:
        logger.warning(
            "Policy-Fallback used for %d findings; top miss types: %s",
            fallback_count,
            sorted(miss_types.items(), key=lambda x: -x[1])[:5],
        )

    return findings


# ====================================================================
# EXPORTS
# ====================================================================
__all__ = [
    "POLICY_VERSION",
    "Severity",
    "SeverityPolicy",
    "SeverityProvenance",
    "SEVERITY_POLICIES",
    "SEVERITY_CVSS_RANGE",
    "extract_context_flags",
    "lookup_policy",
    "apply_policy",
    "apply_policy_for_cve",
]
