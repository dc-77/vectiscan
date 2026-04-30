"""
report-worker/reporter/severity_policy.py

Deterministische, auditierbare Severity-Vergabe.
Spec: docs/specs/2026-Q2-determinism/02-severity-policy.md

Vorgesehener Aufruf-Punkt:
    findings = severity_policy.apply_policy(findings, scan_context)
in report-worker/reporter/worker.py NACH der Phase-3-Korrelation und
VOR business_impact.recompute().

POLICY_VERSION wird in DB-Spalte report_findings_data.policy_version
festgehalten und bei Cache-Invalidierung im AI-Cache verwendet.

TODO(claude-code): Eingebettet sind ~40 Regeln. Falls beim Implementieren
auffällt dass eine Regel fehlt oder eine context_flag-Extraktion nicht
deterministisch ableitbar ist, in 02-severity-policy.md dokumentieren und
neue Regel anlegen — NIE in der Sonnet-Pipeline ad-hoc entscheiden lassen.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

# ====================================================================
# POLICY VERSION
# ====================================================================
# Bei jeder Änderung der Regeln HIER hochziehen. Wird im AI-Cache-Key
# eingebaut, damit Cache nach Policy-Update automatisch invalidiert.
POLICY_VERSION = "2026-04-24.1"


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
            self.CRITICAL: 5,
            self.HIGH: 4,
            self.MEDIUM: 3,
            self.LOW: 2,
            self.INFO: 1,
        }[self]


# ====================================================================
# SCHEMA
# ====================================================================
class SeverityPolicy(BaseModel):
    """
    Eine einzelne Policy-Regel.
    matches_when ist ein Dict mit context-flag-Bedingungen, die ALLE
    erfüllt sein müssen. Ein leeres Dict bedeutet "matcht immer".
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
        # Format: SP-<DOMAIN>-NNN
        return v


class SeverityProvenance(BaseModel):
    """Wird auf jedes Finding gehängt für Audit-Trail."""
    policy_id: str
    policy_decision: Severity
    policy_version: str = POLICY_VERSION
    tool_severities: dict[str, str] = Field(default_factory=dict)
    context_flags: dict[str, Any] = Field(default_factory=dict)
    rationale: str
    rule_references: list[str] = Field(default_factory=list)


# ====================================================================
# REGEL-REGISTRY
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
        rationale="Statische Seite ohne Session — HSTS-Fehlen ist Hardening-Issue, kein praktisches Risiko",
        references=["CWE-523", "OWASP2025-A02"],
    ),
    SeverityPolicy(
        policy_id="SP-HDR-002",
        finding_type="hsts_missing",
        matches_when={"is_session_path": True},
        final_severity=Severity.LOW,
        cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        cvss_score=2.6,
        rationale="Session-bearing path ohne HSTS — SSL-Stripping-Risiko bei MitM",
        references=["CWE-523", "OWASP2025-A02", "OWASP2021-A05"],
    ),
    SeverityPolicy(
        policy_id="SP-HDR-003",
        finding_type="hsts_no_includesubdomains",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="HSTS aktiviert aber Subdomains nicht eingeschlossen — Hardening",
        references=["CWE-523"],
    ),
    SeverityPolicy(
        policy_id="SP-HDR-004",
        finding_type="hsts_short_maxage",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="HSTS max-age < 6 Monate — Best-Practice-Verstoß ohne praktisches Risiko",
        references=["CWE-523"],
    ),
    SeverityPolicy(
        policy_id="SP-HDR-005",
        finding_type="xcto_missing",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="X-Content-Type-Options fehlt — MIME-Sniffing-Risiko nur in alten Browsern",
        references=["CWE-693", "OWASP2025-A06"],
    ),
    SeverityPolicy(
        policy_id="SP-HDR-006",
        finding_type="xfo_missing",
        matches_when={"is_session_path": False},
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="Clickjacking-Schutz fehlt, aber keine Session-Pages — Theoretisches Risiko",
        references=["CWE-1021"],
    ),
    SeverityPolicy(
        policy_id="SP-HDR-007",
        finding_type="xfo_missing",
        matches_when={"is_session_path": True},
        final_severity=Severity.LOW,
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        cvss_score=3.1,
        rationale="Clickjacking-Schutz fehlt auf Session-Path — UI-Redress-Risiko",
        references=["CWE-1021", "OWASP2025-A06"],
    ),
    SeverityPolicy(
        policy_id="SP-HDR-008",
        finding_type="referrer_policy_missing",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="Privacy-Hardening — kein direktes Sicherheitsrisiko",
        references=["CWE-200"],
    ),
    SeverityPolicy(
        policy_id="SP-HDR-009",
        finding_type="permissions_policy_missing",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="Browser-Feature-Policy nicht restriktiv gesetzt — Hardening",
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
        rationale="Statische Seite ohne inline-Scripts oder Forms — kein praktisches XSS-Risiko",
        references=["CWE-693", "OWASP2025-A05"],
    ),
    SeverityPolicy(
        policy_id="SP-CSP-002",
        finding_type="csp_missing",
        matches_when={"form_present": True},
        final_severity=Severity.LOW,
        cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=3.8,
        rationale="Form-Page ohne CSP — wenn XSS-Lücke existiert, fehlt zusätzliche Schutzschicht",
        references=["CWE-693", "OWASP2025-A05", "OWASP2021-A05"],
    ),
    SeverityPolicy(
        policy_id="SP-CSP-003",
        finding_type="csp_unsafe_inline",
        matches_when={"form_present": True},
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=5.4,
        rationale="CSP erlaubt unsafe-inline auf Form-Page — schwächt XSS-Schutz signifikant",
        references=["CWE-693", "OWASP2025-A05"],
    ),
    SeverityPolicy(
        policy_id="SP-CSP-004",
        finding_type="csp_unsafe_eval",
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=5.4,
        rationale="CSP erlaubt unsafe-eval — eval()-basierte XSS möglich",
        references=["CWE-95", "OWASP2025-A05"],
    ),
    SeverityPolicy(
        policy_id="SP-CSP-005",
        finding_type="csp_wildcard_source",
        final_severity=Severity.LOW,
        cvss_score=3.1,
        rationale="Wildcard `*` in CSP source-list schwächt Whitelisting",
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
        rationale="Session-Cookie ohne Secure-Flag auf HTTPS-Site — über HTTP übertragbar",
        references=["CWE-614", "OWASP2025-A02"],
    ),
    SeverityPolicy(
        policy_id="SP-COOK-002",
        finding_type="cookie_no_httponly",
        matches_when={"cookie_session": True},
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
        cvss_score=5.7,
        rationale="Session-Cookie ohne HttpOnly — XSS kann Session-Token lesen",
        references=["CWE-1004", "OWASP2025-A07"],
    ),
    SeverityPolicy(
        policy_id="SP-COOK-003",
        finding_type="cookie_no_samesite",
        matches_when={"cookie_session": True},
        final_severity=Severity.LOW,
        cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
        cvss_score=2.6,
        rationale="Session-Cookie ohne SameSite — CSRF-Mitigation-Layer fehlt",
        references=["CWE-352", "CWE-1275", "OWASP2025-A01"],
    ),
    SeverityPolicy(
        policy_id="SP-COOK-004",
        finding_type="cookie_no_secure",
        matches_when={"cookie_session": False},
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="Tracking-Cookie ohne Secure — kein Auth-Risiko",
        references=["CWE-614"],
    ),
    SeverityPolicy(
        policy_id="SP-COOK-005",
        finding_type="cookie_no_samesite",
        matches_when={"cookie_session": False},
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="Tracking-Cookie ohne SameSite — kein State-Change-Vektor",
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
        rationale="Form ist GET-only oder ohne State-Change — kein CSRF-Vektor",
        references=["CWE-352"],
    ),
    SeverityPolicy(
        policy_id="SP-CSRF-002",
        finding_type="csrf_token_missing",
        matches_when={"state_change": True, "auth_present": False},
        final_severity=Severity.LOW,
        cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
        cvss_score=2.6,
        rationale="State-Change ohne Auth — CSRF möglich, aber Schaden begrenzt",
        references=["CWE-352", "OWASP2025-A01"],
    ),
    SeverityPolicy(
        policy_id="SP-CSRF-003",
        finding_type="csrf_token_missing",
        matches_when={"state_change": True, "auth_present": True},
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:H/A:N",
        cvss_score=5.4,
        rationale="Authenticated state-change ohne CSRF-Token — Account-Takeover-Risiko",
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
        rationale="Server-Banner verrät Version — Recon-Vorteil für Angreifer",
        references=["CWE-200", "CWE-497"],
    ),
    SeverityPolicy(
        policy_id="SP-DISC-002",
        finding_type="server_banner_no_version",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="Server-Banner ohne Version — generische Information",
        references=["CWE-200"],
    ),
    SeverityPolicy(
        policy_id="SP-DISC-003",
        finding_type="nginx_status_endpoint_open",
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=5.3,
        rationale="Internal-Stats-Endpoint öffentlich — Internals leaken",
        references=["CWE-200", "CWE-538"],
    ),
    SeverityPolicy(
        policy_id="SP-DISC-004",
        finding_type="phpinfo_exposed",
        final_severity=Severity.HIGH,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=7.5,
        rationale="phpinfo() exposed — komplette Server-Konfiguration, Pfade, Versionen",
        references=["CWE-200", "CWE-497", "OWASP2025-A05"],
    ),
    SeverityPolicy(
        policy_id="SP-DISC-005",
        finding_type="directory_listing_enabled",
        final_severity=Severity.LOW,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=3.7,
        rationale="Directory-Listing aktiv — File-Discovery erleichtert",
        references=["CWE-548"],
    ),
    SeverityPolicy(
        policy_id="SP-DISC-006",
        finding_type="error_message_with_stack",
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=5.3,
        rationale="Stack-Traces in Fehlerseiten — Pfade, Versionen, Lib-Names leaken",
        references=["CWE-209", "CWE-497"],
    ),
    SeverityPolicy(
        policy_id="SP-DISC-007",
        finding_type="git_directory_exposed",
        final_severity=Severity.HIGH,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=7.5,
        rationale=".git/-Verzeichnis öffentlich — Source-Code-Leak möglich",
        references=["CWE-538", "OWASP2025-A05"],
    ),
    SeverityPolicy(
        policy_id="SP-DISC-008",
        finding_type="env_file_exposed",
        final_severity=Severity.CRITICAL,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=9.8,
        rationale=".env-Datei öffentlich — API-Keys, DB-Credentials, Secrets exposed",
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
        rationale="TLS-Version unter BSI TR-03116-4 Minimum — Compliance-Verstoß",
        references=["BSI-TR-03116-4", "CWE-326"],
    ),
    SeverityPolicy(
        policy_id="SP-TLS-002",
        finding_type="tls_weak_cipher_suites",
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=5.9,
        rationale="Schwache Cipher-Suiten verfügbar — Man-in-the-Middle-Angriffe möglich",
        references=["CWE-327", "CWE-326"],
    ),
    SeverityPolicy(
        policy_id="SP-TLS-003",
        finding_type="tls_no_pfs",
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=5.9,
        rationale="Perfect Forward Secrecy fehlt — Bei Key-Compromise ist alle Historie lesbar",
        references=["CWE-310"],
    ),
    SeverityPolicy(
        policy_id="SP-TLS-004",
        finding_type="tls_certificate_expired",
        final_severity=Severity.HIGH,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        cvss_score=7.5,
        rationale="TLS-Zertifikat abgelaufen — Browser-Warnung, User akzeptieren = MitM",
        references=["CWE-298", "CWE-295"],
    ),
    SeverityPolicy(
        policy_id="SP-TLS-005",
        finding_type="tls_certificate_expiring_30d",
        final_severity=Severity.LOW,
        cvss_score=2.0,
        rationale="TLS-Zertifikat läuft in <30 Tagen ab — Erneuerung erforderlich",
        references=["CWE-298"],
    ),
    SeverityPolicy(
        policy_id="SP-TLS-006",
        finding_type="tls_self_signed",
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
        cvss_score=5.7,
        rationale="Self-signed Zertifikat in öffentlicher PKI — keine Vertrauenskette",
        references=["CWE-295", "CWE-296"],
    ),
    SeverityPolicy(
        policy_id="SP-TLS-007",
        finding_type="hsts_preload_missing",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="HSTS-Preload-List-Eintrag fehlt — Hardening, kein direktes Risiko",
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
        rationale="DNSSEC nicht aktiviert — DNS-Spoofing-Risiko",
        references=["CWE-345", "CWE-290"],
    ),
    SeverityPolicy(
        policy_id="SP-DNS-002",
        finding_type="dnssec_chain_broken",
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        cvss_score=5.9,
        rationale="DNSSEC aktiviert aber Chain-of-Trust gebrochen — false sense of security",
        references=["CWE-345"],
    ),
    SeverityPolicy(
        policy_id="SP-DNS-003",
        finding_type="caa_missing",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="CAA-Record fehlt — kein autorisierter CA festgelegt",
        references=["CWE-295"],
    ),
    SeverityPolicy(
        policy_id="SP-DNS-004",
        finding_type="spf_missing",
        matches_when={"mx_present": True},
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        cvss_score=4.7,
        rationale="SPF fehlt für Mail-Domain — Spoofing-Schutz fehlt",
        references=["CWE-290"],
    ),
    SeverityPolicy(
        policy_id="SP-DNS-005",
        finding_type="spf_softfail",
        final_severity=Severity.LOW,
        cvss_score=3.1,
        rationale="SPF mit ~all (softfail) statt -all (hardfail) — schwacher Schutz",
        references=["CWE-290"],
    ),
    SeverityPolicy(
        policy_id="SP-DNS-006",
        finding_type="dmarc_missing",
        matches_when={"mx_present": True},
        final_severity=Severity.MEDIUM,
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        cvss_score=4.7,
        rationale="DMARC fehlt für Mail-Domain — Phishing-Schutz fehlt",
        references=["CWE-290"],
    ),
    SeverityPolicy(
        policy_id="SP-DNS-007",
        finding_type="dmarc_p_none",
        final_severity=Severity.LOW,
        cvss_score=3.1,
        rationale="DMARC mit p=none — nur Monitoring, keine Durchsetzung",
        references=["CWE-290"],
    ),
    SeverityPolicy(
        policy_id="SP-DNS-008",
        finding_type="dkim_missing",
        matches_when={"mx_present": True},
        final_severity=Severity.LOW,
        cvss_score=3.1,
        rationale="DKIM-Signierung fehlt — Mail-Authentifizierung schwächer",
        references=["CWE-290"],
    ),
    SeverityPolicy(
        policy_id="SP-DNS-009",
        finding_type="mta_sts_missing",
        final_severity=Severity.INFO,
        cvss_score=0.0,
        rationale="MTA-STS-Policy fehlt — Mail-TLS-Hardening optional",
        references=["RFC-8461"],
    ),

    # ----------------------------------------------------------------
    # CVE-DRIVEN (SP-CVE-*)
    # ----------------------------------------------------------------
    SeverityPolicy(
        policy_id="SP-CVE-001",
        finding_type="cve_finding",
        matches_when={"cve_in_kev": True},
        final_severity=Severity.CRITICAL,
        rationale="CVE in CISA Known Exploited Vulnerabilities — aktive Ausnutzung beobachtet",
        references=["CISA-KEV"],
    ),
    SeverityPolicy(
        policy_id="SP-CVE-002",
        finding_type="cve_finding",
        matches_when={"cve_ransomware": True},
        final_severity=Severity.CRITICAL,
        rationale="CVE mit Ransomware-Verbindung — höchstes Risiko für KMU",
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
    # SP-CVE-004 (Standard CVSS-Mapping) ist KEINE statische Regel,
    # sondern Fallback-Logik in apply_policy_for_cve()

    # ----------------------------------------------------------------
    # EOL SOFTWARE (SP-EOL-*)
    # ----------------------------------------------------------------
    SeverityPolicy(
        policy_id="SP-EOL-001",
        finding_type="software_eol",
        matches_when={"tech": "exchange"},
        final_severity=Severity.HIGH,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=9.8,
        rationale="Exchange EOL — ProxyLogon/ProxyShell-Vulnerability-Klasse",
        references=["CWE-1104", "CISA-KEV"],
    ),
    SeverityPolicy(
        policy_id="SP-EOL-002",
        finding_type="software_eol",
        matches_when={"tech": ["php", "nodejs", "python"]},
        final_severity=Severity.MEDIUM,
        cvss_score=5.3,
        rationale="EOL-Runtime — keine Security-Patches mehr",
        references=["CWE-1104"],
    ),
    SeverityPolicy(
        policy_id="SP-EOL-003",
        finding_type="software_eol",
        matches_when={"tech": ["nginx", "apache", "iis"]},
        final_severity=Severity.MEDIUM,
        cvss_score=5.3,
        rationale="EOL-Webserver — Bekannte CVE-Klassen ohne Patch",
        references=["CWE-1104"],
    ),
    SeverityPolicy(
        policy_id="SP-EOL-004",
        finding_type="software_eol",
        matches_when={"tech": "wordpress", "major_version_behind": True},
        final_severity=Severity.HIGH,
        cvss_score=7.5,
        rationale="WordPress mehrere Major-Versionen hinter Aktuell — bekannte RCE-Pfade",
        references=["CWE-1104"],
    ),
]


# ====================================================================
# CONTEXT-FLAG-EXTRAKTION
# ====================================================================
def extract_context_flags(finding: dict, scan_context: dict) -> dict[str, Any]:
    """
    Aus Tool-Outputs deterministisch Context-Flags ableiten.

    finding: dict aus Phase 3 mit u.a. `url`, `evidence`, `tool_source`
    scan_context: dict mit globalen Scan-Daten:
        - host_inventory
        - phase1_tech_profiles (CMS, framework)
        - phase2_results (zap_alerts, headers, cookies)
        - phase3_threat_intel (cve_kev, cve_epss)
        - dns_records (mx_present, dnssec, …)

    Returns: dict mit allen Flags für lookup_policy().

    TODO(claude-code): Diese Funktion ist das Herzstück. Jede Flag muss
    aus realen Tool-Outputs ableitbar sein, NIE aus KI-Heuristik.
    Wenn ein Flag nicht ableitbar ist, weglassen statt raten — die
    Policy fällt dann auf die generischere Regel zurück.
    """
    flags: dict[str, Any] = {}

    # is_session_path: Path-Pattern-Check
    SESSION_PATTERNS = ("/login", "/logout", "/account", "/admin",
                        "/cart", "/checkout", "/profile", "/dashboard",
                        "/auth", "/oauth", "/sso", "/portal")
    url = finding.get("url", "").lower()
    flags["is_session_path"] = any(p in url for p in SESSION_PATTERNS)

    # form_present: aus ZAP-Spider HTML-Parse
    # TODO(claude-code): Zugriff auf scan_context["phase2_results"][host]["forms"]
    flags["form_present"] = bool(finding.get("evidence", {}).get("forms_on_page"))

    # cookie_session: aus ZAP-Cookie-Analyse
    cookie_info = finding.get("evidence", {}).get("cookie", {})
    flags["cookie_session"] = (
        cookie_info.get("session_cookie", False)
        or cookie_info.get("name", "").lower() in {
            "phpsessid", "jsessionid", "asp.net_sessionid", "sessionid",
            "session", "auth", "token", "sid", "_ga"  # _ga ist tracker, nicht session — invertieren
        }
    )

    # inline_scripts: aus ZAP-Spider HTML-Parse
    flags["inline_scripts"] = bool(finding.get("evidence", {}).get("has_inline_scripts"))

    # state_change: aus ZAP-Request-Analyse
    method = finding.get("evidence", {}).get("http_method", "GET").upper()
    flags["state_change"] = method in {"POST", "PUT", "DELETE", "PATCH"}

    # auth_present: aus ZAP-Login-Form-Heuristik
    flags["auth_present"] = bool(finding.get("evidence", {}).get("login_form_detected"))

    # https_in_use
    flags["https_in_use"] = url.startswith("https://")

    # mx_present: aus Phase 0 DNS-Records
    dns_records = scan_context.get("dns_records", {})
    flags["mx_present"] = bool(dns_records.get("mx", []))

    # cve_in_kev / cve_epss_high / cve_ransomware: aus Phase 3 Enrichment
    threat_intel = finding.get("threat_intel", {})
    flags["cve_in_kev"] = threat_intel.get("in_kev", False)
    flags["cve_ransomware"] = threat_intel.get("kev_ransomware", False)
    flags["cve_epss_high"] = (threat_intel.get("epss_score", 0.0) or 0.0) > 0.5

    # tech, major_version_behind aus Phase 1
    tech_profile = scan_context.get("tech_profiles", {}).get(
        finding.get("host", ""), {})
    flags["tech"] = tech_profile.get("primary_tech", "").lower()
    flags["major_version_behind"] = tech_profile.get("major_version_behind", False)

    # port_management: aus nmap
    port = finding.get("port")
    if port is not None:
        flags["port_management"] = port in {22, 3389, 5900, 8080, 8443, 10000}

    return flags


# ====================================================================
# POLICY LOOKUP
# ====================================================================
def _matches_context(policy: SeverityPolicy, flags: dict[str, Any]) -> bool:
    """
    Prüft ob alle policy.matches_when-Bedingungen in flags erfüllt sind.
    - Bool-Werte: exact match
    - String: exact match (case-sensitive — flags sollten lowercase sein)
    - Liste: flag IN liste
    """
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
    """
    Findet die spezifischste Policy für einen Finding-Typ.
    Spezifität = Anzahl matchender context_flags.
    Tiebreaker: policy_id alphabetisch (deterministisch).
    """
    candidates = [p for p in SEVERITY_POLICIES if p.finding_type == finding_type]
    matching = [p for p in candidates if _matches_context(p, context_flags)]

    if not matching:
        return None

    # Sort: most specific (most matches_when keys) first, dann policy_id ASC
    matching.sort(key=lambda p: (-len(p.matches_when), p.policy_id))
    return matching[0]


# ====================================================================
# CVE-FALLBACK (SP-CVE-004)
# ====================================================================
def apply_policy_for_cve(finding: dict,
                         context_flags: dict[str, Any]) -> Optional[SeverityPolicy]:
    """
    CVE-Findings durchlaufen erst SP-CVE-001..003.
    Wenn keine matched, fallback: CVSS → Severity (SP-CVE-004 dynamisch).
    """
    static = lookup_policy("cve_finding", context_flags)
    if static is not None:
        return static

    # Fallback: derived from CVSS
    cvss = finding.get("cvss_score", 0.0) or 0.0
    return SeverityPolicy(
        policy_id="SP-CVE-004",
        finding_type="cve_finding",
        final_severity=Severity.from_cvss(cvss),
        cvss_score=cvss,
        rationale=f"CVE-Standard-Mapping aus NVD-CVSS {cvss}",
        references=["NVD"],
    )


# ====================================================================
# HAUPT-FUNKTION
# ====================================================================
def apply_policy(findings: list[dict], scan_context: dict) -> list[dict]:
    """
    Wendet Policies auf alle Findings an.
    Modifiziert Findings IN-PLACE: setzt severity, policy_id, severity_provenance.

    Returns: dieselbe Liste, mutiert.
    """
    fallback_count = 0
    miss_types: dict[str, int] = {}

    for finding in findings:
        finding_type = finding.get("finding_type") or finding.get("type")
        if not finding_type:
            logger.warning("Finding without finding_type: %s",
                          finding.get("title", "<unknown>"))
            continue

        flags = extract_context_flags(finding, scan_context)

        # Special-Case: CVE-Findings haben dynamischen Fallback
        if finding_type == "cve_finding":
            policy = apply_policy_for_cve(finding, flags)
        else:
            policy = lookup_policy(finding_type, flags)

        if policy is None:
            # Fallback: Tool-Severity behalten, aber mit SP-FALLBACK markieren
            fallback_count += 1
            miss_types[finding_type] = miss_types.get(finding_type, 0) + 1

            # Tool-severity auf Severity-Enum mappen
            tool_severity_str = (finding.get("severity") or "info").lower()
            try:
                tool_severity = Severity(tool_severity_str)
            except ValueError:
                tool_severity = Severity.INFO

            finding["severity"] = tool_severity.value
            finding["policy_id"] = "SP-FALLBACK"
            finding["severity_provenance"] = SeverityProvenance(
                policy_id="SP-FALLBACK",
                policy_decision=tool_severity,
                tool_severities={finding.get("tool_source", "unknown"): tool_severity_str},
                context_flags=flags,
                rationale=f"Keine Policy-Regel für finding_type='{finding_type}' — Tool-Severity übernommen",
                rule_references=[],
            ).model_dump(mode="json")
            continue

        # Policy gefunden — Severity überschreiben
        finding["severity"] = policy.final_severity.value
        finding["policy_id"] = policy.policy_id

        # CVSS aus Policy übernehmen, wenn verfügbar
        if policy.cvss_score is not None:
            finding["cvss_score"] = policy.cvss_score
        if policy.cvss_vector is not None:
            finding["cvss_vector"] = policy.cvss_vector

        # Provenance
        tool_severities = {
            finding.get("tool_source", "unknown"): finding.get("_original_severity",
                                                                finding.get("severity"))
        }
        finding["severity_provenance"] = SeverityProvenance(
            policy_id=policy.policy_id,
            policy_decision=policy.final_severity,
            tool_severities=tool_severities,
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
    "extract_context_flags",
    "lookup_policy",
    "apply_policy",
]
