"""CWE reference data for prompt injection and post-processing validation."""

import re
from typing import Any

import structlog

log = structlog.get_logger()

# Mapping: finding type keywords → recommended CWEs
CWE_REFERENCE = {
    "exposed_port_no_auth": {"cwes": ["CWE-306"], "desc": "Missing Authentication for Critical Function"},
    "exposed_port_with_auth": {"cwes": ["CWE-200"], "desc": "Exposure of Sensitive Information"},
    "missing_security_headers": {"cwes": ["CWE-693"], "desc": "Protection Mechanism Failure"},
    "clickjacking": {"cwes": ["CWE-1021"], "desc": "Improper Restriction of Rendered UI Layers"},
    "ssl_tls_weakness": {"cwes": ["CWE-326", "CWE-327"], "desc": "Inadequate Encryption Strength"},
    "information_disclosure": {"cwes": ["CWE-200", "CWE-213"], "desc": "Exposure of Sensitive Information"},
    "missing_spf_dmarc_dkim": {"cwes": ["CWE-290"], "desc": "Authentication Bypass by Spoofing"},
    "cleartext_transmission": {"cwes": ["CWE-319"], "desc": "Cleartext Transmission of Sensitive Info"},
    "directory_listing": {"cwes": ["CWE-548"], "desc": "Exposure Through Directory Listing"},
    "outdated_software": {"cwes": ["CWE-1104"], "desc": "Use of Unmaintained Third Party Components"},
    "xss": {"cwes": ["CWE-79"], "desc": "Cross-site Scripting"},
    "sql_injection": {"cwes": ["CWE-89"], "desc": "SQL Injection"},
    "open_redirect": {"cwes": ["CWE-601"], "desc": "URL Redirection to Untrusted Site"},
    "default_credentials": {"cwes": ["CWE-798"], "desc": "Use of Hard-coded Credentials"},
    "csrf": {"cwes": ["CWE-352"], "desc": "Cross-Site Request Forgery"},
    "ssrf": {"cwes": ["CWE-918"], "desc": "Server-Side Request Forgery"},
    "path_traversal": {"cwes": ["CWE-22"], "desc": "Path Traversal"},
    "command_injection": {"cwes": ["CWE-78"], "desc": "OS Command Injection"},
    "cookie_no_secure_flag": {"cwes": ["CWE-614"], "desc": "Sensitive Cookie Without Secure Flag"},
    "missing_hsts": {"cwes": ["CWE-311"], "desc": "Missing Encryption of Sensitive Data"},
    "zone_transfer": {"cwes": ["CWE-200"], "desc": "DNS Zone Transfer Information Exposure"},
}

# Prompt-ready CWE reference string for injection into system prompts
CWE_PROMPT_BLOCK = """
CWE-ZUORDNUNG (verbindlich — verwende genau diese CWEs):
- Offener Port/Dienst (MySQL, Telnet, Mail-Ports, Admin-Panel): CWE-284 (Improper Access Control)
- Admin-Panel öffentlich erreichbar (wp-admin, /admin, phpMyAdmin): CWE-284
- Klartext-Protokoll ohne TLS (FTP, Telnet, HTTP): CWE-319 (Cleartext Transmission)
- Fehlende Security Headers (X-Frame, CSP, HSTS, etc.): CWE-693 (Protection Mechanism Failure)
- Fehlende SPF/DMARC/DKIM: CWE-290 (Authentication Bypass by Spoofing)
- Veraltete Software (Apache, PHP, WordPress, Plugins): CWE-1104 (Unmaintained Components)
- Dangling CNAME / Subdomain Takeover: CWE-350 (Reliance on Reverse DNS)
- Information Disclosure (Banner, robots.txt, Stack-Traces): CWE-200
- SSL/TLS-Schwäche (veraltete Version, schwache Cipher): CWE-326
- Directory Listing: CWE-548
- XSS: CWE-79 | SQL Injection: CWE-89 | CSRF: CWE-352 | SSRF: CWE-918
- Open Redirect: CWE-601 | Default Credentials: CWE-798
- Wenn KEIN CWE klar passt: "cwe": "" (leer lassen, NICHT erfinden!)

CVSS-REFERENZWERTE (verwende diese als Anker für konsistente Bewertungen):
- MySQL/DB-Port offen ohne Auth: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 HIGH
- Telnet offen: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 HIGH
- FTP Klartext aktiv: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3 MEDIUM
- Admin-Panel offen: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3 MEDIUM
- Fehlende Security-Header: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N = 4.3 MEDIUM
- DKIM/SPF fehlt: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N = 4.3 MEDIUM
- DMARC none/quarantine: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N = 3.1 LOW
- HTTP ohne HTTPS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3 MEDIUM
"""

# Top ~50 CWEs relevant for web security scanning — used for post-validation
KNOWN_CWES = {
    "CWE-16", "CWE-20", "CWE-22", "CWE-74", "CWE-77", "CWE-78", "CWE-79",
    "CWE-89", "CWE-94", "CWE-119", "CWE-125", "CWE-190", "CWE-200",
    "CWE-213", "CWE-250", "CWE-269", "CWE-276", "CWE-284", "CWE-287",
    "CWE-290", "CWE-295", "CWE-306", "CWE-311", "CWE-312", "CWE-319",
    "CWE-326", "CWE-327", "CWE-330", "CWE-345", "CWE-350", "CWE-352",
    "CWE-384", "CWE-400", "CWE-434", "CWE-502", "CWE-522", "CWE-532",
    "CWE-548", "CWE-601", "CWE-611", "CWE-614", "CWE-639", "CWE-693",
    "CWE-732", "CWE-757", "CWE-770", "CWE-776", "CWE-798", "CWE-862",
    "CWE-863", "CWE-918", "CWE-942", "CWE-1004", "CWE-1021", "CWE-1104",
}


# ---------------------------------------------------------------------------
# Post-processing CWE correction — deterministic, pattern-based
# ---------------------------------------------------------------------------

# Order matters: first match wins. More specific patterns before general ones.
_CWE_CORRECTIONS: list[tuple[str, str]] = [
    # Access Control — offene Ports/Dienste/Admin-Panels
    (r"MySQL|MariaDB|Postgres|Datenbank.*Port|DB.*exponiert|DB.*erreichbar", "CWE-284"),
    (r"Admin.*erreichbar|Admin.*Panel|Adminbereich|wp-admin|phpMyAdmin|/admin\b", "CWE-284"),
    (r"Telnet.*offen|Telnet.*aktiv|Telnet.*exponiert|Port\s*23\b", "CWE-284"),
    (r"SSH.*exponiert|SSH.*erreichbar|Port\s*22\b.*exponiert", "CWE-284"),
    (r"(?:Mail|POP3|IMAP|SMTP).*exponiert|Mail.*Dienst.*offen", "CWE-284"),
    (r"Port.*exponiert|Dienst.*exponiert|Ports.*expo", "CWE-284"),
    # Cleartext transmission
    (r"FTP.*Klartext|FTP.*unverschl|FTP.*ohne.*TLS|FTP.*ohne.*Verschl", "CWE-319"),
    (r"HTTP\s+ohne\s+HTTPS|unverschl.*HTTP|kein.*HTTPS", "CWE-319"),
    # E-Mail security
    (r"DKIM|DMARC|SPF.*fehlt|SPF.*Softfail|E-Mail.*Spoofing", "CWE-290"),
    # Subdomain takeover
    (r"Dangling.*CNAME|Subdomain.*Takeover|Subdomain.*Übernahme", "CWE-350"),
    # Protection mechanisms
    (r"WAF.*fehlt|kein.*WAF|WAF.*erkannt", "CWE-693"),
    (r"Security.*Header|HTTP.*Header.*fehl|HSTS.*fehl", "CWE-693"),
    # Outdated software
    (r"Veraltete?.*Software|veraltete?.*Version|End.of.Life|EOL", "CWE-1104"),
    (r"Apache\s+\d|nginx\s+\d|PHP\s+\d|WordPress\s+\d", "CWE-1104"),
]


def correct_cwe_mappings(result: dict[str, Any]) -> dict[str, Any]:
    """Correct CWE assignments based on finding title patterns.

    Runs AFTER Claude's response is parsed. Deterministic, pattern-based
    corrections for commonly misclassified findings (e.g. CWE-200 catch-all).
    """
    for finding in result.get("findings", []):
        title = finding.get("title", "")
        original_cwe = finding.get("cwe", "")
        for pattern, correct_cwe in _CWE_CORRECTIONS:
            if re.search(pattern, title, re.IGNORECASE):
                if original_cwe != correct_cwe:
                    log.info("cwe_corrected",
                             title=title[:50],
                             old_cwe=original_cwe,
                             new_cwe=correct_cwe)
                    finding["cwe"] = correct_cwe
                break  # first match wins
    return result
