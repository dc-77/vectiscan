"""CWE reference data for prompt injection and post-processing validation."""

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
CWE-REFERENZ (verwende NUR diese CWEs wenn sie zum Finding passen):
- Exponierter Port/Service ohne Auth: CWE-306
- Exponierter Port MIT Auth (Info Exposure): CWE-200
- Information Disclosure (Banner, robots.txt, Pfade): CWE-200 oder CWE-213
- Fehlende Security Headers (X-Frame, CSP, etc.): CWE-693
- Clickjacking (fehlender X-Frame-Options): CWE-1021
- SSL/TLS-Schwäche (veraltete Version, schwache Cipher): CWE-326 oder CWE-327
- Fehlende SPF/DMARC/DKIM: CWE-290
- Klartext-Übertragung (FTP, HTTP ohne TLS): CWE-319
- Fehlende HSTS: CWE-311
- Directory Listing: CWE-548
- Veraltete Software: CWE-1104
- XSS: CWE-79
- SQL Injection: CWE-89
- Open Redirect: CWE-601
- Default Credentials: CWE-798
- CSRF: CWE-352
- SSRF: CWE-918
- DNS Zone Transfer: CWE-200
- Cookie ohne Secure-Flag: CWE-614
- Wenn KEIN CWE klar passt: "cwe": "" (leer lassen, NICHT erfinden!)
"""

# Top ~50 CWEs relevant for web security scanning — used for post-validation
KNOWN_CWES = {
    "CWE-16", "CWE-20", "CWE-22", "CWE-74", "CWE-77", "CWE-78", "CWE-79",
    "CWE-89", "CWE-94", "CWE-119", "CWE-125", "CWE-190", "CWE-200",
    "CWE-213", "CWE-250", "CWE-269", "CWE-276", "CWE-284", "CWE-287",
    "CWE-290", "CWE-295", "CWE-306", "CWE-311", "CWE-312", "CWE-319",
    "CWE-326", "CWE-327", "CWE-330", "CWE-345", "CWE-352", "CWE-384",
    "CWE-400", "CWE-434", "CWE-502", "CWE-522", "CWE-532", "CWE-548",
    "CWE-601", "CWE-611", "CWE-614", "CWE-639", "CWE-693", "CWE-732",
    "CWE-757", "CWE-770", "CWE-776", "CWE-798", "CWE-862", "CWE-863",
    "CWE-918", "CWE-942", "CWE-1004", "CWE-1021", "CWE-1104",
}
