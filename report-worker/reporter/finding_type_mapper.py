"""Mappt Claude-extrahierte Findings auf Policy-kompatible finding_type-Strings.

Hintergrund: severity_policy.lookup_policy() braucht einen finding_type, um
die richtige Regel zu finden. Claude liefert aber Title + Description in
freiem Text. Dieses Modul klassifiziert deterministisch ueber Keywords +
Tool-Source.

Wichtige Designentscheidung: NUR exakte Keywords/Pattern. Kein KI-Lookup,
kein Fuzzy-Matching. Wenn nichts greift → None → severity_policy nutzt
SP-FALLBACK.

Wartung: Neue Finding-Typen hier ergaenzen UND in severity_policy.py eine
passende Regel anlegen. Spec: docs/deterministic/02-severity-policy.md.
"""

from __future__ import annotations

import re
from typing import Optional


# Pattern-Tabelle: (regex auf title|description|cwe, finding_type)
# Reihenfolge ist wichtig — spezifischere Pattern zuerst.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # ── Information Disclosure ───────────────────────────
    (re.compile(r"\b\.env\b|env[-_ ]?file\s*expos", re.I), "env_file_exposed"),
    (re.compile(
        r"\.git[/\\]"                                  # .git/ or .git\
        r"|\.git\s+(?:directory|folder|repo)"          # .git directory / folder / repo
        r"|git\s+(?:directory|folder)\s*(?:expos|access)",  # git directory exposed/accessible
        re.I,
     ), "git_directory_exposed"),
    (re.compile(r"phpinfo\(\)|phpinfo\s*expos|phpinfo\s*page", re.I),
        "phpinfo_exposed"),
    (re.compile(r"directory\s*list|ls\s*-la\s*expos|index\s*of\s*/", re.I),
        "directory_listing_enabled"),
    (re.compile(r"stack\s*trace|exception\s*detail|error\s*page\s*reveal", re.I),
        "error_message_with_stack"),
    (re.compile(r"nginx[\s_]?status\s*(?:endpoint|page)", re.I),
        "nginx_status_endpoint_open"),
    (re.compile(r"server[-_ ]?banner.*version|version\s*disclos", re.I),
        "server_banner_with_version"),
    (re.compile(r"server[-_ ]?banner|server\s*header", re.I),
        "server_banner_no_version"),

    # ── Cookies ──────────────────────────────────────────
    (re.compile(r"cookie.*\bsecure\b.*(?:miss|not\s*set|fehlt)", re.I),
        "cookie_no_secure"),
    (re.compile(r"cookie.*httponly.*(?:miss|not\s*set|fehlt)", re.I),
        "cookie_no_httponly"),
    (re.compile(r"cookie.*samesite.*(?:miss|not\s*set|fehlt)", re.I),
        "cookie_no_samesite"),

    # ── CSP ──────────────────────────────────────────────
    (re.compile(r"\bcsp\b.*unsafe[-_ ]?inline", re.I), "csp_unsafe_inline"),
    (re.compile(r"\bcsp\b.*unsafe[-_ ]?eval", re.I), "csp_unsafe_eval"),
    (re.compile(r"\bcsp\b.*wildcard|\bcsp\b.*\*", re.I), "csp_wildcard_source"),
    (re.compile(r"\bcontent[-_ ]?security[-_ ]?policy\b.*(?:miss|fehlt|not\s*set)", re.I),
        "csp_missing"),
    (re.compile(r"\bcsp\b.*(?:miss|fehlt|not\s*set)", re.I), "csp_missing"),

    # ── HSTS ─────────────────────────────────────────────
    (re.compile(r"hsts.*preload.*(?:miss|fehlt)", re.I), "hsts_preload_missing"),
    (re.compile(r"hsts.*include[-_ ]?subdomains.*(?:miss|fehlt)", re.I),
        "hsts_no_includesubdomains"),
    (re.compile(r"hsts.*max[-_ ]?age.*(?:short|<\s*15\d{6}|6\s*month)", re.I),
        "hsts_short_maxage"),
    (re.compile(r"\bhsts\b.*(?:miss|fehlt|not\s*set)|strict[-_ ]?transport[-_ ]?security.*(?:miss|fehlt)", re.I),
        "hsts_missing"),

    # ── Andere Header ────────────────────────────────────
    (re.compile(r"x[-_ ]?content[-_ ]?type[-_ ]?options.*(?:miss|fehlt|not\s*set)", re.I),
        "xcto_missing"),
    (re.compile(r"x[-_ ]?frame[-_ ]?options.*(?:miss|fehlt|not\s*set)", re.I),
        "xfo_missing"),
    (re.compile(r"referrer[-_ ]?policy.*(?:miss|fehlt|not\s*set)", re.I),
        "referrer_policy_missing"),
    (re.compile(r"permissions[-_ ]?policy.*(?:miss|fehlt|not\s*set)", re.I),
        "permissions_policy_missing"),

    # ── CSRF ─────────────────────────────────────────────
    (re.compile(r"csrf[-_ ]?token.*(?:miss|fehlt|not\s*set)|cross[-_ ]?site\s*request\s*forgery", re.I),
        "csrf_token_missing"),

    # ── TLS / Certificate ────────────────────────────────
    (re.compile(r"tls.*(?:1\.0|1\.1)|ssl\s*(?:v2|v3)|protocol\s*(?:obsolete|deprecat)", re.I),
        "tls_below_tr03116_minimum"),
    (re.compile(r"weak\s*cipher|cipher\s*suite\s*(?:weak|insecure)", re.I),
        "tls_weak_cipher_suites"),
    (re.compile(r"perfect\s*forward\s*secrecy|\bpfs\b.*(?:miss|fehlt)", re.I),
        "tls_no_pfs"),
    (re.compile(r"certificate.*(?:expired|abgelaufen)", re.I),
        "tls_certificate_expired"),
    (re.compile(r"certificate.*(?:expir|laeuft).*(?:30|<\s*\d+)\s*(?:day|tag)", re.I),
        "tls_certificate_expiring_30d"),
    (re.compile(r"self[-_ ]?signed.*certificate|certificate.*self[-_ ]?signed", re.I),
        "tls_self_signed"),

    # ── DNS / Mail ───────────────────────────────────────
    (re.compile(r"dnssec.*(?:chain|broken|invalid)", re.I), "dnssec_chain_broken"),
    (re.compile(r"\bdnssec\b.*(?:miss|fehlt|not\s*(?:active|enabled|configured))", re.I),
        "dnssec_missing"),
    (re.compile(r"\bcaa\b.*(?:miss|fehlt|not\s*set)", re.I), "caa_missing"),
    (re.compile(r"\bspf\b.*(?:soft[-_ ]?fail|~all)", re.I), "spf_softfail"),
    (re.compile(r"\bspf\b.*(?:miss|fehlt|not\s*(?:configured|set|present))", re.I),
        "spf_missing"),
    (re.compile(r"\bdmarc\b.*p[\s=:]*none", re.I), "dmarc_p_none"),
    (re.compile(r"\bdmarc\b.*(?:miss|fehlt|not\s*(?:configured|set|present))", re.I),
        "dmarc_missing"),
    (re.compile(r"\bdkim\b.*(?:miss|fehlt|not\s*(?:configured|set|present))", re.I),
        "dkim_missing"),
    (re.compile(r"mta[-_ ]?sts.*(?:miss|fehlt|not\s*(?:configured|set))", re.I),
        "mta_sts_missing"),

    # ── EOL Software ─────────────────────────────────────
    (re.compile(r"end[-_ ]?of[-_ ]?life|\beol\b|out[-_ ]?of[-_ ]?support|veraltet|unsupported\s*version", re.I),
        "software_eol"),
]


def map_finding_type(finding: dict) -> Optional[str]:
    """Klassifiziert ein Claude-Finding in einen severity_policy finding_type.

    Reihenfolge der Auswertung:
    1. Wenn `cve` oder `cve_id` gesetzt → "cve_finding"
    2. Pattern-Matching ueber title + description + cwe (in dieser Reihenfolge)
    3. Wenn nichts greift: None (Caller faellt auf SP-FALLBACK zurueck)
    """
    # 1. CVE-Finding hat eigenen Pfad in severity_policy
    if finding.get("cve") or finding.get("cve_id"):
        return "cve_finding"
    # CVE-IDs koennen auch im title/cwe-Feld stehen
    title = str(finding.get("title") or "")
    if re.search(r"\bCVE-\d{4}-\d{4,7}\b", title):
        return "cve_finding"

    # 2. Pattern-Match auf konkateniertem Suchtext
    parts: list[str] = []
    for key in ("title", "description", "impact", "cwe"):
        v = finding.get(key)
        if isinstance(v, str):
            parts.append(v)
    haystack = " | ".join(parts)
    if not haystack:
        return None

    for pattern, finding_type in _PATTERNS:
        if pattern.search(haystack):
            return finding_type

    return None


def annotate_finding_types(findings: list[dict]) -> list[dict]:
    """Setzt finding_type IN-PLACE auf jedem Finding (wenn nicht schon gesetzt)."""
    for f in findings:
        if not f.get("finding_type"):
            inferred = map_finding_type(f)
            if inferred:
                f["finding_type"] = inferred
    return findings


__all__ = ["map_finding_type", "annotate_finding_types"]
