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
    # ── WordPress Plugin- / Theme-Vulnerabilities ────────
    # Sammeltyp fuer alle bekannten WP-Plugin/Theme-Schwachstellen.
    # Faengt Findings wie "Slider Revolution", "Complianz", "Betheme",
    # "WPBakery", "Elementor", "Divi", "Yoast", "WooCommerce" etc. ab.
    (re.compile(
        r"\b(?:slider\s*revolution|complianz|betheme|wp\s*bakery|elementor|"
        r"divi|yoast|woo[-_ ]?commerce|jetpack|burst\s*statistics|"
        r"contact\s*form\s*7|wp[-_ ]?super[-_ ]?cache|all[-_ ]?in[-_ ]?one[-_ ]?seo|"
        r"wpforms|monsterinsights|akismet|advanced\s*custom\s*fields|"
        r"buddypress|bbpress|gravity\s*forms|easy\s*digital\s*downloads)\b",
        re.I,
     ), "wordpress_plugin_vulnerability"),
    # Generisch: "WordPress-Plugin ... Schwachstelle" / "WordPress theme ..."
    (re.compile(
        r"wordpress[-_ ]?(?:plugin|theme).*(?:schwachstelle|vulnerab|cve|exploit|xss|"
        r"sqli|rce|file\s*read|file\s*upload|object\s*injection|csrf|disclos)",
        re.I,
     ), "wordpress_plugin_vulnerability"),
    # WordPress Core: Login + Benutzer-Enumeration
    (re.compile(
        r"wordpress[-_ ]?(?:login|admin).*(?:benutzer[-_ ]?enum|user[-_ ]?enum|"
        r"oeffentlich|publicly\s*accessible|exposed|expon)",
        re.I,
     ), "wordpress_user_enumeration"),
    # Generische User-Enumeration (Author-Archive, WP-JSON, ID-Probing)
    (re.compile(
        r"(?:user|benutzer)[-_ ]?(?:enumeration|enumerat|aufzaehl|disclos)|"
        r"author[-_ ]?(?:enum|archive\s*expos)",
        re.I,
     ), "user_enumeration"),

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
    (re.compile(r"directory\s*list|ls\s*-la\s*expos|index\s*of\s*/|verzeichnis[-_ ]?listing", re.I),
        "directory_listing_enabled"),
    (re.compile(
        r"stack\s*trace|exception\s*detail|error\s*page\s*reveal|"
        r"fehlermeldung.*(?:stack|trace|pfad)|stack[-_ ]?trace.*(?:offen|expos|sichtbar)",
        re.I,
     ), "error_message_with_stack"),
    (re.compile(r"nginx[\s_]?status\s*(?:endpoint|page|seite)", re.I),
        "nginx_status_endpoint_open"),
    # Server-Banner: erweitert um "Apache-Versionsinformation",
    # "PHP-Versions(information|disclosure)", "Versionsinformation im Header",
    # "Server-Header verraet/zeigt Version" etc.
    (re.compile(
        r"(?:apache|nginx|iis|php|openssh|ssh|tomcat|jetty|caddy)[-_ ]?versions?(?:[-_ ]?information)?|"
        r"server[-_ ]?(?:banner|header).*(?:version|verraet|zeigt|preisgibt|disclos)|"
        r"version.*(?:disclos|preisgegeben|im\s*header|im\s*banner|in\s*server[-_ ]?header)|"
        r"(?:server|software|tech)[-_ ]?version[-_ ]?(?:disclosure|leakage|information)",
        re.I,
     ), "server_banner_with_version"),
    (re.compile(r"server[-_ ]?banner|server[-_ ]?header(?!.*version)", re.I),
        "server_banner_no_version"),

    # ── Cookies ──────────────────────────────────────────
    # "Cookie ohne Secure-Flag" / "Secure-Flag fehlt"
    (re.compile(
        r"(?:cookie.*\bsecure\b|secure[-_ ]?flag|secure[-_ ]?attribut).*"
        r"(?:miss|not\s*set|fehlt|nicht\s*(?:gesetzt|aktiv|vorhanden))",
        re.I,
     ), "cookie_no_secure"),
    (re.compile(
        r"(?:cookie.*httponly|httponly[-_ ]?flag|httponly[-_ ]?attribut).*"
        r"(?:miss|not\s*set|fehlt|nicht\s*(?:gesetzt|aktiv|vorhanden))",
        re.I,
     ), "cookie_no_httponly"),
    (re.compile(
        r"(?:cookie.*samesite|samesite[-_ ]?(?:flag|attribut)).*"
        r"(?:miss|not\s*set|fehlt|nicht\s*(?:gesetzt|aktiv|vorhanden))",
        re.I,
     ), "cookie_no_samesite"),
    # "Cookie-Sicherheitsattribute fehlen" — generisch, kein spezifisches Flag
    # genannt → wir mappen auf cookie_no_secure (verbreitetste/relevante Default-Lücke).
    # Pattern erlaubt "Sicherheits" (deutsches Genitiv-Fugenelement) und Verneinung
    # vor ODER nach dem Keyword.
    (re.compile(
        r"cookie[-_ ]?(?:sicherheit|security)\w*[-_ ]?attribut\w*.*(?:fehl|miss|not\s*set)",
        re.I,
     ), "cookie_no_secure"),

    # ── CSP ──────────────────────────────────────────────
    (re.compile(r"\bcsp\b.*unsafe[-_ ]?inline", re.I), "csp_unsafe_inline"),
    (re.compile(r"\bcsp\b.*unsafe[-_ ]?eval", re.I), "csp_unsafe_eval"),
    (re.compile(r"\bcsp\b.*wildcard|\bcsp\b.*\*", re.I), "csp_wildcard_source"),
    (re.compile(
        r"\bcontent[-_ ]?security[-_ ]?policy\b.*(?:miss|fehlt|not\s*set|nicht\s*gesetzt)",
        re.I,
     ), "csp_missing"),
    (re.compile(r"\bcsp\b.*(?:miss|fehlt|not\s*set|nicht\s*gesetzt)", re.I),
        "csp_missing"),

    # ── HSTS ─────────────────────────────────────────────
    (re.compile(r"hsts.*preload.*(?:miss|fehlt)", re.I), "hsts_preload_missing"),
    (re.compile(r"hsts.*include[-_ ]?subdomains.*(?:miss|fehlt)", re.I),
        "hsts_no_includesubdomains"),
    (re.compile(r"hsts.*max[-_ ]?age.*(?:short|<\s*15\d{6}|6\s*month|kurz)", re.I),
        "hsts_short_maxage"),
    (re.compile(
        r"\bhsts\b.*(?:miss|fehlt|not\s*set|nicht\s*gesetzt)|"
        r"strict[-_ ]?transport[-_ ]?security.*(?:miss|fehlt|not\s*set|nicht\s*gesetzt)",
        re.I,
     ), "hsts_missing"),

    # ── Andere Header ────────────────────────────────────
    # "Fehlende Security-Header" generisch → wir mappen auf xfo_missing
    # (wichtigster Vertreter; spezifischere Pattern weiter oben gewinnen).
    (re.compile(
        r"(?:fehlende|missing)\s*security[-_ ]?header(?!.*specific)",
        re.I,
     ), "xfo_missing"),
    (re.compile(
        r"x[-_ ]?content[-_ ]?type[-_ ]?options.*(?:miss|fehlt|not\s*set|nicht\s*gesetzt)",
        re.I,
     ), "xcto_missing"),
    (re.compile(
        r"x[-_ ]?frame[-_ ]?options.*(?:miss|fehlt|not\s*set|nicht\s*gesetzt)|"
        r"clickjack(?:ing)?[-_ ]?(?:schutz|protection).*(?:fehlt|miss)",
        re.I,
     ), "xfo_missing"),
    (re.compile(
        r"referrer[-_ ]?policy.*(?:miss|fehlt|not\s*set|nicht\s*gesetzt)",
        re.I,
     ), "referrer_policy_missing"),
    (re.compile(
        r"permissions[-_ ]?policy.*(?:miss|fehlt|not\s*set|nicht\s*gesetzt)",
        re.I,
     ), "permissions_policy_missing"),

    # ── CSRF ─────────────────────────────────────────────
    (re.compile(
        r"csrf[-_ ]?token.*(?:miss|fehlt|not\s*set)|"
        r"cross[-_ ]?site\s*request\s*forgery|"
        r"\bcsrf\b(?!.*(?:protect|schutz))",  # CSRF ohne Schutz erwaehnt
        re.I,
     ), "csrf_token_missing"),

    # ── SSH / Brute-Force ────────────────────────────────
    (re.compile(
        r"ssh.*(?:brute[-_ ]?force|fail2ban|rate[-_ ]?limit).*(?:miss|fehlt|kein|ohne)|"
        r"ssh.*(?:nicht[-_ ]?standard|non[-_ ]?standard).*port.*(?:ohne|miss|fehlt)",
        re.I,
     ), "ssh_no_brute_force_protection"),

    # ── TLS / Certificate ────────────────────────────────
    (re.compile(
        r"tls.*(?:1\.0|1\.1)|ssl\s*(?:v2|v3)|protocol\s*(?:obsolete|deprecat|veraltet)",
        re.I,
     ), "tls_below_tr03116_minimum"),
    (re.compile(
        r"(?:weak|schwache?)\s*cipher|cipher\s*suite\s*(?:weak|insecure|schwach)",
        re.I,
     ), "tls_weak_cipher_suites"),
    (re.compile(
        r"perfect\s*forward\s*secrecy|\bpfs\b.*(?:miss|fehlt|kein)",
        re.I,
     ), "tls_no_pfs"),
    (re.compile(
        r"(?:certificate|zertifikat).*(?:expired|abgelaufen|outdated)",
        re.I,
     ), "tls_certificate_expired"),
    (re.compile(
        r"(?:certificate|zertifikat).*(?:expir|laeuft).*(?:30|<\s*\d+)\s*(?:day|tag)",
        re.I,
     ), "tls_certificate_expiring_30d"),
    (re.compile(
        r"self[-_ ]?signed.*(?:certificate|zertifikat)|"
        r"(?:certificate|zertifikat).*(?:self[-_ ]?signed|selbst[-_ ]?signiert)",
        re.I,
     ), "tls_self_signed"),

    # ── DNS / Mail ───────────────────────────────────────
    (re.compile(r"dnssec.*(?:chain|broken|invalid|defekt|gebrochen)", re.I),
        "dnssec_chain_broken"),
    (re.compile(
        r"\bdnssec\b.*(?:miss|fehlt|not\s*(?:active|enabled|configured)|nicht\s*aktiv)",
        re.I,
     ), "dnssec_missing"),
    (re.compile(r"\bcaa\b[-_ ]?(?:record)?.*(?:miss|fehlt|not\s*set|nicht\s*gesetzt)",
                re.I), "caa_missing"),
    (re.compile(r"\bspf\b.*(?:soft[-_ ]?fail|~all|softfail|hardfail.*(?:fehlt|miss))",
                re.I), "spf_softfail"),
    # SPF missing: Verneinung vor ODER nach SPF
    (re.compile(
        r"(?:kein|fehlend|fehlt|no|missing)[\w\s]*\bspf\b|"
        r"\bspf\b[-_ ]?(?:record)?.*(?:miss|fehlt|not\s*(?:configured|set|present)|nicht\s*(?:gesetzt|konfiguriert))",
        re.I,
     ), "spf_missing"),
    # DMARC quanruantine — neu (war bisher Lücke!)
    (re.compile(
        r"dmarc[-_ ]?(?:policy)?.*(?:p[\s=:]*quarantine|quarantine[-_ ]?policy|"
        r"auf\s*['\"]?quarantine['\"]?)",
        re.I,
     ), "dmarc_p_quarantine"),
    (re.compile(
        r"dmarc[-_ ]?(?:policy)?.*(?:p[\s=:]*none|none[-_ ]?policy|"
        r"auf\s*['\"]?none['\"]?|kein\s*enforcement)",
        re.I,
     ), "dmarc_p_none"),
    (re.compile(
        r"\bdmarc\b[-_ ]?(?:record)?.*(?:miss|fehlt|not\s*(?:configured|set|present)|nicht\s*(?:gesetzt|konfiguriert))",
        re.I,
     ), "dmarc_missing"),
    # DKIM missing: Verneinung vor ODER nach DKIM
    (re.compile(
        r"(?:kein|fehlend|fehlt|no|missing)[\w\s-]*\bdkim\b|"
        r"\bdkim\b[-_ ]?(?:konfiguration|configuration|record)?.*"
        r"(?:miss|fehlt|not\s*(?:configured|set|present)|nicht\s*(?:gesetzt|konfiguriert))",
        re.I,
     ), "dkim_missing"),
    (re.compile(
        r"mta[-_ ]?sts.*(?:miss|fehlt|not\s*(?:configured|set)|nicht\s*(?:gesetzt|konfiguriert))",
        re.I,
     ), "mta_sts_missing"),

    # ── EOL Software ─────────────────────────────────────
    (re.compile(
        r"end[-_ ]?of[-_ ]?life|\beol\b|out[-_ ]?of[-_ ]?support|"
        r"veraltet|unsupported\s*version|nicht\s*mehr\s*unterstuetzt",
        re.I,
     ), "software_eol"),
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
