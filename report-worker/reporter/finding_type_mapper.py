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
    # ── Datenbank-Port-Exposition (sehr spezifisch zuerst) ─
    # Muss VOR generischen "Port exponiert" Patterns matchen.
    (re.compile(
        r"(?:mysql|mariadb|postgres|postgresql|mongodb|redis|elastic|elasticsearch|"
        r"cassandra|couchdb|dynamodb)[-_ ]?(?:datenbank|database|server|port|service|dienst)?"
        r".*(?:expon|publicly|oeffentlich|erreichbar|exposed|offen|3306|5432|27017|6379)",
        re.I,
     ), "database_port_exposed"),
    (re.compile(
        r"(?:port|tcp)[-_ ]?(?:3306|5432|27017|6379|9200|11211).*(?:expon|offen|erreichbar)",
        re.I,
     ), "database_port_exposed"),

    # ── Cross-Domain / CORS Fehlkonfiguration ──────────────
    (re.compile(
        r"cross[-_ ]?(?:domain|origin)[-_ ]?(?:fehl|miss|konfig|configuration|policy)|"
        r"\bcors\b.*(?:fehl|miss|wildcard|misconfig|insecure|unsicher)|"
        r"access[-_ ]?control[-_ ]?allow[-_ ]?origin.*(?:wildcard|\*|miss|fehl)",
        re.I,
     ), "cors_misconfiguration"),

    # ── JavaScript-Library-Vulnerability ───────────────────
    (re.compile(
        r"(?:verwundbare?|veraltete?|vulnerable|outdated)\s*(?:javascript|js)[-_ ]?(?:bibliothek|library)|"
        r"(?:javascript|js)[-_ ]?(?:bibliothek|library).*(?:verwundbar|veraltet|vulnerable|outdated|cve)|"
        r"\b(?:jquery|bootstrap|angularjs|moment\.js|lodash|underscore)\b\s*[<\d.]+.*(?:verwundbar|outdated|veraltet|vuln)",
        re.I,
     ), "js_library_vulnerable"),

    # ── Private IP / Information-Leak in Antworten ─────────
    (re.compile(
        r"(?:private|interne)?\s*ip[-_ ]?(?:adress|address)e?n?.*(?:in|via|durch).*"
        r"(?:antwort|response|http[-_ ]?antwort|http[-_ ]?response|leak|disclos|exposed|offengelegt|preisgegeben)|"
        r"(?:rfc[-_ ]?1918|10\.\d|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.).*(?:expon|leak|disclos|offengelegt|preisgegeben)",
        re.I,
     ), "private_ip_disclosure"),

    # ── Subresource Integrity (SRI) ────────────────────────
    (re.compile(
        r"(?:fehlende?|missing)\s*(?:sub[-_ ]?resource[-_ ]?integrity|sri)|"
        r"\bsri\b.*(?:fehl|miss|not[-_ ]?set|nicht[-_ ]?gesetzt)|"
        r"(?:sri|integrity)[-_ ]?hash.*(?:fehl|miss)",
        re.I,
     ), "sri_missing"),

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
    # Framework-Dev-Build muss VOR generic directory_listing kommen — sonst
    # matcht Haiku-Fallback react.development.js auf "Directory-Listing".
    (re.compile(
        r"react[.-]?development\.js|vue[.-]?runtime\.dev|angular[.-]?dev|"
        r"react[.-]?dom[.-]?development|"
        r"development[-_ ]?build.*(?:eingebunden|production|deployed|exposed)|"
        r"dev[-_ ]?(?:build|mode|version).*(?:eingebunden|im\s*production|production)",
        re.I,
     ), "framework_dev_build_exposed"),
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
    # B1 Mai 2026: zusaetzlich "Server- und Technologie-Versionsinformationen",
    # "versionsinformation in http", "server-banner mit version" (Title-Template-Form),
    # "(nginx|apache|iis|php)/X.Y" als Banner-Marker.
    (re.compile(
        r"(?:apache|nginx|iis|php|openssh|ssh|tomcat|jetty|caddy)[-_ ]?versions?(?:[-_ ]?information)?|"
        r"server[-_ ]?(?:banner|header).*(?:version|verraet|zeigt|preisgibt|disclos)|"
        r"version.*(?:disclos|preisgegeben|im\s*header|im\s*banner|in\s*server[-_ ]?header)|"
        r"(?:server|software|tech)[-_ ]?version[-_ ]?(?:disclosure|leakage|information)|"
        r"server[-_ –—]?\s*und\s*technologie[-_ ]?versions?information|"
        r"server[-_ ]?\s*und\s*tech[-_ ]?versions?information|"
        r"(?:technologie|tech)[-_ ]?versions?information(?:en)?\s*in\s*http|"
        r"versions?information(?:en)?\s*in\s*(?:http|header|banner)|"
        # Banner-Format mit `/`-Trenner (z.B. nginx/1.22.1 — nicht "PHP 5.6"):
        r"(?:nginx|apache|iis|php|openssh)/\d+(?:\.\d+){1,3}|"
        r"server[-_ ]?banner\s*mit\s*versions?[-_ ]?info|"
        r"server[-_ ]?\s*und\s*technologie[-_ ]?versions?[-_ ]?info",
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
    # B1 Mai 2026: zusaetzlich "Unsichere Cookie-Konfiguration", "Cookie-Konfiguration unsicher",
    # "Session-Cookie ohne ..." (Template-Form ohne explizites "fehl").
    (re.compile(
        r"cookie[-_ ]?(?:sicherheit|security)\w*[-_ ]?attribut\w*.*(?:fehl|miss|not\s*set)|"
        r"unsicher\w*\s*cookie[-_ ]?konfiguration|"
        r"cookie[-_ ]?konfiguration\s*unsicher|"
        r"session[-_ ]?cookie\s+ohne\s+(?:secure|httponly|samesite)",
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
    # F-P0A-002 — TLS-RPT/BIMI/DMARC pct/NSEC3 (POLICY_VERSION 2026-05-09.1)
    (re.compile(
        r"tls[-_ ]?rpt.*(?:miss|fehlt|not\s*(?:configured|set)|nicht\s*(?:gesetzt|konfiguriert))|"
        r"(?:miss|fehlt|kein|no)[\w\s-]*\btls[-_ ]?rpt\b|"
        r"\b_smtp\._tls\b|\bRFC[-_ ]?8460\b",
        re.I,
     ), "tls_rpt_missing"),
    (re.compile(
        r"\bbimi\b.*(?:miss|fehlt|not\s*(?:configured|set)|nicht\s*(?:gesetzt|konfiguriert))|"
        r"(?:miss|fehlt|kein|no)[\w\s-]*\bbimi\b|"
        r"\bdefault\._bimi\b",
        re.I,
     ), "bimi_missing"),
    (re.compile(
        r"dmarc.*pct\s*[<=]\s*?\d{1,3}|"
        r"dmarc.*pct[\s=:]*(?:[1-9]?\d)\b|"
        r"dmarc[-_ ]?(?:policy)?.*(?:teilweise|partial(?:[\s-]?enforcement)?|nicht\s*voll(?:staendig)?\s*aktiv|nur\s*\d{1,2}\s*%)",
        re.I,
     ), "dmarc_pct_partial"),
    (re.compile(
        r"nsec3.*iterations?\s*(?:>\s*0|=\s*[1-9]\d*|nicht\s*0|non[-_ ]?zero)|"
        r"\bRFC[-_ ]?9276\b|"
        r"nsec3param.*iterations?",
        re.I,
     ), "nsec3_iterations_nonzero"),

    # ── EOL Software ─────────────────────────────────────
    # B1 Mai 2026: zusaetzlich "vor End-of-Life", "ohne Sicherheitsupdates",
    # "kein Support mehr", "Microsoft hat den Support eingestellt"
    (re.compile(
        r"end[-_ ]?of[-_ ]?life|\beol\b|out[-_ ]?of[-_ ]?support|"
        r"veraltet|unsupported\s*version|nicht\s*mehr\s*unterstuetzt|"
        r"vor\s+end[-_ ]?of[-_ ]?life|"
        r"ohne\s+sicherheitsupdates|"
        r"keine?\s*sicherheitsupdates\s+mehr|"
        r"support\s+(?:eingestellt|beendet|laeuft\s*aus)|"
        r"(?:exchange|windows\s*server|sql\s*server)\s+(?:200[0-9]|201[0-9])\s+(?:vor|wird|ist).*(?:eol|end[-_ ]?of[-_ ]?life|support)",
        re.I,
     ), "software_eol"),

    # ── F-P0A-003 — URLhaus / Threat-Intel Compromise ──────
    # WICHTIG: keine breite `host.*kompromit`-Regel — die matcht greedy bis zu
    # jedem "kompromittierten Netz/Zwischennetz" im Impact-Text und holt sich
    # auch FTP-Cleartext-Befunde rein. Stattdessen explizit URLhaus-spezifische
    # Phrasen.
    (re.compile(
        r"\burlhaus\b|"
        r"abuse\.ch|"
        r"(?:listed|gelistet)\s+(?:as|als)\s+(?:compromised|kompromittiert)|"
        r"(?:malware|phishing|c2|c&c|command[-_ ]?and[-_ ]?control)[-_ ]"
        r"(?:distribut|hosting|infrastruktur)|"
        # "Host kompromittiert" als feste Phrase (max 20 Zeichen Abstand —
        # erlaubt z.B. "Host xyz.de wird aktiv kompromittiert" aber
        # blockiert greedy multi-sentence-Sprung).
        r"(?:host|domain)\b[^.!?]{0,20}\bkompromit",
        re.I,
     ), "urlhaus_compromise_detected"),
]


# M2 Track 2b (P0-05): Banner-Service-Discriminator-Patterns. Wenn
# finding_type=="server_banner_with_version" gesetzt wird, leiten wir
# zusaetzlich title_vars["service"] = "ssh"|"http"|"smtp"|"ftp" ab.
_BANNER_SERVICE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # SSH: OpenSSH-Banner haben Praefix "SSH-2.0-"
    (re.compile(
        r"\bSSH-2\.0\b|\bOpenSSH\b|\blibssh\b|\bdropbear\b|"
        r"ssh[-_ ]?(?:banner|server|service|dienst)|"
        r"\b(?:port\s*)?22\b.*(?:ssh|banner)",
        re.I,
     ), "ssh"),
    # HTTP/Web: Apache/nginx/IIS/X-Powered-By
    (re.compile(
        r"\b(?:apache|nginx|iis|microsoft-iis|caddy|lighttpd|tomcat|jetty)\b"
        r"|x[-_ ]?powered[-_ ]?by"
        r"|http[-_ ]?(?:header|banner|response)"
        r"|server[-_ ]?(?:header).*(?:apache|nginx|iis)",
        re.I,
     ), "http"),
    # SMTP: ESMTP/Postfix/Sendmail/Exim
    (re.compile(
        r"\bESMTP\b|\bPostfix\b|\bSendmail\b|\bExim\b|\bMailEnable\b|"
        r"smtp[-_ ]?(?:banner|server|service|greeting)|"
        r"\b220\b.*smtp",
        re.I,
     ), "smtp"),
    # FTP: ProFTPD/vsftpd/Pure-FTPd
    (re.compile(
        r"\bProFTPD\b|\bvsftpd\b|\bPure-FTPd\b|\bFileZilla\s*Server\b|"
        r"ftp[-_ ]?(?:banner|server|service|greeting)|"
        r"\b220\b.*ftp",
        re.I,
     ), "ftp"),
]


def _detect_banner_service(finding: dict) -> Optional[str]:
    """Leitet aus evidence/title/description/affected den Service-Typ
    eines info_disclosure_banner-Findings ab. Returns: "ssh"|"http"|"smtp"|"ftp"|None.
    """
    blobs: list[str] = []
    for key in ("title", "description", "evidence", "affected", "service", "protocol"):
        v = finding.get(key)
        if isinstance(v, str):
            blobs.append(v)
        elif isinstance(v, dict):
            # evidence kann dict sein → str-Werte sammeln
            for vv in v.values():
                if isinstance(vv, str):
                    blobs.append(vv)
    haystack = " | ".join(blobs)
    if not haystack:
        return None
    for pat, svc in _BANNER_SERVICE_PATTERNS:
        if pat.search(haystack):
            return svc
    return None


# M2 Track 2b (P0-03): Mail-Security Cross-Check zwischen Title-Pattern und Body.
# "SPF im Title aber DKIM im Body" → re-klassifizieren auf das Body-Pattern.
_MAIL_KEY_PATTERNS = {
    "spf":   re.compile(r"\bSPF\b", re.I),
    "dkim":  re.compile(r"\bDKIM\b", re.I),
    "dmarc": re.compile(r"\bDMARC\b", re.I),
}

# Mapping: erkannter Body-Key → severity_policy finding_type
_MAIL_KEY_TO_FINDING_TYPE = {
    "spf":   "spf_missing",
    "dkim":  "dkim_missing",
    "dmarc": "dmarc_missing",
}


def _crosscheck_mail_security(finding: dict, mapped_type: Optional[str]) -> Optional[str]:
    """Wenn mapped_type ein SPF/DKIM/DMARC-_missing-Typ ist, pruefe ob Body
    einen ANDEREN Mail-Key staerker erwaehnt. Falls ja → re-klassifizieren.

    Beispiel: Title "SPF fehlt", Description "DKIM-Record nicht gesetzt".
    → return "dkim_missing".

    Falls alle drei Keys (SPF + DKIM + DMARC) im Body genannt sind → mapped_type
    bleibt (generischer Mail-Security-Sammelbefund).
    """
    if mapped_type not in {"spf_missing", "dkim_missing", "dmarc_missing"}:
        return None

    title = str(finding.get("title") or "")
    body_parts = [
        str(finding.get("description") or ""),
        str(finding.get("impact") or ""),
        str(finding.get("evidence") or ""),
    ]
    body = " | ".join(body_parts)
    if not body.strip():
        return None

    title_keys = {k for k, p in _MAIL_KEY_PATTERNS.items() if p.search(title)}
    body_keys = {k for k, p in _MAIL_KEY_PATTERNS.items() if p.search(body)}

    # Wenn alle drei im Body genannt sind → generisch bleiben.
    if body_keys >= {"spf", "dkim", "dmarc"}:
        return mapped_type

    # Wenn mapped_type aus Title-Pattern resultiert (z.B. "spf_missing") aber
    # body_keys NUR einen anderen Key enthaelt → re-klassifizieren.
    type_to_key = {"spf_missing": "spf", "dkim_missing": "dkim", "dmarc_missing": "dmarc"}
    current_key = type_to_key[mapped_type]
    other_body_keys = body_keys - {current_key}

    # Wenn current_key NICHT im Body, aber genau ein anderer Key DA ist → switch
    if current_key not in body_keys and len(other_body_keys) == 1:
        new_key = next(iter(other_body_keys))
        return _MAIL_KEY_TO_FINDING_TYPE[new_key]

    # Wenn current_key auch im Body ist, behalten wir mapped_type bei
    # (Body bestaetigt Title).
    return None


def map_finding_type(finding: dict) -> Optional[str]:
    """Klassifiziert ein Claude-Finding in einen severity_policy finding_type.

    Reihenfolge der Auswertung:
    1. Wenn `cve` oder `cve_id` gesetzt → "cve_finding"
    2. Pattern-Matching ueber title + description + cwe (in dieser Reihenfolge)
    3. M2 Track 2b: Mail-Security-Crosscheck (P0-03) — SPF/DKIM/DMARC
       Title vs. Body, re-klassifizieren wenn Body abweicht.
    4. Wenn nichts greift: None (Caller faellt auf SP-FALLBACK zurueck)
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

    mapped: Optional[str] = None
    for pattern, finding_type in _PATTERNS:
        if pattern.search(haystack):
            mapped = finding_type
            break

    # 3. Mail-Security Cross-Check
    if mapped:
        crosschecked = _crosscheck_mail_security(finding, mapped)
        if crosschecked:
            mapped = crosschecked

    return mapped


def annotate_finding_types(findings: list[dict],
                            use_ai_fallback: bool = True) -> list[dict]:
    """Setzt finding_type IN-PLACE auf jedem Finding (wenn nicht schon gesetzt).

    B2 (Mai 2026): wenn Regex-Match leer bleibt UND `use_ai_fallback=True`,
    wird Haiku via `ai_finding_type_fallback.map_finding_type_via_ai`
    befragt (gecacht 30 Tage). Bei API-Fehler oder unklarem Ergebnis →
    finding_type bleibt None (= SP-FALLBACK in severity_policy).

    Marker `_finding_type_source` auf jedem Finding fuer QA/Audit:
      "regex" | "ai_fallback" | "preset"
    """
    needs_ai: list[dict] = []
    for f in findings:
        if f.get("finding_type"):
            f.setdefault("_finding_type_source", "preset")
        else:
            inferred = map_finding_type(f)
            if inferred:
                f["finding_type"] = inferred
                f["_finding_type_source"] = "regex"
            else:
                needs_ai.append(f)

        # M2 Track 2b (P0-05): Wenn finding_type == "info_disclosure_banner"
        # oder "server_banner_with_version" → service-Discriminator ableiten.
        ft = f.get("finding_type") or ""
        if ft in ("info_disclosure_banner", "server_banner_with_version"):
            tv = f.get("title_vars")
            if not isinstance(tv, dict):
                tv = {}
                f["title_vars"] = tv
            if not tv.get("service"):
                svc = _detect_banner_service(f)
                if svc:
                    tv["service"] = svc

    if use_ai_fallback and needs_ai:
        try:
            from reporter.ai_finding_type_fallback import map_finding_type_via_ai
            from concurrent.futures import ThreadPoolExecutor
            # F-RPT-004: parallelisiert Cold-Cache-Faelle (5-60s -> 1-3s).
            # max_workers=5 schont Anthropic-Rate-Limits (Haiku Tier-1: 50 RPM
            # = 0.83 req/s; max_workers=5 x 1s Latenz = 5 req/s — bleibt unter
            # Limit; SDK-Retry/Backoff bei 429 bereits aktiv).
            with ThreadPoolExecutor(max_workers=5) as ex:
                futs = {ex.submit(map_finding_type_via_ai, f): f for f in needs_ai}
                for fut in futs:
                    f = futs[fut]
                    try:
                        ai_type = fut.result(timeout=10)
                    except Exception:
                        ai_type = None
                    if ai_type:
                        f["finding_type"] = ai_type
                        f["_finding_type_source"] = "ai_fallback"
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(
                "ai_fallback_unavailable err=%s", e)

    return findings


__all__ = ["map_finding_type", "annotate_finding_types"]
