"""Tabellen und Muster fuer die Pruefungen (Session S2).

Alles, was in YAML-Ausdruecken als GROSSGESCHRIEBENER Name auftaucht, steht hier.
Jede Aenderung an dieser Datei bumpt CATALOG_VERSION (siehe version.py). Quellen:
report-prototype/build/catalog_sim.py (Ports, Titel), spec/06 Abschnitt 4 (Ignorier-
liste, Auffangregeln), reporter/facts/tool_coverage.py (Coverage-Codes) und die
Aggregation ueber die 36 Snapshot-Orders (ZAP-IDs, Passivports).
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------- Ports

DB_PORTS: dict[int, str] = {
    1433: "MSSQL", 1521: "Oracle", 3306: "MariaDB/MySQL", 5432: "PostgreSQL", 5984: "CouchDB",
    6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

# Ports, die fuer sich genommen eine Verwaltungsoberflaeche anzeigen (ohne Produktnachweis).
# Reine Alternativports (8080, 8443, 8000, 2222) stehen bewusst nicht hier; sie laufen ueber
# http_alt_port bzw. ssh_alt_port, sofern kein Produkt aus ADMIN_PRODUCTS dahinter steht.
ADMIN_PORTS: dict[int, str] = {
    111: "rpcbind", 2083: "cPanel", 2087: "WHM", 3128: "Proxy", 4433: "Firewall-Verwaltung",
    5060: "SIP", 8006: "Proxmox", 8880: "Plesk", 9443: "Portainer", 10000: "Webmin",
}

# Produkt- und Titelmuster fuer Verwaltungsoberflaechen (nmap product, Shodan product, Seitentitel).
ADMIN_PRODUCTS = re.compile(
    r"sw-cp-server|plesk|webmin|miniserv|portainer|proxmox|cpanel|fortigate|fortinet|sonicwall|rustdesk|"
    r"jitsi|phpmyadmin|kubernetes|swagger", re.I)
# S6b-2 (spec/09 Q13, E1): Hosting-Verwaltungen, die ein Hoster auf geteilten Servern
# betreibt. Auf einem geteilten System richtet sich die Empfehlung an den Hoster.
HOSTING_PANELS = re.compile(r"sw-cp-server|plesk|cpanel|whm|directadmin|ispconfig|froxlor|webmin|miniserv", re.I)
ADMIN_TITLES = re.compile(
    r"plesk|cpanel|portainer|proxmox|webmin|phpmyadmin|fortigate|fortinet|sonicwall|jitsi|rustdesk|"
    r"gitlab|jenkins|grafana|kibana|swagger ui|kubernetes dashboard", re.I)
LOGIN_TITLES = re.compile(
    r"outlook|\bowa\b|roundcube|webmail|nextcloud|openotp|web applications portal|bitwarden|"
    r"remote desktop|rd web|citrix|\bvpn\b|sslvpn|anmelden|\blog ?in\b", re.I)
DEFAULT_TITLES = re.compile(
    r"default page|default web|iis windows|apache2 .* default|welcome to nginx|froxlor|plesk default|"
    r"web server's default|it works|test page", re.I)
DIRECTORY_LISTING_TITLES = re.compile(r"^\s*index of\s*/", re.I)
DEV_HOST_PREFIX = re.compile(r"^(dev|test|testing|staging|stage|demo|old|alt|preview)\.", re.I)
YEAR_HINT = re.compile(r"(?<![0-9])(2003|2008|2012|2016|2019|2022)(?![0-9])")
CDN_PRODUCTS = re.compile(r"cloudflare|cloudfront|akamai|fastly|incapsula|imperva|edgecast", re.I)
# Cloudflare-Edge-Ports, die Shodan an jeder Edge-IP meldet (spec/06 Abschnitt 4, heuel.com).
CDN_PASSIVE_PORTS = frozenset({2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880})

MAIL_PORTS: dict[int, str] = {25: "SMTP", 110: "POP3", 143: "IMAP", 587: "Submission"}
LEGACY_PORTS: dict[int, str] = {21: "FTP", 110: "POP3", 143: "IMAP"}
WEB_PORTS = frozenset({80, 443})
SSH_PORT = 22

# Sensible Pfade (feroxbuster/ffuf, nur Status 200). Enge Liste, Inhalt wird nicht geprueft.
SENSITIVE_PATHS = re.compile(
    r"(/\.git/(HEAD|config)$|/\.env$|/\.env\.[a-z]+$|\.sql$|\.sql\.gz$|\.bak$|/phpinfo\.php$|"
    r"/\.DS_Store$|/wp-config\.php\.(bak|old|save)$|/\.htpasswd$|/\.aws/credentials$|/\.svn/entries$)", re.I)

KNOWN_PORTS: frozenset[int] = frozenset(
    {21, 22, 25, 53, 80, 106, 110, 139, 143, 443, 445, 465, 587, 993, 995, 3389, 8000, 8080, 8443, 2222}
    | set(DB_PORTS) | set(ADMIN_PORTS) | set(MAIL_PORTS))

# ---------------------------------------------------------------- Geteilte Systeme
# S6b-1 (spec/09 Q3, Entscheidung DC 24.09.2026, Umfang wie in spec/09 markiert): auf
# einem geteilten Server (Hoster) liegen diese Pruefungen beim Betreiber, weil der
# Kunde den Dienst nicht selbst aendern kann: Verwaltungsoberflaechen, FTP, POP3, IMAP
# und SMTP, das Banner eines Dienstes und fremde Dienste auf Zusatzports. Datenbankports,
# TLS-Konfiguration, Zertifikat, Sicherheits-Header, Inhalte und Webanwendung bleiben
# beim Kunden. Auf einer Plattform (SaaS, Baukasten, CDN) liegt alles Hostbezogene beim
# Plattformbetreiber; nur DNS- und Mail-Eintraege der Domain bleiben beim Kunden.
SHARED_OPERATOR_CHECKS: frozenset[str] = frozenset({
    "admin_service_exposed", "admin_service_exposed_passive", "admin_panel_hoster", "admin_service_unconfirmed",
    "ftp_plaintext", "legacy_protocols_present", "mail_plaintext", "service_banner_version", "http_alt_port",
    "ssh_alt_port",
})
PLATFORM_CUSTOMER_SCOPES: frozenset[str] = frozenset({"dns", "dns.dangling_cnames", "target", "scan"})

# ---------------------------------------------------------------- TLS

TLS_LEGACY = ("SSLv2", "SSLv3", "TLS1.0", "TLS1.1")
TLS_WEAK_CIPHER_KEYS = frozenset({"null", "anon", "export", "low", "3des", "rc4"})
TLS_HARD_VULNS = frozenset({"Heartbleed", "CCS", "ROBOT", "POODLE", "DROWN", "FREAK", "LOGJAM", "Ticketbleed"})
TLS_SOFT_VULNS = frozenset({"SWEET32", "BEAST", "RC4", "CRIME"})
TLS_COMPRESSION_VULNS = frozenset({"BREACH"})
# S6b-2 (spec/09 Q4, Teil 2 JW): BREACH gilt laut testssl fuer statische Seiten nicht
# ("Can be ignored for static pages"), LUCKY13 meldet testssl nur experimentell. Beide
# loesen keinen Befund aus und stehen als Werkzeugmeldung im Anhang.
TLS_REPORTED_VULNS = frozenset({"BREACH", "LUCKY13"})
HSTS_MIN_MAX_AGE = 15552000
CERT_EXPIRING_DAYS = 30
# S6b-2 (E2): bis sieben Tage Unverzueglich, acht bis 14 Tage Hygiene hoch, darueber bis
# CERT_EXPIRING_DAYS mittelfristig.
CERT_URGENT_DAYS = 7
CERT_SOON_DAYS = 14
DOMAIN_EXPIRING_DAYS = 30
ABUSEIPDB_FAIL_SCORE = 25

# ---------------------------------------------------------------- ZAP-Alert-Familien
# Paare (plugin_id, Namensmuster). Snapshot-Alerts tragen oft keine plugin_id, deshalb
# zaehlt immer beides. Die Namen sind ZAP-Originalnamen (Englisch, nicht Kundentext).

ZAP_INFO_DISCLOSURE = [("2", r"private ip disclosure"), ("10096", r"timestamp disclosure"),
                       ("10027", r"suspicious comments"), ("90022", r"application error disclosure"),
                       ("10023", r"information disclosure - debug"), ("10024", r"information disclosure - sensitive"),
                       ("10025", r"information disclosure - sensitive"), ("10009", r"in page banner information leak"),
                       ("10044", r"big redirect detected"), ("10017", r"cross-domain javascript source"),
                       ("10061", r"x-aspnet-version response header")]
ZAP_CSRF = [("10202", r"absence of anti-csrf tokens")]
ZAP_JS_LIBRARY = [("10003", r"vulnerable js library")]
ZAP_ACTIVE = [("40018", r"sql injection"), ("40019", r"sql injection"), ("40020", r"sql injection"),
              ("40021", r"sql injection"), ("40022", r"sql injection"), ("40024", r"sql injection"),
              ("40012", r"cross site scripting"), ("40014", r"cross site scripting"),
              ("40016", r"cross site scripting"), ("40017", r"cross site scripting"),
              ("6", r"path traversal"), ("7", r"remote file inclusion"), ("90019", r"code injection"),
              ("90020", r"command injection"), ("90023", r"xml external entity"), ("40046", r"server side request forgery"),
              ("40008", r"parameter tampering"), ("40009", r"server side include")]
ZAP_DIRECTORY_LISTING = [("0", r"directory browsing")]
ZAP_SESSION_URL = [("3", r"session id in url rewrite")]
ZAP_CORS = [("40040", r"cors header"), ("10098", r"cross-domain misconfiguration")]
ZAP_SRI = [("90003", r"sub resource integrity attribute missing")]
# S6b-2 (spec/09 Q14): Familien, die eine Katalogregel ausloesen, wenn ZAP sie mit
# Konfidenz High meldet. Darunter stehen sie als Werkzeugmeldung im Anhang.
# Cookie-Meldungen (S6b-2, spec/09 Teil 2 HL): ohne eigene Regel, unter High im Anhang, ab
# High als Beobachtung ohne Regel; cookie_flags bleibt die Regel fuer header_check.
ZAP_COOKIE = [("10010", r"cookie no httponly flag"), ("10011", r"cookie without secure flag"),
              ("10054", r"cookie (without|with) samesite attribute")]
ZAP_RATED = (ZAP_ACTIVE + ZAP_CSRF + ZAP_CORS + ZAP_DIRECTORY_LISTING + ZAP_SESSION_URL + ZAP_SRI
             + ZAP_COOKIE)

# ---------------------------------------------------------------- Banner und Schutzsysteme
# S6b-2 (spec/09 Q4): Versionskennungen, die zum Protokoll gehoeren und sich nicht abschalten
# lassen. Das SSH-Protokoll verlangt die Kennung im Banner, der MariaDB/MySQL-Handshake
# uebertraegt die Serverversion immer.
# S6b-2 (spec/09 Q4): nmap nennt bei PostgreSQL "9.6.0 or later", eine aus dem Protokoll
# abgeleitete Untergrenze. Das ist keine Versionsangabe des Dienstes.
VERSION_LOWER_BOUND = re.compile(r"\bor later\b", re.I)
BANNER_FIXED = re.compile(r"\bssh\b|openssh|dropbear|mysql|mariadb", re.I)
# S6b-2 (spec/09 Q12): Erkennung ohne benanntes Produkt (Generic-Heuristik von wafw00f).
WAF_GENERIC = re.compile(r"generic|unknown", re.I)

# ---------------------------------------------------------------- Coverage
# Code -> (Status, Text). Unbekannte Codes ergeben not_testable mit generischem Text.
COVERAGE_REASONS: dict[str, tuple[str, str]] = {
    "no_ssl": ("not_applicable", "Kein TLS-Dienst auf diesem Host, TLS-Prüfung entfällt."),
    "cms_not_wordpress": ("not_applicable", "Kein WordPress erkannt, WordPress-Prüfung entfällt."),
    "no_web": ("not_applicable", "Kein Webdienst auf diesem Host, Web-Prüfung entfällt."),
    "no_api_urls": ("not_applicable", "Keine API-Endpunkte gefunden, Parameter-Prüfung entfällt."),
    "no_zap_context": ("not_applicable", "Kein Web-Kontext für die passive Webanalyse, Prüfung entfällt."),
    "not_in_package": ("not_applicable", "Nicht Bestandteil des gebuchten Pakets."),
    "passive_only_policy": ("not_applicable", "Nur passive Webanalyse vorgesehen."),
    # S6b-1 (spec/09 Q9): ein Portscan ohne offenen Port ist kein Messergebnis. Die
    # Abwesenheit eines Dienstes ist damit nicht belegt; bis S6b-1 galt er als "ok".
    "no_open_ports": ("not_testable", "Der Portscan fand keinen offenen Port; ob dort Dienste erreichbar sind, ist damit nicht belegt."),
    "unreachable_from_scanner": ("not_testable", "Vom Prüfstand aus nicht erreichbar: der Portscan fand keinen offenen Port, eine Passivquelle meldet dort jedoch Dienste."),
    "no_data": ("ok", "Abfrage ohne Treffer."),
    "wordlist_missing": ("not_testable", "Wortliste im Scanner fehlte, Verzeichnis-Prüfung nicht durchgeführt."),
    "does_not_exist": ("not_testable", "Aktive Webanalyse ist im Scanner fehlgeschlagen."),
    "zap_api_error": ("not_testable", "Aktive Webanalyse ist im Scanner fehlgeschlagen."),
    "zap_unreachable": ("not_testable", "Die Webanalyse-Komponente war nicht erreichbar."),
    "zap_no_alerts": ("not_testable", "Die passive Webanalyse lieferte keine Meldungen; Ergebnis nicht belastbar."),
    "target_invalid_ipv6": ("not_testable", "IPv6-Adresse wurde vom Portscan nicht geprüft."),
    "target_skipped": ("not_testable", "Ziel wurde vom Portscan übersprungen."),
    "nmap_no_runstats": ("not_testable", "Der Portscan hat keine Bilanz hinterlassen; Ergebnis nicht belastbar."),
    "no_ipv6_route": ("not_testable", "Der Prüfstand hatte keine IPv6-Verbindung zu dieser Adresse; über IPv6 erreichbare Dienste konnten nicht geprüft werden."),
    "host_unreachable": ("not_testable", "Host war während des Scans nicht erreichbar."),
    "web_unreachable_after_portscan": ("not_testable", "Der Host hat nach dem Portscan weitere Verbindungen abgewiesen; Web-Prüfungen nicht möglich."),
    "unreachable": ("not_testable", "Virtueller Host war über HTTP nicht erreichbar."),
    "second_target_unlabeled": ("not_testable", "Für diese weitere Domain liegen keine eigenen DNS-Abfragen vor."),
    "no_dns_facts": ("not_testable", "Keine DNS-Fakten für diese Domain."),
    "no_api_key": ("not_testable", "Quelle ohne Zugangsschlüssel, nicht abgefragt."),
    "no_tech_signals": ("not_testable", "Keine Technologie-Signale erkannt."),
    "timeout": ("not_testable", "Werkzeug lief in einen Timeout."),
    "connect": ("not_testable", "Keine Verbindung zum Dienst möglich."),
    "ai_skip": ("not_testable", "Werkzeug wurde von der Scan-Steuerung übersprungen."),
    "no_tool_runs": ("not_testable", "Zu diesem Host liegt kein Laufprotokoll vor; welche Prüfungen stattgefunden haben, ist nicht belegt."),
    "no_coverage_rows": ("not_testable", "Zu diesem Werkzeug liegt kein Laufprotokoll vor."),
    "no_urls_spidered": ("not_testable", "Keine URLs gefunden, Webanalyse ohne Grundlage."),
    "no_output": ("not_testable", "Werkzeug lieferte keine Ausgabe."),
    "mail_capabilities_unknown": ("not_testable", "Der Maildienst nannte keine Fähigkeiten; STARTTLS-Angebot manuell prüfen."),
    # S6b-2 (spec/08 Punkt 4): der Portscan belegt beim FTP-Dienst weder TLS-Zwang noch
    # Klartext-Anmeldung. Ohne Beleg kein Befund "ohne TLS-Zwang".
    "ftp_tls_unknown": ("not_testable", "Ob der FTP-Dienst eine Anmeldung ohne Transportverschlüsselung ablehnt, zeigt der Portscan nicht."),
    "tls_protocols_unknown": ("not_testable", "Die Liste der angebotenen TLS-Protokolle lag für diesen Dienst nicht vor."),
    "tls_ciphers_unknown": ("not_testable", "Die Liste der angebotenen Verschlüsselungsverfahren lag für diesen Dienst nicht vor."),
    # S6b-1 (spec/09 Q10): httpx hat den Dienst gesehen, testssl nicht. "Nicht verfuegbar"
    # waere falsch; bekannt ist die ausgehandelte Verbindung, nicht die ganze Liste.
    "tls_protocols_partial": ("not_testable", "Die Transportverschlüsselung ist nur über die ausgehandelte Verbindung belegt; die vollständige Liste der angebotenen Protokolle lag nicht vor."),
    "tls_ciphers_partial": ("not_testable", "Die Transportverschlüsselung ist nur über die ausgehandelte Verbindung belegt; die vollständige Liste der angebotenen Verfahren lag nicht vor."),
    "wordpress_unknown": ("not_testable", "Zur WordPress-Installation lagen keine Angaben zu Kern, Erweiterungen und Benutzern vor."),
    "cert_unknown": ("not_testable", "Zertifikatsdetails nicht verfügbar."),
    "version_unknown": ("not_testable", "Version von außen nicht bestimmbar."),
    "no_enrichment": ("not_testable", "Zu den erkannten Versionen lag keine Fremdbewertung aus Schwachstellendatenbanken vor."),
    "whois_unavailable": ("not_testable", "Die Abfrage der Domain-Registrierungsdaten lieferte kein Ergebnis."),
    "insufficient_facts": ("not_testable", "Die Werkzeugdaten reichen für eine Aussage zu dieser Prüfung nicht aus."),
    # S6a (#15 Teil 2): ohne Selektor ist DKIM nicht pruefbar, nie "fehlt". Mit bekannter
    # Liste der abgefragten Selektoren ersetzt reporter/v3/chapters.py den Text durch
    # einen, der Anzahl und Beispiele nennt.
    "dkim_selector_unknown": ("not_testable", "DKIM ohne Selektor aus einer echten E-Mail nicht prüfbar: unter den gängigen Selektoren war kein Schlüssel veröffentlicht. Ob die Domain signiert, zeigt der Kopf einer echten E-Mail (DKIM-Signature, Angabe s=)."),
    "precondition_not_met": ("not_applicable", "Voraussetzung der Prüfung nicht gegeben."),
    "coverage_unknown": ("not_testable", "Ob dieses Werkzeug gelaufen ist, geht aus den Protokollen nicht hervor."),
    "rohtext_nicht_geladen": ("not_testable", "Die Werkzeugausgabe war zu groß und wurde nicht geladen; Ergebnis nicht belastbar."),
    "testssl_nicht_getestet": ("not_testable", "testssl konnte diese Schwachstelle nicht prüfen (Zeitüberschreitung oder Verbindungsfehler)."),
}
GENERIC_NOT_TESTABLE = "Diese Prüfung war mit den vorliegenden Daten nicht möglich."

# Werkzeuge, die ein Fixture mit coverage_default ok je Host bzw. je Domain bekommt.
HOST_TOOLS = ("nmap", "header_check", "httpx", "testssl", "zap", "zap_spider", "zap_active", "feroxbuster", "ffuf_param",
              "ffuf_sensitive", "wpscan", "webtech", "wafw00f", "web_probe")
DOMAIN_TOOLS = ("dns_records", "dns_security", "whois", "abuseipdb", "otx", "urlhaus", "greynoise", "securitytrails", "shodan",
                "phase3_correlation")

# ---------------------------------------------------------------- Familien
# Vokabular aus catalog_sim.py und expected/junkerwerk.json; der Katalogtest prueft,
# dass jede Family aus der Soll-Liste von mindestens einem Check erzeugt wird.
FAMILIES: frozenset[str] = frozenset({
    "db_exposed", "smb_exposed", "rdp_exposed", "admin_service_exposed", "ftp_exposed", "mail_plaintext",
    "legacy_protocols_present", "http_no_tls", "http_alt_port", "ssh_alt_port", "sensitive_path_exposed",
    "http_trace_enabled", "default_page_exposed", "login_portal_exposed", "dev_host_public",
    "web_vulnerability_active", "web_vulnerability_reported", "urlhaus_compromise", "software_eol", "software_lifecycle_review",
    "passive_service_unverified", "cve_known", "wordpress_plugin_vulnerable", "wordpress_core_outdated",
    "user_enumeration", "spf_missing", "spf_permissive", "spf_softfail", "dmarc_missing", "dmarc_none",
    "dmarc_quarantine", "dkim_missing", "mta_sts_missing", "tls_rpt_missing", "dane_missing",
    "dnssec_missing", "caa_missing", "dns_axfr", "dns_dangling", "domain_expiring", "ip_reputation",
    "tls_legacy_protocols", "tls_weak_ciphers", "tls_no_13", "tls_known_vulnerability", "tls_weakness",
    "tls_no_fallback_protection", "cert_expired", "cert_expiring", "cert_hostname_mismatch",
    "cert_chain_incomplete", "cert_self_signed", "hsts_missing", "hsts_short", "csp_missing", "csp_weak",
    "security_headers_incomplete", "header_duplicate", "banner_version_disclosure", "cookie_flags",
    "csrf_token_missing", "info_disclosure", "js_library_outdated", "directory_listing", "session_in_url",
    "cors_misconfiguration", "sri_missing", "waf_present",
    # S6b-2 (spec/08 Punkt 6): Domain ohne Mailbetrieb ohne Faelschungsschutz.
    "mail_spoofing_unprotected",
})

# Namen, die in Ausdruecken als Tabellen sichtbar sind.
EXPR_TABLES: dict[str, object] = {
    k: v for k, v in globals().items()
    if k.isupper() and not k.startswith("_") and k not in {"COVERAGE_REASONS", "FAMILIES", "EXPR_TABLES",
                                                          "HOST_TOOLS", "DOMAIN_TOOLS", "GENERIC_NOT_TESTABLE"}
}
