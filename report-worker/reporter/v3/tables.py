# -*- coding: utf-8 -*-
"""Feste Tabellen der Reportdaten v3: Impressum, Pakete, Werkzeuge, Skalen, Posture.

Alles hier ist Stammdatum, kein abgeleiteter Wert. Die Skalen- und Triage-Texte stammen
aus dem Prototyp (spec/03), die Werkzeugliste aus der Methodikseite. Werkzeuge stehen
ohne Versionsnummer, weil der Gate-Check des Prototyps das verlangt (spec/03 Regel 11).
"""
from __future__ import annotations

from reporter.v3 import levels as _levels

# ---------------------------------------------------------------- Impressum

PROVIDER = {
    "classification": "Vertraulich",
    "provider": "Vectigal GmbH",
    "provider_address": "Olpe 31-33 · 44135 Dortmund",
    "provider_contact": "kontakt@vectigal.ai · vectigal.ai",
    "provider_register": "Amtsgericht Dortmund HRB 38214 · USt-IdNr. DE462853393",
    "provider_responsible": "Daniel Czischke, Geschäftsführer",
}

# ---------------------------------------------------------------- Pakete
# Der kanonische Paketkatalog liegt unter catalog/packages.catalog.json im Repo-Wurzel-
# verzeichnis und damit ausserhalb des Docker-Build-Kontexts dieses Workers (VEC-289).
# Deshalb hier eine eigene, kleine Tabelle nur fuer die Anzeige.
PACKAGE_LABELS: dict[str, tuple[str, str]] = {
    "webcheck": ("WebCheck", "WEBCHECK"),
    "perimeter": ("Perimeter", "PERIMETERSCAN"),
    "compliance": ("Compliance", "COMPLIANCE-SCAN"),
    "supplychain": ("SupplyChain", "SUPPLYCHAIN-SCAN"),
    "insurance": ("Insurance", "INSURANCE-SCAN"),
    "tlscompliance": ("TLS-Compliance", "TLS-COMPLIANCE-SCAN"),
    # Legacy-Aliase (CLAUDE.md)
    "basic": ("WebCheck", "WEBCHECK"),
    "professional": ("Perimeter", "PERIMETERSCAN"),
    "nis2": ("Compliance", "COMPLIANCE-SCAN"),
}


def package_labels(package: str) -> tuple[str, str]:
    return PACKAGE_LABELS.get((package or "").lower(), (package or "Scan", "SCAN"))


# ---------------------------------------------------------------- Leitwerkzeuge
# S6 (spec/08 Punkt 10): Der Abdeckungshinweis auf Seite 3 feuerte, sobald fuer
# einen Host irgendein Werkzeug ohne Ergebnis blieb. Bei dortmund-beach war das
# ein einziges Nebenwerkzeug (ffuf_sensitive) bei 30 von 39 erfolgreichen
# Laeufen, und der Bericht sagte trotzdem "keine oder nur eine teilweise aktive
# Pruefung". Jetzt zaehlen nur noch die Werkzeuge, die das Paket ausmachen.
LEAD_TOOLS: dict[str, tuple[str, ...]] = {
    "webcheck": ("nmap", "testssl", "zap"),
    "perimeter": ("nmap", "testssl", "zap_active"),
    "compliance": ("nmap", "testssl", "zap_active"),
    "supplychain": ("nmap", "testssl", "zap_active"),
    "insurance": ("nmap", "testssl", "zap_active"),
    "tlscompliance": ("nmap", "testssl"),
}
LEAD_TOOLS_DEFAULT: tuple[str, ...] = ("nmap", "testssl")


def lead_tools(package: str) -> tuple[str, ...]:
    key = (package or "").lower()
    key = {"basic": "webcheck", "professional": "perimeter", "nis2": "compliance"}.get(key, key)
    return LEAD_TOOLS.get(key, LEAD_TOOLS_DEFAULT)


# ---------------------------------------------------------------- Werkzeugliste
# (Zeile, Zweck, Konfidenz) je Anzeigename, dazu die Coverage-Werkzeuge, die dahinter
# stehen. Eine Zeile erscheint nur, wenn mindestens eines ihrer Werkzeuge gelaufen ist.
# Reihenfolge ist die Reihenfolge im Anhang.
#
# "ZAP Active Scan" war seit S0a von der Methodikseite genommen, weil das Werkzeug in 42
# Produktionsscans nie ein Ergebnis geliefert hat. S0b hat die Ursache behoben (fehlende
# Scanner-IDs im Image); der erste erfolgreiche Produktionslauf war am 18.09.2026
# (Auftrag 14272c00 gegen dortmund-beach.com, zap_active status=ok mit Alert-Liste im
# Tar). Seitdem steht die Zeile wieder hier. ffuf und VirusTotal bleiben draussen:
# ffuf_sensitive laeuft zwar seit dem Wordlist-Fix aus S0a, endet aber regelmaessig im
# Timeout, und fuer VirusTotal gibt es bewusst keinen Zugang (Entscheidung DC, spec/07).
TOOL_ROWS: list[tuple[str, str, str, tuple[str, ...]]] = [
    ("nmap", "Portscan der häufigsten TCP-Ports, Dienst- und Versionserkennung",
     "hoch (Dienste), mittel (Versionen)", ("nmap",)),
    ("testssl.sh", "Protokolle, Verfahren, Zertifikate und bekannte Schwächen der Transportverschlüsselung",
     "hoch", ("testssl",)),
    ("httpx, header_check", "HTTP-Antworten, Technologien und Sicherheits-Header je virtuellem Host",
     "hoch", ("httpx", "header_check")),
    ("OWASP ZAP (passiv, Spider)", "Passive Analyse von Antworten, Formularen und Headern",
     "mittel", ("zap", "zap_spider", "zap_ajax_spider")),
    ("OWASP ZAP (Active Scan)", "Aktive Prüfung der Webanwendung auf gängige Schwachstellenklassen",
     "mittel", ("zap_active",)),
    ("feroxbuster", "Verzeichnis- und Datei-Enumeration", "mittel", ("feroxbuster",)),
    ("wpscan", "Prüfung einer WordPress-Installation auf Kern, Plugins und Nutzer",
     "hoch (Abgleich mit Schwachstellendatenbank)", ("wpscan",)),
    ("webtech, wafw00f", "Web-Technologien und vorgelagerte Schutzsysteme",
     "mittel", ("webtech", "wafw00f")),
    ("dnsx, subfinder, gobuster, Certspotter, SecurityTrails",
     "Ermittlung der Hostnamen, DNS-Auflösung und DNS-Sicherheitseinträge",
     "hoch", ("dns_records", "dnsx", "subfinder", "gobuster_dns", "certspotter", "crtsh",
              "dns_security", "web_probe")),
    ("Shodan, AbuseIPDB, OTX, URLhaus", "Passive Dienst- und Reputationsdaten",
     "mittel (Passivquelle, Zeitversatz)",
     ("shodan", "abuseipdb", "otx", "urlhaus", "greynoise", "securitytrails")),
    ("NVD, EPSS, CISA KEV", "Abgleich erkannter Versionen mit Fremdquellen zu Schwachstellen",
     "hoch (autoritative Fremdquelle)", ("phase3_correlation",)),
]

# Werkzeuge, deren Zeile nur erscheint, wenn der Abgleich auch etwas erbracht
# hat. Der Korrelator laeuft in jedem Auftrag; die Fremdquellen werden nur
# abgefragt, wenn eine Schwachstellennummer zu pruefen war (S5b).
ENRICHMENT_TOOLS = ("phase3_correlation",)

# ---------------------------------------------------------------- testssl-Kennungen
# S6 (spec/08 Punkt 18 und offener Punkt 2 nach S5b): Anhang A.3 hatte die
# Spalte "Bezeichnung" leer, weil sie nur aus einer Fremdbewertung kam und die
# in keinem Produktionslauf vorlag. Die Namen der testssl-Pruefungen sind
# allgemein bekannt und stehen deshalb hier als feste Tabelle; erfunden wird
# nichts, der Basiswert bleibt leer.
TESTSSL_NAMES: dict[str, str] = {
    "BEAST": "BEAST (CBC in TLS 1.0)",
    "BEAST_CBC_TLS1": "BEAST (CBC in TLS 1.0)",
    "BREACH": "BREACH (HTTP-Kompression)",
    "CCS": "CCS Injection",
    "CRIME_TLS": "CRIME (TLS-Kompression)",
    "DROWN": "DROWN (SSLv2)",
    "DROWN_hint": "DROWN (SSLv2 auf verwandtem Dienst)",
    "FREAK": "FREAK (Export-RSA)",
    "heartbleed": "Heartbleed",
    "LOGJAM": "Logjam (schwache Diffie-Hellman-Gruppen)",
    "LOGJAM-common_primes": "Logjam (verbreitete Primzahlen)",
    "LUCKY13": "Lucky 13 (CBC-Zeitangriff)",
    "POODLE_SSL": "POODLE (SSLv3)",
    "RC4": "RC4-Verfahren",
    "ROBOT": "ROBOT (RSA-Padding-Orakel)",
    "secure_client_renego": "Client-seitige Neuverhandlung",
    "secure_renego": "Sichere Neuverhandlung",
    "SWEET32": "Sweet32 (64-Bit-Blockchiffren)",
    "ticketbleed": "Ticketbleed",
    "winshock": "Winshock (Schannel)",
}


def testssl_name(test_id: str) -> str:
    """Deutsche Bezeichnung einer testssl-Pruefung, sonst die Kennung selbst."""
    return TESTSSL_NAMES.get(test_id, test_id)


# ---------------------------------------------------------------- Skalen (Anhang A)

# S6b-2 (spec/09 Q13, E1): die Verwaltungsfaelle stehen in ``levels.ADMIN_EXPOSURE``, aus
# derselben Tabelle wie die Einstufung der Verwaltungspruefungen. Vorher nannte A.2
# "Verwaltungsoberflaechen" kritisch, waehrend die Regel "erhoeht" vergab.
EXPOSURE_SCALE: list[tuple[str, str]] = _levels.exposure_scale()

HYGIENE_SCALE: list[tuple[str, str]] = [
    ("hoch", "Abweichung mit direktem Bezug zu Anmeldedaten, Authentizität oder Zugangswegen; "
             "zeitnah beheben."),
    ("mittel", "Abweichung, die Angriffe erleichtert oder Schutzmechanismen aushebelt; im "
               "nächsten Wartungszyklus beheben."),
    ("niedrig", "Best-Practice-Abweichung ohne unmittelbare Auswirkung; bei Gelegenheit beheben."),
]

# Bedeutung je Ampelfarbe. Welche Dringlichkeit dazugehoert, steht nicht hier,
# sondern folgt aus der Abbildungstabelle in ``reporter/v3/levels.py``; A.1 setzt
# beides in ``triage_rows()`` zusammen. Vorher stand die Dringlichkeit doppelt,
# einmal hier als Satz und einmal in der Ableitung, und beide liefen auseinander
# (spec/08 Punkt 1).
TRIAGE_MEANING: list[tuple[str, str]] = [
    ("rot", "Akutes Risiko, das ohne Vorbedingungen ausnutzbar ist, einen kritischen "
            "Dienst exponiert oder von einem Werkzeug aktiv nachgewiesen wurde."),
    ("gelb", "Handlungsbedarf mit erkennbarem Angriffsweg."),
    ("blau", "Verbesserung ohne akutes Risiko."),
    ("gruen", "Positiver Befund: Schutzmaßnahme vorhanden und wirksam."),
]


def triage_rows() -> list[tuple[str, str, str]]:
    """(Anzeigename, Farbe, Text) fuer Anhang A.1, Dringlichkeit aus levels.py."""
    from reporter.v3 import levels as L

    out: list[tuple[str, str, str]] = []
    for status, meaning in TRIAGE_MEANING:
        phrase = L.urgency_phrase(status)
        text = f"{meaning} Dringlichkeit: {phrase}." if phrase else meaning
        # S6b-2 (E2): benannte Ausnahmen der Abbildungstabelle stehen bei Rot.
        if status == L.TRIAGE_URGENT.status and L.urgent_phrase():
            text = f"{text} {L.urgent_phrase()}"
        out.append((L.STATUS_LABELS[status], status, text))
    return out


def stage_box() -> str:
    """Erklaerung der Zeitstufen unter dem Massnahmenplan, aus denselben Werten."""
    from reporter.v3 import levels as L

    parts = [f"{L.URGENCY_BY_STAGE[s]}: {L.STAGE_WINDOW[s]}" for s in L.STAGE_ORDER]
    return " · ".join(parts)

# ---------------------------------------------------------------- Posture (Kapitel 3)
# Vier Blöcke; jedes Item zeigt auf Pruefungen des Katalogs. ``per_host`` erzeugt ein
# Item je Host, ``items`` je eines fuer den ganzen Auftrag.
#
# Die erste Pruefung eines Items ist die leitende: sie entscheidet zwischen
# "unauffaellig" und "nicht pruefbar". Die uebrigen koennen nur noch auf
# "Handlungsbedarf" ziehen. Ohne diese Reihenfolge wuerde eine nebensaechliche
# Pruefung, die auf einem unerreichbaren virtuellen Host mangels Antwort besteht, das
# Item als unauffaellig ausweisen.
POSTURE_BLOCKS: list[dict[str, object]] = [
    {
        "name": "E-Mail-Authentizität",
        "short": "E-Mail-Authentizität",
        "items": [
            ("SPF", ("spf_missing", "spf_permissive", "spf_softfail", "mail_spoofing_unprotected")),
            ("DKIM", ("dkim_missing",)),
            ("DMARC", ("dmarc_missing", "dmarc_none", "dmarc_quarantine", "mail_spoofing_unprotected")),
            ("MTA-STS", ("mta_sts_missing",)),
            ("TLS-RPT, DANE", ("tls_rpt_missing", "dane_missing")),
        ],
    },
    {
        "name": "DNS-Hygiene",
        "short": "DNS-Hygiene",
        "items": [
            ("DNSSEC", ("dnssec_missing",)),
            ("CAA", ("caa_missing",)),
            ("Abruf der gesamten Zone", ("dns_zone_transfer",)),
            ("Verwaiste Einträge", ("dns_dangling_cname",)),
        ],
    },
    {
        "name": "Transportverschlüsselung",
        "short": "Transportverschlüsselung",
        "per_host": ("tls_legacy_protocols", "tls_no_13", "tls_weak_ciphers", "tls_weakness",
                     "tls_no_fallback_scsv", "hsts_short"),
        "items": [
            ("Zertifikate", ("cert_expired", "cert_expiring", "cert_expiring_later",
                             "cert_chain_incomplete", "cert_hostname_mismatch", "cert_self_signed")),
        ],
    },
    {
        "name": "Sicherheits-Header",
        "short": "Sicherheits-Header",
        "per_host": ("security_headers_incomplete", "csp_missing", "csp_weak", "hsts_missing",
                     "header_duplicate"),
        "items": [],
    },
]

# ---------------------------------------------------------------- Technik-Tabelle
# ``software.note`` aus S1 ist eine Notiz des Faktenbauers an den Betreiber, kein
# Kundentext ("MariaDB-Kompatibilitaetspraefix 5.5.5 entfernt", "KI-Skip durch Regel
# verworfen"). Was davon den Kunden betrifft, steht hier in seiner Sprache; alles
# andere erscheint nicht im Bericht.
TECH_NOTE_MAP: dict[str, str] = {
    "Bereichsangabe": "Version von außen nicht genau bestimmbar",
    "Versionsangabe nicht numerisch": "Version von außen nicht genau bestimmbar",
    "Kein OWA-Build": "Produktlinie von außen nicht bestimmbar",
}


def tech_note(note: str | None) -> str:
    if not note:
        return ""
    for prefix, text in TECH_NOTE_MAP.items():
        if note.startswith(prefix):
            return text
    return ""


# ---------------------------------------------------------------- Pruefungen in Kundensprache
# S6b-1 (spec/09 Q10): jede Zeile der Einschraenkungstabelle nennt die betroffenen
# Pruefungen, nie ein Werkzeug. Test: jedes Werkzeug der Abdeckung und jede Familie des
# Katalogs hat hier einen Namen (tests/v3/test_s6b1_coverage.py).
TOOL_CHECKS: dict[str, str] = {
    "nmap": "Portscan und Diensterkennung",
    "testssl": "Transportverschlüsselung",
    "header_check": "Sicherheits-Header",
    "httpx": "Erkennung der Webdienste",
    "webtech": "Erkennung der Web-Technologien",
    "wafw00f": "Erkennung vorgelagerter Schutzsysteme",
    "zap": "Webanalyse",
    "zap_spider": "Webanalyse",
    "zap_ajax_spider": "Webanalyse",
    "zap_active": "Aktive Prüfung der Webanwendung",
    "feroxbuster": "Suche nach nicht verlinkten Pfaden",
    "gobuster_dir": "Suche nach nicht verlinkten Pfaden",
    "ffuf_sensitive": "Suche nach sensiblen Dateien",
    "ffuf_param": "Suche nach Parametern der Webanwendung",
    "wpscan": "WordPress-Prüfung",
    "whois": "Registrierungsdaten der Domain",
    "dns": "DNS- und E-Mail-Einträge",
    "dns_records": "DNS- und E-Mail-Einträge",
    "dns_security": "DNS-Sicherheitseinträge",
    "axfr": "Abruf der gesamten DNS-Zone",
    "dnsx": "Auflösung der Hostnamen",
    "gobuster_dns": "Ermittlung der Hostnamen",
    "subfinder": "Ermittlung der Hostnamen",
    "crtsh": "Ermittlung der Hostnamen",
    "certspotter": "Ermittlung der Hostnamen",
    "web_probe": "Erreichbarkeit der Hostnamen",
    "shodan": "Passive Dienstdaten",
    "securitytrails": "Passive DNS-Daten",
    "abuseipdb": "Reputationsdaten",
    "otx": "Reputationsdaten",
    "urlhaus": "Reputationsdaten",
    "greynoise": "Reputationsdaten",
    "virustotal": "Reputationsdaten",
    "phase3_correlation": "Abgleich mit Schwachstellendatenbanken",
    "searchsploit": "Abgleich mit Schwachstellendatenbanken",
}
TOOL_CHECKS_FALLBACK = "Weitere Prüfungen"

FAMILY_CHECKS: dict[str, str] = {
    "admin_service_exposed": "Verwaltungsoberflächen",
    "banner_version_disclosure": "Versionsangaben der Dienste",
    "caa_missing": "CAA-Einträge",
    "cert_chain_incomplete": "Zertifikatskette",
    "cert_expired": "Gültigkeit der Zertifikate",
    "cert_expiring": "Gültigkeit der Zertifikate",
    "cert_hostname_mismatch": "Namen im Zertifikat",
    "cert_self_signed": "Aussteller der Zertifikate",
    "cookie_flags": "Cookie-Attribute",
    "cors_misconfiguration": "Freigaben für fremde Ursprünge (CORS)",
    "csp_missing": "Content-Security-Policy",
    "csp_weak": "Content-Security-Policy",
    "csrf_token_missing": "Schutz der Formulare",
    "cve_known": "Bekannte Schwachstellen der erkannten Versionen",
    "dane_missing": "DANE",
    "db_exposed": "Datenbankdienste",
    "default_page_exposed": "Auslieferungsseiten der Hersteller",
    "dev_host_public": "Test- und Entwicklungssysteme",
    "directory_listing": "Verzeichnisauflistung",
    "dkim_missing": "DKIM-Signatur",
    "dmarc_missing": "DMARC-Richtlinie",
    "dmarc_none": "DMARC-Richtlinie",
    "dmarc_quarantine": "DMARC-Richtlinie",
    "dns_axfr": "Abruf der gesamten DNS-Zone",
    "dns_dangling": "Verwaiste DNS-Einträge",
    "dnssec_missing": "DNSSEC",
    "domain_expiring": "Laufzeit der Domain",
    "ftp_exposed": "FTP-Dienste",
    "header_duplicate": "Doppelte Header",
    "hsts_missing": "HSTS",
    "hsts_short": "HSTS",
    "http_alt_port": "Webdienste auf Zusatzports",
    "http_no_tls": "HTTPS-Angebot",
    "http_trace_enabled": "HTTP-Methoden",
    "info_disclosure": "Preisgegebene Angaben",
    "ip_reputation": "Reputation der Adressen",
    "js_library_outdated": "JavaScript-Bibliotheken",
    "legacy_protocols_present": "Ältere Übertragungsprotokolle",
    "login_portal_exposed": "Anmeldeportale",
    "mail_plaintext": "Verschlüsselung der Mailzugänge",
    "mail_spoofing_unprotected": "Fälschungsschutz für Domains ohne Mailbetrieb",
    "mta_sts_missing": "MTA-STS",
    "passive_service_unverified": "Dienste laut Passivquelle",
    "rdp_exposed": "Windows-Fernwartung (RDP)",
    "security_headers_incomplete": "Sicherheits-Header",
    "sensitive_path_exposed": "Sensible Pfade und Dateien",
    "session_in_url": "Sitzungskennungen in Adressen",
    "smb_exposed": "Windows-Dateifreigabe (SMB)",
    "software_eol": "Herstellerpflege der Software",
    "software_eol_runtime": "Herstellerpflege der Software",
    "software_lifecycle_review": "Herstellerpflege der Software",
    "spf_missing": "SPF-Eintrag",
    "spf_permissive": "SPF-Eintrag",
    "spf_softfail": "SPF-Eintrag",
    "sri_missing": "Integrität eingebundener Skripte",
    "ssh_alt_port": "SSH auf Zusatzports",
    "tls_known_vulnerability": "Bekannte TLS-Schwachstellen",
    "tls_legacy_protocols": "TLS-Protokollversionen",
    "tls_no_13": "TLS 1.3",
    "tls_no_fallback_protection": "Schutz vor Protokoll-Herabstufung",
    "tls_rpt_missing": "TLS-Berichte (TLS-RPT)",
    "tls_weak_ciphers": "Verschlüsselungsverfahren",
    "tls_weakness": "TLS-Schwächen",
    "urlhaus_compromise": "Einträge in Schadcode-Listen",
    "user_enumeration": "Preisgabe von Benutzernamen",
    "waf_present": "Vorgelagerte Schutzsysteme",
    "web_vulnerability_active": "Aktive Prüfung der Webanwendung",
    "web_vulnerability_reported": "Meldungen der Webanalyse",
    "wordpress_core_outdated": "WordPress-Kern",
    "wordpress_plugin_vulnerable": "WordPress-Erweiterungen",
}

# Dienstname laut Passivquelle (Shodan-Modul), wenn kein Produkt genannt ist (E5).
PASSIVE_SERVICES: dict[str, str] = {
    "smtp": "SMTP", "smtps": "SMTPS", "submission": "SMTP-Submission", "imap": "IMAP", "imap-ssl": "IMAPS",
    "pop3": "POP3", "pop3-ssl": "POP3S", "http": "HTTP", "https": "HTTPS", "ftp": "FTP", "ssh": "SSH",
    "dns-tcp": "DNS", "dns-udp": "DNS", "rdp": "RDP", "mysql": "MySQL", "postgresql": "PostgreSQL",
}

# Werkzeuge, die bewusst nicht Teil des Produkts sind. Ihr Fehlen ist keine
# Einschraenkung der Pruefung, sondern eine Festlegung (Entscheidung DC, spec/07).
OUT_OF_PRODUCT_TOOLS: frozenset[str] = frozenset({"virustotal"})

# ---------------------------------------------------------------- Dienste und Rollen

LEGACY_PORTS: frozenset[int] = frozenset({21, 23, 25, 110, 143})
DB_PORTS: frozenset[int] = frozenset({1433, 3306, 5432, 6379, 9200, 27017})

# S6b-1 (spec/09 Q2): Rollen nur mit Fakt. Je Rolle Anzeigename und Risikotext; die
# Belegregeln stehen in reporter/v3/roles.py. "Kalender" nur mit Exchange-Fakt,
# "Datenbank" nur mit Datenbankport, Mail nur, wenn MX, ein SPF-Mechanismus oder ein
# Autodiscover-Name auf den Host zeigt.
ROLE_DEFS: dict[str, tuple[str, str]] = {
    "mail_kalender": (
        "Mail- und Kalenderplattform",
        "Über dieses System laufen E-Mail und Termine des Unternehmens. Ein Zugriff darauf trifft "
        "Vertraulichkeit und Arbeitsfähigkeit zugleich."),
    "mail": (
        "E-Mail-Server",
        "Über dieses System läuft E-Mail des Unternehmens. Ein Zugriff darauf trifft die "
        "Vertraulichkeit der Korrespondenz."),
    "mail_versand": (
        "E-Mail-Versand laut SPF",
        "Dieses System darf laut SPF-Eintrag E-Mail im Namen der Domain versenden. Ein Missbrauch "
        "trifft die Glaubwürdigkeit der eigenen Absenderadresse."),
    "webmail": (
        "Mail-Webzugang",
        "Webzugang zu den Postfächern. Erbeutete Zugangsdaten öffnen darüber die E-Mail der "
        "Mitarbeitenden."),
    "passwort": (
        "Passwortverwaltung",
        "Tresor für Zugangsdaten. Ein Zugriff darauf öffnet die Konten, deren Kennwörter dort liegen."),
    "kollaboration": (
        "Kollaboration",
        "Gemeinsame Ablage und Zusammenarbeit. Betroffen wären Dokumente und die Konten der "
        "Beteiligten."),
    "anmeldeportal": (
        "Anmeldeportal",
        "Zentrale Anmeldung für Anwendungen. Wer hier Zugangsdaten errät oder abgreift, erreicht die "
        "dahinterliegenden Dienste."),
    "website": (
        "Website",
        "Außendarstellung des Unternehmens. Betroffen wären vor allem Seiteninhalte und "
        "Formulareingaben."),
    "datenbank": (
        "Datenbankdienst",
        "Datenbestände hinter den Anwendungen. Ein von außen erreichbarer Datenbankdienst ist ein "
        "direktes Ziel für Anmeldeversuche."),
    "fernzugang": (
        "Fernzugang und Verwaltung",
        "Der Weg von außen in das Unternehmensnetz. Solche Zugänge sind das bevorzugte Ziel, weil "
        "hinter ihnen alles Weitere liegt."),
    "dateiaustausch": (
        "Dateiaustausch",
        "Austausch von Dateien mit Dritten. Die Inhalte und die verwendeten Zugangsdaten sind hier "
        "das Schutzgut."),
}
# Reihenfolge, in der Rollen genannt werden; die spezifischere zuerst.
ROLE_ORDER: tuple[str, ...] = ("mail_kalender", "mail", "webmail", "passwort", "kollaboration",
                               "anmeldeportal", "fernzugang", "datenbank", "dateiaustausch", "website",
                               "mail_versand")
ROLE_FALLBACK = "Nicht näher bestimmbar"
ROLE_FALLBACK_MEANING = ("Die Aufgabe dieses Systems ist von außen nicht eindeutig erkennbar; sie sollte "
                         "intern geklärt werden.")

# Woerter, mit denen ein Text eine Rolle behauptet (Prosa-Gate und v3_checks). Ein Wort
# steht nur, wenn eine Rolle mit dieser Kategorie belegt ist.
ROLE_WORDS: dict[str, tuple[str, ...]] = {
    "kalender": ("kalender", "termine"),
    "mail": ("korrespondenz", "postfach", "postfächer", "mailserver", "e-mail-server", "mailsystem",
             "e-mail-system", "mailplattform"),
    "datenbank": ("datenbank",),
    "fernzugang": ("fernzugang", "fernwartung", "vpn"),
    "passwort": ("passwortverwaltung", "passworttresor", "passwort-tresor", "kennworttresor"),
    "kollaboration": ("kollaboration", "zusammenarbeit", "dateiablage"),
    "webmail": ("webmail", "mail-webzugang", "outlook im web"),
    "anmeldeportal": ("anmeldeportal", "single sign-on"),
}
# Welche Wortkategorien eine belegte Rolle erlaubt.
ROLE_CATEGORIES: dict[str, frozenset[str]] = {
    "mail_kalender": frozenset({"mail", "kalender"}),
    "mail": frozenset({"mail"}),
    "mail_versand": frozenset({"mail"}),
    "webmail": frozenset({"webmail", "mail"}),
    "passwort": frozenset({"passwort"}),
    "kollaboration": frozenset({"kollaboration"}),
    "anmeldeportal": frozenset({"anmeldeportal"}),
    "fernzugang": frozenset({"fernzugang"}),
    "datenbank": frozenset({"datenbank"}),
    "dateiaustausch": frozenset(),
    "website": frozenset(),
}
