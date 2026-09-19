# -*- coding: utf-8 -*-
"""Feste Tabellen der Reportdaten v3: Impressum, Pakete, Werkzeuge, Skalen, Posture.

Alles hier ist Stammdatum, kein abgeleiteter Wert. Die Skalen- und Triage-Texte stammen
aus dem Prototyp (spec/03), die Werkzeugliste aus der Methodikseite. Werkzeuge stehen
ohne Versionsnummer, weil der Gate-Check des Prototyps das verlangt (spec/03 Regel 11).
"""
from __future__ import annotations

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
     ("shodan", "abuseipdb", "otx", "urlhaus", "greynoise", "securitytrails", "whois")),
    ("NVD, EPSS, CISA KEV", "Abgleich erkannter Versionen mit Fremdquellen zu Schwachstellen",
     "hoch (autoritative Fremdquelle)", ("phase3_correlation",)),
]

# ---------------------------------------------------------------- Skalen (Anhang A)

EXPOSURE_SCALE: list[tuple[str, str]] = [
    ("kritisch", "Dienst, der nicht an das öffentliche Interface gehört (Datenbanken, "
                 "Verwaltungsoberflächen, Fernwartung) und aus dem Internet erreichbar ist."),
    ("erhöht", "Dienst mit legitimem Zweck, aber ohne erkennbare Zugriffsbeschränkung oder "
               "mit ungeklärter Funktion."),
]

HYGIENE_SCALE: list[tuple[str, str]] = [
    ("hoch", "Abweichung mit direktem Bezug zu Anmeldedaten, Authentizität oder Zugangswegen; "
             "zeitnah beheben."),
    ("mittel", "Abweichung, die Angriffe erleichtert oder Schutzmechanismen aushebelt; im "
               "nächsten Wartungszyklus beheben."),
    ("niedrig", "Best-Practice-Abweichung ohne unmittelbare Auswirkung; bei Gelegenheit beheben."),
]

TRIAGE: list[tuple[str, str, str]] = [
    ("Rot", "rot", "Akutes Risiko, das ohne Vorbedingungen ausnutzbar ist oder einen kritischen "
                   "Dienst exponiert. Dringlichkeit: Unverzüglich (24 bis 72 Stunden)."),
    ("Gelb", "gelb", "Handlungsbedarf mit erkennbarem Angriffsweg. Dringlichkeit: In Kürze "
                     "(1 bis 2 Wochen) oder Mittelfristig (nächster Wartungszyklus)."),
    ("Blau", "blau", "Verbesserung ohne akutes Risiko. Dringlichkeit: Mittelfristig oder "
                     "Strategisch (laufendes Quartal)."),
    ("Grün", "gruen", "Positiver Befund: Schutzmaßnahme vorhanden und wirksam."),
]

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
            ("SPF", ("spf_missing", "spf_permissive", "spf_softfail")),
            ("DKIM", ("dkim_missing",)),
            ("DMARC", ("dmarc_missing", "dmarc_none", "dmarc_quarantine")),
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
            ("Zertifikate", ("cert_expired", "cert_expiring", "cert_chain_incomplete",
                             "cert_hostname_mismatch", "cert_self_signed")),
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


# ---------------------------------------------------------------- Dienste und Rollen

LEGACY_PORTS: frozenset[int] = frozenset({21, 23, 25, 110, 143})
DB_PORTS: frozenset[int] = frozenset({1433, 3306, 5432, 6379, 9200, 27017})

# Rolle eines Hosts fuer die Tabelle in Kapitel 2, nach erkannter Software und Ports.
ROLE_RULES: list[tuple[str, tuple[str, ...], tuple[int, ...]]] = [
    ("Mail- und Kalenderplattform", ("exchange", "dovecot", "postfix", "exim", "courier"), (25, 465, 587, 993, 995)),
    ("Website und Datenbanken", ("apache", "nginx", "iis", "litespeed"), (80, 443, 3306, 5432)),
    ("Fernzugang und Verwaltung", ("openssh", "rdgateway", "sonicwall", "fortinet", "pfsense"), (22, 3389, 4433, 8443)),
    ("Dateiaustausch", ("proftpd", "vsftpd", "pure-ftpd"), (21,)),
]
ROLE_FALLBACK = "Nicht näher bestimmbar"
