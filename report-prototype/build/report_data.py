# -*- coding: utf-8 -*-
"""Kuratierte Datenbasis für den Junkerwerk-Report (Prototyp).

Jede Zahl und jede Aussage ist gegen die Rohdaten in input/{multi,de,hu}/ geprüft
(siehe spec/01-rohdaten-analyse.md). Dieses Modul ist bewusst reine Daten, kein Layout:
build_report.py rendert daraus template.html.j2.
"""

DATA = {
    "meta": {
        "customer": "Junkerwerk Linder GmbH & Co. KG",
        "customer_short": "Junkerwerk",
        "domains": ["junkerwerk.de", "junkerwerk.hu"],
        "package": "Perimeter",
        "package_label": "PERIMETERSCAN",
        "scan_date": "31.08.2026",
        "scan_window": "31.08.2026, 16:10 bis 16:56 Uhr (MESZ)",
        "report_date": "01.09.2026",
        "report_version": "1.0",
        "report_id": "VS-JW-2026-0831",
        "orders": [
            {"label": "Lauf 1 (beide Domains)", "id": "0bf16342-ed96-4b0e-a596-05aee3a62cb5"},
            {"label": "Lauf 2 (junkerwerk.de)", "id": "2572eebc-6135-40e6-b1d2-e9dfccc20ae6"},
            {"label": "Lauf 3 (junkerwerk.hu)", "id": "a6df9d9d-eccd-49d1-8dd3-b00a5e005108"},
        ],
        "hosts_total": 6,
        "hosts_ipv4": 5,
        "hosts_ipv6": 1,
        "fqdns_total": 15,
        "tool_runs": 330,
        "raw_findings": 211,
        "after_fp": 143,
        "consolidated": 15,
        "positives": 8,
        "policy_version": "2026-06-01.1",
        "classification": "Vertraulich",
        "provider": "Vectigal GmbH",
        "provider_address": "Olpe 31-33 · 44135 Dortmund",
        "provider_contact": "kontakt@vectigal.ai · vectigal.ai",
        "provider_register": "Amtsgericht Dortmund HRB 38214 · USt-IdNr. DE462853393",
        "provider_responsible": "Daniel Czischke, Geschäftsführer",
    },

    # ------------------------------------------------------------------
    # Schicht 1: Auf einen Blick
    # ------------------------------------------------------------------
    "glance": {
        "overall": "HOCH",
        "overall_status": "rot",
        "overall_text": (
            "Ein Befund erfordert unverzügliches Handeln: Zwei Datenbankdienste des Webservers sind "
            "direkt aus dem Internet erreichbar. Die übrigen Befunde betreffen die Härtung von Zugangs- "
            "und Verwaltungsportalen, die E-Mail-Authentizität und die Transportverschlüsselung. "
            "Akut ausnutzbare Schwachstellen mit bekannten Exploits wurden nicht nachgewiesen."
        ),
        "categories": [
            {"key": "A", "name": "Perimeter-Exposition", "status": "rot", "level": 4,
             "note": "Datenbankports 3306/5432 öffentlich; Verwaltungs- und Remote-Zugänge exponiert"},
            {"key": "B", "name": "Patch- & EOL-Status", "status": "gelb", "level": 2,
             "note": "Exim 4.96 (Passivquelle) veraltet; Lifecycle Windows Server 2016 endet 01/2027"},
            {"key": "C", "name": "E-Mail-Authentizität", "status": "gelb", "level": 2,
             "note": "SPF und DKIM vorhanden, DMARC fehlt für beide Domains"},
            {"key": "D", "name": "Web- & Transport-Hygiene", "status": "gelb", "level": 2,
             "note": "3DES und kurzes HSTS am Zwei-Faktor-Portal, Zertifikat passt nicht zu openotp.junkerwerk.hu, TLS 1.0/1.1 am RD-Gateway-Host"},
            {"key": "E", "name": "Konfiguration & Informations-Hygiene", "status": "blau", "level": 1,
             "note": "Versionsbanner, HTTP TRACE, kein DNSSEC/CAA"},
        ],
        "levers": [
            {"n": 1, "title": "Datenbank-Fernzugriff auf dem Webserver schließen",
             "effect": "Beseitigt das einzige rote Risiko. Ein Eingriff beim Hosting-Anbieter (Hetzner Managed Server) schließt MariaDB und PostgreSQL gleichzeitig.",
             "refs": ["VS-2026-001"]},
            {"n": 2, "title": "Zugangs- und Verwaltungsportale prüfen und härten",
             "effect": "SonicWall-Interface, Remote-Desktop-Gateway-Host und Zwei-Faktor-Portal sind die Eintrittspunkte in das Firmennetz. Notwendigkeit, Patchstand und TLS-Konfiguration in einem Durchgang klären.",
             "refs": ["VS-2026-002", "VS-2026-003", "VS-2026-009", "VS-2026-010", "VS-2026-012"]},
            {"n": 3, "title": "E-Mail-Authentizität mit DMARC abschließen",
             "effect": "SPF und DKIM sind bereits vorhanden. Mit DMARC können Empfänger gefälschte Absender im Namen von junkerwerk.de und junkerwerk.hu abweisen.",
             "refs": ["VS-2026-007"]},
        ],
        "context": (
            "Geprüft wurde die von außen erreichbare Angriffsfläche der Domains junkerwerk.de und "
            "junkerwerk.hu am 31.08.2026: 15 Hostnamen auf 6 IP-Adressen (5 IPv4, 1 IPv6), verteilt auf "
            "einen Hetzner Managed Server (Website, Datenbanken) und den Telekom-Anschluss des Unternehmens "
            "(Exchange, Remote-Zugang, Zwei-Faktor-Portal). Drei Scandurchgänge wurden zu einem Ergebnis "
            "zusammengeführt. Innenperspektive, Mitarbeiterszenarien und Social Engineering sind nicht "
            "Teil dieser Prüfung."
        ),
        "coverage_warning": (
            "Die Hauptwebsite (www.junkerwerk.de, www.junkerwerk.hu) hat nach dem Portscan weitere "
            "Verbindungen des Scanners abgewiesen. Ihre Applikationsebene (Header, TLS, Formulare) ist "
            "deshalb nicht bewertet; Details in Kapitel 2."
        ),
    },

    # ------------------------------------------------------------------
    # Schicht 1.2: Geschäftskontext (datengetrieben, keine Branchenschablone)
    # ------------------------------------------------------------------
    "business": {
        "lead": (
            "Was der Scan über das Unternehmen sichtbar macht, bestimmt, welche Befunde wirklich zählen. "
            "Die Systeme im Scope sind keine Marketing-Websites, sondern die Infrastruktur, über die "
            "Mitarbeitende arbeiten: E-Mail, Fernzugang, Zwei-Faktor-Anmeldung."
        ),
        "observed": [
            {"system": "Exchange Server (mail., outlook., autodiscover.junkerwerk.de)",
             "meaning": "Selbst betriebene E-Mail- und Kalenderplattform; Korrespondenz, Angebote, Bestellungen und Kundendaten laufen hier zusammen. Der SPF-Record zeigt zusätzlich Microsoft 365 und den E-Mail-Filter Hornetsecurity."},
            {"system": "Zwei-Faktor-Portal (openotp.junkerwerk.de / .hu, RCDevs WebADM)",
             "meaning": "Standard-Portal von OpenOTP: Mitarbeitende registrieren hier ihre OTP-Token und FIDO-Geräte, melden neue Geräte an, setzen Passwörter zurück und nutzen Single Sign-on (OpenID/SAML). Ein Portal, das Zugangsdaten und Gerätebindungen verwaltet, ist ein bevorzugtes Phishing-Ziel und muss selbst vorbildlich abgesichert sein. Die .hu-Variante deutet auf einen Standort in Ungarn hin."},
            {"system": "Remote-Desktop-Gateway (rdgw., rdgw-2016., cloud., team.junkerwerk.de)",
             "meaning": "Die Hostnamen weisen auf ein Remote-Desktop-Gateway hin, also den Fernzugriff auf Arbeitsplätze im Firmennetz. Solche Gateways sind in der Praxis ein häufiger Erstzugang bei Ransomware-Vorfällen."},
            {"system": "SonicWall-Firewall (217.243.248.28, Port 4433, Passivquelle)",
             "meaning": "Das Sicherheits-Gateway vor dem Standortnetz. Ein von außen erreichbares Firewall-Webinterface ist ein hochwertiges Ziel, weil eine Übernahme das gesamte Standortnetz betrifft."},
            {"system": "Website und Datenbanken (Hetzner Managed Server)",
             "meaning": "Unternehmenswebsite mit Nachhaltigkeitsbereich sowie MariaDB- und PostgreSQL-Instanzen. Welche Anwendungen die Datenbanken nutzen, ist von außen nicht erkennbar; typisch sind Website-Inhalte und Formulardaten."},
        ],
        "implication": (
            "Für ein produzierendes Unternehmen liegt das größte Schadenspotenzial nicht im Verlust der "
            "Website, sondern im Stillstand von E-Mail, Fernzugang und Produktionsplanung. Die Befunde "
            "dieses Berichts sind deshalb danach priorisiert, wie nah sie an diesen Zugangswegen liegen. "
            "Der rote Befund (Datenbanken) betrifft den Hoster-Server und damit eher Website- und "
            "Kontaktdaten; die gelben Befunde betreffen fast ausnahmslos den Standortanschluss und damit "
            "den Weg ins Firmennetz. Bei einem Vorfall mit personenbezogenen Daten gilt die Meldepflicht "
            "nach Art. 33 DSGVO innerhalb von 72 Stunden."
        ),
    },

    # ------------------------------------------------------------------
    # Schicht 2.1: Umfang & Methodik
    # ------------------------------------------------------------------
    "scope": {
        "lead": (
            "Der Scan hat 6 IP-Adressen mit 15 Hostnamen erfasst. Für vier Hosts liegt eine vollständige "
            "aktive Prüfung vor, für den Webserver nur der Portscan und für die IPv6-Adresse keine Prüfung. "
            "Diese Lücken sind unten benannt, damit die Ergebnisse nicht vollständiger wirken, als sie sind."
        ),
        "hosts": [
            {"ip": "188.40.3.130", "fqdns": "junkerwerk.de, www.junkerwerk.de, nachhaltigkeit.junkerwerk.de, junkerwerk.hu, www.junkerwerk.hu",
             "operator": "Hetzner Managed Server (dedi2230.your-server.de)", "role": "Website, Datenbanken, Mail-Relay des Hosters",
             "coverage": "Portscan vollständig; Web-Prüfung nicht möglich (Scanner blockiert)", "cov": "teil"},
            {"ip": "217.243.248.28", "fqdns": "mail., outlook., autodiscover.junkerwerk.de",
             "operator": "Junkerwerk (Telekom-Anschluss)", "role": "Exchange Server SE, Firewall-Interface (passiv)",
             "coverage": "vollständig", "cov": "voll"},
            {"ip": "217.243.248.29", "fqdns": "cloud., team., rdgw., rdgw-2016.junkerwerk.de",
             "operator": "Junkerwerk", "role": "Windows-Server, IIS, vermutlich RD-Gateway",
             "coverage": "vollständig", "cov": "voll"},
            {"ip": "217.243.248.30", "fqdns": "openotp.junkerwerk.de, openotp.junkerwerk.hu",
             "operator": "Junkerwerk", "role": "Zwei-Faktor-Portal, SMTP-Archiv (passiv)",
             "coverage": "vollständig", "cov": "voll"},
            {"ip": "217.243.248.27", "fqdns": "ticket.junkerwerk.de",
             "operator": "Junkerwerk", "role": "keine erreichbaren Dienste",
             "coverage": "vollständig (keine offenen Ports)", "cov": "voll"},
            {"ip": "2a01:4f8:d0a:3124::2", "fqdns": "nachhaltigkeit.junkerwerk.de (AAAA)",
             "operator": "Hetzner (IPv6 desselben Servers)", "role": "wie 188.40.3.130",
             "coverage": "nicht geprüft (IPv6)", "cov": "keine"},
        ],
        "out_of_scope": [
            "Interne Netzsegmente, Arbeitsplätze, mobile Geräte und der Standort in Ungarn hinter der Firewall.",
            "Authentifizierte Prüfungen (kein Login in Exchange, OpenOTP oder Verwaltungsoberflächen).",
            "Social Engineering, Phishing-Simulationen, physische Sicherheit.",
            "Domains außerhalb des Auftrags, obwohl sichtbar: www.junkerwerk.com (Weiterleitungsziel des Webservers) und junkerwerk-solingen.de (im SMTP-Banner des Exchange-Servers).",
        ],
        "limitations": [
            {"what": "Website ohne Applikationsprüfung",
             "detail": "Nach dem Portscan um 16:16 Uhr hat 188.40.3.130 alle weiteren HTTPS-Verbindungen des Scanners abgewiesen (testssl: „Can't connect“, Header-Prüfung: „reachable: false“). Header, TLS, Formulare und Verzeichnisse von www.junkerwerk.de, www.junkerwerk.hu und nachhaltigkeit.junkerwerk.de sind unbewertet. Vermutlich greift eine automatische Sperre des Hosters; eine Nachprüfung braucht die Freischaltung der Scanner-Adresse."},
            {"what": "IPv6 nicht geprüft",
             "detail": "2a01:4f8:d0a:3124::2 gehört laut Reverse-DNS zum selben Hetzner-Server; der IPv6-Portscan lieferte kein Ergebnis."},
            {"what": "Nur passive Web-Analyse",
             "detail": "Aktive Schwachstellensuche in Webanwendungen (Injection-Tests, Parameter-Fuzzing) war in diesem Lauf nicht verfügbar; bewertet wurden Header, TLS, Verzeichnisse und Formulare."},
            {"what": "Passivquellen",
             "detail": "Ports 25 (SMTP) auf 217.243.248.28 und .30 sowie 4433 (SonicWall) stammen aus Shodan (30./31.08.2026) und waren vom Scanner aus nicht erreichbar; im Bericht als „passiv“ gekennzeichnet, jeweils mit Verifikationsschritt."},
            {"what": "Versionen aus Bannern",
             "detail": "Versionsangaben von Distributionspaketen (OpenSSH 9.2p1, Exim 4.96) sagen nichts über Sicherheits-Backports aus; der Bericht leitet daraus keine CVE-Befunde ab, sondern nennt Prüfpunkte."},
        ],
        "method_phases": [
            {"n": "0", "name": "Aufklärung (passiv)", "text": "Subdomain-Quellen (SecurityTrails, Shodan, Certspotter, subfinder), DNS- und E-Mail-Records, Reputationsdienste. Ergebnis: 12 Hostnamen für .de, 3 für .hu, 6 IP-Adressen."},
            {"n": "1", "name": "Technologie-Erkennung", "text": "Portscan der 1.000 häufigsten TCP-Ports mit Versionserkennung (nmap), Web-Technologie- und WAF-Erkennung. Ergebnis: 17 Dienste auf 4 Hosts, 3 weitere nur passiv."},
            {"n": "2", "name": "Tiefenprüfung", "text": "TLS-Analyse (testssl.sh), Sicherheits-Header, HTTP-Analyse (httpx), Verzeichnis-Enumeration (feroxbuster), passive Webanalyse (OWASP ZAP), je virtuellem Host."},
            {"n": "3", "name": "Korrelation und Bewertung", "text": "Zusammenführung über Werkzeuge und Läufe, Dedup, Abgleich mit NVD und CISA-KEV, Bewertung nach Severity-Policy 2026-06-01.1, Durchsicht jedes Befunds gegen die Rohdaten."},
        ],
        "numbers": [
            {"v": "3", "l": "Scandurchgänge"},
            {"v": "330", "l": "Werkzeugläufe"},
            {"v": "211", "l": "Rohmeldungen"},
            {"v": "15", "l": "Befunde im Bericht"},
        ],
        "standard_note": (
            "Einordnung: automatisierte externe Schwachstellenanalyse, angelehnt an die Prüfphasen "
            "Aufklärung, Schwachstellenanalyse und Bericht. Kein Penetrationstest: Bedrohungsmodellierung, "
            "Ausnutzung gefundener Schwächen und weiterführende Zugriffe finden nicht statt "
            "(BSI-Klassifikation: Black-Box, von außen, vorsichtig, automatisiert)."
        ),
        "ai_note": (
            "Sprachmodelle steuern die Priorisierung der Hosts, die Konfiguration der Tiefenprüfung und die "
            "Klassifizierung neuer Muster; die Severity-Bewertung ist regelbasiert. Jeder Befund wurde gegen "
            "die Werkzeug-Rohdaten geprüft, Meldungen ohne Beleg wurden verworfen (Anhang D)."
        ),
        "can_cannot": {
            "can": [
                "erreichbare Dienste, Versionen und Konfigurationsschwächen aus Angreifersicht",
                "E-Mail- und DNS-Authentizität, TLS-Konfiguration, Sicherheits-Header",
                "bekannte Schwachstellenmuster ohne Anmeldung",
            ],
            "cannot": [
                "Schwachstellen hinter einer Anmeldung (Exchange, OpenOTP, Verwaltungsoberflächen)",
                "Patchstände, die sich nicht im Banner zeigen (Distributions-Backports, Exchange-SUs, Firewall-Firmware)",
                "Fehlkonfigurationen im Inneren, Berechtigungen, Backups, Notfallprozesse",
            ],
            "advice": "Für die Zugangs-Infrastruktur (Firewall, RD-Gateway, Zwei-Faktor-Portal) empfehlen wir ergänzend eine Konfigurationsprüfung mit Administratorzugang.",
        },
    },

    # ------------------------------------------------------------------
    # Schicht 2.2: Architektur-Sicht
    # ------------------------------------------------------------------
    "architecture": {
        "lead": (
            "Zwei Welten: Der Hetzner-Server trägt Websites und Datenbanken, der Telekom-Anschluss des "
            "Standorts E-Mail, Fernzugang und Zwei-Faktor-Anmeldung. Die geschäftskritischen Befunde liegen am Standort."
        ),
        "tech": [
            {"host": "188.40.3.130 · Hetzner Managed Server", "rows": [
                {"c": "Apache httpd", "v": "unbekannt", "src": "Banner", "conf": "hoch", "status": "unbekannt", "st": "grau", "note": "Website nach Portscan nicht mehr erreichbar"},
                {"c": "MariaDB", "v": "10.11.18 (Debian 12)", "src": "nmap, Shodan", "conf": "hoch", "status": "aktuell", "st": "gruen", "note": "LTS-Zweig, Support bis 02/2028"},
                {"c": "PostgreSQL", "v": "≥ 9.6, nicht bestimmbar", "src": "nmap, Shodan", "conf": "mittel", "status": "unbekannt", "st": "grau", "note": "Version nicht im Handshake"},
                {"c": "OpenSSH", "v": "9.2p1 (Debian 12)", "src": "nmap", "conf": "hoch", "status": "aktuell", "st": "gruen", "note": "gepflegtes Distributionspaket"},
                {"c": "ProFTPD (FTP/SFTP)", "v": "unbekannt", "src": "nmap", "conf": "hoch", "status": "unbekannt", "st": "grau", "note": "TLS erzwungen"},
                {"c": "Exim (SMTP 465/587)", "v": "unbekannt", "src": "nmap", "conf": "hoch", "status": "unbekannt", "st": "grau", "note": ""},
                {"c": "Courier POP3, Dovecot IMAP", "v": "unbekannt", "src": "nmap", "conf": "hoch", "status": "unbekannt", "st": "grau", "note": "STARTTLS, Login ohne TLS gesperrt"},
            ]},
            {"host": "217.243.248.28 · mail / outlook / autodiscover", "rows": [
                {"c": "Microsoft Exchange Server SE", "v": "Build 15.2.2562", "src": "OWA-Ressourcen, Header X-FEServer", "conf": "hoch", "status": "aktuell (RTM-Linie)", "st": "gruen", "note": "CU-/SU-Stand von außen nicht prüfbar"},
                {"c": "Microsoft IIS", "v": "10.0", "src": "Banner", "conf": "hoch", "status": "aktuell", "st": "gruen", "note": "Windows-Version nicht bestimmbar"},
                {"c": "ASP.NET", "v": "4.0.30319", "src": "Header", "conf": "hoch", "status": "aktuell", "st": "gruen", "note": ""},
                {"c": "SonicWall (Port 4433)", "v": "unbekannt", "src": "Shodan (passiv)", "conf": "mittel", "status": "unbekannt", "st": "gelb", "note": "vom Scanner nicht erreichbar"},
            ]},
            {"host": "217.243.248.29 · cloud / team / rdgw / rdgw-2016", "rows": [
                {"c": "Microsoft IIS (443, 8443)", "v": "10.0", "src": "nmap, Banner, Shodan", "conf": "hoch", "status": "aktuell", "st": "gruen", "note": "Standardseite, TRACE aktiv"},
                {"c": "Windows Server", "v": "nicht bestimmbar", "src": "Hostname rdgw-2016", "conf": "niedrig", "status": "Lifecycle prüfen", "st": "gelb", "note": "Extended Support 2016 endet 12.01.2027"},
            ]},
            {"host": "217.243.248.30 · openotp (.de / .hu)", "rows": [
                {"c": "RCDevs WebADM / OpenOTP", "v": "unbekannt", "src": "Seitentitel, Pfade", "conf": "mittel", "status": "unbekannt", "st": "grau", "note": "Zwei-Faktor-Portal"},
                {"c": "Apache httpd", "v": "unbekannt", "src": "Banner", "conf": "hoch", "status": "unbekannt", "st": "grau", "note": ""},
                {"c": "Exim (Port 25, archiv.junkerwerk.de)", "v": "4.96", "src": "Shodan (passiv)", "conf": "mittel", "status": "veraltet", "st": "gelb", "note": "aktuell 4.98; Backport möglich"},
            ]},
        ],
        "services": [
            {"host": "188.40.3.130", "label": "Hetzner Managed Server", "ports": [
                {"p": "21", "s": "FTP (TLS)", "st": "blau"}, {"p": "22", "s": "SFTP", "st": "gruen"}, {"p": "80", "s": "HTTP", "st": "gruen"},
                {"p": "110", "s": "POP3 STLS", "st": "blau"}, {"p": "143", "s": "IMAP STARTTLS", "st": "blau"}, {"p": "222", "s": "SSH", "st": "gruen"},
                {"p": "443", "s": "HTTPS", "st": "gruen"}, {"p": "465", "s": "SMTPS", "st": "gruen"}, {"p": "587", "s": "Submission", "st": "gruen"},
                {"p": "993", "s": "IMAPS", "st": "gruen"}, {"p": "995", "s": "POP3S", "st": "gruen"},
                {"p": "3306", "s": "MariaDB", "st": "rot"}, {"p": "5432", "s": "PostgreSQL", "st": "rot"}]},
            {"host": "217.243.248.28", "label": "Exchange", "ports": [
                {"p": "443", "s": "HTTPS OWA", "st": "gruen"}, {"p": "25", "s": "SMTP (passiv)", "st": "grau"}, {"p": "4433", "s": "SonicWall (passiv)", "st": "gelb"}]},
            {"host": "217.243.248.29", "label": "cloud / rdgw", "ports": [
                {"p": "443", "s": "HTTPS IIS", "st": "gelb"}, {"p": "8443", "s": "HTTPS IIS", "st": "gelb"}]},
            {"host": "217.243.248.30", "label": "openotp", "ports": [
                {"p": "443", "s": "HTTPS OpenOTP", "st": "gelb"}, {"p": "25", "s": "SMTP Exim (passiv)", "st": "gelb"}]},
            {"host": "217.243.248.27", "label": "ticket", "ports": []},
        ],
        "services_note": "Rot: offener Datenbankdienst · Gelb: Dienst mit Befund · Blau: Altprotokoll mit TLS-Zwang · Grau: nur aus Passivquelle bekannt. Die IPv6-Adresse wurde nicht geprüft.",
        "posture": [
            {"name": "E-Mail-Authentizität (beide Domains)", "short": "E-Mail-Authentizität", "items": [
                {"l": "SPF", "ok": True, "v": "vorhanden, ~all"}, {"l": "DKIM", "ok": True, "v": "hse1, hse2"},
                {"l": "DMARC", "ok": False, "v": "fehlt"}, {"l": "MTA-STS", "ok": False, "v": "fehlt"},
                {"l": "TLS-RPT, DANE", "ok": False, "v": "fehlt"}]},
            {"name": "DNS-Hygiene", "short": "DNS-Hygiene", "items": [
                {"l": "DNSSEC", "ok": False, "v": "nicht signiert"}, {"l": "CAA", "ok": False, "v": "fehlt"},
                {"l": "Zonentransfer", "ok": True, "v": "abgewiesen"}, {"l": "Dangling CNAME", "ok": True, "v": "keine"}]},
            {"name": "TLS-Konfiguration", "short": "TLS-Konfiguration", "items": [
                {"l": "Exchange OWA", "ok": True, "v": "TLS 1.2/1.3"}, {"l": "openotp", "ok": False, "v": "nur 1.2, 3DES"},
                {"l": "cloud/rdgw", "ok": False, "v": "TLS 1.0/1.1 aktiv"}, {"l": "Zertifikate", "ok": True, "v": "gültig, Chain OK"}]},
            {"name": "Sicherheits-Header (von 7)", "short": "Sicherheits-Header", "items": [
                {"l": "Exchange OWA", "ok": False, "v": "0 von 7"}, {"l": "cloud/rdgw", "ok": False, "v": "0 von 7"},
                {"l": "openotp", "ok": True, "v": "5 von 7, CSP schwach"}, {"l": "Website", "ok": None, "v": "nicht prüfbar"}]},
        ],
        "screens_lead": "Sichtprüfung aller erreichbaren Web-Oberflächen der geprüften Hosts.",
        "screens": [
            {"file": "www-junkerwerk-de.jpg", "host": "www.junkerwerk.de", "what": "Unternehmenswebsite (Apache, Hetzner)"},
            {"file": "www-junkerwerk-hu.jpg", "host": "www.junkerwerk.hu", "what": "antwortet mit 403 Forbidden"},
            {"file": "nachhaltigkeit-junkerwerk-de.jpg", "host": "nachhaltigkeit.junkerwerk.de", "what": "antwortet mit 403 Forbidden"},
            {"file": "mail-junkerwerk-de.jpg", "host": "mail.junkerwerk.de", "what": "Outlook Web App, identisch auf outlook. und autodiscover."},
            {"file": "cloud-junkerwerk-de.jpg", "host": "cloud.junkerwerk.de", "what": "IIS-Standardseite, identisch auf team., rdgw., rdgw-2016."},
            {"file": "openotp-junkerwerk-de.jpg", "host": "openotp.junkerwerk.de", "what": "WebADM-Portal, identisch auf openotp.junkerwerk.hu (dort mit Zertifikatswarnung)"},
        ],
        "reputation": "Reputation und Threat-Intelligence: AbuseIPDB 0/100 für alle sechs Adressen, keine OTX-Pulses, kein URLhaus-Treffer, keine Übereinstimmung mit CISA KEV.",
        "notes": [
            "Der Hetzner-Server ist ein Managed Server, auf dem laut Passivquellen weitere Domains Dritter liegen (Shared Hosting). Die Trennung zwischen den Kunden liegt in der Verantwortung des Hosters.",
            "Port 80 des Webservers leitet auf https://www.junkerwerk.com weiter. Diese Domain war nicht Teil des Auftrags; sie sollte in einen Folgescan aufgenommen werden.",
            "www.junkerwerk.hu und nachhaltigkeit.junkerwerk.de antworten mit 403 Forbidden (Scan und Nachaufnahme). Ob die Seiten absichtlich gesperrt sind, sollte die Website-Betreuung klären.",
            "Reputation und Threat-Intelligence: AbuseIPDB 0/100 für alle sechs Adressen, keine OTX-Pulses, kein URLhaus-Treffer, keine Übereinstimmung mit CISA KEV.",
        ],
    },

    # ------------------------------------------------------------------
    # Schicht 2.3: Befund-Landschaft
    # ------------------------------------------------------------------
    "landscape_lead": (
        "15 Befunde in fünf Kategorien. Die Kategorien entsprechen der Ampel auf Seite 2; innerhalb "
        "jeder Kategorie sind die Befunde nach Status und Dringlichkeit sortiert. Grün markierte "
        "Punkte am Ende sind positive Feststellungen, die beibehalten werden sollten."
    ),
    "positives": [
        {"cat": "A", "title": "Kein direkt exponiertes RDP (3389) oder SMB (445) auf den geprüften Hosts", "text": "ticket.junkerwerk.de (217.243.248.27) zeigt keinerlei erreichbare Dienste."},
        {"cat": "A", "title": "FTP-, POP3-, IMAP- und SMTP-Dienste des Webservers erzwingen TLS vor der Anmeldung", "text": "FTP verlangt AUTH TLS, IMAP sperrt LOGIN vor STARTTLS, SMTP bietet AUTH erst nach STARTTLS an."},
        {"cat": "B", "title": "Exchange Server Subscription Edition im Einsatz", "text": "Der sichtbare Build 15.2.2562 gehört zur aktuellen Produktlinie; kein Exchange 2016/2019 mehr im Perimeter."},
        {"cat": "C", "title": "SPF und DKIM für beide Domains vorhanden, eingehende Mail über Hornetsecurity gefiltert", "text": "Damit fehlt für vollständige Absender-Authentizität nur noch DMARC."},
        {"cat": "C", "title": "Kein Zonentransfer möglich, keine verwaisten CNAME-Einträge", "text": "Kein Subdomain-Takeover-Risiko erkennbar."},
        {"cat": "D", "title": "Alle HTTPS-Dienste mit gültigen, korrekt verketteten Zertifikaten", "text": "Sectigo-Wildcard *.junkerwerk.de (RSA 4096, gültig bis 11.12.2026) und Hetzner-Zertifikat (gültig bis 02.11.2026), OCSP Stapling aktiv."},
        {"cat": "D", "title": "Outlook Web App nur mit TLS 1.2 und 1.3, Forward Secrecy", "text": "Keine veralteten Protokolle auf dem Exchange-Server."},
        {"cat": "E", "title": "Keine Einträge in Reputations- und Threat-Intelligence-Quellen", "text": "AbuseIPDB 0/100 für alle sechs Adressen, keine OTX-Pulses, kein URLhaus-Treffer."},
    ],

    # ------------------------------------------------------------------
    # Maßnahmenplan (ohne Aufwand, ohne Kosten)
    # ------------------------------------------------------------------
    "plan": [
        {"prio": "Unverzüglich", "st": "rot", "action": "Externen Datenbankzugriff auf dem Hetzner-Server abschalten oder auf feste Quelladressen beschränken (Verwaltungsoberfläche des Hosters bzw. Hosting-Partner); anschließend Datenbank-Passwörter rotieren.", "refs": ["VS-2026-001"], "effect": "Schließt das einzige rote Risiko"},
        {"prio": "In Kürze", "st": "gelb", "action": "SonicWall-Webinterface auf Port 4433 klären: Portaltyp (SSL-VPN oder Verwaltung), Firmwarestand gegen Hersteller-Advisories, Zwei-Faktor-Pflicht, Zugriff auf benötigte Quellnetze beschränken.", "refs": ["VS-2026-002"], "effect": "Sichert das Sicherheits-Gateway selbst"},
        {"prio": "In Kürze", "st": "gelb", "action": "Windows-Server 217.243.248.29: Funktion klären (RD-Gateway?), Port 8443 abschalten falls ungenutzt, IIS-Standardseite entfernen, TLS 1.0/1.1 deaktivieren, HTTP TRACE abschalten.", "refs": ["VS-2026-003", "VS-2026-012"], "effect": "Verkleinert die Angriffsfläche des Fernzugangs"},
        {"prio": "In Kürze", "st": "gelb", "action": "Zwei-Faktor-Portal: 3DES-Cipher entfernen, TLS 1.3 aktivieren, HSTS auf mindestens ein Jahr, Kompression für dynamische Seiten abschalten; Zertifikat um openotp.junkerwerk.hu ergänzen oder den .hu-Hostnamen stilllegen.", "refs": ["VS-2026-009", "VS-2026-010"], "effect": "Beseitigt Zertifikatswarnungen und Downgrade-Risiken am Anmeldeportal"},
        {"prio": "In Kürze", "st": "gelb", "action": "SMTP-Dienst auf archiv.junkerwerk.de: Exim-Patchstand prüfen, Port 25 auf die Zustellnetze von Hornetsecurity beschränken.", "refs": ["VS-2026-004"], "effect": "Entfernt einen ungeprüften Mailserver aus der Angriffsfläche"},
        {"prio": "In Kürze", "st": "gelb", "action": "DMARC für junkerwerk.de und junkerwerk.hu einführen: zunächst p=none mit Reporting-Adresse, nach Auswertung p=quarantine, dann p=reject; SPF von ~all auf -all umstellen.", "refs": ["VS-2026-007"], "effect": "Empfänger können gefälschte Absender abweisen"},
        {"prio": "Mittelfristig", "st": "blau", "action": "Content-Security-Policy des Zwei-Faktor-Portals ohne unsafe-inline/unsafe-eval (Nonces), doppelte Header bereinigen, Anti-CSRF-Token im Login-Formular.", "refs": ["VS-2026-011"], "effect": "Härtet das Portal gegen Skript-Injektion"},
        {"prio": "Mittelfristig", "st": "blau", "action": "Sicherheits-Header auf Outlook Web App und IIS ergänzen (HSTS, X-Content-Type-Options, X-Frame-Options); Versionsbanner, X-Powered-By und X-FEServer unterdrücken.", "refs": ["VS-2026-013", "VS-2026-014"], "effect": "Weniger Angriffsvorbereitung, Schutz vor Downgrade"},
        {"prio": "Strategisch", "st": "blau", "action": "Lifecycle planen: Windows Server 2016 (Extended Support endet 12.01.2027) und Exchange SE Cumulative Updates; nicht benötigte Altprotokolle (FTP, POP3, IMAP ohne TLS-Port) abschalten.", "refs": ["VS-2026-005", "VS-2026-006"], "effect": "Vermeidet ungeplante EOL-Schulden"},
        {"prio": "Strategisch", "st": "blau", "action": "MTA-STS und TLS-RPT für beide Domains (setzt gültige Zertifikate auf den Hornetsecurity-MX voraus); DNSSEC und CAA beim Registrar united-domains aktivieren.", "refs": ["VS-2026-008", "VS-2026-015"], "effect": "Erzwingt Transportverschlüsselung und schützt DNS-Antworten"},
    ],

    # ------------------------------------------------------------------
    # Schicht 3: Befund-Details
    # ------------------------------------------------------------------
    "findings": [
        {
            "id": "VS-2026-001", "cat": "A", "status": "rot", "urgency": "Unverzüglich",
            "title": "Datenbankdienste MariaDB (3306) und PostgreSQL (5432) auf dem Webserver aus dem Internet erreichbar",
            "affected": "188.40.3.130 (junkerwerk.de, junkerwerk.hu), Ports 3306 und 5432",
            "source": "aktiv (nmap), bestätigt durch Shodan",
            "scale": "exposure", "level": "kritisch",
            "found": "Der Hetzner-Server, der die Websites beider Domains trägt, beantwortet Verbindungen auf den Datenbankports 3306 (MariaDB 10.11.18) und 5432 (PostgreSQL, Version nicht bestimmbar) aus dem gesamten Internet. MariaDB nimmt den Anmelde-Handshake an (Authentifizierung per Passwort, mysql_native_password). PostgreSQL weist fremde Quellen laut Passivquelle auf Datenbankebene ab („no pg_hba.conf entry“), der Dienst ist dennoch erreichbar und gibt sich zu erkennen. Bei Hetzner Managed Servern ist der externe Datenbankzugriff eine optionale Komfortfunktion des Hosters.",
            "evidence": "$ nmap -sV -p 3306,5432 188.40.3.130\n3306/tcp open  mysql       MySQL 5.5.5-10.11.18-MariaDB-0+deb12u1\n| mysql-info: Protocol 10, Auth Plugin Name: mysql_native_password\n5432/tcp open  postgresql  PostgreSQL DB 9.6.0 or later\n\nShodan 31.08.2026: 5432 -> \"FATAL: no pg_hba.conf entry for host ...\"",
            "threat": None,
            "impact": "Ein von außen erreichbarer Datenbankdienst erlaubt Passwort-Rateangriffe rund um die Uhr und macht jede künftige Schwachstelle im Datenbankserver sofort ausnutzbar. Betroffen wären die Inhalte der Website-Datenbanken, typischerweise Seiteninhalte, Formulareingaben und Kontaktdaten. Datenbankdienste gehören grundsätzlich nicht an das öffentliche Interface.",
            "recommendation": [
                ("Unverzüglich", "Externen Datenbankzugriff in der Hetzner-Verwaltung (konsoleH) deaktivieren oder, falls eine externe Anwendung ihn benötigt, auf deren feste IP-Adressen beschränken. Falls der Server durch eine Agentur betreut wird: dort beauftragen."),
                ("In Kürze", "Datenbank-Zugangsdaten rotieren und die Zugriffsprotokolle der letzten Monate auf fremde Anmeldeversuche prüfen."),
                ("Mittelfristig", "Administrativen Datenbankzugriff ausschließlich über SSH-Tunnel (Port 222) oder VPN."),
            ],
            "verify": "$ nmap -sV -p 3306,5432 188.40.3.130    # erwartet: filtered oder closed",
            "policy": "SP-DB-001",
        },
        {
            "id": "VS-2026-002", "cat": "A", "status": "gelb", "urgency": "In Kürze",
            "title": "SonicWall-Webinterface auf Port 4433 des Exchange-Anschlusses laut Passivquelle erreichbar",
            "affected": "217.243.248.28, Port 4433",
            "source": "passiv (Shodan, 30.08.2026); vom Scanner nicht erreichbar, Port außerhalb der geprüften Top-1000",
            "scale": "hygiene", "level": "hoch",
            "found": "Shodan meldet für 217.243.248.28 ein SonicWall-Webinterface auf Port 4433 (HTTP 200, typische Header einer SonicWall-Oberfläche). Der Port liegt außerhalb der im Scan geprüften 1.000 häufigsten Ports und wurde nicht aktiv verifiziert. Ob es sich um das SSL-VPN-Portal (erwartbar) oder die Verwaltungsoberfläche handelt, ist von außen nicht erkennbar. Firewall-Produkte dieses Herstellers standen 2024 und 2025 wiederholt auf der Liste aktiv ausgenutzter Schwachstellen der CISA (Known Exploited Vulnerabilities).",
            "evidence": "Shodan 2026-08-30, 217.243.248.28:4433\nHTTP/1.1 200 OK\nServer: Web Server\nX-Frame-Options: SAMEORIGIN ...\nproduct: SonicWall",
            "threat": None,
            "impact": "Ein exponiertes Firewall-Interface ist ein hochwertiges Ziel: Eine Übernahme betrifft den gesamten Standortanschluss inklusive Exchange, Fernzugang und internem Netz. SSL-VPN-Portale ohne Zwei-Faktor-Anmeldung sind ein häufiger Erstzugang bei Ransomware-Vorfällen.",
            "recommendation": [
                ("In Kürze", "Klären, welche Funktion auf 4433 läuft. Verwaltungsoberflächen dürfen nicht aus dem Internet erreichbar sein; SSL-VPN nur mit Zwei-Faktor-Anmeldung und aktuellem Firmwarestand."),
                ("In Kürze", "Firmware gegen die Sicherheitshinweise des Herstellers (PSIRT) abgleichen; lokale Benutzerkonten und Standard-Admin prüfen."),
                ("Mittelfristig", "Zugriff auf das Portal auf benötigte Länder oder Quellnetze beschränken, Anmeldeversuche überwachen."),
            ],
            "verify": "$ curl -skI --max-time 10 https://217.243.248.28:4433/    # erwartet: kein Verwaltungs-Login ohne Zugangsbeschränkung; Firmware laut Hersteller aktuell",
            "policy": "manuell (Passivquelle)",
        },
        {
            "id": "VS-2026-003", "cat": "A", "status": "gelb", "urgency": "In Kürze",
            "title": "Windows-Server hinter cloud/team/rdgw/rdgw-2016.junkerwerk.de exponiert IIS-Standardseite auf 443 und 8443",
            "affected": "217.243.248.29 (cloud., team., rdgw., rdgw-2016.junkerwerk.de), Ports 443 und 8443",
            "source": "aktiv (nmap, httpx, feroxbuster, Shodan)",
            "scale": "hygiene", "level": "mittel",
            "found": "Vier Hostnamen zeigen auf denselben Windows-Server mit IIS 10.0. Auf Port 443 und 8443 antwortet ausschließlich die unveränderte IIS-Startseite („IIS Windows Server“), die HTTP-Methode TRACE ist aktiv. Die Hostnamen rdgw und rdgw-2016 deuten auf ein Remote-Desktop-Gateway hin; dessen Endpunkte (/RDWeb, /rpc) wurden im Scan nicht geprüft. Ob Port 8443 eine Funktion hat, ist nicht erkennbar.",
            "evidence": "$ nmap -sV -p 443,8443 217.243.248.29\n443/tcp  open ssl/http Microsoft IIS httpd 10.0  http-title: IIS Windows Server\n8443/tcp open ssl/http Microsoft IIS httpd 10.0  http-title: IIS Windows Server\n| http-methods: Potentially risky methods: TRACE\n\n$ curl -sI https://cloud.junkerwerk.de/  ->  Server: Microsoft-IIS/10.0, X-Powered-By: ASP.NET",
            "threat": None,
            "impact": "Ein Remote-Desktop-Gateway ist der Fernzugang auf Arbeitsplätze und Anwendungen im Firmennetz und damit ein bevorzugtes Ziel für Passwortangriffe und Schwachstellen in Windows-Komponenten. Zusätzliche Ports und Standardseiten vergrößern die Angriffsfläche ohne Nutzen. Die Bezeichnung „2016“ lässt einen Windows Server 2016 vermuten, dessen erweiterter Support am 12.01.2027 endet (siehe VS-2026-006).",
            "recommendation": [
                ("In Kürze", "Funktion des Servers klären. Port 8443 schließen, falls ungenutzt; IIS-Standardseite durch eine leere 403-Antwort ersetzen; TRACE deaktivieren."),
                ("In Kürze", "Falls RD-Gateway: Zwei-Faktor-Anmeldung (z. B. über das vorhandene OpenOTP), Kontosperrung nach Fehlversuchen, aktuelle Windows-Updates, nur benötigte Quellnetze."),
                ("Mittelfristig", "TLS 1.0/1.1 auf dem Server deaktivieren (VS-2026-012) und Sicherheits-Header setzen (VS-2026-013)."),
            ],
            "verify": "$ curl -skI https://cloud.junkerwerk.de:8443/          # erwartet: keine Verbindung\n$ curl -sk -X TRACE https://cloud.junkerwerk.de/     # erwartet: 405 oder 501",
            "policy": "manuell",
        },
        {
            "id": "VS-2026-004", "cat": "B", "status": "gelb", "urgency": "In Kürze",
            "title": "SMTP-Dienst Exim 4.96 auf archiv.junkerwerk.de laut Passivquelle erreichbar, Version ohne aktuelle Herstellerpflege",
            "affected": "217.243.248.30 (archiv.junkerwerk.de, gleicher Host wie openotp.junkerwerk.de), Port 25",
            "source": "passiv (Shodan, 30.08.2026); Port 25 war vom Scanner aus gefiltert",
            "scale": "hygiene", "level": "mittel",
            "found": "Shodan meldet auf 217.243.248.30 einen SMTP-Dienst Exim 4.96 mit dem Banner „archiv.junkerwerk.de“ (vermutlich E-Mail-Archivierung). Exim 4.96 stammt aus 2022; die Sicherheitslücken vom Herbst 2023 (u. a. CVE-2023-42115, Ausführung von Code ohne Anmeldung im AUTH-Handling) wurden erst in 4.96.1 und 4.97 behoben, aktuell ist 4.98. Ob die Lücken per Distributions-Backport geschlossen sind, ist am Banner nicht ablesbar. Der Dienst war vom Scanner aus nicht erreichbar, was auf eine quell-IP-abhängige Firewall-Regel hindeutet.",
            "evidence": "Shodan 2026-08-30, 217.243.248.30:25\n220 archiv.junkerwerk.de ESMTP Exim 4.96 Sun, 30 Aug 2026 14:48:52 +0200\n250-SIZE 52428800 ... 250 STARTTLS\n\n$ nmap -p 25 217.243.248.30  ->  filtered (vom Scanner aus)",
            "threat": {"cves": ["CVE-2023-42115 (Basiswert 9.8 laut ZDI/NVD, betrifft Exim bis 4.96 ohne Fix)"], "kev": "nein", "note": "Fremdbewertung; Zuordnung rein versionsbasiert, nicht verifiziert"},
            "impact": "Ein ungepatchter, aus dem Internet erreichbarer Mailserver ist ein direkter Weg auf den Host, der zugleich das Zwei-Faktor-Portal trägt. Ein Archivserver muss Mail nur von den eigenen Systemen oder vom Filterdienst annehmen, nicht aus dem gesamten Internet.",
            "recommendation": [
                ("In Kürze", "Patchstand des Exim-Pakets prüfen (bei Debian: Sicherheitsupdates seit Oktober 2023 installiert?). Andernfalls aktualisieren."),
                ("In Kürze", "Port 25 auf die Zustellnetze von Hornetsecurity und interne Systeme beschränken."),
                ("Mittelfristig", "Archivierung und Zwei-Faktor-Portal auf getrennte Systeme verteilen."),
            ],
            "verify": "intern: $ exim -bV   # Version und Distributions-Patchlevel\nextern: $ nc -vz -w 5 217.243.248.30 25   # erwartet von fremder Quelle: keine Verbindung",
            "policy": "SP-EOL-001 (Passivquelle)",
        },
        {
            "id": "VS-2026-005", "cat": "A", "status": "blau", "urgency": "Strategisch",
            "title": "Altprotokolle FTP, POP3 und IMAP auf dem Webserver erreichbar (jeweils mit TLS-Zwang)",
            "affected": "188.40.3.130, Ports 21, 110, 143",
            "source": "aktiv (nmap)",
            "scale": "hygiene", "level": "niedrig",
            "found": "Der Hetzner-Server bietet FTP (21), POP3 (110) und IMAP (143) an. Alle drei erzwingen TLS vor der Anmeldung (FTP: „requires SSL“, IMAP: LOGINDISABLED bis STARTTLS, POP3: STLS). Eine Klartext-Übertragung von Zugangsdaten ist damit nicht möglich; die Dienste sind dennoch Angriffsfläche, sofern sie nicht benötigt werden. SFTP (22) sowie IMAPS/POP3S (993/995) stehen als Alternativen bereit.",
            "evidence": "21/tcp  open ftp   ProFTPD (requires SSL)\n143/tcp open imap  Dovecot imapd  CAPABILITY ... STARTTLS LOGINDISABLED\n110/tcp open pop3  Courier pop3d  CAPA: STLS",
            "threat": None,
            "impact": "Gering. Jeder erreichbare Dienst ist ein potenzieller Angriffspunkt bei künftigen Schwachstellen; ungenutzte Dienste bringen keinen Gegenwert.",
            "recommendation": [
                ("Strategisch", "Mit dem Hosting-Partner klären, welche dieser Dienste genutzt werden; nicht benötigte in der Hetzner-Verwaltung deaktivieren. Für Dateiübertragung SFTP bevorzugen."),
            ],
            "verify": "$ nmap -p 21,110,143 188.40.3.130    # nach Abschaltung: filtered oder closed",
            "policy": "manuell",
        },
        {
            "id": "VS-2026-006", "cat": "B", "status": "blau", "urgency": "Strategisch",
            "title": "Lifecycle-Prüfung: Windows Server 2016 (Hinweis aus Hostname) und Exchange-Updatestand",
            "affected": "217.243.248.29 (rdgw-2016.junkerwerk.de), 217.243.248.28 (Exchange Server SE)",
            "source": "Ableitung aus Hostname und OWA-Build; Versionen nicht direkt messbar",
            "scale": "hygiene", "level": "mittel",
            "found": "Der Hostname rdgw-2016 lässt einen Windows Server 2016 vermuten; dessen erweiterter Support endet am 12.01.2027, danach gibt es keine Sicherheitsupdates mehr. Der Exchange-Server läuft als Subscription Edition (Build 15.2.2562, RTM-Linie von Juli 2025); ob nachfolgende Cumulative und Security Updates installiert sind, ist von außen nicht feststellbar. Beides sind keine akuten Schwachstellen, aber Termine, die in die Planung gehören.",
            "evidence": "DNS: rdgw-2016.junkerwerk.de -> 217.243.248.29\nhttpx: Outlook Web App 15.2.2562; Header x-feserver: EXCHANGE-SE",
            "threat": None,
            "impact": "Ein Fernzugangs-Gateway ohne Sicherheitsupdates ab Januar 2027 wäre ein erhebliches Risiko. Exchange-Sicherheitsupdates werden regelmäßig aktiv ausgenutzt; ein Rückstand von wenigen Wochen kann ausreichen.",
            "recommendation": [
                ("Strategisch", "Betriebssystem des RD-Gateway-Hosts feststellen; bei Windows Server 2016 Migration bis Ende 2026 einplanen."),
                ("Mittelfristig", "Exchange SE: aktuelles Cumulative Update und das jüngste Security Update prüfen, Update-Prozess mit festem Rhythmus festlegen."),
            ],
            "verify": "intern: winver / Get-ComputerInfo auf dem Gateway; Exchange: Get-ExchangeServer | fl AdminDisplayVersion",
            "policy": "manuell",
        },
        {
            "id": "VS-2026-007", "cat": "C", "status": "gelb", "urgency": "In Kürze",
            "title": "DMARC-Richtlinie fehlt für junkerwerk.de und junkerwerk.hu; SPF endet mit Softfail",
            "affected": "DNS-Zonen junkerwerk.de und junkerwerk.hu",
            "source": "aktiv (DNS-Abfragen), bestätigt durch SecurityTrails und Shodan",
            "scale": "hygiene", "level": "hoch",
            "found": "Beide Domains haben einen SPF-Record (Exchange-Adresse 217.243.248.28, Microsoft 365, Hornetsecurity) mit Softfail (~all) und DKIM-Schlüssel über Hornetsecurity (Selektoren hse1, hse2). Es existiert jedoch kein _dmarc-Eintrag. Ohne DMARC bleibt es dem Empfänger überlassen, was mit Mails geschieht, die SPF oder DKIM nicht bestehen; ein Softfail wird in der Praxis meist zugestellt.",
            "evidence": "$ dig +short TXT junkerwerk.de\n\"v=spf1 a mx ip4:217.243.248.28 include:spf.protection.outlook.com include:spf.hornetsecurity.com ~all\"\n$ dig +short TXT _dmarc.junkerwerk.de\n(leer)\n$ dig +short TXT _dmarc.junkerwerk.hu\n(leer)",
            "threat": None,
            "impact": "Angreifer können E-Mails im Namen von junkerwerk.de oder junkerwerk.hu an Kunden, Lieferanten und Mitarbeitende senden (Rechnungsbetrug, CEO-Fraud), ohne dass Empfängersysteme diese zuverlässig abweisen. Mit SPF und DKIM ist die Vorarbeit geleistet; DMARC ist der fehlende Schlussstein.",
            "recommendation": [
                ("In Kürze", "Für beide Domains einen DMARC-Record mit p=none und einer Reporting-Adresse (rua) anlegen und vier Wochen Berichte auswerten."),
                ("Mittelfristig", "Auf p=quarantine, dann p=reject anheben; SPF von ~all auf -all umstellen, sobald alle legitimen Versender erfasst sind."),
            ],
            "verify": "$ dig +short TXT _dmarc.junkerwerk.de    # erwartet: v=DMARC1; p=...; rua=mailto:...\n$ dig +short TXT _dmarc.junkerwerk.hu",
            "policy": "SP-DNS-004 / SP-DNS-005",
        },
        {
            "id": "VS-2026-008", "cat": "C", "status": "blau", "urgency": "Strategisch",
            "title": "Keine Durchsetzung der Transportverschlüsselung für eingehende E-Mail (MTA-STS, TLS-RPT, DANE fehlen)",
            "affected": "DNS-Zonen junkerwerk.de und junkerwerk.hu (MX: Hornetsecurity)",
            "source": "aktiv (DNS-Abfragen)",
            "scale": "hygiene", "level": "niedrig",
            "found": "Für beide Domains existieren weder ein MTA-STS-Record noch TLS-RPT oder DANE/TLSA. Sendende Mailserver können damit nicht erkennen, dass die Zustellung ausschließlich verschlüsselt erfolgen soll; ein Angreifer mit Netzzugriff könnte STARTTLS unterdrücken.",
            "evidence": "$ dig +short TXT _mta-sts.junkerwerk.de   (leer)\n$ dig +short TXT _smtp._tls.junkerwerk.de  (leer)\n$ dig +short TLSA _25._tcp.mx01.hornetsecurity.com  (leer)",
            "threat": None,
            "impact": "Gering im Alltag, relevant bei gezielten Angriffen auf den Mailtransport. Die Maßnahme ist mit Hornetsecurity als MX-Betreiber ohne eigene Infrastruktur umsetzbar.",
            "recommendation": [
                ("Strategisch", "MTA-STS-Policy (mode: testing, dann enforce) mit den Hornetsecurity-MX veröffentlichen und TLS-RPT-Berichte an eine Postfachadresse leiten."),
            ],
            "verify": "$ dig +short TXT _mta-sts.junkerwerk.de    # erwartet: v=STSv1; id=...\n$ curl -s https://mta-sts.junkerwerk.de/.well-known/mta-sts.txt",
            "policy": "SP-DNS-008",
        },
        {
            "id": "VS-2026-009", "cat": "D", "status": "gelb", "urgency": "In Kürze",
            "title": "TLS-Konfiguration des Zwei-Faktor-Portals: 3DES-Cipher, kein TLS 1.3, HSTS nur einen Tag, HTTP-Kompression aktiv",
            "affected": "openotp.junkerwerk.de und openotp.junkerwerk.hu (217.243.248.30), Port 443",
            "source": "aktiv (testssl.sh, httpx)",
            "scale": "hygiene", "level": "mittel",
            "found": "Das Portal bietet ausschließlich TLS 1.2 an (kein TLS 1.3) und akzeptiert drei 3DES-Cipher-Suiten (SWEET32, CVE-2016-2183). Der HSTS-Header ist auf 86.400 Sekunden gesetzt, also einen Tag statt der empfohlenen zwölf Monate. Antworten werden komprimiert (gzip), was bei Seiten mit Sitzungsgeheimnissen BREACH-Angriffe begünstigt. Zertifikat und Schlüssel sind in Ordnung (RSA 4096, Sectigo, gültig bis 11.12.2026).",
            "evidence": "testssl.sh openotp.junkerwerk.de:443\n TLS 1.3    not offered\n Triple DES Ciphers / IDEA   offered\n  xc012 ECDHE-RSA-DES-CBC3-SHA, x16 EDH-RSA-DES-CBC3-SHA, x0a DES-CBC3-SHA\n SWEET32    VULNERABLE, uses 64 bit block ciphers\n BREACH     potentially NOT ok, \"gzip\" HTTP compression detected\n Strict Transport Security   86400 s = 1 day is too short",
            "threat": {"cves": ["CVE-2016-2183 (SWEET32, Basiswert 7.5 laut NVD; praktische Ausnutzung erfordert Netzposition und lange Sitzungen)"], "kev": "nein", "note": "Fremdbewertung; eigene Einstufung Hygiene mittel, da keine Ausnutzung ohne Man-in-the-Middle"},
            "impact": "Das Portal nimmt Anmeldedaten und Einmalcodes entgegen. Schwache Cipher und kurzes HSTS erleichtern Downgrade- und Abhörangriffe in fremden Netzen (Hotel, Mobilfunk), also genau dort, wo Zwei-Faktor-Portale genutzt werden.",
            "recommendation": [
                ("In Kürze", "3DES-Suiten aus der Apache-SSLCipherSuite entfernen, TLS 1.3 aktivieren, HSTS auf max-age=31536000 setzen."),
                ("Mittelfristig", "Kompression für dynamische Seiten des Portals deaktivieren; Cipher-Liste auf AEAD-Suiten mit Forward Secrecy beschränken."),
            ],
            "verify": "$ openssl s_client -connect openotp.junkerwerk.de:443 -cipher 'DES-CBC3-SHA'   # erwartet: handshake failure\n$ openssl s_client -connect openotp.junkerwerk.de:443 -tls1_3                  # erwartet: Verbindung\n$ curl -sI https://openotp.junkerwerk.de/ | grep -i strict-transport         # erwartet: max-age>=31536000",
            "policy": "SP-TLS-002 / SP-HDR-004",
        },
        {
            "id": "VS-2026-010", "cat": "D", "status": "gelb", "urgency": "In Kürze",
            "title": "Zertifikat passt nicht zum Hostnamen openotp.junkerwerk.hu",
            "affected": "openotp.junkerwerk.hu (CNAME auf openotp.junkerwerk.de, 217.243.248.30)",
            "source": "aktiv (httpx, testssl.sh, Lauf 3)",
            "scale": "hygiene", "level": "hoch",
            "found": "Der Hostname openotp.junkerwerk.hu zeigt per CNAME auf das deutsche Portal. Der Server liefert dafür das Zertifikat *.junkerwerk.de aus, das den ungarischen Namen nicht abdeckt. Jeder Browser zeigt beim Aufruf eine Zertifikatswarnung.",
            "evidence": "httpx openotp.junkerwerk.hu:443\n subject_cn: *.junkerwerk.de   subject_an: [*.junkerwerk.de, junkerwerk.de]\n sni: openotp.junkerwerk.hu   mismatched: true\ntestssl: cert_trust  HIGH  (hostname mismatch)",
            "threat": None,
            "impact": "Nutzer eines Anmeldeportals, die Zertifikatswarnungen gewohnheitsmäßig wegklicken, erkennen einen echten Man-in-the-Middle-Angriff nicht mehr. Für ein Zwei-Faktor-Portal ist das eine schwerwiegende Gewöhnung.",
            "recommendation": [
                ("In Kürze", "Entweder ein Zertifikat mit Subject Alternative Name openotp.junkerwerk.hu ausrollen oder den .hu-Hostnamen abschalten und die Nutzer auf openotp.junkerwerk.de leiten."),
            ],
            "verify": "$ openssl s_client -connect openotp.junkerwerk.hu:443 -servername openotp.junkerwerk.hu </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName   # erwartet: enthält openotp.junkerwerk.hu",
            "policy": "SP-TLS-004",
        },
        {
            "id": "VS-2026-011", "cat": "D", "status": "gelb", "urgency": "Mittelfristig",
            "title": "Content-Security-Policy des Zwei-Faktor-Portals erlaubt Inline-Skripte; doppelte Header; Login-Formular ohne Anti-CSRF-Token",
            "affected": "openotp.junkerwerk.de und openotp.junkerwerk.hu, u. a. /openid/login_uid.php, /selfdesk/",
            "source": "aktiv (Header-Prüfung, OWASP ZAP passiv)",
            "scale": "hygiene", "level": "mittel",
            "found": "Die CSP des Portals enthält 'unsafe-inline' und 'unsafe-eval' für alle Quellen und hebt damit ihren Schutz gegen eingeschleuste Skripte weitgehend auf. X-Frame-Options und Cache-Control werden doppelt gesendet (Browser verhalten sich dann uneinheitlich). Das Login-Formular trägt kein Anti-CSRF-Token.",
            "evidence": "Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: www.google.com ...\nZAP: Multiple X-Frame-Options Header Entries (https://openotp.junkerwerk.de/)\nZAP: Absence of Anti-CSRF Tokens (https://openotp.junkerwerk.de/openid/login_uid.php)",
            "threat": None,
            "impact": "Für sich genommen keine ausnutzbare Schwachstelle. Sollte im Portal oder einem seiner Plugins eine Cross-Site-Scripting-Lücke auftreten, verhindert die aktuelle CSP nichts. Bei Anmeldeportalen zählt die Tiefe der Verteidigung.",
            "recommendation": [
                ("Mittelfristig", "CSP mit Nonces oder Hashes statt 'unsafe-inline'/'unsafe-eval'; Header-Dubletten in der Apache- bzw. WebADM-Konfiguration bereinigen."),
                ("Mittelfristig", "Anti-CSRF-Token im Login-Formular und SameSite-Attribut für Sitzungs-Cookies (Herstellerkonfiguration RCDevs prüfen)."),
            ],
            "verify": "$ curl -sI https://openotp.junkerwerk.de/ | grep -ic x-frame-options    # erwartet: 1\n$ curl -sI https://openotp.junkerwerk.de/ | grep -i content-security-policy | grep -c unsafe   # erwartet: 0",
            "policy": "SP-CSP-001 / SP-CSRF-001",
        },
        {
            "id": "VS-2026-012", "cat": "D", "status": "gelb", "urgency": "Mittelfristig",
            "title": "Veraltete Protokolle TLS 1.0 und 1.1 auf dem RD-Gateway-Host, kein Downgrade-Schutz",
            "affected": "217.243.248.29 (cloud., team., rdgw., rdgw-2016.junkerwerk.de), Ports 443 und 8443",
            "source": "aktiv (testssl.sh)",
            "scale": "hygiene", "level": "mittel",
            "found": "Der Server bietet neben TLS 1.2 und 1.3 auch TLS 1.0 und 1.1 an, die seit 2021 als unsicher gelten (RFC 8996). Unter TLS 1.0 sind CBC-Cipher aktiv (BEAST-Muster, in modernen Clients abgemildert). TLS_FALLBACK_SCSV wird nicht unterstützt, HSTS fehlt. testssl-Gesamtnote B.",
            "evidence": "testssl.sh cloud.junkerwerk.de:443\n TLS 1      offered (deprecated)\n TLS 1.1    offered (deprecated)\n TLS_FALLBACK_SCSV   Downgrade attack prevention NOT supported\n Strict Transport Security   not offered\n Grade capped to B. TLS 1.1 offered",
            "threat": None,
            "impact": "Verbindungen älterer Clients können auf schwache Protokolle heruntergestuft werden. Bei einem Remote-Desktop-Gateway betrifft das die Sitzungen der Mitarbeitenden von außerhalb.",
            "recommendation": [
                ("Mittelfristig", "TLS 1.0 und 1.1 serverseitig deaktivieren (SCHANNEL-Registrierung oder IIS Crypto), Cipher-Reihenfolge auf AEAD-Suiten mit Forward Secrecy setzen."),
                ("Mittelfristig", "HSTS aktivieren, sobald alle Hostnamen dauerhaft HTTPS liefern."),
            ],
            "verify": "$ openssl s_client -connect cloud.junkerwerk.de:443 -tls1     # erwartet: handshake failure\n$ openssl s_client -connect cloud.junkerwerk.de:443 -tls1_1   # erwartet: handshake failure",
            "policy": "SP-TLS-001",
        },
        {
            "id": "VS-2026-013", "cat": "D", "status": "blau", "urgency": "Mittelfristig",
            "title": "Sicherheits-Header auf Outlook Web App und IIS-Server nicht gesetzt",
            "affected": "mail., outlook., autodiscover.junkerwerk.de (217.243.248.28); cloud.junkerwerk.de (217.243.248.29)",
            "source": "aktiv (Header-Prüfung, OWASP ZAP passiv)",
            "scale": "hygiene", "level": "niedrig",
            "found": "Keiner der sieben geprüften Sicherheits-Header (HSTS, X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, Referrer-Policy, Permissions-Policy, X-XSS-Protection) ist auf den OWA-Hostnamen und dem IIS-Server gesetzt. Microsoft unterstützt HSTS für Exchange seit 2019 CU14 offiziell.",
            "evidence": "$ curl -sI https://mail.junkerwerk.de/\nHTTP/1.1 302  Location: https://mail.junkerwerk.de/owa/\nServer: Microsoft-IIS/10.0   X-FEServer: EXCHANGE-SE\n(keine Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options)\nSecurity-Header-Score: 0/7 (mail, outlook, autodiscover, cloud)",
            "threat": None,
            "impact": "Ohne HSTS kann eine erste HTTP-Anfrage in fremden Netzen umgeleitet werden; ohne Framing-Schutz sind Clickjacking-Szenarien auf der OWA-Anmeldeseite möglich. Insgesamt geringe Auswirkung, aber schnell umsetzbar.",
            "recommendation": [
                ("Mittelfristig", "Auf dem Exchange-Server HSTS nach Microsoft-Anleitung aktivieren; X-Content-Type-Options: nosniff und X-Frame-Options: SAMEORIGIN in IIS auf beiden Servern setzen."),
            ],
            "verify": "$ curl -sI https://mail.junkerwerk.de/owa/ | grep -i strict-transport-security    # erwartet: max-age>=31536000",
            "policy": "SP-HDR-001",
        },
        {
            "id": "VS-2026-014", "cat": "E", "status": "blau", "urgency": "Mittelfristig",
            "title": "Versions- und Systeminformationen in Antwort-Headern und Bannern; HTTP TRACE aktiv",
            "affected": "217.243.248.28 (X-FEServer, Server), 217.243.248.29 (Server, X-Powered-By, TRACE), 217.243.248.30 (Exim-Banner), 188.40.3.130 (Dienst-Banner)",
            "source": "aktiv (Header-Prüfung, nmap), Shodan",
            "scale": "hygiene", "level": "niedrig",
            "found": "Die Server nennen Produkt und Version (Microsoft-IIS/10.0, ASP.NET, Exim 4.96, OpenSSH 9.2p1) und der Exchange-Server verrät mit X-FEServer seinen internen Hostnamen EXCHANGE-SE. Auf 217.243.248.29 ist die HTTP-Methode TRACE aktiv.",
            "evidence": "Server: Microsoft-IIS/10.0   X-Powered-By: ASP.NET   X-FEServer: EXCHANGE-SE\nnmap 217.243.248.29: http-methods: Potentially risky methods: TRACE\n220 archiv.junkerwerk.de ESMTP Exim 4.96",
            "threat": None,
            "impact": "Erleichtert Angreifern die Vorbereitung (Auswahl passender Exploits, Namensschema interner Systeme). Kein direktes Risiko.",
            "recommendation": [
                ("Mittelfristig", "Server-Header und X-Powered-By in IIS entfernen (Request Filtering, URL Rewrite), X-FEServer per Rewrite-Regel unterdrücken, TRACE in IIS deaktivieren, Exim-Banner ohne Version (smtp_banner)."),
            ],
            "verify": "$ curl -sI https://cloud.junkerwerk.de/ | grep -iE 'server:|x-powered-by'    # erwartet: keine Versionsangabe",
            "policy": "SP-DISC-001",
        },
        {
            "id": "VS-2026-015", "cat": "E", "status": "blau", "urgency": "Strategisch",
            "title": "DNS-Zonen ohne DNSSEC-Signatur und ohne CAA-Record",
            "affected": "junkerwerk.de, junkerwerk.hu (Nameserver united-domains)",
            "source": "aktiv (DNS-Abfragen)",
            "scale": "hygiene", "level": "niedrig",
            "found": "Beide Zonen sind nicht DNSSEC-signiert; es gibt keinen CAA-Record, der festlegt, welche Zertifizierungsstellen Zertifikate für die Domains ausstellen dürfen.",
            "evidence": "$ dig +dnssec SOA junkerwerk.de   ->  kein RRSIG, ad-Flag fehlt\n$ dig CAA junkerwerk.de           ->  (leer)",
            "threat": None,
            "impact": "Gering. DNSSEC schützt vor gefälschten DNS-Antworten (relevant für E-Mail-Umleitung), CAA verhindert die unbemerkte Ausstellung von Zertifikaten durch fremde Stellen.",
            "recommendation": [
                ("Strategisch", "DNSSEC beim Registrar united-domains aktivieren; CAA-Record für die genutzte Zertifizierungsstelle (Sectigo, ggf. Let's Encrypt) setzen."),
            ],
            "verify": "$ dig +dnssec SOA junkerwerk.de | grep -c RRSIG    # erwartet: >=1\n$ dig +short CAA junkerwerk.de                     # erwartet: 0 issue \"sectigo.com\"",
            "policy": "SP-DNS-001",
        },
    ],

    # ------------------------------------------------------------------
    # Anhänge
    # ------------------------------------------------------------------
    "appendix": {
        "exposure_scale": [
            {"l": "kritisch", "t": "Dienst, der nicht an das öffentliche Interface gehört (Datenbanken, Verwaltungsoberflächen, Fernwartung) und aus dem Internet erreichbar ist."},
            {"l": "erhöht", "t": "Dienst mit legitimem Zweck, aber ohne erkennbare Zugriffsbeschränkung oder mit ungeklärter Funktion."},
        ],
        "cve_refs": [
            {"cve": "CVE-2016-2183", "name": "SWEET32 (3DES-Cipher-Suiten)", "score": "7.5", "src": "NVD", "ref": "VS-2026-009", "note": "praktische Ausnutzung erfordert Man-in-the-Middle und lange Sitzungen"},
            {"cve": "CVE-2023-42115", "name": "Exim AUTH Out-of-bounds Write", "score": "9.8", "src": "ZDI / NVD", "ref": "VS-2026-004", "note": "versionsbasierte Zuordnung, Distributions-Backport nicht ausgeschlossen"},
        ],
        "hygiene_scale": [
            {"l": "hoch", "t": "Abweichung mit direktem Bezug zu Anmeldedaten, Authentizität oder Zugangswegen; zeitnah beheben."},
            {"l": "mittel", "t": "Abweichung, die Angriffe erleichtert oder Schutzmechanismen aushebelt; im nächsten Wartungszyklus beheben."},
            {"l": "niedrig", "t": "Best-Practice-Abweichung ohne unmittelbare Auswirkung; bei Gelegenheit beheben."},
        ],
        "triage": [
            {"l": "Rot", "st": "rot", "t": "Akutes Risiko, das ohne Vorbedingungen ausnutzbar ist oder einen kritischen Dienst exponiert. Dringlichkeit: Unverzüglich (24 bis 72 Stunden)."},
            {"l": "Gelb", "st": "gelb", "t": "Handlungsbedarf mit erkennbarem Angriffsweg. Dringlichkeit: In Kürze (1 bis 2 Wochen) oder Mittelfristig (nächster Wartungszyklus)."},
            {"l": "Blau", "st": "blau", "t": "Verbesserung ohne akutes Risiko. Dringlichkeit: Mittelfristig oder Strategisch (laufendes Quartal)."},
            {"l": "Grün", "st": "gruen", "t": "Positiver Befund: Schutzmaßnahme vorhanden und wirksam."},
        ],
        "inventory": [
            {"host": "188.40.3.130", "port": "21", "svc": "FTP (ProFTPD, TLS erzwungen)", "ref": "VS-2026-005"},
            {"host": "188.40.3.130", "port": "22", "svc": "SFTP (ProFTPD mod_sftp)", "ref": "kein Befund"},
            {"host": "188.40.3.130", "port": "80", "svc": "HTTP (Apache), Weiterleitung auf www.junkerwerk.com", "ref": "kein Befund"},
            {"host": "188.40.3.130", "port": "110", "svc": "POP3 (Courier, STLS)", "ref": "VS-2026-005"},
            {"host": "188.40.3.130", "port": "143", "svc": "IMAP (Dovecot, STARTTLS, LOGINDISABLED)", "ref": "VS-2026-005"},
            {"host": "188.40.3.130", "port": "222", "svc": "SSH (OpenSSH 9.2p1)", "ref": "kein Befund"},
            {"host": "188.40.3.130", "port": "443", "svc": "HTTPS (Apache), www.junkerwerk.de u. a.", "ref": "nicht geprüft"},
            {"host": "188.40.3.130", "port": "465", "svc": "SMTPS (Exim)", "ref": "kein Befund"},
            {"host": "188.40.3.130", "port": "587", "svc": "SMTP Submission (Exim, STARTTLS)", "ref": "kein Befund"},
            {"host": "188.40.3.130", "port": "993", "svc": "IMAPS", "ref": "kein Befund"},
            {"host": "188.40.3.130", "port": "995", "svc": "POP3S", "ref": "kein Befund"},
            {"host": "188.40.3.130", "port": "3306", "svc": "MariaDB 10.11.18", "ref": "VS-2026-001"},
            {"host": "188.40.3.130", "port": "5432", "svc": "PostgreSQL (Version unbekannt)", "ref": "VS-2026-001"},
            {"host": "217.243.248.28", "port": "443", "svc": "HTTPS Outlook Web App (Exchange SE, IIS 10.0)", "ref": "VS-2026-013, VS-2026-014"},
            {"host": "217.243.248.28", "port": "25", "svc": "SMTP (passiv, Shodan 30.08.)", "ref": "kein Befund"},
            {"host": "217.243.248.28", "port": "4433", "svc": "SonicWall-Webinterface (passiv, Shodan 30.08.)", "ref": "VS-2026-002"},
            {"host": "217.243.248.29", "port": "443", "svc": "HTTPS IIS 10.0 (Standardseite)", "ref": "VS-2026-003, VS-2026-012"},
            {"host": "217.243.248.29", "port": "8443", "svc": "HTTPS IIS 10.0 (Standardseite)", "ref": "VS-2026-003"},
            {"host": "217.243.248.30", "port": "443", "svc": "HTTPS Apache, RCDevs WebADM/OpenOTP", "ref": "VS-2026-009 bis 011"},
            {"host": "217.243.248.30", "port": "25", "svc": "SMTP Exim 4.96 (passiv, Shodan 30.08.)", "ref": "VS-2026-004"},
            {"host": "217.243.248.27", "port": "keine", "svc": "keine erreichbaren Dienste", "ref": "kein Befund"},
            {"host": "2a01:4f8:d0a:3124::2", "port": "keine", "svc": "nicht geprüft (IPv6)", "ref": "kein Befund"},
        ],
        "tools": [
            {"t": "nmap", "u": "Portscan Top-1000 TCP, Dienst- und Versionserkennung", "c": "hoch (Dienste), mittel (Versionen)"},
            {"t": "testssl.sh", "u": "TLS-Protokolle, Cipher, Zertifikate, bekannte TLS-Schwachstellen", "c": "hoch"},
            {"t": "httpx, header_check", "u": "HTTP-Antworten, Technologien, Sicherheits-Header je virtuellem Host", "c": "hoch"},
            {"t": "OWASP ZAP (passiv, Spider)", "u": "Passive Analyse von Antworten, Formularen, Headern", "c": "mittel"},
            {"t": "feroxbuster", "u": "Verzeichnis- und Datei-Enumeration", "c": "mittel"},
            {"t": "webtech, wafw00f", "u": "Web-Technologien, WAF-Erkennung", "c": "mittel"},
            {"t": "dnsx, subfinder, gobuster, Certspotter, SecurityTrails", "u": "Subdomain-Ermittlung, DNS-Auflösung, DNS-Sicherheitsrecords", "c": "hoch"},
            {"t": "Shodan, AbuseIPDB, OTX, URLhaus", "u": "Passive Dienst- und Reputationsdaten", "c": "mittel (Passivquelle, Zeitversatz)"},
        ],
        "filtering": (
            "In den drei Durchgängen erzeugten die Werkzeuge 211 Rohmeldungen. Nach Zusammenführung "
            "gleicher Meldungen mehrerer Werkzeuge und Läufe (68 Doppelmeldungen), Prüfung gegen die "
            "Rohdaten und Bündelung nach Sachverhalt verbleiben 15 Befunde und 8 positive Feststellungen. "
            "Verworfen wurden insbesondere: Klartext-Meldungen für Dienste mit TLS-Zwang, EOL-Meldungen "
            "aufgrund fehlinterpretierter Versionsstrings (MariaDB-Kompatibilitätspräfix, „9.6.0 or later“) "
            "sowie versionsbasierte CVE-Zuordnungen zu Distributionspaketen. Die vollständigen "
            "Werkzeugausgaben liegen vor und werden auf Anfrage bereitgestellt."
        ),
        "repeat": [
            "Nachprüfung der Sofortmaßnahme (VS-2026-001) nach Umsetzung, gezielt auf die betroffenen Ports.",
            "Wiederholung des Perimeter-Scans nach Abschluss der Maßnahmen „In Kürze“, spätestens in 12 Monaten.",
            "Zusätzlich nach jeder größeren Änderung der Zugangs-Infrastruktur (Firewall-Wechsel, neues Gateway, Exchange-Migration) und bei jedem Verdacht auf einen Vorfall.",
            "Aufnahme von www.junkerwerk.com und der IPv6-Adresse in den nächsten Scan; Freischaltung der Scanner-Adresse beim Hoster, damit die Website auf Applikationsebene geprüft werden kann.",
        ],
        "disclaimer": (
            "Dieser Bericht bildet den von außen sichtbaren Zustand der genannten Systeme am 31.08.2026 ab. "
            "Er beruht auf automatisierten Prüfungen ohne Zugangsdaten und ersetzt weder einen manuellen "
            "Penetrationstest noch eine Konfigurationsprüfung mit Administratorrechten. Bereits am Folgetag "
            "können neue Schwachstellen bekannt werden oder Konfigurationen sich ändern. Aussagen aus "
            "Passivquellen sind als solche gekennzeichnet und nicht durch eigene Messung bestätigt. Die "
            "Vectigal GmbH übernimmt keine Gewähr für Vollständigkeit; die Umsetzung der Empfehlungen liegt "
            "in der Verantwortung des Auftraggebers und seiner Dienstleister. Der Bericht ist vertraulich "
            "und ausschließlich für den Auftraggeber bestimmt."
        ),
    },
}

CATEGORY_NAMES = {c["key"]: c["name"] for c in DATA["glance"]["categories"]}
