# 09 Gegenlesen der Scan-Runde vom 23.09.2026 (Claude)

Grundlage: die sieben Perimeter-Aufträge der Scan-Runde, alle mit Engine `catalog`, Layout `v3`, Gate `strict`, Prüfkatalog 2026-09-23.2, Faktenschema 1.0.4, jeweils Version 1 in `pending_review`. PDFs und Rohdaten (`/api/orders/:id`, `/results`, `/findings`, `/events`) liegen lokal unter `report-prototype/out/` und `out/scanrunde-2026-09-23/<id8>/` (gitignored, Kundendaten). Maßstab wie in spec/08: Würde ein IT-Leiter oder ein Hoster beim Lesen den Bericht anzweifeln?

Vorgehen: Jeder Bericht wurde vollständig gelesen (Text und alle Seiten visuell), jede Aussage gegen `results.json` und `findings.json` geprüft. Sechs Berichte hat je ein Prüfagent nach einheitlichem Raster gelesen, lumbeck-wolter Claude selbst. Die tragenden Aussagen hat Claude an den Rohdaten nachgeprüft: Zertifikatsablauf castenow, CAA castenow, AbuseIPDB heuel, leere nmap-Ausgaben bergersysteme, wpscan-Kernversion dortmund-beach, gobuster/dnsx lumbeck-wolter, MariaDB/PostgreSQL-Lesung lumbeck-wolter, DMARC lumbeck-wolter.

| Kürzel | Auftrag | Ziel | Seiten | Befunde | Positiv | Gate (Fehler/Warnungen) | ohne Regel | Gesamt |
|---|---|---|---|---|---|---|---|---|
| DB | 1fbc92b9 | dortmund-beach.com | 24 | 13 | 4 | 0/1 (Seite 23 halbleer) | 1 | MITTEL |
| LW | c3d5724c | lumbeck-wolter.de | 15 | 6 | 5 | 0/0 | 2 | HOCH |
| JW | 31d67a02 | junkerwerk.de, junkerwerk.hu | 26 | 15 | 4 | 0/0 | 4 | HOCH |
| HE | 3cf01f8d | huendgen-entsorgung.de | 19 | 10 | 7 | 0/0 | 3 | MITTEL |
| BS | 68d59573 | bergersysteme.com | 24 | 12 | 5 | 0/2 (6 ohne Regel, Seite 23 halbleer) | 6 | MITTEL |
| CA | 1f8bc977 | castenow.de | 33 | 20 | 9 | 0/1 (Seite 32 halbleer) | 3 | MITTEL |
| HL | 2e56abe1 | heuel.com | 23 | 11 | 6 | 0/0 | 3 | MITTEL |

## Ergebnis in drei Sätzen

Die S6- und S6a-Korrekturen halten: eine Abbildungstabelle für Ampel und Dringlichkeit, Rot nur bei Exposition kritisch, ZAP-Meldungen mit Konfidenz Low überwiegend im Anhang, befundspezifische nmap-Nachweise ohne Python-Darstellungen, Berichtsnummer stabil, DKIM ohne Selektor „nicht prüfbar", RDP/SMB-Positivbefund mit neuem Titel und korrektem Wegfall. Kein Bericht ist trotzdem in dieser Form auslieferbar: die Discovery verliert in sechs von sieben Aufträgen Hostnamen, Rollen und Prosa unterstellen Mail- und Kalenderplattformen, die es nicht gibt, Textbausteine je Bündel behaupten mehr als die getroffene Regel, und Hosts ohne ein einziges Messergebnis gelten als vollständig geprüft. Keiner dieser Punkte ist ein Renderer-Problem; sie liegen in Discovery, Faktenbildung, Katalogtexten und Reportdaten und brauchen Fixtures aus genau diesen sieben Aufträgen.

Keinen der sieben Berichte freigeben. Nach S6b `requeue-report` für alle sieben (gleiche Fakten, neue Texte), nach den Scanner-Korrekturen eine zweite Scan-Runde gegen dieselben Ziele.

## Teil 1: Querschnittsbefunde (in mindestens drei Berichten)

Priorität P1: falsche oder widersprüchliche Aussage im Kundentext oder falscher Prüfumfang, vor jeder Auslieferung beheben. P2: Darstellung oder Vollständigkeit, in S6b. P3: später.

### Q1 Discovery verliert Hostnamen (Scanner, P1)
gobuster_dns läuft in allen sieben Aufträgen nach 180 s in den Timeout. Die Teilausgabe hat das Format `fqdn ip,ip`; sie geht ungeparst an dnsx, dnsx fragt die ganze Zeile als Namen ab und meldet NXDOMAIN (Beleg LW: dnsx `"host": "eset.lumbeck-wolter.de 85.22.176.108"`, Antwort SOA der Root-Zone). Verloren:
- LW: eset.lumbeck-wolter.de (85.22.176.108, liegt im SPF-Netz `ip4:85.22.176.0/24`, also Kundennetz), ftp.lumbeck-wolter.de (217.160.231.158).
- JW: archiv.junkerwerk.de (217.243.248.30, neben .28 und .29).
- HE: ftp.huendgen-entsorgung.de (87.79.4.40), ftp.mail.huendgen-entsorgung.de (217.160.231.238). Das ist der FTP-Fall, gegen den die S6a-Regressionssperre #30 gebaut wurde; er kam in Produktion gar nicht an.
- BS: 24 Namen, darunter adfs (62.217.52.170), api, cloud, files und 19 ecom-Namen; discovery_health zählt 42 Subdomains, der Bericht nennt 11 Hostnamen.
- HL: as2.heuel.com (194.25.29.98, eigene Adresse), control.heuel.com.
- CA: nur autodiscover (Microsoft), bitwarden kam über subfinder.
`discovery_health` meldet `tools_with_zero_results: []` und warnt nicht.
Korrektur: erstes Feld parsen, Teilausgabe bei Timeout übernehmen, Timeout-Fixture; Gate-Warnung, wenn gefundene FQDNs nicht im Host-Inventar ankommen; gobuster_dns bei Wildcard-DNS überspringen (DB).

### Q2 Rollen und Prosa erfinden Mail-, Kalender- und Datenbanksysteme (Reportdaten, Prosa, P1)
Die Rolle „Mail- und Kalenderplattform" samt „Über dieses System läuft die geschäftliche Korrespondenz" entsteht aus offenen Mailports, obwohl MX, SPF und Autodiscover woanders hinzeigen: LW (MX Hornetsecurity, SPF outlook; der Host ist ein Hetzner Managed Server mit Exim/Dovecot des Hosters), JW (Exchange dem Hetzner-Webserver 188.40.3.130 zugeschrieben, weil zap_spider dort 44 URLs fremder Hosts einsammelte), BS (Plesk-Server als Mailplattform, das eigentliche Exchange 62.217.52.166 und M365 „nicht näher bestimmbar"), CA (ubb-wiki), HL (Hetzner-Webhosting), DB (MX mail1.spacekoelnsrv1.de, anderer Host). „Kalender" hat in keinem Auftrag einen Fakt. „Website und Datenbanken" und „Fernzugang und Verwaltung" stehen bei Hosts ohne Datenbank- oder Fernzugangsdienst (HE Duda-Plattform, JW .28/.29, CA bitwarden mit Website-Risikotext „Seiteninhalte, Formulareingaben und Kontaktdaten").
Korrektur: Mailrolle nur, wenn MX, SPF-Mechanismus oder Autodiscover auf den Host zeigt; Kalender nur mit Kalender-Fakt; Datenbanken nur mit Datenbankport; eigene Rollen für Passwortverwaltung, Kollaboration, Mail-Webzugang, Anmeldeportal; die Prosa-KI bekommt nur belegte Rollen.

### Q3 Geteilte Systeme werden als Kundensystem bewertet und aktiv geprüft (Scanner und Katalog, P1, Entscheidung DC)
Hetzner Managed Server mit Fremddomains (LW dedi5705 mit flott.de; JW 188.40.3.130 mit erbbauverein.de; HL www51.your-server.de mit help-ev.de), Plesk-Sammelserver (CA ubb-wiki auf 92.205.163.53 mit netscope-media.de und dem Shoutcast-Stream tonausstrom.de auf 8000/8001; BS 92.205.224.174 mit dirak.de), Plattformen und CDN (HE Duda/multiscreensite; BS Cloudflare 198.202.211.1; CA CloudFront von umfrageonline.com; HL Vercel und IONOS-Ingress). Folgen: Befunde auf Serverebene, die der Kunde nicht beheben kann (Plesk, FTP, Mailports des Hosters), Cloudflare-Standardports 2083/2087/8880 als „Verwaltungsoberfläche von www" (BS VS-003), und bei CA lief zap_active (sqli, xss, lfi, cmdi) 730 s gegen Shoutcast und Plesk fremder Kunden. Freigegeben war die Adresse, weil ein Kunden-Hostname auf sie zeigt, nicht die Dienste anderer Kunden auf derselben Adresse.
Korrektur: Fakt „geteiltes System" aus fremden Namen in Zertifikaten und Shodan, rDNS des Hosters, CNAME auf SaaS, AbuseIPDB `usageType`; Befunde auf solchen Hosts als „beim Hoster/Plattformbetreiber" mit Empfehlung an den Betreiber; aktive Prüfung nur gegen die VHosts des Kunden. Entscheidung E3.

### Q4 Textbausteine je Bündel statt je Regel (Katalogtexte, P1, umfasst spec/08 Punkt 15)
Der Text eines Bündels behauptet, was eine andere Regel des Bündels meinen würde:
- „unveränderte Auslieferungsseite des Herstellers" ohne Titel- oder Body-Fakt: HE 444 (Titel „Hündgen Entsorgungs GmbH & Co. KG Web Applications Po…") und 8443 (403), CA 8000 (Shoutcast), HL 8443 (FortiOS ohne Titel).
- „lässt veraltete Protokolle und Verfahren zu", „kann eine schwächere Verbindung erzwingen" bei `tls_no_13`, BREACH oder LUCKY13, während der eigene Nachweis nur TLS 1.2/1.3 zeigt: DB, BS, CA, HL. BREACH auf einer 301 oder statischen Seite (testssl: „Can be ignored for static pages") hängt bei CA sogar als CVE an einem Zertifikatsbefund.
- CA VS-019 „fehlen Einträge, die … die Ausstellung eingrenzen": CAA ist vorhanden (`issue "sectigo.com"`, `"amazonaws.com"`, `issuewild "sectigo.com"`), getroffen hat nur `dnssec_missing`.
- HE VS-001 „Abgelaufene Zertifikate erneuern und die vollständige Vertrauenskette hinterlegen": testssl `Chain of trust Ok`, einziger Fakt „läuft in 17 Tagen ab"; die Prosa übernimmt die falsche Kette.
- DMARC-Text: „nicht durchsetzend", „wirkungslos", „Rückmeldungen erreichen Sie nicht", Maßnahme „Richtlinie mit Meldeadresse veröffentlichen" bei `p=quarantine` (HE, HL) oder vorhandener `rua` (DB, BS, CA, HL); bei fehlendem DMARC (LW, JW) lautet der Titel trotzdem „nicht durchsetzend" (Rest von spec/08 Punkt 6).
- `legacy_protocols_present`: „Ob eine Verschlüsselung erzwungen wird, zeigt diese Prüfung nicht" neben „TLS erzwungen=ja" im eigenen Nachweis und dem Positivbefund „Datei- und Mailzugänge erzwingen TLS" (LW, JW, HL).
- `service_banner_version`: SSH-Banner und MariaDB-Handshake gehören zum Protokoll und lassen sich nicht entfernen; „PostgreSQL unbekannt" ist keine Versionspreisgabe; „nicht benötigte Methoden" ohne Methoden-Fakt (LW, JW, BS, CA, HL); JW „TRACE aktiv" nur aus der OPTIONS-Antwort.
- „Formularschutz" im Titel ohne Formular-Fakt, „doppelte Header bereinigen" ohne doppelte Header (alle mit Header-Befund).
- `dane_missing` feuert in allen sieben, obwohl der MX in einer fremden Zone liegt (Hornetsecurity, spacekoelnsrv1.de) und die Kundenzone nicht signiert ist; der Kunde kann das nicht umsetzen.
Korrektur: Titel, Befundtext, Auswirkung und Empfehlung je getroffener Regel zusammensetzen; ein Bündel gruppiert nur. Vorbedingungen: `dane_missing` nur bei MX in eigener, signierter Zone; `dmarc_policy_weak` nur mit DMARC, eigener Text für quarantine; `http_alt_port` sagt „zusätzlicher Webport, Zweck klären". Jede Textaussage bekommt im Katalog die Fakten-Bedingung, unter der sie stehen darf, und einen Test, der Aussage ohne Fakt als Gate-Fehler meldet.

### Q5 Empfehlungsstaffel beginnt vor der Dringlichkeit des Befunds (Katalog, P1, klein)
Alle sieben: gelbe Befunde „In Kürze" beginnen mit „Unverzüglich:", mittelfristige mit „In Kürze:" (LW nur VS-003; CA neun Befunde). A.1 reserviert „Unverzüglich" für Rot. Korrektur: die erste Empfehlungsstufe ist die Dringlichkeit aus `levels.py`, weitere Stufen relativ; Test über alle Golden-Aufträge.

### Q6 Maßnahmenplan gruppiert nach Priorität und Effekt (Reportdaten, P1, S6a-Nachbesserung)
Der S6a-Fix hat Doppelzeilen bei gleichem Effekt entfernt, gruppiert aber nicht nach Maßnahmentext: gleicher Text in zwei oder drei Zeilen (DB, JW, HE, BS, CA mit drei Header-Zeilen und je zwei Zertifikats- und Protokollzeilen, HL), verschiedene Texte in einer Zeile (alle). Der Effekt „Schützt die Authentizität der eigenen E-Mail" steht in allen sieben bei DNSSEC/CAA; „Verkleinert die Angriffsfläche" bei TLS-Zwang und WordPress-Update (DB). Hebeltitel sind Befundtitel und nennen Hosts, die sie nicht vollständig adressieren (HE Hebel 3, HL Hebel 3).
Korrektur: eine Zeile je Maßnahmentext; Effekt und Hebeltitel je Regel.

### Q7 Nachweis trägt die Behauptung nicht (Reportdaten, P1, Rest spec/08 Punkt 3)
Die SPF/DMARC-Zeile aus dns_records ist in allen sieben der Nachweis für MTA-STS, TLS-RPT, DANE, DNSSEC und CAA, obwohl `dns_security` die tragenden Fakten enthält (`has_dns_record false`, `tlsrpt_present false`, `dnssec_signed false`, `has_caa`). DB VS-003 (WordPress-Kernversion) zeigt die header_check-Zeile statt der wpscan-Version. Kürzung mitten im tragenden Wert: „max-age..." (DB), „Ket..." (HE), „Kette vollstaendig=ne..." (CA), „P..." (CA). Shodan- und nmap-Zeilen doppelt (BS, JW, HL). Rohwerte: „gueltig_bis", „vollstaendig", „Pruefung=", „Pflegestatus=unknown", „Kernstand=outdated", „scan_results:testssl:…", „pre_128cipher" (DB, BS, CA, HL).
Korrektur: Nachweis ist die `evidence` der Fakten der getroffenen Regel, je Fakt eine Zeile, nie im tragenden Feld kürzen; Werte-Übersetzungstabelle mit Umlauten.

### Q8 Sicherheits-Header an Weiterleitung, Fehler- oder Challenge-Seite gemessen (Scanner, P1)
header_check bewertet 301/302 mit `content-length 0`, 403-Seiten und die Vercel-Challenge (429). Folge: falsche Befunde. HE und JW melden für das Outlook-Portal fehlendes X-Frame-Options, die Endseite `/owa/auth/logon.aspx` setzt `SAMEORIGIN`; CA meldet `csp_missing`, `/login/` liefert `frame-ancestors 'self'`; HL VS-004 „unvollständig" bei header_check-Score 7/7; BS bewertet eine 301 und eine 403 als Webseite; DB-Befunde laufen auf den Parking-Host.
Korrektur: header_check folgt Weiterleitungen und bewertet die Endantwort; Header-Regeln nur auf 200 mit HTML; HSTS zusätzlich an der ersten Antwort; Challenge und 4xx ergeben „nicht prüfbar".

### Q9 Hosts ohne Messergebnis gelten als vollständig geprüft; Abdeckungshinweis an falscher Bedingung (Reportdaten, P1, Regression spec/08 Punkt 10)
BS: vier Hosts (62.217.52.162, .166, .171, 79.140.188.181) mit leerer nmap-Ausgabe (nur Kopf- und Fußzeile, 135 Zeichen), testssl `no_ssl`, ZAP `no_zap_context`, header_check `reachable=false`; Bericht: grüner Punkt „Portscan und Tiefenprüfung vollständig". Shodan sah dort am selben Tag Exchange/OWA (.166), Bitwarden (.171) und das Ticketsystem (.162). HL 195.225.241.75 und CA bitwarden sowie umfrage ebenso. Umgekehrt: leerer gelber Kasten „HINWEIS ZUR ABDECKUNG" (DB, HE, CA); CA zählt in Kapitel 2 ffuf_sensitive-Timeouts als Abdeckungslücke („Für 3 Hosts …") und verschweigt, dass für www.castenow.de alle drei ZAP-Läufe ausfielen (`ZAP unreachable at http://zap-3:8090`). BS nennt im Kasten nur die Microsoft-Adresse 40.99.150.120, nicht die vier unerreichten Hosts.
Korrektur: Abdeckungsstatus nur aus nmap (mindestens ein Port), testssl und ZAP; kein Port bei Passivfund jünger als sieben Tage ergibt „vom Prüfstand aus nicht erreichbar" mit Einschränkungszeile, Posture „nicht prüfbar" und Abdeckungshinweis; Kasten nur mit Text rendern. Zum BS-Fall siehe E4.

### Q10 Einschränkungstabelle und TLS-Zuordnung (Reportdaten, P1, Regression spec/08 Punkte 11 und 12)
Eine Zeile je Ursache ist nicht erreicht: JW 15, BS 16, HL 15 Zeilen; die IPv6-Adresse allein in fünf Zeilen (JW, HL), testssl mit einer SNI in drei Zeilen (Protokolle, Verfahren, Zertifikat). Zeilen ohne Prüfungsnamen („Die Werkzeugdaten reichen für eine Aussage zu dieser Prüfung nicht aus", „Werkzeug lief in einen Timeout", „Werkzeug wurde übersprungen") in allen sieben; Werkzeugnamen `ffuf_sensitive`, `zap_spider`, `zap_active` im Kundentext. „TLS-Protokolle lagen nicht vor" und Posture „nicht prüfbar" für Hosts, auf denen testssl vollständig lief, nur mit anderer SNI oder für die zweite A-Adresse (HE www, CA www und mail, HL 217.72.203.132, JW autodiscover). DB „Abgleich mit den Schwachstellendatenbanken ohne Ergebnis" neben „laut wpscan bekannte Schwachstellen: 12".
Korrektur: testssl-Fakten über IP:Port und Zertifikats-SAN an alle VHosts binden; Folgeausfälle einer Wurzelursache unterdrücken; Zeile ohne Prüfungsname ist Gate-Fehler; Text „keine CVSS-Fremdbewertung" statt „ohne Ergebnis".

### Q11 Dashboard-Techniktabelle und Technologietabelle (Reportdaten und Dashboard, P1 für das Dashboard)
Die Hostkarte im Dashboard liest `reports.tech_profiles[].tech_rows`; die baut im Katalogweg noch der alte `reporter/tech_table_builder.py` (`worker.py` um Zeile 1474), nicht die Versionsnormalisierung aus `facts/versions.py`, die das PDF nutzt. Folge LW und JW: „MySQL 5.5.5-10.11.18-MariaDB-0+deb12u1" mit EOL 2018-12-31 (der Präfix `5.5.5-` ist der Kompatibilitätsvorsatz von MariaDB, tatsächlich MariaDB 10.11) und „PostgreSQL DB 9.6.0 or later" mit EOL 2021-11-11 (nmap nennt eine Untergrenze). Das PDF zeigt richtig „MariaDB 10.11.18" und Patch/EOL grün. Der Satz „veraltete PostgreSQL 9.6" im Kasten Host-Strategie stammt aus KI #1 (Haiku), die Shodans „9.6.0 or later" genauso liest.
Im PDF (spec/08 Punkt 17 offen, dazu neu): „jQuery 3.4.1" aus „jQuery Migrate 3.4.1" (DB, CA; liest sich als jQuery vor 3.5 mit bekannter XSS-Lücke); Quelle „webtech" bei Zeilen, die webtech nicht geliefert hat oder wo webtech `no_tech_signals` meldete (LW, JW, HL); Plesk „unbekannt", obwohl nmap „Plesk Obsidian 18.0.80/18.0.81" liefert (BS, CA); Technologien des Weiterleitungsziels beim Ausgangshost (BS, HL, CA umfrage mit Drupal von www).
Korrektur: `tech_rows` im Katalogweg aus den Fakten bauen, `tech_table_builder` nur unter `engine=legacy`; Normalisierung nie über Namensgrenzen; Quelle ist das liefernde Werkzeug; Ergebnisse mit `final_url` auf anderem Host diesem Host zuordnen. Für KI #1: „or later" im Prompt als Untergrenze kennzeichnen (Scanner-KI, eigener kleiner Fix).

### Q12 Positivbefunde ohne tragfähigen Fakt (Katalog, P1)
HL „Keine Einträge in Reputationsquellen": AbuseIPDB meldet für 216.150.1.65 `totalReports 26`, `numDistinctUsers 9`, `lastReportedAt 2026-09-21`, Score 0 nur wegen `isWhitelisted true`. „Web Application Firewall vorhanden … filtert Angriffe" aus der Generic-Heuristik von wafw00f (HE, CA) oder aus der Antwort des Weiterleitungsziels (BS). „✔ Zertifikate unauffällig" für Hosts, deren Mail-TLS nie geprüft wurde und deren nmap selbstsignierte, abgelaufene Plesk-Zertifikate auf 110/143/465/993/995 zeigt (BS). „kein Eintrag zeigt auf ein aufgegebenes Ziel" bei Posture „Verwaiste Einträge entfällt" (DB, LW).
Korrektur: Reputation positiv nur bei `totalReports 0` für alle Adressen, CDN-Adressen ausnehmen und benennen; WAF nur mit benanntem Produkt aus der eigenen Antwort; „unauffällig" nur, wenn alle TLS-Dienste des Hosts geprüft sind; „entfällt" zählt nicht als bestanden.

### Q13 Einstufung von Verwaltungsoberflächen widerspricht A.2 (Katalog, Entscheidung DC)
A.2 definiert „kritisch: Dienst, der nicht an das öffentliche Interface gehört (Datenbanken, Verwaltungsoberflächen, Fernwartung)". Die Regel `admin_service_exposed` vergibt „erhöht": DB Webmin (nmap `Server: MiniServ`, `session_login`; der Bericht zeigt nur nmaps Vermutung `snet-sensor-mgmt?`), BS und CA Plesk mit Anmeldung, JW VS-002 passiv als „Hygiene hoch". Dazu passive Admin-Befunde ohne Fingerabdruck: HL VS-001 (Hebel 1, „Zuerst ist zu klären") auf 4433 nur aus einem Shodan-Banner `Server: xxxx` vom 11.09., im Nachweis mit dem Datum des Host-Updates (23.09.); BS Cloudflare-Ports; CA 8880 als „unbekannt", obwohl der Banner `sw-cp-server` (Plesk) zeigt und derselbe Dienst schon VS-001 ist. Entscheidung E1.

### Q14 ZAP-Meldungen unter Konfidenz High tragen Befunde (Katalog, P1, Regression spec/08 Punkt 2)
`csrf_token_missing` feuert auf „Absence of Anti-CSRF Tokens" mit Konfidenz Low am WordPress-Login (DB, CA) und an Portalen (HL VS-002, VS-004, dort auch „Cross-Domain Misconfiguration" Medium); Quelle als „aktiv (zap_active)" angegeben, obwohl 10202 eine passive Regel ist und `active: 0`. Korrektur: Konfidenzfilter vor der Regelauswertung, Low und Medium nur als Werkzeugmeldung; Quelle „passiv (ZAP)".

### Q15 Firmenname und Kurzname (Reportdaten, P2)
Kurzname in Fußzeile und PDF-Titel: „Hündgen Entsorgungs" (HE, abgeschnitten), „Junkerwerk Linder GmbH + Co." (JW, „KG" fehlt), „Josef Heuel" (HL, liest sich wie eine Person). JW trägt drei Schreibweisen (Deckblatt „GmbH + Co. KG", Fußzeile „GmbH + Co.", 2.1 „GmbH & Co." aus dem AbuseIPDB-Feld `isp`), BS zwei. Firmenname, Mitarbeiterzahl und Branche stehen in keiner exportierten Datei; die Quelle (Recherche-KI oder Kundenkontext) ist im Nachhinein nicht prüfbar (HE „rund 140 Mitarbeitende", CA „45 Mitarbeitenden").
Korrektur: Kurzname als eigenes Feld im Kundenkontext; Rechtsform-Erkennung um „+ Co. KG" und „u. Co."; Quelle jedes Kontextfelds in den Fakten führen; AbuseIPDB-Angaben als „Netzbetreiber laut RIPE" kennzeichnen.

### Q16 Adress- und Hostzuordnung (Scanner und Reportdaten, P2)
testssl prüft bei DNS-Rotation eine andere Adresse als den Host (HE 52.59.120.70 statt 18.197.248.23, CA .123 statt .120, HL 216.150.1.129 statt .65). IPv6-Adressen ohne Route werden über den Hostnamen, also über IPv4, „gemessen" und bekommen eine eigene Technologietabelle (JW, HL). Hostnamen mit IPv4 und IPv6 zählen doppelt (JW „8 Hostnamen" bei 7, HL 12 bei 11). LW hat laut Shodan-DNS AAAA 2a01:4f8:d0a:668b::2, der Bericht erwähnt IPv6 gar nicht, JW und HL führen ihre IPv6-Adresse als Host: uneinheitlich, und dnsx fragt kein AAAA ab. JW: für junkerwerk.hu liefen nur dns_records und dns_security, keine Hostermittlung; der Bericht nennt .hu als geprüfte Angriffsfläche.
Korrektur: Werkzeuge an die IP binden, geprüfte IP ausweisen; ohne IPv6-Route Phase 2 für die Adresse mit Grund überspringen; AAAA aktiv auflösen; Hostnamen eindeutig zählen, IPv4 und IPv6 mit gleichem rDNS als ein System mit zwei Adressen; Discovery je Zieldomain, Prüfumfang je Domain ausweisen.

### Q17 Scanner-Ausfälle und Lücken (Scanner, P1 bis P2)
- Port 25 sieht nmap in keinem Auftrag, Shodan auf mindestens neun Hosts, teils vom selben Tag; 465 und 587 sieht nmap. Vermutlich ausgehende Sperre am Prüfstand (E5).
- Hetzner-Server (`your-server.de`) sperren nach dem vollen Portscan: LW 116.202.77.64, JW 188.40.3.130, HL 213.133.104.51, danach testssl „Can't connect", header_check `reachable=false`, zap_active `url_not_found`. Der Bericht benennt das korrekt, geprüft ist trotzdem nur der Portscan. Vorschlag: Phase 2 vor dem vollen Portscan oder Portscan mit niedrigerer Rate für diese Netze.
- ZAP: `ZAP unreachable` für www.castenow.de ohne zweiten Versuch; zap_active gegen einen 403-VHost (HL edi, 10 s), die eigentliche Anwendung ose.heuel.com/webmodule-ee blieb ungeprüft; zap_spider sammelt hostübergreifend (JW, #27); passive Meldungen 0 auf Hosts mit belegten Header-Lücken (HE, BS), Abholung prüfen.
- testssl nur auf 443 mit einer SNI; FTPS, STARTTLS auf 25/110/143/587 und 465/993/995 sowie weitere HTTPS-Ports (8443, 444) nie geprüft (alle sieben).
- Stille Ausfälle als „ok": header_check `reachable=false`, feroxbuster mit einem Verbindungsfehler (CA bitwarden), nmap mit Status `failed` bei Exit 0 (JW IPv6).
- feroxbuster und ffuf zielen auf die Apex-Weiterleitung statt auf die `final_url` (HE, CA) oder laufen trotz `skip_tools` (BS); ffuf_sensitive schickt eine PHP/CMS-Liste gegen Exchange (HE).
- Exchange-Pfade /ecp, /EWS, /autodiscover nie angefragt (CA, `ai_skip`).

### Q18 Fehlende Lebenszyklus- und Aktualitätslogik (Katalog, P2)
HE: Exchange 2019 Build 15.2.1748 (CU15) mit öffentlichem OWA, Patch/EOL grün; Exchange 2019 hat seit dem 14.10.2025 keinen Herstellersupport, das Datum gehört mit Quelle in den Katalog; für diesen Kunden wäre das Hebel 1. DB: WordPress 6.5.12 hat wpscan `release_date 2026-09-22`, `vulnerabilities []`; der Bericht nennt die Version zweimal „veraltet und unsicher" und „ohne Herstellerpflege (Support beendet 2024-07-16)" (Rest spec/08 Punkt 5). DB: Debian 11 aus `OpenSSH 8.4p1 Debian 5+deb11u7` erkennbar, ohne Abgleich (Ende der LTS gegen endoflife.date prüfen). CA: Zertifikat mailstore.castenow.de läuft am 24.09.2026 23:59 UTC ab (testssl `expires < 30 days (1)`), Einstufung „In Kürze (1 bis 2 Wochen)" (E2).

## Teil 2: Einzelbefunde je Auftrag (nicht in Teil 1)

- DB: Nachweis-URL `wp-json/wp/v2/users` für den Benutzernamen steht in keinem Rohdatum, wpscan fand `badmin` über `/wp-json/oembed/1.0/embed` (ebenso CA); Empfehlung und Verifikation zielen auf den falschen Weg. Bildschirmfoto „pflege.dortmund-beach.com" zeigt die WordPress-Startseite, pflege ist ein froxlor-Parking-Host ohne eigenes Bild; Wildcard `*.dortmund-beach.com` weiter in Hostlisten und VS-004 (Rest spec/08 Punkt 13). Port 443 über die IP zeigt `http-title: froxlor` (zweite Verwaltungsoberfläche, unsicher, ohne Regel). 587 bietet `AUTH PLAIN LOGIN` vor STARTTLS und ist grün.
- LW: VS-001 unterstellt für PostgreSQL „Passwort-Rateangriffe rund um die Uhr"; Shodan-Banner auf 5432 zeigt `FATAL: no pg_hba.conf entry for host`, fremde Quellen werden vor der Anmeldung abgewiesen (ebenso JW). MariaDB liefert dagegen einen Handshake mit `mysql_native_password`. `db_exposed` soll die Ports getrennt beschreiben.
- JW: LUCKY13 nur bei .29 als CVE, testssl meldet es auf .28 ebenso („experimental potentially VULNERABLE"); experimentelle testssl-Meldungen gleich behandeln. Positivbündel RDP/SMB fehlt für .29 ohne Ausschlussgrund (unsicher, Regelstand prüfen). „Datenbankportsträfe" (fehlendes Leerzeichen über den Seitenwechsel).
- HE: 444 ist ein Firmenportal („Web Applications Po…"), nur nmap hat es gesehen; Tiefenprüfung für jeden HTTP(S)-Port, den nmap findet. 18.197.248.23 als Kundensystem mit „nicht benötigte Ports schließen" (Duda-Plattform, Q3).
- BS: VS-003 Cloudflare-Kante als Verwaltungsoberfläche von www; autodiscover-IP 40.99.150.120 (Microsoft) als Host gezählt mit „intern zu klären" statt „Drittanbieter, nicht geprüft" (Grund steht in `ai_host_skip`). Einstufung gleicher Header-Sachverhalt: VS-006 mittel, VS-010 niedrig.
- CA: VS-012 Shoutcast eines Fremdkunden als „Auslieferungsseite"; mailstore liefert nur „Access through untrusted domain" (400), die Einschränkung fehlt; Exchange „nachweislich gepflegte Version" ist nur die Produktlinie (SE RTM aus dem OWA-Pfad), der Patchstand ist nicht sichtbar; AUTO-OVERRIDE wertet die Weiterleitung umfrage auf www als eigenen Inhalt, Nachweis VS-015 zeigt das www-Zertifikat statt CN=umfrage.castenow.de.
- HL: Screenshots „Redirector" für webportal (zweimal) und ose zeigen eine Anmeldemaske; ZAP-Meldungen „Cookie Without Secure Flag" und „Cookie No HttpOnly Flag" an `login.seam` fehlen, „Timestamp Disclosure" gleichrangig steht im Anhang; Werkzeugmeldungen mit falscher Spalte „Betrifft" und englischen Titeln; FortiSSH gegen Shodan `SSH-2.0-WingFTPServer` auf 20.79.218.75:22 (unsicher).

## Teil 3: Darstellung (alle oder fast alle Berichte, P2)

- Kapitel-Kicker („KAPITEL 2 · FÜR DIE IT-LEITUNG") allein am Seitenende, Überschrift auf der Folgeseite; ebenso Tabellenköpfe (JW 2.2, HL Maßnahmenplan) und „ANHANG A". Kicker, Überschrift und Tabellenkopf mit dem Folgeinhalt zusammenhalten; Gate-Prüfung „Kicker ohne Überschrift auf derselben Seite".
- Vierte Posture-Karte und Bildschirmfotos ragen rechts über den Satzspiegel.
- Harter Umbruch vor „Anhang D bis F" erzeugt eine fast leere Seite, oft mit einer einzigen Tabellenzeile (DB 23, BS 23, CA 32, HL 22); dazu halbleere Seiten im Anhang (JW 25, HE 18) und nach Befundkarten, die nach „Was wurde gefunden" umbrechen (CA 17 und 23). Das Gate meldet nur DB, BS und CA 32.
- Deckblatt bricht „Version / 1.0" um; die Version selbst ist S6b-Punkt (Auslieferungsversion).
- rDNS überdruckt in 2.1 die Abdeckungsspalte (BS, CA, HL); IPv6-Adresse bricht mitten in der Adresse um (HL).
- Service-Karte: Legende „Blau: Altprotokoll", blau sind auch 443, 8443, 222 und Webports mit niedrigem Befund; 443 grün trotz VHost-Befunden; Anhang B ohne Befundbezug für VHost-Befunde (alle). Farbe und Befundspalte aus derselben Zuordnung über VHost und Port.
- Numerus und Platzhalter: „Der Host A, B, C bietet seinen Webdienst" (HE, BS, JW), „Der Host den geprüften Hosts bietet" (CA, HL), „Betrifft: den geprüften Hosts" (CA, 15 Zeilen), „(1 Tage)" (CA), „Portscan vollständig; Der Host" (LW, JW, BS).
- Betroffen-Listen mit doppelten Namen je Regel (alle mit Header-Befund), englische Werkzeugmeldungstitel, doppelte Bildschirmfotos (HE Apex und www, HL webportal).

## Teil 4: Beobachtungen ohne Regel (22 in sieben Aufträgen)

- `passive_port_unverified` Port 25 (DB, LW, JW, BS, CA, HL): keine Befundregel, zuerst E5 klären; danach Dienstname aus dem Shodan-Modul (`smtp`) statt „unbekannt" und eine SMTP-Prüfung (STARTTLS, AUTH vor STARTTLS, VRFY) als Regel.
- `passive_port_unverified` auf IPv6 (JW, HL 80/443): keine Regel, über die IPv6-Einschränkung abdecken; die Banner zeigen geteiltes Hosting.
- `passive_port_unverified` auf unerreichten Hosts (BS .162, .166, .171): Regel „Dienst laut Passivquelle, vom Prüfstand nicht erreicht" je Host, zusammen mit Q9.
- `service_unknown_port` (HE 1000/1001/1002 ohne Banner, CA 8001 Shoutcast-Quellport eines Fremdkunden): Prüfung „offener Dienst ohne Kennung" mit Exposition erhöht und Anzeige „nicht identifiziert (Port 1000)" statt nmap-Portname; im Scanner Nachprobe mit `-sV --version-all`; CA über Q3 (fremder Name im Zertifikat).
- Nicht in `unprocessed`, aber in den Rohdaten: wpscan `interesting_findings` (XML-RPC, readme.html, externes WP-Cron), SMTP VRFY, froxlor auf dem Standard-VHost, Session-Cookies ohne Secure und HttpOnly an Login-Seiten. Jeder Werkzeugfund ohne Regel gehört in `unprocessed`, sonst sieht ihn niemand.
- Der Zielwert 5 wurde nur bei BS überschritten; nach Q3 und Q9 blieben dort drei bis vier.

## Teil 5: Was stimmt

- Abbildungstabelle: in allen sieben passen Ampel, Kategoriefarbe, Befundzeile, A.1, A.2-Liste, Maßnahmenplan-Priorität, Zählzeile auf Seite 2 und Gesamtbewertung zusammen; Rot nur bei Exposition kritisch (LW, JW Datenbanken).
- ZAP Path Traversal (Konfidenz Low) steht bei DB und CA als Werkzeugmeldung im Anhang; ZAP-Nachweise bei HL zeigen Kennung, Risiko, Konfidenz, Adresse, Beleg und CWE; nirgends „nachgewiesen".
- nmap-Nachweise im Format `IP:Port/tcp Dienst=… Produkt=… Version=…`; keine `None`, `True`, `False`, keine Policy- oder Prototyp-Begriffe; Referenzzeile „Prüfkatalog 2026-09-23.2, Regel …".
- Berichtsnummer `VS-2026-0923-<vier Zeichen>` auf Deckblatt, allen Fußzeilen und im Impressum.
- DKIM: mit gefundenen Selektoren (hse1, hse2 bei JW, HE, BS, CA, HL) vorhanden, ohne Selektor „nicht prüfbar" mit 62 Selektoren und Anhangliste (DB).
- RDP/SMB-Positivbefund: neuer Titel, entfällt korrekt bei FTP, SSH außerhalb 22 und Verwaltungsoberfläche (DB, BS, HL), nennt die ausgeschlossenen Hosts (CA), höchstens drei VHosts je Host.
- Kein Platzhalter „Auftraggeber", kein Personenzusatz; „multi-target" erscheint nirgends im JW-Bericht; Prüfzeiträume stimmen mit den Zeitstempeln; die Prosa ist bei Hündgen seit !89 da, Umlaute korrekt.
- Anhang E „Freischaltung der Scanner-Adresse" steht nur, wo eine echte Sperre belegt ist (LW, JW, HL, BS WAF).
- PDF-Techniktabelle liest MariaDB und PostgreSQL richtig (anders als das Dashboard, Q11).

## Teil 6: Vorschlag Zuschnitt und Entscheidungen

Zuschnitt (Vorschlag Claude):
- **S6b Katalog und Reportdaten** (bisheriger Umfang: spec/08 Punkte 4, 5, 6, 14, 15, 17, 20, 21, die offenen Punkte nach S6a) plus Q2, Q4, Q5, Q6, Q7, Q9 (Berichtsteil), Q10, Q11, Q12, Q13 nach E1, Q14, Q15, Q18 und Teil 3. Fixtures: die sieben Aufträge dieser Runde als Golden-Fixtures, `negative.json` aus dieser Runde neu (S6a-Punkt 3). Das ist groß; wenn es nicht in eine Session passt, Q2, Q9, Q10 und Q11 als S6b-1 (Umfang, Rollen, Dashboard), Q4 bis Q7 und Q12 bis Q14 als S6b-2 (Texte und Regeln).
- **S6c Scanner und Discovery**: Q1, Q3 (Fakt geteiltes System, aktive Prüfung nur gegen Kunden-VHosts), Q8, Q16, Q17. Scanner-Änderungen wirken erst mit neuen Scans.
- Danach `requeue-report` für die sieben Aufträge (prüft S6b ohne neue Scans) und eine zweite Scan-Runde gegen dieselben sieben Ziele (prüft S6c), Gegenlesen als spec/10.
- S7 und das IPv6-Paket (#20 bis #22) danach; Q16 greift dem IPv6-Paket vor.

Entscheidungen DC:
- **E1** Verwaltungsoberfläche mit Anmeldung (Plesk, Webmin): Exposition kritisch, also Rot und Unverzüglich, oder A.2 so ändern, dass Hosting-Panels ausdrücklich „erhöht" sind. Empfehlung Claude: Webmin und Panels ohne vorgelagerten Schutz kritisch, Hosting-Panels des Hosters auf geteilten Systemen erhöht mit Empfehlung an den Hoster.
- **E2** Zertifikat mit Restlaufzeit bis sieben Tage: als Ausnahme Unverzüglich (Rot) in `levels.py` und A.1 aufnehmen, oder Gelb bleiben. Empfehlung Claude: Unverzüglich ab sieben Tagen, Hygiene hoch ab 14 Tagen, darüber mittelfristig.
- **E3** Scope bei geteiltem Hosting und CDN: aktive Prüfungen (zap_active, ffuf, feroxbuster) nur gegen die VHosts des Kunden, Dienste fremder Kunden auf derselben Adresse und CDN-Kanten nur passiv. Empfehlung Claude: ja, und die Scan-Freigabe im Admin weist geteilte Adressen vor dem Release aus.
- **E4** Der Prüfstand geht mit 62.217.52.174 ins Internet, die vier unerreichten BS-Adressen liegen teils im selben Netz (62.217.52.162, .166, .171). Verdacht: kein Hairpin oder Firewall-Regel zwischen DMZ und eigenem Netz; 79.140.188.181 ist ein anderer Anschluss. Bitte prüfen; bis dahin sind eigene Ziele in diesem Netz vom Prüfstand aus nicht prüfbar und gehören als solche in den Bericht.
- **E5** Ausgehend Port 25 am Prüfstand: freischalten lassen (Firewall der DMZ oder Provider) oder als feste Einschränkung „SMTP auf Port 25 vom Prüfstand aus nicht prüfbar" in jeden Bericht.
- **E6** Freigabe: keinen der sieben Berichte freigeben. Die Aufträge bleiben in `pending_review` bis zum `requeue-report` nach S6b.
