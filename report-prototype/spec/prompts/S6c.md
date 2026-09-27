# Startprompt S6c: Scanner und Discovery

Kontext: Lies zuerst report-prototype/spec/05-architektur-befund-und-plan.md, dann
spec/07-claude-code-handover.md (Abschnitt 9 ab „Abschluss S6b-1"), spec/09-gegenlesen-scanrunde.md
(Q1, Q3, Q8, Q16, Q17, Teil 4, Entscheidungen E3 bis E5), spec/10-gegenlesen-scanrunde-2.md (Teil 5,
Zuschnitt S6c, sowie die Scanner-Belege in R1, R3, R4, R5, R19) und spec/11-gegenlesen-scanrunde-3.md
(Teil 5 Zuschnitt S6c, die Scanner-Belege in T1, T2, T7, T8 und die Entscheidung E19). Diese Dateien
sind die Wahrheit für dieses Vorhaben; ältere Markdown-Dateien im Repo können veraltet sein. Bei
Widerspruch: Code und spec/05 bis 11 gelten, sonst nachfragen. Leitprinzipien: kein Befund ohne Fakt aus einem Werkzeug; keine KI-erzeugten
Befunde, Einstufungen oder CVSS-Werte; keine Zusagen im Kundenreport; jede Scanner-Änderung hat ein
Fixture aus Rohdaten (Timeout-Teilausgabe, Weiterleitung, Challenge, leere nmap-Ausgabe); Deutsch in
Texten mit echten Umlauten, ASCII nur in Bezeichnern, Dateinamen und IDs; keine Gedankenstriche in
Texten. Arbeite im Plan-Modus, zeige den Plan, warte auf Freigabe. Am Ende: Tests grün, kurze
Zusammenfassung, Liste offener Fragen.
Schritt 0: git merge main --no-edit im Worktree (S6b-3, S6b-4 und der Nachtrag zu S6b-4 müssen gemerged
sein). Nichts an spec/ ändern.
Regeln: Jedes Abbild kommt aus der eigenen Registry ghcr.io/dc-77/vectiscan/, Fremdabbilder nur
gespiegelt und per Digest gepinnt (scripts/ops/mirror-images.sh, tests/test_compose_images.py); ein
neues Werkzeug im scan-worker-Abbild wird zur Build-Zeit installiert und in Issue #34 vermerkt. Nicht
mergen, während Scans laufen (Issue #32). Aktive Prüfungen laufen nur gegen freigegebene Ziele; die
Fixtures dieser Session sind Rohdaten, keine Live-Scans. Scanner-Änderungen wirken erst mit neuen
Scans: nach dem Merge startet Claude die zweite Scan-Runde gegen dieselben sieben Ziele.

Aufgabe S6c: die Scanner- und Discovery-Punkte aus spec/09 und spec/10, je Punkt mit Fixture.
(1) Q1 Discovery: gobuster_dns-Ausgabe zeilenweise als „fqdn ip[,ip]" parsen, erstes Feld an dnsx,
Teilausgabe bei Timeout übernehmen; Timeout-Fixture aus der Scan-Runde (JW archiv, HE ftp, BS 24 Namen,
HL as2 und control, CA autodiscover, LW eset und ftp müssen im Inventar ankommen); discovery_health
warnt, wenn gefundene FQDNs nicht im Inventar sind (tools_with_zero_results reicht nicht); gobuster_dns
bei Wildcard-DNS überspringen (DB); die 18 Q8-Markierungen in expected_map.json werden hier aufgelöst,
soweit sie Discovery und Header betreffen.
(2) Q8 header_check: Weiterleitungen folgen und die Endantwort bewerten, HSTS zusätzlich an der ersten
Antwort; Status, location und Antwortlänge in die Ausgabe; doppelte Header zusammenführen statt
überschreiben (CA x-powered-by); 4xx, 429 und Challenge-Seiten (x-vercel-mitigated, Cloudflare-
Challenge) als „nicht prüfbar" mit Grund; Fixtures JW .28 (302 auf /owa/), CA ubb-wiki (302 auf
/login/), CA Nextcloud (400), HL online (429 Challenge), BS ftp (403), BS bergersysteme.com (301).
(3) Q16 Scannerteil: alle Werkzeuge an die IP des Host-Inventars binden und die geprüfte IP ausweisen
(testssl bei DNS-Rotation: HE 52.59.120.70 statt 18.197.248.23, CA 3.174.98.123 statt .120, HL
216.150.1.129 statt .65); AAAA aktiv auflösen und als additional_ips des Systems führen (BS
2a00:1169:118:23d0:: und 2620:cb:2000::1, LW 2a01:4f8:d0a:668b::2); ohne IPv6-Route Phase 2 für die
Adresse mit Grund überspringen; Discovery je Zieldomain (junkerwerk.hu).
(4) Q17 Ausfälle und Lücken: testssl je TLS-Port mit --starttls (21, 25, 110, 143, 465, 587, 993, 995,
8443, 444, 10000), nicht nur 443 mit einer SNI; testssl je VHost-SNI, wenn Zertifikate abweichen (BS
ftp); zap_active auf die final_url des Inhalts-VHosts (HL ose statt edi 403, CA www statt Apex) und
zap_extra_urls nur für Kunden-VHosts (E3: CA :8000, :8001, :8800 Fremddienste dürfen nie aktiv geprüft
werden); ZAP unreachable mit zweitem Versuch oder Ausfall als failed (CA www zap-3); feroxbuster und
ffuf auf die final_url statt auf die Apex-Weiterleitung (HE, CA), ffuf_sensitive mit Exchange-Liste
gegen Exchange (/ecp, /EWS, /autodiscover, /mapi, /Microsoft-Server-ActiveSync) statt PHP/CMS-Liste;
stille Ausfälle als failed: header_check reachable=false, feroxbuster mit Verbindungsfehler oder
total_scans 0, nmap ohne Hostbericht (BS vier Hosts, HL 195.225.241.75: „keine Antwort" statt „kein
offener Port"), wafw00f Timeout; waf_body_marker nur bei belegter Sperr- oder Challenge-Seite (BS
198.202.211.1 bekam normale 200 und 404); Hetzner-Sperre nach dem vollen Portscan (LW, JW, HL): Phase 2
vor dem vollen Portscan oder Portscan mit niedrigerer Rate für your-server.de-Netze, Ergebnis messen;
Ports ohne Kennung mit -sV --version-all nachproben (HE 1000 bis 1002, CA 8001, HL 8443).
(5) SMTP-Fakt: je SMTP-Port (25, 465, 587) die EHLO-Fähigkeiten vor STARTTLS (AUTH-Verfahren, VRFY,
STARTTLS) als Fakt aus nmap smtp-commands oder eigener Sonde; danach Katalogregel
smtp_auth_before_starttls (Fixture DB 587, BS 25 laut Shodan) und Fakt für smtp_vrfy_enabled; Port 25
bleibt bis E5 vom Prüfstand aus nicht prüfbar, die E5-Einschränkung bleibt.
(6) ZAP: Konfidenz und Risiko je Meldung in die Rohausgabe und in die Fakten, top_alerts nicht auf 20
kürzen (Konfidenzfilter Q14 ist sonst nicht prüfbar); AJAX-Spider je Instanz serialisieren oder
scan_in_progress einmal nachfassen (#27); Cookie-Meldungen an Login-Seiten mit URL.
(7) whois (#35): fehlgeschlagener Abruf ist failed, nicht ok mit no_data; Quelle reparieren oder das
Werkzeug aus dem Paket nehmen; dasselbe Muster bei urlhaus und securitytrails prüfen (spec/10 R6).
Dazu eine RDAP-Abfrage je Adresse (rdap.org oder die RIR-Endpunkte) als Fakt netblock_owner mit Quelle
RIR, damit die Netzbetreiber-Spalte im Bericht eine echte Registry-Quelle bekommt (spec/11 T2, E17);
bis dahin bleibt „laut AbuseIPDB".
(7a) Ports mit ?-Namen (spec/11 T1 Scannerteil): imap-capabilities, pop3-capabilities, smtp-commands
und ssl-cert als Kennungsfakten je Port exportieren, nicht nur den nmap-Dienstnamen; XML-RPC bei
castenow: wpscan meldet es dort nicht, deshalb eine eigene Sonde auf /xmlrpc.php (POST system.listMethods)
als Fakt wordpress_xmlrpc, Fixture DB (aktiv) und CA.
(7b) Aus spec/11 Teil 6 (Scannerteil): redirect_probe exportiert die Header der Endantwort getrennt von
der ersten Antwort, auch bei clientseitigen Weiterleitungen (HL ose „Redirector" auf login.seam, HL online
Vercel auf www, CA mail und mail2 302 auf /owa/); KI #1 und ai_phase2_config wählen Regeln (etwa
hosted-cms-webflow) nur aus Antworten desselben Hosts, nie aus dem Weiterleitungsziel (BS 92.205.224.174
bekam die Webflow-Regel und verlor die aktive Webanalyse von ftp und Plesk); zap_spider-URLs fremder
Hostnamen nicht in tech_profiles.cms übernehmen (JW „Microsoft Exchange" am Hetzner-Host); die
AXFR-Rohausgabe je Domain und Nameserver in den Export (bisher nur zone_transfer true/false, für
junkerwerk.hu kein Lauf); Zonentransfer, dnsx und Hostsuche je Zieldomain (junkerwerk.hu); ZAP-Meldungen
mit URL und Statuscode der Antwort, damit Meldungen an Abwehrseiten (HL online 429) und Nebenpfaden
(robots.txt, sitemap.xml) zugeordnet werden können; AbuseIPDB maxAgeInDays im Export; feroxbuster und
ffuf mit Statistik auch bei Timeout, ferner ose.heuel.com als Ziel statt nur edi.
(8) KI #1 (Host-Strategie) und ai_phase2_config: keine Fremdports in zap_extra_urls (E3), Drittanbieter-
Skip mit Grund (bleibt), „or later" als Untergrenze (S6a2 bleibt); aiStrategy „veraltete PostgreSQL 9.6"
darf nicht mehr entstehen (JW).
Nicht tun: Katalogtexte, Reportdaten, Darstellung (S6b-3, S7); Prüfstand-Netz E4 und Port-25-Freigabe
E5 (klärt DC außerhalb des Codes).
Abnahme: alle Suiten grün (scan-worker-Tests mit den neuen Fixtures, report-worker unverändert grün);
Golden-Facts aus den Rohdaten der Scan-Runde bleiben gültig, neue Fakten kommen nur mit neuen Scans.
Nach dem Merge zweite Scan-Runde gegen die sieben Ziele (macht Claude über die API, nacheinander, kein
Merge während der Scans), darin der Nachscan der gefundenen, nicht geprüften Namen nach spec/11 E19
(LW eset und ftp, HE ftp und ftp.mail, JW archiv, HL as2 und control, BS nur nach Klärung von E4);
neue Aufträge werden Golden-Fixtures, Gegenlesen als spec/12. Push über SSH,
MR gegen main, Merge nach grüner Pipeline mit Source-Branch entfernen, danach Merge-Commit,
MR-Nummer und Ergebnisse melden.
