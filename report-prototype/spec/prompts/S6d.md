# Startprompt S6d: Berichtsseite liest die S6c-Rohfelder, Issues #4, #16, #18, kleiner Scanner-Nachtrag

Kontext: Lies zuerst report-prototype/spec/05-architektur-befund-und-plan.md, dann
spec/07-claude-code-handover.md (Abschnitt 9 ab „Abschluss S6b-4n", vor allem „Abschluss S6c" mit den
zwei Feststellungen für spec/12), spec/11-gegenlesen-scanrunde-3.md (Teil 5 Zuschnitt, Teil 6 mit N2, N3,
N4, N6, N13, die Entscheidungen E17, E19, E24, E27) und die Übergabetabelle docs/S6C-NEW-RAW-FIELDS.md
(je neuem Rohfeld Werkzeug, Feldname, Struktur, Fixture, zugehöriger Punkt). Diese Dateien sind die
Wahrheit für dieses Vorhaben; ältere Markdown-Dateien im Repo können veraltet sein. Bei Widerspruch: Code
und spec/05 bis 11 gelten, sonst nachfragen. Leitprinzipien: kein Befund ohne Fakt aus einem Werkzeug;
keine KI-erzeugten Befunde, Einstufungen oder CVSS-Werte; keine Zusagen im Kundenreport; Quellenangabe im
Bericht nur aus dem Werkzeug, das den Wert geliefert hat; jede Änderung hat ein Fixture aus Rohdaten;
Deutsch in Texten mit echten Umlauten, ASCII nur in Bezeichnern, Dateinamen und IDs; keine
Gedankenstriche in Texten. Arbeite im Plan-Modus, zeige den Plan, warte auf Freigabe. Am Ende: Tests
grün, kurze Zusammenfassung, Liste offener Fragen.
Schritt 0: git merge main --no-edit im Worktree (S6c, MR !106 `cf542059`, muss gemerged sein; spec/07
enthält den Abschluss S6c). Nichts an spec/ ändern.
Regeln: Jedes Abbild kommt aus der eigenen Registry ghcr.io/dc-77/vectiscan/, Fremdabbilder nur
gespiegelt und per Digest gepinnt. Nicht mergen, während Scans laufen (Issue #32, vor dem Merge prüfen).
Die Session startet keine Scans und kein requeue-report; Claude erzeugt die Berichte nach dem Merge neu
und liest gegen. Rohdaten für die neuen Fakten: die drei S6c-Probeaufträge 4394b0b7 (dortmund-beach.com),
f9a2a2f6 (junkerwerk.de und junkerwerk.hu), cd28d260 (castenow.de) werden neue Golden-Fixtures (Tars mit
testssl_<port>.json, testssl_sni_<host>.json, nmap_versionall.xml, xmlrpc_probe.json, smtp_ehlo_<port>,
provider_block_probe, Endantwort-Header aus redirect_probe, ZAP-Meldungen mit Konfidenz und Statuscode);
rdap lief dort als not_in_package, das RDAP-Fixture kommt aus den scan-worker-Tests von S6c. Die
bisherigen Golden-Fixtures ohne die neuen Dateien bleiben gültig: fehlt ein neues Rohfeld, verhält sich
der Bericht wie heute (Rückwärtskompatibilität, Beispiel Spalte „laut AbuseIPDB" ohne RDAP).

Aufgabe S6d, Teil A (report-worker, Faktenschema 1.4.0, Katalogversion neu): der Konsum der S6c-Rohfelder.
(A1) netblock_owner aus rdap als Fakt mit Quelle RIR (RIPE, ARIN, APNIC, LACNIC, AFRINIC laut Antwort);
Spalte „Netzbetreiber (laut <RIR>)" in 2.1 und Anhang B, Alias-Tabelle aus S6b-4 bleibt für den
Anschlussbetreiber-Zusatz; ohne rdap-Lauf weiter „laut AbuseIPDB" (spec/11 T2, E17).
(A2) TLS je Port und je SNI: testssl_<port>.json und testssl_sni_<host>.json als eigene tls[]-Einträge mit
Port und SNI, nicht mehr `assigned_from` über das Zertifikat; Abdeckung „geprüfte TLS-Ports je Host" aus
den echten Läufen; Positivbefunde und Befunde (Protokolle, Cipher, Zertifikat, service_cert_expired an
Mailports) je Port aus dem Lauf dieses Ports; Betroffenenliste einmal je Port (spec/11 S7-Punkt
„dreifach" bei BS VS-003 fällt damit weg); `failed` mit skipReason als Einschränkung, nicht als
„vollständig".
(A3) Dienstkennung je Port (spec/11 T1): imap-capabilities, pop3-capabilities, smtp-commands, ssl-cert und
nmap_versionall.xml als Kennungsfakten; „nicht identifiziert" nur, wenn keiner dieser Fakten greift;
Beobachtung service_unknown_port nur dann.
(A4) SMTP: aus smtp_ehlo_<port> die Fakten smtp_auth_before_starttls und smtp_vrfy_enabled (aktiv, ersetzt
die reine Passivquelle); Katalogregel smtp_auth_before_starttls (Vorschlag Gelb, Mittelfristig, Text: AUTH
wird vor STARTTLS angeboten, Zugangsdaten könnten unverschlüsselt übertragen werden; Fixture DB 587, BS 25
laut Shodan); die unprocessed-Art smtp_auth_before_starttls entfällt, sobald die Regel greift; Port 25
bleibt bis E5 vom Prüfstand aus nicht prüfbar, die E5-Zeile bleibt.
(A5) XML-RPC: wordpress_xmlrpc_enabled aus xmlrpc_probe.json (CA) zusätzlich zu wpscan; Nachweis nennt die
Sonde.
(A6) Endantwort (spec/11 N3, E24): Header-Befunde „bewertet an der Endseite" nur mit den Endantwort-Headern
aus redirect_probe; bei clientseitigen Weiterleitungen (HL ose, HL online, CA mail) die Endantwort-Header
aus dem neuen Feld; header_check redirect_eval mit Status und location in der Einschränkung; HSTS an der
ersten Antwort bleibt nach E24.
(A7) ZAP: Konfidenz und Risiko je Meldung aus dem Export, Konfidenzfilter nach spec/09 Q14 wirksam; Anhang C
mit URL je Meldung; Meldungen an Abwehr- und Fehlerseiten (Status 429, 4xx) und an Nebenpfaden
(robots.txt, sitemap.xml) werden nicht der Zielseite zugerechnet, sondern mit Pfad im Anhang geführt.
(A8) provider_block_probe als Fakt: Einschränkung „Zielnetz sperrt die Prüfadresse nach dem Portscan"
mit Dauer und den davon betroffenen Prüfungen, Abdeckung „Portscan vollständig; danach abgewiesen" aus dem
Fakt statt aus Ableitung; ohne Sperre kein Text.
(A9) AXFR je Domain: Zonentransfer-Positivbefund nur mit dem Fakt der jeweiligen Domain (JW P06
junkerwerk.hu); discovery_health.found_not_in_inventory als Fakt für die Liste „gefunden, nicht geprüft"
in Kapitel 2 mit Gate-Warnung namen_nicht_geprueft; Hostsuche je Zieldomain in Prüfumfang je Domain.
(A10) AbuseIPDB maxAgeInDays im Reputations-Positivbefund („keine Meldungen in den letzten n Tagen").
(A11) Ehrliche Ausfälle: no_ipv6_route, ZAP unreachable, whois no_data, Timeouts von feroxbuster und ffuf
mit Statistik als Einschränkung je Ursache (Bausteine aus S6b-1), nie als „vollständig" oder als
Positivbefund.
(A12) facts_builder: alle Dateien aus docs/S6C-NEW-RAW-FIELDS.md werden gelesen, file_unknown_or_unparsable
nur noch für wirklich unbekannte Dateien; an den drei Probeaufträgen sinkt die Zahl der unprocessed-
Einträge dieser Art auf 0, sonst ist ein Feld vergessen.

Aufgabe S6d, Teil B (Issues Berichtsseite):
(B1) #16 wordpress_plugin_vulnerable: Schwachstellenzahlen und CVE-Kennungen nur aus dem wpscan-Feed im
Rohdatum, nie aus KI-Text; Nachweis zählt, was der Feed liefert, und nennt die Kennungen nach Schwere;
Fixture DB.
(B2) #18 httpx-Abdeckung je VHost: tool_coverage liest den VHost aus dem Dateinamen httpx_<slug>.json,
Abdeckung je VHost wie bei header_check; Fixture aus einem Auftrag mit mehreren VHosts (CA).
(B3) #4 reporter/validation/tests in die pytest-testpaths und damit in CI; Pipeline muss die Tests zählen.

Aufgabe S6d, Teil C (kleiner Scanner-Nachtrag, scan-worker, je Punkt Fixture aus Rohdaten):
(C1) #22 otx, securitytrails und whois je Domain eines Mehrziel-Auftrags (Rest von #12), _domain-Etikett wie
bei dns_records; Fixture f9a2a2f6.
(C2) #19 NAT64-synthetische AAAA-Adressen (64:ff9b::/96) erkennen, nicht als IPv6-Ziel führen, im Inventar
mit Grund markieren; Fixture aus dem S2b-Beleg (dortmund-beach.com).
(C3) Per-Port-Sonden (testssl je Port und SNI, nmap_versionall, smtp_ehlo) auf Hosts, die nach S6c gedrosselt
werden, nacheinander mit Pause statt gleichzeitig, damit die Prüfungen vollständig durchlaufen
(Messbefund aus JW f9a2a2f6: gleichzeitige Sonden brechen dort ab); Pause und Reihung konfigurierbar,
provider_block_probe misst das Ergebnis in der Testrunde.
(C4) testssl_<port> mit status failed trägt einen skipReason (kein TLS auf dem Port, Verbindung
abgewiesen, Timeout), damit A2 und A11 die Ursache nennen können.
(C5) Issues schließen mit Beleg im Kommentar: #27 und #35 (umgesetzt in !106, belegt an den drei
Probeaufträgen), dazu #22, #19, #16, #18, #4 nach Umsetzung.

Nicht tun: Darstellung und Layout (R20, spec/11 S7-Punkte, E27-Admin-Hinweis, #24: S7a nach dieser
Session); Pakete und Export (S7b); IPv6-Route und Dual-Stack (#8, #20, #21); Prüfstand-Netz E4 und
Port-25-Freigabe E5; keine Scans, kein requeue, nichts an spec/. Entscheidungen, die im Plan zu
bestätigen sind: Einstufung der smtp-Regel (A4), Wortlaut der neuen Einschränkungen (A8, A11).
Abnahme: alle Suiten grün (report-worker, PDF-Suite, scan-worker mit den neuen Fixtures, api);
Golden-Neubau mit den zehn plus drei Fixtures, Abweichungen je Punkt A1 bis C4 in
report-worker/tests/golden/README.md, Abschnitt „Abgleich S6c-Rohfelder nach S6d"; an den drei
Probeaufträgen: 0 Gate-Fehler, 0 file_unknown_or_unparsable, Netzbetreiber mit RIR-Quelle nur, wenn ein
rdap-Fixture vorliegt, sonst „laut AbuseIPDB"; die alten Fixtures ohne neue Dateien rendern unverändert
bis auf die Punkte, die A2 bis A11 aus vorhandenen Daten ändern (je Punkt in der README begründet).
Push über SSH, MR gegen main, Merge nach grüner Pipeline und nur, wenn kein Scan läuft, Source-Branch
entfernen, danach Merge-Commit, MR-Nummer, Testzahlen, Abweichungen und offene Fragen melden. Danach
schreibt Claude den Startprompt S7a (Darstellung) auf dem neuen Stand; die Testrunde gegen die sieben
Ziele mit dem Nachscan nach E19 und das Gegenlesen als spec/13 folgen nach S7a.
