# Startprompt S6b-4 Nachtrag: Positivbefunde, Weiterleitungen, Bausteine nach spec/11 Teil 6

Kontext: Lies zuerst report-prototype/spec/07-claude-code-handover.md (Abschnitt 9 ab „Abschluss S6b-3")
und spec/11-gegenlesen-scanrunde-3.md, dort Teil 6 (Nachtrag: Querschnittsbefunde N1 bis N15,
Entscheidungen E24 bis E26) ganz sowie Teil 2 und Teil 5 zur Einordnung. Diese Dateien sind die Wahrheit
für dieses Vorhaben; bei Widerspruch gelten Code und spec/05 bis 11, sonst nachfragen. Leitprinzipien:
kein Befund ohne Fakt aus einem Werkzeug; kein Positivbefund ohne Messung; keine Zusagen im Kundenreport;
jede Regel, jede Textbedingung und jede Gate-Regel hat ein Fixture; Deutsch in Texten mit echten
Umlauten, ASCII nur in Bezeichnern, Dateinamen und IDs; keine Gedankenstriche in Texten. Arbeite im
Plan-Modus, zeige den Plan, warte auf Freigabe. Am Ende: Tests grün, kurze Zusammenfassung, Liste
offener Fragen.
Schritt 0: git merge main --no-edit im Worktree (S6b-4 ist gemerged: MR !104 `d917d8e7`). Nichts an
spec/ ändern. Fixtures sind die sieben Golden-Aufträge der Scan-Runde; die Rohdaten der Berichte vom
27.09. (Erzeugung 5, LW 7, JW 11) liegen bei Claude unter out/scanrunde-2026-09-27b/, die Golden-Fixtures
tragen dieselben Rohdaten. Neue Sollwerte tragen die N-Nummer aus spec/11 Teil 6. Die Entscheidungen
E24 bis E26 gelten, wie DC sie in spec/11 Teil 6 bestätigt hat; ist eine offen, den Vorschlag in
Klammern umsetzen und das in der Zusammenfassung nennen.
Regeln: Jedes Abbild kommt aus der eigenen Registry ghcr.io/dc-77/vectiscan/; der Nachtrag braucht kein
neues Abbild. Nicht mergen, während Scans laufen (Issue #32): vor dem Merge den Auftragsstatus prüfen.
Der Scanner bleibt unberührt; Scanner-Punkte aus Teil 6 (Endantwort-Header in redirect_probe, KI-Regelwahl
nicht aus Weiterleitungszielen, AXFR-Rohausgabe) gehen an S6c und werden nur gemeldet.

Aufgabe: die Berichtsseite von N1 bis N15, je Punkt mit Fixture, keine neuen Faktenfamilien.
(1) N1 CSP-Positivbefund nur bei script-src oder default-src und ohne csp_weak am selben Host; CSP nur
mit frame-ancestors als Variante von csp_missing („Inhaltsrichtlinie nur mit frame-ancestors, keine Regel
für Skriptquellen"). Fixtures HE www, CA ubb-wiki und www.
(2) N2 nach E24: HSTS-Positivbefund an 301 und 400 zulässig mit Zusatz „gemessen an der Weiterleitung
(301)" beziehungsweise „(400)", 2.2 nimmt HSTS von „Endseite nicht bewertet" aus; an 429 und
Challenge-Antworten nie, auch nicht aus der ersten Antwort in redirect_probe; Namen ohne eigene Messung
(BS „+cdn") erscheinen nicht in Titel oder Positivbefund. Fixtures CA mailstore und umfrage, HL online,
BS VS-007.
(3) N3: „bewertet an der Endseite" nur, wenn die Header aus der Endantwort stammen: final_url nach
HTTP-Weiterleitung ohne location im Header-Satz und ohne Titel „Redirector"; bei clientseitiger
Weiterleitung (Header-Satz gleich der ersten Antwort: gleicher etag oder content-length wie header_check)
ZAP je URL als Quelle und die dort nicht gemessenen Header als Einschränkung „nur an der
Weiterleitungsseite gemessen" (nicht als fehlend); CA mail und mail2: Referrer- und Permissions-Policy als
„nicht gemessen". Gate nachweis_ohne_regelfakt um „Endseite ohne Endantwort" erweitern. Fixtures HL ose,
HL online, CA mail und mail2, JW outlook (Gegenprobe, echte Endantwort).
(4) N4: Rollen, Technikzeilen, Anhang-C-Zuordnung und Bildquellen nur aus Antworten desselben Hosts
(final_domain gleich VHost); bei Weiterleitung auf einen anderen Host Rolle „Weiterleitung auf <Ziel>"
plus die eigenen Dienste aus nmap (Mail- und Dateidienste); die Scan-Steuerungsregel im Bericht mit Grund
nennen („wegen Weiterleitung auf die Webflow-Seite"). Fixtures HL 213.133.104.51 (webportal, dl), HL
online (GTM, Facebook Pixel gehören zu www), BS 92.205.224.174.
(5) N5: Posture, Anhang B, Positivbefunde und 2.1 je Name mit „gemessen an <Adresse>", Posture „○ am
Namen gemessen (<Adresse>)" statt ✔ an der Inventaradresse, kein „vollständig" für eine Inventaradresse
ohne eigene Messung; zweite A-Einträge (HL 216.150.16.65) ins Inventar als „nicht geprüft"; die
DNS-Rotations-Zeile um „Technologie-Erkennung (httpx)" ergänzen. Fixtures HE .23, HL .65, CA .120.
(6) N6: Kategorie grün nur mit mindestens einer Messung ihrer Faktenfamilie, sonst grau „nicht bewertbar
(… nicht möglich, siehe 2.2)" wie Kategorie B; Positivbefund je Domain nur mit Fakt je Domain (Gate
„Positiv gegen Rohfakt"); geteilte CDN-Adressen im Reputations-Positivbefund als „Reputation nicht
kundenbezogen" oder weglassen; lastReportedAt innerhalb des Fensters ist kein Positiv. Fixtures LW
Kategorie D, JW P06 .hu, BS P06.
(7) N7: rua je Adresse trennen (eigene Domain: „Berichte an … auswerten"; fremde: „Auswertung beim
Dienstleister anfordern"); der Betreiber-Satz nur aus CNAME-Delegation von _dmarc oder SPF mx, nicht aus
dem MX. Fixtures BS VS-005, DB VS-005.
(8) N8: Zertifikatshinweis „gültiges Zertifikat desselben Namens an" nur bei gleicher Linie (SAN-Satz und
Aussteller) und gleicher Zuständigkeit und nur von Quellen mit Chain of trust Ok; die Variante „am
Berichtsdatum abgelaufen, sofern nicht erneuert" auch in Hebel, Planeffekt und Auswirkung. Fixtures HE
VS-004, CA VS-003.
(9) N9: Zielversion aus wpscan getrennt: „fehlerbereinigt ab <max fixed_in>" und „neueste laut wpscan
<latest_version>"; liegt fixed_in über latest_version, Hinweis „Verzeichnis von wpscan veraltet" statt
„aktuell"; Kindtheme ohne latest_version als „nicht bestimmbar (eigenes Kindtheme, Elterntheme siehe
VS-…)"; Plaketten in 3.1 nur „veraltet" oder „LTS", Anzahl, Zielversion und Datum in der Hinweisspalte;
Produktnamen statt Slugs in Betroffen und Plan. Fixtures DB, LW, JW.
(10) N10: Passivvariante am selben Produkt nur als Portzusatz im ersten Satz, eine Stufe, eine
Verifikation, ein Titelbaustein („Verwaltungsoberfläche Plesk auf 443, 8443 und laut Passivquelle
8880"); „laut Zertifikat oder Passivquelle" nur mit dem tatsächlichen Fakt und im richtigen Numerus;
Bausteine je Regel einmal (DB VS-012, JW VS-014); X-FEServer nie unter „Version"; BS VS-003
Betroffenenliste einmal, „Mailclients", Hebel „für die Maildienste"; CA VS-001 Satzfolge. Fixtures BS
und CA VS-001, DB VS-012, JW VS-014, BS VS-003.
(11) N11: secureserver.net und host.secureserver.net in die Hoster-Alias-Tabelle (Host Europe); Zählung
mit Quelle („laut Passivquelle 2 weitere Domains"); 8800 ohne Domainfakt nicht als Fremddienst
behaupten („Icecast, Zuordnung nicht belegt"); Fremddienste in der Service-Karte grau „nicht bewertet";
2.1 für CA .80 „Server von planwerk6.de, laut Passivquelle geteilt"; Drittanbieter-Zeilen mit eigener
Quelle („laut Namensauflösung und SPF") statt in der AbuseIPDB-Spalte. Fixtures CA .53 und .80, LW und
HL autodiscover.
(12) N12: Anhang C nennt je Meldung den Fundort („an Nebenpfaden robots.txt, sitemap.xml", „an der
Sicherheitsabfrage"); Meldungen zu Headern, die ein Befund oder Positivbefund am selben Host bewertet,
entfallen im Anhang; X-AspNet-Version für alle Namen mit httpx-Beleg im Befund (CA mail, mail2);
Shodan os, Skript-URLs und Cookies zählen als zweite Quelle; Neos über die Alias-Tabelle; LUCKY13 nur
für Namen mit eigenem testssl-Lauf; Werkzeuge ohne Daten in Anhang C als „ohne Ergebnis"; Anhang-D-Satz
aus fp_by_reason („n gleiche Meldungen der Webanalyse zusammengeführt"). Fixtures CA, HL, JW, HE, DB.
(13) N13: 2.2 „Protokolle und Verfahren nicht bewertet, Zertifikat aus dem Portscan" für Ports mit
nmap-Zertifikat; Pfadsuche-Zeile auch bei Timeout, fehlender Statistik, total_scans 0 und nie
angefragter Anwendung (HL ose); wafw00f-Timeout als Zeile; E4-Zeile „Ergebnisse eigener Messungen liegen
nicht vor; VS-… beruhen allein auf der Passivquelle"; ZAP-Zeile mit Ursache, „ohne Meldungen" bei
zap_active complete und 0 Meldungen; kein „vollständig" bei Kurzlauf unter 60 s oder nur einem VHost;
Wortlaut „abgebrochen: der Scanner vermutete in der Startseite (200) ein Abwehrmerkmal"; Zählungen
„n Adressen, davon m nur aus DNS oder ohne Antwort"; Numerus bei einer AAAA-Adresse; Gate-Text
ipv6_ohne_inventar „nicht im Scan-Inventar, im Bericht als ungeprüft ausgewiesen". Fixtures BS, HL, DB,
LW, CA, JW, HE.
(14) N14: Rollen aus SPF a (E-Mail-Versand), aktiv bestätigten Mailports (Mailabruf und Einlieferung),
db_exposed (Datenbanken erreichbar), Passivpfad /owa/ (Mail-Webzugang laut Passivquelle) und
Seitentitel (HE 444). Fixtures DB, LW, JW, HE, BS.
(15) N15 nach E25: Anmeldenamen in Personenform im Kundentext nur als Anzahl und Fundweg; Referrer-Policy-
Auswirkung („ohne Header gilt die Voreinstellung des Browsers; ältere Browser geben die vollständige
Adresse weiter"); 587 „Anmeldung erst nach STARTTLS"; A.1-Ausnahme auf cert_expiring eingrenzen und
service_cert_expired getrennt nennen; 53 „DNS", tcpwrapped „Dienst ohne Antwort", nmap-Zeilen mit ?
unverändert; „Hosteintrag der Passivquelle aktualisiert am"; Numerus- und Klammerreste, doppeltes Präfix
(HE), Positivlisten mit Plattformzusatz in Klammern hinter der Adresse; Cloudflare-Standardports mit
Banner-Kennung und Satz zur CDN-Kante; 8880 Plesk; ProFTPD eine Zeile; Cookiebot und Etracker gleich
behandeln; HL 4433 in unprocessed. Fixtures wie in Teil 6 genannt.
Nicht tun: Scanner (S6c); Darstellung aus spec/10 R20 (S7) außer den Plaketten aus N9; neue
Faktenfamilien.
Abnahme: alle Suiten grün, Golden-Rebuild mit Abweichungen je N-Nummer in
report-worker/tests/golden/README.md, Abgleichliste aller Aussagen aus spec/11 Teil 6 (erledigt oder
offen mit Grund). Nach dem Merge setzt Claude die bestätigten Firmennamen, macht requeue-report für alle
sieben und prüft stichprobenartig. Push über SSH, MR gegen main, Merge nach grüner Pipeline mit
Source-Branch entfernen, danach stoppen und Merge-Commit, MR-Nummer, Pipelinenummern, Testzahlen und
offene Fragen melden; kein requeue-report und kein Gegenlesen durch die Session.
