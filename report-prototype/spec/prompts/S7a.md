# Startprompt S7a: Darstellung des Perimeter-Berichts, E27 Admin-Hinweis, #24

Kontext: Lies zuerst report-prototype/spec/05-architektur-befund-und-plan.md, dann
spec/07-claude-code-handover.md (Abschnitt 9 ab „Abschluss S6c", vor allem „Zuschnitt nach S6c" und
„Abschluss S6d"), spec/10-gegenlesen-scanrunde-2.md (R20 Darstellung mit allen Einzelstellen) und
spec/11-gegenlesen-scanrunde-3.md (Teil 2 die R20-Zeile, Teil 5 der S7-Absatz, Teil 6 N9 Plaketten und die
Entscheidung E27). Diese Dateien sind die Wahrheit für dieses Vorhaben; ältere Markdown-Dateien im Repo
können veraltet sein. Bei Widerspruch: Code und spec/05 bis 11 gelten, sonst nachfragen. Leitprinzipien:
kein Befund ohne Fakt aus einem Werkzeug; keine KI-erzeugten Befunde, Einstufungen oder CVSS-Werte; keine
Zusagen im Kundenreport; jede Änderung hat ein Fixture aus Rohdaten; Deutsch in Texten mit echten
Umlauten, ASCII nur in Bezeichnern, Dateinamen und IDs; keine Gedankenstriche in Texten. Arbeite im
Plan-Modus, zeige den Plan, warte auf Freigabe. Am Ende: Tests grün, kurze Zusammenfassung, Liste
offener Fragen.
Schritt 0: git merge main --no-edit im Worktree (S6d, MR !107 `11d93079`, muss gemerged sein; Faktenschema
1.4.0, Katalog 2026-09-29.1). Nichts an spec/ ändern.
Regeln: Jedes Abbild kommt aus der eigenen Registry ghcr.io/dc-77/vectiscan/, Fremdabbilder nur
gespiegelt und per Digest gepinnt. Nicht mergen, während Scans laufen (Issue #32, vor dem Merge prüfen).
Die Session startet keine Scans und kein requeue-report; Claude erzeugt nach dem Merge neu und liest
gegen. Grundlage sind die 24 Golden-Fixtures und die drei Testaufträge 4394b0b7, f9a2a2f6, cd28d260 in
ihrer Fassung vom 29.09. (Version 2). Diese Session ändert Darstellung, Reihenfolge, Umbrüche, Beschriftung
und Anhänge; Fakten, Katalogregeln, Einstufungen und Befundzahlen bleiben gleich, mit einer Ausnahme
(Punkt 0). Wo ein Darstellungspunkt einen Wert braucht, der schon in den Reportdaten liegt (Endadresse
aus redirect_probe, Hostsuche je Domain aus discovery_health), darf er gelesen werden.

Aufgabe S7a.
(0) Vorab, einziger Inhaltspunkt: Dienstkennungen nie aus Fehlertexten eines Werkzeugs. Bei cd28d260 steht
an 92.205.163.53:8000 der nmap-Text „ERROR: Script execution failed (use -d to debug)" als Kennung in
Kapitel 2 und in einer Betroffen-Zeile. Kennungen aus nmap_versionall, Bannern und Titeln werden gegen eine
Liste von Fehler- und Hinweismustern gefiltert (ERROR, failed, use -d, Timeout, Traceback und ähnliche),
der Port gilt dann als „nicht identifiziert" mit dem vorhandenen Regelweg; Gate-Regel
werkzeugfehler_im_kundentext als Fehler; Fixture cd28d260.
(1) R20 Umbrüche: kein Überschriften-, Kicker- oder Einleitungssatz allein am Seitenende (3.4 mit
Einleitung, Maßnahmenplan-Überschrift getrennt von der Tabelle), kein Kopf einer Befundkarte allein am
Seitenfuß (CA VS-003, LW VS-001), Hebel 2 und 3 nicht allein oben auf Seite 3 (DB, BS, JW, HE, HL, CA),
Tabellenköpfe wiederholt; halbleere Seiten vor Positivbefunden, Befundkarten und Kapitelanfängen
(Füllprüfung aus S6b-1: DB 17, CA 19 und 29 nach S6d, 2d2d4f39 Seite 28, 4e6b6883 27, historisch DB 14, JW 9,
HE 8, LW 16); Ziel: keine halbleere Seite in den 24 Golden-Aufträgen und den drei Testaufträgen, oder je
Rest ein Grund in der README; erzwungene Seitenwechsel nur, wenn der Folgeinhalt sonst zerrissen würde.
(2) R20 Bilder: bei Weiterleitungen zeigt das Foto die Endadresse und die Unterschrift nennt sie
(„online.heuel.com, weitergeleitet auf www.heuel.com", CA umfrage); gleiche Fotos werden zusammengefasst
(„mail, mail2 und autodiscover zeigen dieselbe Anmeldeseite", drei OWA-Fotos bei CA, zwei bei JW);
Bildunterschriften aus redirect_probe; Bilder im Satzspiegel.
(3) R20 Legende und Wortlaut: Legende „Gelb in Kürze" nur, wenn ein Gelb-Befund die Stufe In Kürze hat,
sonst die Stufe, die vorkommt (alle sieben); „DKIM-Schlüssel veröffentlicht" statt „DKIM-Signatur
veröffentlicht"; Anhang E nennt nur Stufen, die es im Bericht gibt (HL); Befundtext wiederholt den
Betroffenen nicht nach einem Doppelpunkt (HE, BS); Titelzitat vollständig („/ Bonn", HE);
Verifikationstext nennt nur Ports, die der Host hat.
(4) R20 Service-Karte, Posture, Anhang B: IPv4 und IPv6 desselben Systems als ein Block, IPv6-Adresse
umbruchfest (JW, HL, 2.1); Service-Karte grau für nur per Portscan erfasste Ports, Ampelfarbe nur mit
Messung, rot oder gelb bei Befund am Port (JW 4433, HE 1000 bis 1002, DB 30000, nach T16 prüfen, was
bleibt); Anhang C ohne Spaltenüberlauf (BS).
(5) Technologietabelle (spec/11 N9): Plakette nur „veraltet" oder „LTS", Zielversion, Lückenzahl und
Quelle in der Hinweisspalte, kein Überdruck; Spaltenkopf „Erkennung (Quelle, Konfidenz)" bleibt.
(6) Anhang C (Antwort auf Frage 2 der S6d-Session): Nebenpfad-Instanzen gemischter ZAP-Gruppen
(robots.txt, sitemap.xml, Abwehr- und Fehlerseiten mit Status 4xx oder 429) als eigene Zeile mit Pfad und
Statuscode, ohne eigenen Befund; Zeile je Meldung mit Anzahl und höchstens sechs Betroffenen bleibt.
(7) Kapitel 2 (Antwort auf Frage 3 der S6d-Session, A9-Rest): je Zieldomain eine Zeile „Hostsuche: n Namen
gefunden, m geprüft, k gefunden und nicht geprüft" aus discovery_health, bei Mehrziel-Aufträgen je Domain
(junkerwerk.de und junkerwerk.hu); die Liste „gefunden, nicht geprüft" bleibt.
(8) E27 Admin-Hinweis: im Admin-Review ein Hinweis nach dem Muster frist_vor_berichtsdatum, wenn eine
Fristregel (cert_expiring_later, cert_expiring_soon, service_cert_expired, domain_expiring) am
Berichtsdatum anders ausfiele als am Scantag (HL online.heuel.com: 31 Tage am Scantag, 28 am
Berichtsdatum, Schwelle 30); Stufe und Regelauslösung bleiben am Scantag, im Bericht der bestehende
R18-Hinweis; Fixture aus einem Golden-Auftrag mit passendem Datum oder mit festgesetztem Berichtsdatum im
Test; api- und frontend-Anteil klein, mit Test.
(9) Download und Deckblatt: Dateiname aus der Auslieferungsversion (nicht der Erzeugungsnummer), Deckblatt
„Version n" und Fußzeile „Erzeugung m" konsistent (spec/10 Teil 2 DB).
(10) #24 Speicherbedarf des report-worker mit WeasyPrint messen: `docker stats` während `ops-render-v3` an
den drei größten Golden-Aufträgen, Spitzenwert in `MONITORING.md`, Grenze (1 GB) anpassen oder bestätigen,
Issue #24 mit Messwert schließen.
Nicht tun: Pakete, Rahmenwerk-Tags, Export (S7b nach dem ersten Kundentest); Katalogtexte, Regeln,
Einstufungen, Fakten (außer Punkt 0); Scanner; IPv6-Route; keine Scans, kein requeue, nichts an spec/.
Entscheidungen, die im Plan zu bestätigen sind: Wortlaut der Hostsuche-Zeile (7) und der Legende (3).
Abnahme: alle Suiten grün; PDF-Suite mit neuer Seitenerwartung über `ops-update-pages` und Erklärung je
Auftrag in `report-worker/tests/golden/README.md`, Abschnitt „Darstellung nach S7a"; Füllprüfung ohne
halbleere Seiten in den 24 Golden-Aufträgen und den drei Testaufträgen oder je Rest ein Grund;
Golden-Facts unverändert (`reporter.facts --golden --check` 0 Abweichungen außer Punkt 0 bei cd28d260);
Befundzahlen und Einstufungen aller Golden-Aufträge unverändert; Gate ohne Fehler. Push über SSH, MR gegen
main, Merge nach grüner Pipeline und nur, wenn kein Scan läuft, Source-Branch entfernen, danach
Merge-Commit, MR-Nummer, Testzahlen, Seitenzahlen je Auftrag, Messwert #24 und offene Fragen melden.
Danach macht Claude die Testrunde gegen die sieben Ziele mit dem Nachscan nach spec/11 E19 über die API
(nacheinander, kein Merge während der Scans) und liest als spec/13 gegen; die neuen Aufträge werden
Golden-Fixtures, dann folgt der erste Neukundentest.
