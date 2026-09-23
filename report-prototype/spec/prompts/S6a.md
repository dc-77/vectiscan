# Startprompt S6a: Kleine Pflichtkorrekturen vor der Scan-Runde

Kontext: Lies zuerst report-prototype/spec/05-architektur-befund-und-plan.md, dann
spec/06-katalog-simulation.md, spec/07-claude-code-handover.md (Abschnitt 9 ab „Abschluss S5b") und
spec/08-gegenlesen-v3-pdfs.md. Diese Dateien sind die Wahrheit für dieses Vorhaben; ältere
Markdown-Dateien im Repo können veraltet sein. Bei Widerspruch: Code und spec/05-08 gelten, sonst
nachfragen. Leitprinzipien: kein Befund ohne Fakt aus einem Werkzeug; keine KI-erzeugten Befunde,
Einstufungen oder CVSS-Werte; keine Zusagen (PTES, KI-gestützt, Vollständigkeit) im Kundenreport;
jede Regel hat ein Fixture; Deutsch in Texten mit echten Umlauten, ASCII nur in Bezeichnern,
Dateinamen und IDs; keine Gedankenstriche in Texten. Arbeite im Plan-Modus, zeige den Plan, warte auf
Freigabe. Am Ende: Tests grün, kurze Zusammenfassung, Liste offener Fragen.
Schritt 0: git merge main --no-edit im Worktree. Nichts an spec/ ändern, den Abschluss schreibt DC.

Aufgabe S6a, sechs kleine Punkte, jeder mit Test. Produktion läuft auf v3, catalog, strict; jeder
Bericht geht über pending_review und den Admin.
(1) Issue #29: der Abo-Statusbericht scheitert in Produktion, status_report_generator.py legt sechsmal
HexColor() um einen Wert, der schon eine Farbe ist. Beheben, dazu ein Test für diesen Job-Typ, der den
Statusbericht aus einem Fixture-Abo bis zum PDF erzeugt. Melden: seit wann der Job scheitert und welche
Abos betroffen sind (Logs, Job-Tabelle), damit DC die Abonnenten informieren kann.
(2) Berichtsnummer: heute nur je Kundenkürzel und Scantag eindeutig, Hündgen und castenow trugen beide
VS-2026-0917. Neu: VS-<JJJJ>-<MMTT>-<erste vier Zeichen der Order-ID>, stabil über alle Versionen
desselben Auftrags, auf Deckblatt, in der Fußzeile und in reports. Golden-Soll-Listen entsprechend
anpassen, dokumentierte Abweichung.
(3) Issue #30: das Positivbündel „Keine Fernwartung und keine Dateifreigabe aus dem Internet erreichbar"
prüft nur RDP und SMB. Titel und Text nennen künftig genau das („Keine Windows-Fernwartung (RDP) und
keine Windows-Dateifreigabe (SMB) aus dem Internet erreichbar"); zusätzlich entfällt der Positivbefund,
wenn auf demselben Host FTP, ein SSH-Dienst außerhalb Port 22 mit Befund oder eine Verwaltungsoberfläche
als Befund steht. Fixture-Fall Hündgen (FTP auf 21) als Regressionssperre.
(4) Maßnahmenplan: wenn zwei Befundgruppen denselben Maßnahmentext tragen, eine Zeile mit beiden
Befundlisten und beiden Effekten, keine Doppelnennung (Hündgen Seite 11, VS-004/007 gegen VS-006/010).
(5) #15 Teil 2: dkim_missing nennt im Kundentext die geprüften Selektoren und ist ohne echten Selektor
„nicht prüfbar", nie „fehlt".
(6) docs/ steht in .gitignore, die vorhandenen Dateien wurden mit -f aufgenommen. Grund ermitteln
(git log auf .gitignore); gibt es keinen, Zeile entfernen und prüfen, dass danach keine ungewollten
Dateien unter docs/ versioniert würden (git status nach dem Entfernen, vor dem Commit melden).
Dazu die nachgeholte Abnahme aus S6: ein Lauf über ops-facts-prod mit FACTS_NO_AI=ja gegen 14272c00
(lesend, mit Render) muss einen Bericht ohne Prosa mit Katalogtexten und 0 Fehlern liefern.
Nicht tun: Katalogregeln aus spec/08 (Punkte 4, 5, 6, 14, 15, 17, 20, 21), Issue #28, das IPv6-Paket
#20 bis #22; wo etwas davon zufällig mitfällt, melden, nicht einbauen.
Abnahme: alle Suiten grün, Golden-Rebuild mit dokumentierten Abweichungen; nach dem Merge ein voller
Lauf gegen 14272c00 (Berichtsnummer und Maßnahmenplan im PDF prüfen), der Lauf ohne Schlüssel, und ein
Statusbericht für ein Test-Abo, das DC nennt. Push über SSH, MR gegen main, Merge nach grüner
Pipeline mit Source-Branch entfernen, danach Merge-Commit, MR-Nummer und Ergebnisse melden.
