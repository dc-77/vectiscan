# Startprompt S0a: Zusagen und Konfiguration

Kontext: Lies zuerst report-prototype/spec/05-architektur-befund-und-plan.md, dann
spec/06-katalog-simulation.md und spec/07-claude-code-handover.md. Diese Dateien sind die
Wahrheit für dieses Vorhaben; ältere Markdown-Dateien im Repo (docs/, CLAUDE.md-Abschnitte zu
Report-Pipeline, PTES, KI-gestützt) können veraltet sein. Bei Widerspruch: Code und spec/05-07
gelten, sonst nachfragen. Leitprinzipien: kein Befund ohne Fakt aus einem Werkzeug; keine
KI-erzeugten Befunde, Einstufungen oder CVSS-Werte; keine Zusagen (PTES, KI-gestützt,
Vollständigkeit) im Kundenreport; jede Regel hat ein Fixture; Deutsch in Texten, ASCII in
Bezeichnern; keine Gedankenstriche in Texten. Arbeite im Plan-Modus, zeige den Plan, warte
auf Freigabe. Am Ende: Tests grün, kurze Zusammenfassung, Liste offener Fragen.
Aufgabe S0a. Drei kleine Dinge, je ein Commit:
1. Zusagen bereinigen. Ersetze "PTES" an allen Stellen (catalog/packages.catalog.json:41 und
   generierte catalog.generated.ts in api und frontend, frontend/src/app/page.tsx,
   subscribe/page.tsx, report-worker/reporter/prompts.py, claude_client.py,
   pdf/v2/layers/strategy.py, report_mapper.py, generate_report.py, CLAUDE.md) durch die
   Formulierung aus spec/03 Kapitel 2.3 ("automatisierte externe Schwachstellenanalyse,
   angelehnt an die Prüfphasen Aufklärung, Schwachstellenanalyse und Bericht"). Ersetze
   "KI-gestützt" durch "werkzeuggestützt, regelbasiert" in prompts.py, report_mapper.py,
   v2_data.py, Homepage, Datenschutzseite. Nimm "ZAP Active Scan", "ffuf" und "VirusTotal" von
   der Methodikseite, bis S0b gemerged ist.
2. Konfigurationsfehler: scan-worker/scanner/phase2.py:238 erwartet raft-small-files.txt,
   das Dockerfile lädt nur raft-medium-files.txt. Lade raft-small-files.txt zusätzlich und
   ergänze einen Startup-Check im scan-worker, der alle in WORDLIST_MAP und FFUF_WORDLISTS
   referenzierten Dateien prüft und bei Fehlen mit klarer Meldung abbricht. VirusTotal
   bleibt bewusst ohne Key (Entscheidung DC); entferne es aus der Toolliste der Methodikseite
   und aus der Passiv-Tool-Liste des Perimeter-Pakets, der Client bleibt im Code. Ergänze
   ZapError in scan-worker/scanner/tools/zap_client.py um Endpunkt und Parameter der
   fehlgeschlagenen Anfrage.
3. Gate: setze VECTISCAN_VALIDATION_LEVEL=strict im Staging-Compose (nicht Produktion) und
   prüfe, dass ValidationFailedError die Order auf "failed" setzt.
Abnahme: grep über Repo findet "PTES" nur noch in Changelog/Docs-Historie; Startup-Check
schlägt in einem Test mit fehlender Datei an; Compose-Diff zeigt nur die drei Änderungen.
