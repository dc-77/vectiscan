# Startprompt S0c: Golden-Fixtures

Kontext: Lies zuerst report-prototype/spec/05-architektur-befund-und-plan.md, dann
spec/06-katalog-simulation.md und spec/07-claude-code-handover.md. Diese Dateien sind die
Wahrheit für dieses Vorhaben; ältere Markdown-Dateien im Repo (docs/, CLAUDE.md-Abschnitte zu
Report-Pipeline, PTES, KI-gestützt) können veraltet sein. Bei Widerspruch: Code und spec/05-07
gelten, sonst nachfragen. Leitprinzipien: kein Befund ohne Fakt aus einem Werkzeug; keine
KI-erzeugten Befunde, Einstufungen oder CVSS-Werte; keine Zusagen (PTES, KI-gestützt,
Vollständigkeit) im Kundenreport; jede Regel hat ein Fixture; Deutsch in Texten, ASCII in
Bezeichnern; keine Gedankenstriche in Texten. Arbeite im Plan-Modus, zeige den Plan, warte
auf Freigabe. Am Ende: Tests grün, kurze Zusammenfassung, Liste offener Fragen.
Aufgabe S0c. Lege report-worker/tests/golden/ an. Inhalt: (1) die Roh-Tars aus MinIO
(scan-rawdata/<orderId>.tar.gz) für die drei Junkerwerk-Orders 0bf16342-ed96-4b0e-a596-05aee3a62cb5,
2572eebc-6135-40e6-b1d2-e9dfccc20ae6, a6df9d9d-eccd-49d1-8dd3-b00a5e005108 sowie je einen
Lauf von securess.de (2026-07-19), heuel.com (neuester), castenow.de (2026-07-22),
trunk-immobilien.de, krause-computer.de; Zugriff über die MinIO-Zugangsdaten aus
docker-compose (nicht in den Prompt schreiben, aus .env lesen). (2) Den API-Snapshot aus
report-prototype/input/_all/ als tests/golden/api-snapshot/ (findings, results, order je Order).
(3) Soll-Listen: aus report-prototype/build/report_data.py die 15 Befunde und 8 Positivbefunde
des Junkerwerk-Prototyps als tests/golden/expected/junkerwerk.json (id, family, scale, level,
affected). (4) Negativ-Fixtures: die 35 Falschbefunde aus spec/06 Abschnitt 3 als
tests/golden/negative.json (order, Titel, Grund, welcher Fakt sie widerlegt).
Fixtures anonymisieren: keine Kundennamen außer Junkerwerk (freigegeben) in Dateinamen;
Domains bleiben, weil die Fakten sonst wertlos sind; Verzeichnis in .gitattributes als
binär markieren, Größe prüfen (Tars unter 5 MB je Order, sonst Screenshots entfernen).
Abnahme: pytest findet die Fixtures, ein Smoke-Test entpackt jedes Tar und ruft
parser.parse_scan_data darauf ohne Fehler auf.
