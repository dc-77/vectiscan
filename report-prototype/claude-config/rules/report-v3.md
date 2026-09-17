---
paths: ["report-worker/**", "scan-worker/**", "report-prototype/**", "api/**", "frontend/**"]
---
# Report v3 und Prüfkatalog: verbindliche Regeln

Kontext: Lies zuerst report-prototype/spec/05-architektur-befund-und-plan.md, dann
spec/06-katalog-simulation.md und spec/07-claude-code-handover.md. Diese Dateien sind die
Wahrheit für dieses Vorhaben; ältere Markdown-Dateien im Repo (docs/, CLAUDE.md-Abschnitte zu
Report-Pipeline, PTES, KI-gestützt) können veraltet sein. Bei Widerspruch: Code und spec/05-07
gelten, sonst nachfragen. Leitprinzipien: kein Befund ohne Fakt aus einem Werkzeug; keine
KI-erzeugten Befunde, Einstufungen oder CVSS-Werte; keine Zusagen (PTES, KI-gestützt,
Vollständigkeit) im Kundenreport; jede Regel hat ein Fixture; Deutsch in Texten, ASCII in
Bezeichnern; keine Gedankenstriche in Texten. Arbeite im Plan-Modus, zeige den Plan, warte
auf Freigabe. Am Ende: Tests grün, kurze Zusammenfassung, Liste offener Fragen.

Zusätzlich:
- Neuer Code liegt in report-worker/reporter/facts/, report-worker/reporter/catalog/, report-worker/reporter/pdf/v3/. Der alte Reporter-Pfad wird bis Session S6 nicht verändert, nur per Env umschaltbar gemacht.
- Jede Prüfung im Katalog ist eine YAML-Datei mit Fixture. Einstufungen kommen aus der Entscheidungstabelle, nie aus eigener Einschätzung eines Agents.
- Golden-Tests unter report-worker/tests/golden/ sind das Gate: Drift-Test (drei Junkerwerk-Läufe, eine Ergebnisliste), Negativ-Fixtures (35 Falschbefunde dürfen nicht entstehen).
- Werkzeuge im Kundenreport ohne Versionsnummer. Keine Eigen-CVSS. Keine Aufwände oder Kosten im Kundenreport. Sie-Form.
- Vor einem Merge: Tests grün, kurze Zusammenfassung, offene Fragen als Liste. Push nur auf ausdrückliche Anweisung.
