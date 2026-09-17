# Startprompt S0b: zap_active reparieren

Kontext: Lies zuerst report-prototype/spec/05-architektur-befund-und-plan.md, dann
spec/06-katalog-simulation.md und spec/07-claude-code-handover.md. Diese Dateien sind die
Wahrheit für dieses Vorhaben; ältere Markdown-Dateien im Repo (docs/, CLAUDE.md-Abschnitte zu
Report-Pipeline, PTES, KI-gestützt) können veraltet sein. Bei Widerspruch: Code und spec/05-07
gelten, sonst nachfragen. Leitprinzipien: kein Befund ohne Fakt aus einem Werkzeug; keine
KI-erzeugten Befunde, Einstufungen oder CVSS-Werte; keine Zusagen (PTES, KI-gestützt,
Vollständigkeit) im Kundenreport; jede Regel hat ein Fixture; Deutsch in Texten, ASCII in
Bezeichnern; keine Gedankenstriche in Texten. Arbeite im Plan-Modus, zeige den Plan, warte
auf Freigabe. Am Ende: Tests grün, kurze Zusammenfassung, Liste offener Fragen.
Aufgabe S0b. zap_active hat in 42 Produktionsscans nie ein Ergebnis geliefert: 26× ZAP-API
400 "does_not_exist", 2× "url_not_found", 1× "url_not_in_context", 1× "illegal_parameter"
(Diagnose in spec/07 Abschnitt 4). Ablauf in scan-worker/scanner/phase2.py:1483-1552 und
tools/zap_client.py:255-400, Pool in zap_pool.py.
Vorgehen: (1) Lies den Code und formuliere Hypothesen, an erster Stelle Instanz-Affinität im
ZAP-Pool (Kontext und Policy in Instanz A, Scan in Instanz B) und aufgeräumter Kontext.
(2) Reproduziere lokal mit docker compose gegen ein eigenes Ziel (z. B. ein lokaler
Test-Webserver-Container); lies die ZAP-Logs. (3) Behebe die Ursache, mache addScanPolicy
idempotent, stelle sicher, dass Spider, Kontext, Policy und Active Scan dieselbe
Pool-Verbindung nutzen. (4) Schreibe einen Integrationstest, der Spider plus Active Scan gegen
den Testcontainer fährt und mindestens einen Active-Alert erwartet. (5) Prüfe, dass
zap_active-Ergebnisse (Alerts mit pluginId) im Tar landen und vom Parser gelesen werden.
Nicht tun: Active Scan gegen fremde Ziele ohne Freigabe. Abnahme: Integrationstest grün,
ein Staging-Scan mit zap_active status=ok und Alert-Liste im Tar.
