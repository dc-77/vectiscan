# Startprompt S2c: IPv6-Nachweis, #8 schließen, zwei Golden-Fixtures von Pilotkunden

Kontext: Lies zuerst report-prototype/spec/05-architektur-befund-und-plan.md, dann
spec/06-katalog-simulation.md und spec/07-claude-code-handover.md. Diese Dateien sind die
Wahrheit für dieses Vorhaben; ältere Markdown-Dateien im Repo (docs/, CLAUDE.md-Abschnitte zu
Report-Pipeline, PTES, KI-gestützt) können veraltet sein. Bei Widerspruch: Code und spec/05-07
gelten, sonst nachfragen. Leitprinzipien: kein Befund ohne Fakt aus einem Werkzeug; keine
KI-erzeugten Befunde, Einstufungen oder CVSS-Werte; keine Zusagen (PTES, KI-gestützt,
Vollständigkeit) im Kundenreport; jede Regel hat ein Fixture; Deutsch in Texten mit echten
Umlauten, ASCII nur in Bezeichnern, Dateinamen und IDs; keine Gedankenstriche in Texten.
Arbeite im Plan-Modus, zeige den Plan, warte auf Freigabe. Am Ende: Tests grün, kurze
Zusammenfassung, Liste offener Fragen.
Schritt 0: git merge main --no-edit im Worktree (der Worktree zweigt vom Juli-Stand ab),
danach spec/07 Abschnitt 9 (Abschluss S2b, freigegebene Scanziele), reporter/facts/README.md
und report-worker/tests/golden/README.md frisch lesen.
Aufgabe S2c. S2b hat die Scanner-Defekte #8 bis #12 behoben und #9, #10, #12 am
Nachweis-Scan belegt. #8 (nmap -6) ist nur per Unit-Test belegt, weil kein eigenes Ziel ein
AAAA hat. DC hat die schriftliche Freigabe zweier Pilotkunden für Entwicklungs- und
Nachweis-Scans und am 20.09. zwei Rescans gestartet: lumbeck-wolter.de (Rescan der Order
68cabf05, drei Domains, Perimeter; Hauptdomain und www mit AAAA 2a01:4f8:d0a:668b::2 auf
Hetzner, Dual-Stack) und junkerwerk.de (Rescan der Order 2572eebc; nachhaltigkeit.junkerwerk.de
mit AAAA 2a01:4f8:d0a:3124::2). Die Order-IDs der Rescans stehen in spec/07 oder kommen
von DC. Beide Kunden sind Pilotkunden; ihre Domains dürfen als Golden-Fixture ins Repo
(Domains sichtbar, Screenshots nicht), wie bei Junkerwerk in S0c.
Vorgehen: (1) Tars der beiden Rescans per GitLab-Job ops-export-golden-tars oder ssh
vectigal-docker02 aus MinIO holen, Screenshots entfernen, Manifest mit sha256. (2) #8 prüfen:
in beiden Tars muss nmap für die AAAA-Hosts einen IPv6-Lauf zeigen (Portliste über IPv6),
die Coverage darf kein target_invalid_ipv6 mehr tragen, und die IPv6-Portliste ist gegen
die IPv4-Portliste desselben Hosts zu vergleichen; Abweichungen (Dienste nur über IPv6
erreichbar) sind ein echter Befund und gehören in die Soll-Liste, nicht in eine Ausnahme.
Ergebnis je Host als Tabelle in der Zusammenfassung. Wenn nmap über IPv6 nichts liefert,
Ursache im Tar zeigen (Scanner-Netz ohne IPv6-Route, Zielfirewall, Fehler), nicht raten;
dann bleibt #8 offen mit dokumentiertem Grund. (3) Beide Orders als zwölftes und
dreizehntes Golden-Fixture aufnehmen: Snapshot (scripts/golden/add-order-to-snapshot.py),
Facts bauen, Katalog laufen lassen, Soll-Listen expected/lumbeck-wolter.json und
expected/junkerwerk-rescan.json mit scripts/golden/build-expected-order.py ableiten (strict
false, DC prüft). lumbeck-wolter ist das erste Multi-Domain-Fixture mit DNS je Domain: die
Facts müssen für alle drei Domains eigene DNS-, SPF-, DMARC-Zeilen tragen, sonst ist #12 an
echten Daten nicht belegt; #17 (zweites enumerate-Ziel ohne eigene Hosts) hier prüfen und
im Issue dokumentieren, ob es noch auftritt. (4) Für Junkerwerk zusätzlich den Drift-Test
über jetzt vier Läufe: die Soll-Liste aus expected/junkerwerk.json muss bis auf begründete
Abweichungen (neue IPv6-Fakten, geänderte Software) halten; jede Abweichung in
expected_map.json benennen. (5) Golden-Rebuild (python -m reporter.facts --golden), Katalog-
und v3-Golden neu bauen, alle Suiten grün.
Nicht tun: Scans auslösen (das macht DC im Admin); Prüfkatalog ändern außer Fixtures und
expected_map; Screenshots ins Repo; keine Kundendomains außer den freigegebenen. Abnahme:
Tabelle IPv6-Nachweis je Host, #8 geschlossen oder mit Grund offen, zwei neue
Golden-Fixtures mit Soll-Listen, Drift-Test Junkerwerk über vier Läufe grün, Pipeline grün.
Push über SSH, MR gegen main, nach Merge Commit-Hash und MR-Nummer melden.
