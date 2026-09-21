# Startprompt S5b: Produktionsanbindung der Faktenschicht, WebCheck-Fixture

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
Schritt 0: git merge main --no-edit im Worktree, danach spec/07 Abschnitt 9 ab „Abschluss S3",
reporter/facts/README.md (Anbindung, Datenfallen), reporter/v3/README.md und
reporter/pdf/v3/pipeline.py frisch lesen. Nichts an spec/ ändern, den Abschluss schreibt DC.
Aufgabe S5b. S1 bis S5 sind gemerged, alle Nachweise liefen über den Ops-Job mit Golden-Tar.
Der Produktionspfad im report-worker (worker.py mit VECTISCAN_REPORT_LAYOUT=v3) liefert dem
facts-Builder heute keine tool_runs: `_load_tool_runs` gibt weder `created_at` noch
`raw_output` für header_check, testssl, nmap und ai_* zurück. Folge: die Abdeckung bleibt
`unknown`, TLS-Protokolle fehlen, und das v3-Gate blockiert jeden echten Lauf mit
`abdeckungskapitel_leer` (in S5 an Order 14272c00 gezeigt). Ohne diese Anbindung kann S6 nicht
umschalten. Dazu bleibt Anhang A.3 leer, weil die Phase-3-Anreicherung (KI#4, enrichment) nicht
in den Fakten ankommt, und `cve_*`, `tls_known_vulnerability` sind in echten Läufen nie prüfbar.
Vorgehen: (1) `_load_tool_runs` so erweitern, dass der Worker `build_facts(..., tool_runs=...)`
mit denselben Zeilen versorgt, die der Tar-Eingang liefert (`scan_results` mit `created_at`,
`raw_output`, Status je Werkzeug und Host). Nachweis der Gleichheit: für eine Order, die als
Golden-Fixture vorliegt, müssen die Facts aus dem Produktionspfad und aus dem Tar bis auf
`observed_at`-Formatierung identisch sein; das ist ein Test, kein Augenmaß. (2) Phase-3-
Anreicherung in die Facts: die `ai_*`-Zeilen (Korrelation, CVE-Anreicherung) werden als Fakten
mit `source: enrichment` und Confidence geführt, nie als Befund; damit werden `cve_*` und
Anhang A.3 an echten Daten prüfbar. Prüfe an Junkerwerk (zwei testssl-CVE) und castenow.
(3) Hook `VECTISCAN_FACTS_EXPORT=1`: der Worker legt `facts.json` und das Katalogergebnis
neben den Report in MinIO ab (Schlüssel `<order_id>/facts.json`, `<order_id>/catalog.json`),
damit Admin-Review, Debugging und der S7-Export sie haben; ohne den Schalter ändert sich nichts.
(4) WebCheck-Golden-Fixture aus Order 75338c97 (vectigal.tech und vectiscan.de, S2b-
Nachweislauf, eigene Domains, Issue #23): Tar, Snapshot, Facts, Katalog, Reportdaten, Soll-Liste
(strict false), Render mit Paketvariante webcheck; damit ist die Variante erstmals an echten
Daten geprüft. Vierzehntes Fixture, Manifest 14/14. Beim Snapshot `customer_context` auf
`firmenname` reduzieren: keine Personennamen (Inhaber, Geschäftsführer), keine Adressen, keine
Recherche-Fundstellen ins Repo, auch nicht bei eigenen Domains; das gilt rückwirkend für die
13 bestehenden Snapshots, falls dort seit S5 Kundenkontext liegt. (5) Golden-Rebuild und alle Suiten grün;
die 13 bestehenden Golden-Facts dürfen sich durch (1) und (2) nur dort ändern, wo neue
Enrichment-Fakten hinzukommen, jede andere Abweichung ist ein Fehler.
Abnahme über den Produktionspfad, nicht über den Ops-Job mit Tar: ein Ops-Job, der
`worker.generate_report` mit `VECTISCAN_REPORT_LAYOUT=v3` gegen die Produktions-Order
4e6b6883 (castenow) und 14272c00 (dortmund-beach) aufruft, ohne die Produktionsumschaltung.
Melden: Abdeckung je Host nicht `unknown`, TLS-Protokolle vorhanden, Anhang A.3 gefüllt,
0 Defekte, Facts-Gleichheitstest grün, Speicher und Laufzeit. Produktion bleibt auf v2 und warn.
Nicht tun: Katalogregeln ändern (außer Fixtures und expected_map); worker.py auf v3 umstellen;
Scanner anfassen; Issues #15, #16 (Katalog, vor S6) und das IPv6-Paket (#20 bis #22, nach S6).
Push über SSH, MR gegen main, nach Merge Commit-Hash und MR-Nummer melden.
