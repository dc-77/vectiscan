# Startprompt S2b: Scanner-Defekte vor S3 (Issues #8 bis #14)

Kontext: Lies zuerst report-prototype/spec/05-architektur-befund-und-plan.md, dann
spec/06-katalog-simulation.md und spec/07-claude-code-handover.md. Diese Dateien sind die
Wahrheit für dieses Vorhaben; ältere Markdown-Dateien im Repo (docs/, CLAUDE.md-Abschnitte zu
Report-Pipeline, PTES, KI-gestützt) können veraltet sein. Bei Widerspruch: Code und spec/05-07
gelten, sonst nachfragen. Leitprinzipien: kein Befund ohne Fakt aus einem Werkzeug; keine
KI-erzeugten Befunde, Einstufungen oder CVSS-Werte; keine Zusagen (PTES, KI-gestützt,
Vollständigkeit) im Kundenreport; jede Regel hat ein Fixture; Deutsch in Texten, ASCII in
Bezeichnern; keine Gedankenstriche in Texten. Arbeite im Plan-Modus, zeige den Plan, warte
auf Freigabe. Am Ende: Tests grün, kurze Zusammenfassung, Liste offener Fragen.
Schritt 0: git merge main --no-edit im Worktree (der Worktree zweigt vom Juli-Stand ab),
danach spec/05-07, reporter/facts/README.md (Abschnitt Datenfallen) und
reporter/catalog/README.md frisch lesen.
Aufgabe S2b. S1 (facts.json) und S2 (Prüfkatalog, 72 Prüfungen) sind gemerged. Beide
arbeiten auf den Golden-Facts aus alten Scans. S3 braucht Live-Facts aus dem Scanner, und
S1 hat fünf Defekte im scan-worker dokumentiert, durch die Facts an der Quelle fehlen oder
verloren gehen. Der facts-Builder verarbeitet richtig, was da ist; die Lücke sitzt davor.
GitLab-Issues, alle mit Label "vor S3":
#8 nmap läuft ohne -6, IPv6-Ziele werden nie gescannt (heute target_invalid_ipv6 in facts).
#9 testssl läuft im Perimeter-Paket mit --severity MEDIUM, dadurch fehlen LOW- und
INFO-Zeilen (Protokolle, Cipher-Details), die der Katalog für TLS-Prüfungen braucht.
#10 headers.json und httpx.json werden je VHost überschrieben, es überlebt nur der letzte
VHost eines Hosts; Header-Prüfungen sehen dadurch nur einen Teil der Webseiten.
#11 tech_enricher liest zap_spider.json statt zap_spider_urls.json (falsche Eingabedatei).
#12 Multi-Target: die zweite Domain einer Order bekommt keine eigenen DNS- und Passivläufe,
domainweite Zeilen tragen kein Domainfeld; der Katalog kann für die zweite Domain keine
SPF/DMARC-Aussage treffen (bei Junkerwerk: junkerwerk.hu).
#13 report-worker/reporter/facts/tool_coverage.py: zap mit status ok und null Alerts soll
als "empty" geführt werden, nicht als ok; danach Golden-Facts neu bauen
(python -m reporter.facts --golden), Katalog-Drift-Test muss grün bleiben, der bisherige
Auffang über zap_no_alerts im Katalog kann dann entfallen (mit S2-README abgleichen).
#14 Order 14272c00 (dortmund-beach.com, erster Produktionslauf mit zap_active status=ok,
1269 Alerts, Ziel von DC freigegeben) als elftes Golden-Fixture aufnehmen: Tar per
GitLab-Job ops-export-golden-tars oder ssh vectigal-docker02 aus MinIO holen, Screenshots
entfernen, Manifest mit sha256 wie in S0c, Golden-Facts bauen, Katalog laufen lassen und
eine Soll-Liste expected/dortmund-beach.json anlegen (DC prüft sie vor dem Merge). Damit
werden web_vulnerability_active und sensitive_path_exposed erstmals an echten Daten prüfbar.
Vorgehen: (1) Plan mit Reihenfolge; #8 bis #12 sind scan-worker, #13 und #14 sind
report-worker, trenne sie in eigene Commits. (2) Je Scanner-Defekt: Ursache im Code zeigen,
Fix, Unit-Test mit Fixture, der den Defekt vorher reproduziert und nachher nicht mehr.
Bei #10 muss die Ablage je VHost eindeutig werden (Dateiname oder Struktur), der
facts-Builder liest dann alle VHosts; passe reporter/facts entsprechend an und halte den
Tar-Aufbau in reporter/facts/README.md fest. Bei #12 entscheide mit DC, ob die zweite
Domain eigene DNS- und Passivläufe bekommt oder die domainweiten Zeilen ein Domainfeld
tragen; Vorschlag: beides, weil der Katalog nach domain gruppiert. (3) Golden-Rebuild
und Drift-Test nach jeder Änderung an reporter/facts. (4) Die alten zehn Golden-Tars
bleiben unverändert (historische Rohdaten), nur die daraus gebauten Facts ändern sich.
Nicht tun: Scans gegen Kundendomains; Änderungen am Prüfkatalog außer dem Rückbau von
zap_no_alerts; keine Anpassung der Scanner-KI-Prompts. Abnahme: alle Tests grün (scan-worker
und report-worker), Golden-Facts neu gebaut und Drift-Test grün, elftes Golden-Fixture mit
Soll-Liste im Repo, MR-Pipeline grün. Danach als eigener Schritt nach dem Deploy ein
Nachweis-Scan gegen dortmund-beach.com: IPv6 gescannt (falls das Ziel AAAA hat, sonst
dokumentieren), Header aller VHosts im Tar, testssl mit Protokollzeilen, zweite Domain
mit DNS-Fakten, wenn die Order zwei Domains hat. Ergebnis mit Order-ID melden, dann
schließt DC die Issues.
