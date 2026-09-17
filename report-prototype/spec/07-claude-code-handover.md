# Übergabe an Claude Code: Reihenfolge, Sessions, Startprompts, Einstellungen

Stand 17.09.2026. Intern. Grundlage: spec/04 (Arbeitspakete), spec/05 (Architektur-Befund, Entscheidungen), spec/06 (Katalog-Simulation, Werkzeugabdeckung). Dieses Dokument ist der Fahrplan für die Umsetzung in Claude-Code-Sessions.

## 1. Entschieden und bestätigt (DC, 17.09.)

- Fakten zuerst, Prüfungen aus Regeln, Text zuletzt. Prüfkatalog als Produktdefinition, Befund = nicht bestandene Prüfung, Positivbefund = bestandene Prüfung, Abdeckungslücke = nicht prüfbare Prüfung.
- Katalogtexte als Grundlage, KI nur für Kontextabsätze mit Gate.
- WeasyPrint aus dem Prototyp wird Renderer v3; ReportLab v2 bleibt schaltbar.
- Gate strict, neuer Order-Status `report_blocked`, Admin sieht Defektliste.
- Scanner-KI (#1 bis #4) bleibt, protokolliert Entscheidungen.
- Prüfungen tragen Rahmenwerk-Tags (BSI-Baustein, NIS2-Artikel, ISO-Control, TR-03116) von Anfang an. Pakete sind Mengen von Prüfungen. Kein Paket verspricht ein Rahmenwerk; es liefert „die Prüfungen, die man von außen für Rahmenwerk X machen kann". Prüfergebnisse werden maschinenlesbar exportiert, damit andere Vectigal-Lösungen sie verwenden können.
- zap_active und ffuf_sensitive sollen funktionieren (Diagnose Abschnitt 4).
- VirusTotal: vorerst ohne. Kein Key, kein Vertrag; Reputation aus URLhaus, AbuseIPDB, GreyNoise, OTX. VirusTotal von der Methodikseite streichen.
- Befund-IDs: Kundenkürzel optional (Feld im Bestellprozess, im Admin-Review pflegbar). Mit Kürzel `VS-<Kürzel>-<Jahr>-<lfd>`, ohne Kürzel wie heute `VS-<Jahr>-<lfd>`.
- Kundenkontext (Branche, Mitarbeiterzahl, Systemzweck): optional bei der Beauftragung abfragen, zusätzlich automatische Web-Recherche als Vorschlag, im Admin-Review pflegbar und übersteuerbar. Quelle je Feld wird gespeichert (Kunde, Recherche, Admin).
- Junkerwerk-Rohdaten dürfen als Golden-Fixture ins Repo (Domains sichtbar, Screenshots nicht).
- Modelle in Claude Code: Hauptsessions mindestens Opus, Fable in Spezialfällen. Sonnet nur als Subagent für musterbasierte, testgeprüfte Arbeit (Prüfungen nach Vorlage, Fixtures, Template-Übernahme, Doku, Suchaufgaben), nie für Entwurf, Fehlersuche oder Löschungen. Max-Abo, kein Sparzwang: Effort `high` als Standard, `xhigh` für die Fable-Sessions.

## 2. Branch-Strategie: kein 2.0-Branch

Empfehlung: **Trunk-basiert mit Schalter, kein langlebiger 2.0-Branch.** Gründe:

- Der Scanner bleibt und wird parallel gepflegt (ZAP-Fix, Wordlist, Coverage-Protokoll). Ein 2.0-Branch würde wochenlang von `main` wegdriften, und jede Scanner-Änderung müsste doppelt gemerged werden.
- Die Golden-Fixtures kommen aus Produktionsdaten, und der Vergleich alt gegen neu (v2-Report neben v3-Report für dieselbe Order) ist nur im selben Stand möglich.
- Das Repo hat das Muster schon: `VECTISCAN_REPORT_LAYOUT=v2` schaltet den Renderer. Genauso schaltet `VECTISCAN_REPORT_ENGINE=catalog` den neuen Reporter. Beide Wege laufen in derselben Codebasis, bis v3 zwei Kundenreports ohne Beanstandung geliefert hat.

Konkret: ein kurzlebiger Branch je Session (`claude --worktree <name>` legt ihn an), Merge nach `main` sobald die Tests der Session grün sind, nie länger als ein paar Tage offen. „Version 2.0" ist das Release-Label für den Tag, an dem `catalog` Default wird und die Reparaturkette gelöscht ist (Session S6). Nicht der Name eines Branches.

Neuer Code liegt in eigenen Paketen, damit alt und neu sich nicht berühren: `report-worker/reporter/facts/`, `report-worker/reporter/catalog/`, `report-worker/reporter/pdf/v3/`. Der alte Pfad wird erst in S6 entfernt.

## 3. Reihenfolge und Sessions

Jede Session ist eine Claude-Code-Sitzung in eigenem Worktree mit einem vollständigen Startprompt (Abschnitt 5). Jede endet mit grünen Tests und einem Merge. Größen: S = halber Tag, M = ein bis zwei Tage, L = drei bis fünf Tage, jeweils Session-Laufzeit mit Review durch DC.

| Nr | Session | Größe | Modell | Effort | Abhängig von |
|---|---|---|---|---|---|
| S0a | Zusagen bereinigen, Konfigurationsfehler (Wordlist, ZapError-Endpunkt), Gate strict im Staging | S | opus | high | nichts |
| S0b | zap_active reparieren (Live-Reproduktion gegen ZAP-Pool) | M | fable | xhigh | nichts |
| S0c | Golden-Fixtures anlegen (Tars aus MinIO, API-Snapshot, Soll-Listen) | S | opus | high | nichts |
| S1 | facts.json: Schema, Builder, Versionsnormalisierung, Coverage | L | fable | xhigh | S0c |
| S2 | Prüfkatalog: Engine, 45 Prüfungen, Ignorierliste, Auffangregeln, Fixtures, Drift-Test | L | fable (Engine, Entscheidungstabelle, erste 5 Prüfungen), Sonnet-Subagents (restliche Prüfungen nach Vorlage) | xhigh / high | S1 |
| S3 | Reportdaten v3 + Textkatalog + Prosa-KI mit Gate + Kundenkontext | M | opus | high | S2 |
| S4 | Renderer v3 (WeasyPrint im Worker, Paketvarianten, Schalter) | M | opus | high | S3 (parallel zu S2 möglich mit Prototyp-Daten) |
| S5 | Gate strict in Produktion, `report_blocked`, Admin-Defektliste, Beobachtungen ohne Regel, Kundenkontext-Felder | M | opus | high | S2 |
| S6 | Umschaltung, Reparaturkette entfernen, Doku, CATALOG_VERSION | M | fable | xhigh | S3, S4, S5 |
| S7 | Pakete: Mail-Security, TLS-Compliance, Rahmenwerk-Tags, Export der Prüfergebnisse | M | opus | high | S6 |

Parallel möglich: S0a, S0b, S0c gleichzeitig. S4 neben S2. S5 neben S3. Kritischer Pfad: S0c → S1 → S2 → S3 → S6.

Erwartete Gesamtdauer bei einer Session am Tag: vier bis fünf Wochen bis S6. Bis dahin liefert der Prototyp-Weg (report-prototype, manuell kuratiert) auslieferungsfähige Kundenreports.

## 4. Diagnose der drei toten Werkzeuge

**ffuf_sensitive (0 von 42, „wordlist_missing")**: `phase2.py:238` erwartet `seclists/Discovery/Web-Content/raft-small-files.txt`, das Dockerfile (Zeile 145 ff.) lädt nur `raft-medium-files.txt`. Namensabweichung, nie aufgefallen, weil der Skip als „ok" gezählt wird. Fix: eine curl-Zeile im Dockerfile oder Pfad in `WORDLIST_MAP`/`FFUF_WORDLISTS` auf medium setzen (17,5k Einträge, mit dem Hard-Cap im Kommentar von Zeile 225 abgleichen). Dazu ein Startup-Check im Worker: jede referenzierte Wordlist muss existieren, sonst Fehler beim Start statt 42 stille Skips.

**virustotal (0 von 14, „no_api_key")**: `passive/virustotal_client.py:26` liest `VIRUSTOTAL_API_KEY`; `docker-compose.yml` reicht die Variable an keinen Worker durch (nur `SHODAN_API_KEY`, `ABUSEIPDB_API_KEY`). Fix: Variable in compose und `.env` ergänzen, Key aus einem VirusTotal-Konto. Vorher prüfen: Die kostenlose VT-API ist laut Nutzungsbedingungen nicht für kommerzielle Produkte gedacht; für VectiScan ist entweder ein Premium-Vertrag nötig oder der Verzicht (URLhaus, AbuseIPDB, GreyNoise und OTX decken Reputation bereits ab). Entschieden (DC): vorerst ohne VirusTotal. Prüfung „Domain in Malware-Feeds" stützt sich auf die vier anderen Quellen; VirusTotal wird von der Methodikseite gestrichen und der Client bleibt inaktiv.

**zap_active (0 von 42; 26× `does_not_exist`, 2× `url_not_found`, 1× `url_not_in_context`, 1× `illegal_parameter`)**: Ablauf in `phase2.py:1483-1552`: Policy anlegen (`create_scan_policy`), `start_active_scan(url, context_id, scan_policy)`, pollen. `does_not_exist` liefert ZAP, wenn die angegebene Policy oder der Kontext in *dieser* ZAP-Instanz nicht existiert. Wahrscheinlichste Ursache angesichts des ZAP-Pools (`zap_pool.py`, mehrere Daemons): Kontext und Policy werden in einer Instanz angelegt, der Active-Scan-Aufruf trifft eine andere, oder der Kontext des Spiders ist beim Active Scan schon abgeräumt. `url_not_found` bedeutet leerer Spider-Baum, `url_not_in_context` ein Include-Muster, das die Ziel-URL nicht deckt. Die Fehlermeldung nennt heute nicht, welcher Endpunkt fehlschlug (`ZapError` trägt nur die ZAP-Antwort). Vorgehen in S0b: (1) `ZapError` um Endpunkt und Parameter ergänzen, (2) einen Scan gegen ein eigenes Ziel mit ZAP-Logs reproduzieren, (3) Instanz-Affinität für Kontext, Policy und Scan sicherstellen (dieselbe Pool-Verbindung für alle drei Schritte), (4) `addScanPolicy` idempotent machen (`already_exists` abfangen), (5) Test, der einen vollständigen Spider-plus-Active-Lauf gegen einen lokalen Testcontainer fährt. Bis der Fix produktiv ist: „ZAP Active Scan" von der Methodikseite nehmen.

**Ergebnis S0b (17.09.2026, reproduziert gegen ZAP 2.17.0 mit eigenem Testziel).** Die oben vermutete Instanz-Affinität ist *nicht* die Ursache. Ein erzwungener Split (Kontext und Policy auf Instanz A, Active Scan auf Instanz B) liefert `context_not_found`, nicht `does_not_exist`. Die tatsächliche Ursache liegt eine Stufe früher, in `create_scan_policy`: `enableScanners` bekommt die fest verdrahteten Scanner-IDs aus `CATEGORY_SCANNER_IDS`, und zwei davon sind im Image gar nicht installiert (`40024` SQL Injection SQLite in der Kategorie `sqli`, `40046` SSRF in der Kategorie `ssrf`; beide liegen in Add-ons, die `zaproxy/zap-stable` nicht mitbringt). ZAP lehnt den gesamten Aufruf dann mit `{"code":"does_not_exist","message":"Does Not Exist","detail":"IDs: [40024]"}` ab. In Produktion steht `api.incerrordetails` auf dem Vorgabewert `false`, deshalb fehlt das Feld `detail` und übrig bleibt exakt der Text aus den 42 Scans. Weil `sqli` in jeder Kategorie-Liste steht (Default wie KI #3), scheiterte der Active Scan sofort und mit `durationMs 0`, noch bevor ein einziger Request an das Ziel ging. Zwei IDs im Katalog (`10010`, `10054`) waren zusätzlich passive Regeln, die in einer Active-Scan-Policy nie existieren können. Fix: angeforderte IDs gegen `ascan/view/scanners` schneiden, unbekannte in die Abdeckung schreiben statt an ZAP zu schicken; `addScanPolicy` idempotent; ZAP-Version gepinnt, weil der Regelsatz am Image hängt. Die Instanz-Affinität wurde trotzdem repariert (Thread-Local erreichte die Stage-Threads nicht), ebenso `url_not_found`/`url_not_in_context` (Scanziel war `fqdns[0]` statt eines gespiderten VHosts) und `illegal_parameter` (Doppelpunkte in IPv6-Policy-Namen).

Offen zu S0b:

- **Abnahme.** S0b gilt erst als abgenommen, wenn nach dem Merge auf `main` über `deploy-auto` (sobald MinIO gepinnt ist) ein Scan gegen ein eigenes Ziel (`vectiscan.de` oder `vectigal.tech`, nie ein Kunde) `zap_active status=ok` mit Alert-Liste im Tar liefert.
- **`ZAP_POOL_ENABLED` ist in Produktion nicht gesetzt** (geprüft 17.09.2026 auf vectigal-docker02: in `/opt/apps/vectiscan/.env` kein Eintrag, damit greift der Compose-Default `false` in den Zeilen 261, 331, 375). Produktion läuft also ohne Pool, Worker zu ZAP fest 1:1 über `ZAP_BASE_URL` (`scan-worker-1`→`zap-1`, `-2`→`zap-2`, `-3`→`zap-3`), `zap-4` ist unbenutzt. Zwei Folgerungen. Erstens: der Affinitätsfix ist in Produktion heute wirkungslos, aber richtig für den Tag, an dem der Pool eingeschaltet wird; ohne ihn hätte `ZAP_POOL_ENABLED=true` den Scan sofort gebrochen, weil Lease und tatsächliche Verbindung auseinandergelaufen wären. Zweitens: er bestätigt die Ursachenanalyse. Ohne Pool wird `set_thread_zap_id` nie aufgerufen, alle ZAP-Aufrufe eines Host-Scans landen auf demselben Daemon, ein Instanz-Split war gar nicht möglich. Die fehlende Scanner-ID bleibt damit die einzige Erklärung für die 26 `does_not_exist`.
- **Kategorie `ssrf` ist nicht verfügbar** (Regel 40046 fehlt im Image), `sqli` deckt fünf statt sechs Regeln ab (40024 fehlt). Entscheidung DC: kein Add-on nachziehen, weil SSRF-Tests und SQLite-SQL-Injection gegen fremde Produktionssysteme ohnehin an der Grenze eines automatisierten Außenscans liegen. In `ZapClient.CATEGORIES_UNAVAILABLE` markiert, aus Prompt und Regelkonfiguration entfernt, Drift-Test `scan-worker/tests/test_zap_categories_drift.py`. Wiedervorlage bei der Paketdefinition in S7.
- **Methodikseite:** „ZAP Active Scan" kommt erst mit dem Datum des ersten erfolgreichen Produktionslaufs zurück. Als Aufgabe in S3 eingetragen.

## 5. Startprompts

Alle Prompts setzen voraus: Repo `vectiscan`, Arbeitsordner `report-prototype/` mit `spec/04` bis `spec/07`, `build/catalog_sim.py`, `build/report_data.py`, `build/template.html.j2`, `input/_all/` (API-Snapshot, gitignored). Jede Session beginnt im Plan-Modus; DC prüft den Plan, dann Umsetzung.

Gemeinsamer Vorspann (in jeden Prompt kopieren):

```
Kontext: Lies zuerst report-prototype/spec/05-architektur-befund-und-plan.md, dann
spec/06-katalog-simulation.md und spec/07-claude-code-handover.md. Diese Dateien sind die
Wahrheit für dieses Vorhaben; ältere Markdown-Dateien im Repo (docs/, CLAUDE.md-Abschnitte zu
Report-Pipeline, PTES, KI-gestützt) können veraltet sein. Bei Widerspruch: Code und spec/05-07
gelten, sonst nachfragen. Leitprinzipien: kein Befund ohne Fakt aus einem Werkzeug; keine
KI-erzeugten Befunde, Einstufungen oder CVSS-Werte; keine Zusagen (PTES, KI-gestützt,
Vollständigkeit) im Kundenreport; jede Regel hat ein Fixture; Deutsch in Texten, ASCII in
Bezeichnern; keine Gedankenstriche in Texten. Arbeite im Plan-Modus, zeige den Plan, warte
auf Freigabe. Am Ende: Tests grün, kurze Zusammenfassung, Liste offener Fragen.
```

### S0a Zusagen und Konfiguration

```
<Vorspann>
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
```

### S0b zap_active reparieren

```
<Vorspann>
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
```

### S0c Golden-Fixtures

```
<Vorspann>
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
```

### S1 facts.json

```
<Vorspann>
Aufgabe S1. Baue report-worker/reporter/facts/: ein versioniertes Schema (pydantic) mit den
Entitäten aus spec/05 M1 (scan, target, host, fqdn, service, tls, http, dns, software, passive,
coverage, threat, unprocessed, decisions) und einen Builder build_facts(scan_data_dir,
host_inventory, tech_profiles, correlated_findings, job_payload) -> Facts. Quellen: parser.py
(alle Tool-Parser), phase0/host_inventory.json inkl. dns_findings, tech_profile.json,
correlatedFindings und enrichment aus dem Job-Payload (werden heute nie gelesen, siehe spec/05
B1), record_tool_run-Status je Tool (coverage), waf_block_detector, KI-Strategieentscheidungen
(decisions, nur Protokoll). Pflicht: jedes Faktum trägt source, mode (active/passive),
observed_at, confidence. Versionsnormalisierung als eigenes Modul mit Plausibilität:
MariaDB-Kompatibilitätspräfix ("5.5.5-10.11.18-MariaDB" -> MariaDB 10.11.18), "or later"/
Ranges -> version None, Exchange-Familie aus OWA-Build (15.1 = 2016, 15.2 < 2562 = 2019,
15.2 >= 2562 = SE) und X-FEServer nur als Hinweis, PHP/nginx/Apache aus Bannern, "unbekannt" ist
ein zulässiges Ergebnis. nmap-Capabilities (STARTTLS, STLS, LOGINDISABLED, "requires SSL")
werden zu service.tls_required / service.starttls. CLI: python -m reporter.facts <tar> ->
facts.json. Tests: für jedes Golden-Tar wird facts.json gebaut; Assertions aus spec/01 und
spec/06 Abschnitt 3 (SPF vorhanden bei allen sieben Orders, MariaDB 10.x, Exchange SE bei
Junkerwerk, FTP tls_required bei 212.227.60.78, STARTTLS bei 110/143). Vergleiche die
Extraktion mit report-prototype/build/catalog_sim.py extract_facts als Referenz. Nicht tun:
Befunde erzeugen, Severity, KI-Aufrufe. Abnahme: Tests grün, facts.json für alle
Golden-Orders liegt unter tests/golden/facts/ und ist eingecheckt.
```

### S2 Prüfkatalog

```
<Vorspann>
Aufgabe S2. Baue report-worker/reporter/catalog/: (1) Engine: lädt checks/*.yaml, wertet
Bedingungen über facts.json aus (kleine Ausdruckssprache oder Python-Callables je Check, keine
eval auf Strings), konsolidiert je group_by (global, host, fqdn), erzeugt je Check ein Ergebnis
pass / fail / not_applicable / not_testable(reason) mit Betroffenenliste und Nachweisen
(Faktreferenzen), plus ignore.yaml (ZAP-Informationsalerts mit Begründung) und drei
Auffangregeln (unbekannter Port, ZAP-Alert ohne Zuordnung, Passivport ohne Bestätigung) ->
unprocessed. (2) Checks: portiere die 42 Regeln aus report-prototype/build/catalog_sim.py
apply_rules als YAML mit Feldern id, title, family, scale (exposure|hygiene), level, group_by,
when, positive_when, not_testable_when, affected_template, evidence, references, frameworks
(bsi, nis2, iso27001, tr03116; leer erlaubt), texts (observation, meaning, recommendation[],
verify) aus report-prototype/build/report_data.py. Einstufungen aus severity_policy.py als
Startwerte übernehmen und je Check kommentieren, wo abgewichen wird (z. B. TLS 1.0 ist
Hygiene hoch, nicht 9.1). Arbeitsteilung: Du (Hauptsession) baust Engine, Schema und
Vorlage, legst eine Entscheidungstabelle mit id, family, scale, level, group_by,
positive_when, frameworks je Prüfung an und schreibst die ersten fünf Prüfungen selbst.
Die übrigen Prüfungen erzeugst du parallel über den Subagent .claude/agents/check-author.md
(Sonnet) strikt nach Vorlage und Tabelle; du prüfst jede gegen Tabelle und Katalogtest. Ergänze: SSH auf Nicht-Standardport, HTTP-Alternativport,
sensible Pfade aus feroxbuster/ffuf, WAF vorhanden (positiv), Domain-Ablauf aus whois,
IP-Reputation aus AbuseIPDB/GreyNoise/OTX, bekannte CVE in erkannter Version aus enrichment
(nur mit Fremdquelle), Zonentransfer, Dangling CNAME. (3) Tests: ein Fixture je Check
(positiv und negativ), Drift-Test "drei Junkerwerk-Läufe ergeben dieselbe Ergebnisliste bis
auf Coverage-Unterschiede", Negativ-Fixtures aus tests/golden/negative.json (kein Check darf
sie erzeugen), Vergleich mit tests/golden/expected/junkerwerk.json. CATALOG_VERSION als
Konstante mit Bump-Regel im README des Pakets. Nicht tun: KI-Aufrufe, Renderer, Änderungen
am alten Reporter. Abnahme: alle Tests grün; python -m reporter.catalog <facts.json> gibt die
Ergebnisliste als JSON aus; für alle 36 Orders im API-Snapshot läuft der Katalog ohne Fehler.
```

### S3 Reportdaten v3, Textkatalog, Prosa-KI

```
<Vorspann>
Aufgabe S3. Baue report-worker/reporter/v3/report_data.py: erzeugt aus Facts plus
Katalogergebnis das Datenmodell des Prototyps (Struktur exakt wie
report-prototype/build/report_data.py DATA: meta, glance, business, scope, architecture,
landscape, positives, plan, findings, appendix). Regeln: Gesamtbewertung und Ampel aus den
Check-Ergebnissen (spec/03 Kapitel 1), Kapitel 2 Umfang aus coverage und not_testable,
Kapitel 3 Dienste aus facts.service/http inkl. unbewerteter Zeilen aus unprocessed,
Screenshots aus dem Tar, Plan aus den Empfehlungsstufen der fehlgeschlagenen Checks,
Anhang A.3 nur Fremd-Scores aus facts.threat. IDs: mit Kundenkürzel VS-<Kürzel>-<Jahr>-<lfd>,
ohne Kürzel wie heute VS-<Jahr>-<lfd> (Kürzel ist optional, kommt aus dem Bestellprozess oder
Admin-Review, S5). Kundenkontext (Branche, Mitarbeiterzahl, Systemzweck je System) kommt aus
orders.customer_context (S5) mit Quelle je Feld; fehlt er, bleibt der Kontextabsatz generisch
und der Report sagt das nicht. Dann ein KI-Aufruf (Opus) für vier Felder: Zusammenfassung
Seite 1, Kontextabsatz, Beobachtungssätze je System, Feinschliff der meaning-Texte; Eingabe
sind fertige Befunde und Fakten als JSON, nie Rohdaten; Ausgabe wird gegattert: keine Zahlen,
Hostnamen, CVE-IDs oder Versionsangaben, die nicht in den Eingabedaten stehen, keine
Severity-Wörter, Längenlimit je Feld; bei Verstoß bleibt der Katalogtext. Kosten je Aufruf
loggen (report_cost wie heute). Tests: Datenmodell für alle Golden-Orders baubar; Gate-Test
mit präparierter KI-Antwort (erfundene CVE) fällt zurück auf Katalogtext; ohne API-Key läuft
alles mit Katalogtexten durch. Abnahme: out/<order>-report-data.json für Junkerwerk ist
inhaltlich gleich zu report-prototype/out/report-data.json (Diff nur in Texten der KI-Felder).
```

### S4 Renderer v3

```
<Vorspann>
Aufgabe S4. Übernimm report-prototype/build/template.html.j2 und die Render-Logik aus
build_report.py nach report-worker/reporter/pdf/v3/ (Jinja2, WeasyPrint). Eingabe ist das
Datenmodell aus S3 (bis S3 fertig ist: report-prototype/out/report-data.json als Fixture).
Schritte: WeasyPrint plus Systemabhängigkeiten und Fonts (Inter, DejaVu Sans Mono) ins
report-worker-Image; Assets (Shield-Logo als Makro, Farben aus frontend globals.css) als
Paketressourcen; Schalter VECTISCAN_REPORT_LAYOUT=v3 in worker.py neben v2; Paketvarianten
webcheck (ohne Kapitel 3.4 Screenshots-Raster, kürzer) und perimeter; Sparse-Page-Check und
Gate-Checks aus build_report.py (IDs, Titel, scale/level, Werkzeuge ohne Version,
Plan-Referenzen, Fremd-Scores) als Teil des Renders. Regressionstest: Render von
report-data.json ergibt 25 Seiten, kein SPARSE, Text-Diff gegen report-prototype/out/*.html
nur in Datum. Nicht tun: Layoutänderungen ohne Rücksprache, ReportLab anfassen.
Abnahme: docker compose build läuft, ein Staging-Report mit LAYOUT=v3 liegt in MinIO.
```

### S5 Gate strict, report_blocked, Admin

```
<Vorspann>
Aufgabe S5. (1) Neuer Order-Status report_blocked (Migration, API-Enum, Frontend-Status-
anzeige). (2) worker.py: bei Gate-Fehler unter strict Order -> report_blocked mit Defektliste
in reports.validation_warnings, kein PDF-Upload, kein pending_review. (3) Admin-Review-Seite:
Tab "Defekte" mit der Liste (Check, Meldung, betroffene Befund-ID), Tab "Beobachtungen ohne
Regel" aus facts.unprocessed, Button "Regelvorschlag" (später, nur Platzhalter), Button
"Regenerieren nach Fix". (4) Neue Gate-Checks: unverarbeitete Beobachtungen > 5 -> Warnung;
Tech-Zeile widerspricht Befund (Familie/Version aus derselben software-Entität) -> Fehler;
Coverage-Kapitel leer -> Fehler. (5) Kundenkontext: Migration orders.customer_context
(jsonb: kuerzel, branche, mitarbeiter, systeme[{fqdn, zweck}], je Feld source in
{kunde, recherche, admin}); optionale Felder im Bestellprozess (Frontend, ohne Pflicht);
nach Scanende ein KI-Aufruf mit Web-Recherche (Opus, Websuche) zu Firmenname und Domain,
der nur diese Felder als Vorschlag mit Quelle "recherche" und Fundstellen-URL befüllt, nie
Kundenangaben überschreibt; im Admin-Review Tab "Kunde" mit allen Feldern editierbar
(source wird "admin"). (6) Produktion auf strict erst nach S6, hier vorbereiten.
Tests: Statusübergänge, Gate-Checks mit Fixtures, API-Route liefert Defektliste.
Abnahme: Staging-Order mit absichtlich defekten Daten landet in report_blocked und ist im
Admin sichtbar.
```

### S6 Umschaltung und Aufräumen

```
<Vorspann>
Aufgabe S6. (1) VECTISCAN_REPORT_ENGINE=catalog und LAYOUT=v3 werden Default; v2-Pfad
bleibt eine Release lang per Env erreichbar. (2) Entferne aus dem aktiven Pfad:
consolidate_findings als Prompt-Text, KI#5-Befunderzeugung, ai_finding_type_fallback,
finding_type_mapper, qa_cap, cvss_consistency, claims_guard, title_policy-Smart-Var (Titel
kommen aus dem Katalog). severity_policy.py bleibt als Datenquelle für Einstufungen, bis alle
Werte im Katalog stehen, dann löschen. (3) CATALOG_VERSION und FACTS_SCHEMA_VERSION ins
Impressum und in reports.policy_version. (4) docs/report-pipeline/ auf v3 umschreiben,
alte Doku nach docs/archive/. (5) CLAUDE.md-Abschnitte zur Report-Pipeline ersetzen.
Abnahme: Golden-Tests grün, ein vollständiger Staging-Scan von Order bis PDF ohne KI-Key
liefert einen Report; mit KI-Key liefert er denselben Report mit Prosa; Kosten < 0,20 USD.
```

### S7 Pakete und Export

```
<Vorspann>
Aufgabe S7. (1) packages/*.yaml: ein Paket = Liste von Check-IDs plus Berichtsrahmen
(Kapitelauswahl, Erzähltexte). Pakete: webcheck, perimeter, mail-security (SPF, DKIM, DMARC,
MTA-STS, TLS-RPT, DANE, STARTTLS, Banner), tls-compliance (bestehende TR-03116-Checks in den
Katalog überführen). (2) Rahmenwerk-Tags je Check befüllen: BSI-Grundschutz-Bausteine (nur
Anforderungen, die von außen prüfbar sind, z. B. APP.3.2 Webserver, APP.3.6 DNS-Server,
CON.1 Kryptokonzept, NET.1.1 Netzarchitektur anteilig), NIS2 Art. 21 Abs. 2 Buchstaben, ISO
27001 Annex A. Formulierung im Report immer "Nachweise zu", nie "konform". (3) Export der
Prüfergebnisse je Order als JSON (Check-ID, Ergebnis, Betroffene, Nachweise, Tags,
CATALOG_VERSION) über einen API-Endpunkt, damit andere Vectigal-Lösungen sie verwenden
können. (4) Anhang "Rahmenwerk-Zuordnung" im Report als Tabelle. Abnahme: jedes Paket rendert
für Junkerwerk; Export validiert gegen ein JSON-Schema.
```

## 6. Einstellungen in Claude Code

Verifiziert gegen die aktuelle Dokumentation (code.claude.com/docs), Stand 17.09.2026:

- Modell: `claude --model opus` oder in der Session `/model opus`; Aliasse `opus`, `fable`, `best` (Fable wo verfügbar, sonst Opus), `opus[1m]` für großes Kontextfenster. Vorgabe DC: mindestens Opus in jeder Session, Fable für die Spezialfälle S0b (Fehlersuche im ZAP-Pool), S1 (Schema-Entwurf), S2-Engine und S6 (Umschaltung mit Löschungen). Kein Sonnet, auch nicht für Subagents.
- Fable-Schutzfilter: Bei Inhalten rund um Active Scans, Angriffskategorien (SQLi, XSS, LFI, SSRF) und Scan-Policies schlägt Fables Filter breit an und bietet den Wechsel auf Opus an. In S0b ist das am 17.09. passiert; Antwort „Switch automatically" (per `/config` änderbar). Sessions, die solche Inhalte laufend berühren (S0b, später ZAP-Policy-Arbeit), praktisch auf Opus planen; S1, S2, S6 bleiben Fable.
- Effort: `claude --effort high` (Werte `low`, `medium`, `high`, `xhigh`, `max`). Standard `high`; `xhigh` für S0b, S1, S2-Engine, S6. Max-Abo, also keine Kostenbremse; `max` nur, wenn eine Session sichtbar an Denktiefe scheitert. Ob `--effort` über die Session hinaus gespeichert wird, ist nicht dokumentiert; bei jedem Start mitgeben.
- Plan-Modus: `claude --permission-mode plan` beim Start oder Shift+Tab in der Session. Jede Session beginnt so.
- Worktree je Session: `claude --worktree s1-facts --model fable --effort xhigh --permission-mode plan "<Startprompt>"`. Legt `.claude/worktrees/s1-facts/` auf Branch `worktree-s1-facts` an; `.claude/worktrees/` in `.gitignore`.
- Fortsetzen: `claude --continue` im selben Verzeichnis oder `claude --resume <name>`.
- Budget: entfällt (Max-Abo). Relevant sind nur die Nutzungsfenster des Abos; bei Drosselung die parallelen Sessions auf eine reduzieren statt Modell oder Effort zu senken.
- Regeln fürs Repo: `.claude/rules/report-v3.md` mit dem Vorspann aus Abschnitt 5 und `paths: ["report-worker/**", "scan-worker/**"]`; wird automatisch geladen. `CLAUDE.local.md` (gitignored) für persönliche Vorgaben.
- Subagent für Regelarbeit: `.claude/agents/check-author.md` mit `model: sonnet`, `tools: Read, Grep, Glob, Edit, Bash` und der Anweisung, je Check YAML plus Fixture exakt nach Vorlage und Entscheidungstabelle zu schreiben und den Katalogtest zu fahren; keine eigenen Einstufungen. Die Hauptsession (Fable) legt vorher Engine, Schema, Vorlage und die Tabelle (Einstufung, positive_when, Tags je Prüfung) fest und schreibt die ersten fünf Prüfungen selbst. Der Golden-Test ist das Gate, nicht das Modell. Für Suchaufgaben (read-only) in jeder Session ist Sonnet ebenfalls die richtige Wahl.

## 7. Ablauf je Session

1. Worktree mit Startprompt öffnen (Abschnitt 6), Plan-Modus.
2. Plan lesen. Prüfen, ob er die Abnahmekriterien des Prompts adressiert und nichts außerhalb des Auftrags anfasst. Freigeben.
3. Während der Umsetzung nur bei Rückfragen eingreifen. Am Ende Tests laufen lassen, Zusammenfassung lesen.
4. Review des Diffs (Schwerpunkt: keine KI-Aufrufe an Stellen, die Fakten oder Einstufungen betreffen; keine neuen Zusagen im Kundentext; Fixtures vorhanden).
5. Merge nach `main`, Worktree entfernen, spec/07 Abschnitt 3 Status nachtragen.
6. Nach S1 und S2: die Kennzahlen aus spec/05 Abschnitt 7 einmal messen (Drift auf Golden-Files, Falschbefunde, Kosten) und hier eintragen.

## 8. Geklärt am 17.09.2026

Alle vier Vorfragen sind entschieden und in Abschnitt 1 eingetragen (VirusTotal ohne; Kürzel optional mit Fallback wie heute; Kundenkontext optional bei Beauftragung plus Web-Recherche plus Admin-Review; Junkerwerk-Fixtures freigegeben). Start mit S0a, S0b, S0c ist möglich.

## 9. Startcheckliste (Stand der Prüfung 17.09.2026, Repo auf DCs Rechner)

Befund:

- Repo `vectiscan`, Branch `main`, letzter Commit 23.07.2026. Arbeitsbaum sauber bis auf `.claude/settings.local.json` (lokale Freigaben) und den untracked Ordner `report-prototype/`. Die 545 „geänderten" Dateien, die ein Linux-Git zeigt, sind Zeilenenden (CRLF) und Dateimodus, keine Inhalte.
- Zwei Remotes: `github` (dc-77/vectiscan) und `gitlab` (git-extern.bergersysteme.com, CI/CD mit Rolling Deploy nach `/opt/apps/vectiscan` auf dem Host `vectigal-docker02`). Die GitLab-Remote-URL enthält ein persönliches Zugriffstoken im Klartext. Das Token sollte rotiert und die URL ohne Token gesetzt werden (Git Credential Manager übernimmt die Anmeldung).
- Claude Code ist im Repo bereits genutzt worden (Freigaben für git, ssh vectigal-docker02, python, gitlab-api.sh). Läuft unter Git Bash.
- Kein lokales `.env`; Produktionsgeheimnisse (DB, MinIO, API-Keys) liegen auf `vectigal-docker02` unter `/opt/apps/vectiscan/.env`. S0c holt die Roh-Tars per `ssh vectigal-docker02` aus MinIO; S0b reproduziert den ZAP-Fehler entweder lokal mit `docker-compose.dev.yml` oder auf dem Host.
- `report-prototype/.gitignore` schließt `input/` (18 MB Kundendaten), `out/` und `*.creds` aus. `build/assets/` (200 KB Screenshots Junkerwerk, freigegeben) wird eingecheckt.
- Startprompts liegen als Dateien unter `report-prototype/spec/prompts/S0a.md` bis `S7.md` (Vorspann bereits enthalten). Regeln und Subagent liegen unter `report-prototype/claude-config/` und müssen einmal nach `.claude/` kopiert werden.

Vorbereitung, einmalig, in Git Bash im Repo:

```bash
cd /c/BS-Consulting/Projekte/Coding/vectiscan

# 1. Claude Code aktuell? (Alias fable braucht eine aktuelle Version)
claude --version && claude update

# 2. Regeln und Subagent aktivieren, Worktrees ignorieren
mkdir -p .claude/rules .claude/agents
cp report-prototype/claude-config/rules/report-v3.md .claude/rules/
cp report-prototype/claude-config/agents/check-author.md .claude/agents/
grep -q '^.claude/worktrees/' .gitignore || printf '\n.claude/worktrees/\n' >> .gitignore

# 3. Prototyp und Specs einchecken, damit jeder Worktree sie sieht
git add report-prototype .claude/rules .claude/agents .gitignore
git commit -m "report-prototype: Prototyp Junkerwerk, Specs 00-07, Katalog-Simulation, Claude-Code-Regeln"
git push gitlab main

# 4. GitLab-Token aus der Remote-URL nehmen (danach Token in GitLab rotieren)
git remote set-url gitlab https://git-extern.bergersysteme.com/vectigal/vectiscan.git
```

Start der ersten drei Sessions, je ein Terminal (Git Bash), Plan-Modus, Plan freigeben:

```bash
claude --worktree s0a-claims   --model opus  --effort high  --permission-mode plan \
  "Lies report-prototype/spec/prompts/S0a.md und arbeite den Auftrag ab."

claude --worktree s0b-zap      --model fable --effort xhigh --permission-mode plan \
  "Lies report-prototype/spec/prompts/S0b.md und arbeite den Auftrag ab."

claude --worktree s0c-fixtures --model opus  --effort high  --permission-mode plan \
  "Lies report-prototype/spec/prompts/S0c.md und arbeite den Auftrag ab."
```

Danach, in dieser Reihenfolge, jeweils nach Merge der Vorgänger:

```bash
claude --worktree s1-facts    --model fable --effort xhigh --permission-mode plan "Lies report-prototype/spec/prompts/S1.md und arbeite den Auftrag ab."
claude --worktree s2-catalog  --model fable --effort xhigh --permission-mode plan "Lies report-prototype/spec/prompts/S2.md und arbeite den Auftrag ab."
claude --worktree s4-renderer --model opus  --effort high  --permission-mode plan "Lies report-prototype/spec/prompts/S4.md und arbeite den Auftrag ab."   # parallel zu S2
claude --worktree s3-textdata --model opus  --effort high  --permission-mode plan "Lies report-prototype/spec/prompts/S3.md und arbeite den Auftrag ab."
claude --worktree s5-gate     --model opus  --effort high  --permission-mode plan "Lies report-prototype/spec/prompts/S5.md und arbeite den Auftrag ab."   # parallel zu S3
claude --worktree s6-cutover  --model fable --effort xhigh --permission-mode plan "Lies report-prototype/spec/prompts/S6.md und arbeite den Auftrag ab."
claude --worktree s7-packages --model opus  --effort high  --permission-mode plan "Lies report-prototype/spec/prompts/S7.md und arbeite den Auftrag ab."
```

Status 17.09. abends: S0a fertig (drei Commits auf `worktree-s0a-claims`, 960 + 732 Tests grün; Nachträge: `.env.template` strict auskommentiert, Nuclei-Badge Homepage entfernt, „Claude AI"-Badge bleibt, Persona „Sicherheitsanalyst", Ticket für `validation/tests/test_checks.py` außerhalb der testpaths → S5). S0b neu gestartet auf Opus 5 wegen Fable-Filter, Reproduktion lokal in Docker Desktop mit zwei ZAP-Instanzen und Pool. S0c läuft: Tars per manuellem GitLab-Job `ops-export-golden-tars` (Order-IDs als CI-Variable, Artefakt 1 Tag), castenow alle drei Läufe (Referenz `4e6b6883`), Screenshots immer entfernt mit Manifest.

Befund CI/Deploy (17.09., S0a-Session): `main` hatte seit dem 23.07. keine laufende Pipeline; MR-Pipelines waren nie konfiguriert (nur main, develop, web). Erste Pipeline seit Juli (3049, ausgelöst durch den Prototyp-Push) rot: `deploy-auto` scheitert am Pull `minio/minio:latest` (Docker Hub, einziges mutables Tag im Compose); `trivy-frontend` meldet zwei CRITICAL in next 15.5.12 (Fix 15.5.24); `trivy-api` scheitert am geteilten Trivy-Cache-Lock; `after_script` prune läuft in den Timeout (kosmetisch); `trivy-scan-worker` ist auf `when: never`. Produktion unverändert. Maßnahmen in MR !69: MR-Pipelines aktiviert (workflow-Block), MinIO-Image gepinnt, next gebumpt, Trivy-Cache je Job; Issues für Prune-Timeout und trivy-scan-worker. Lehre: Ohne MR-Pipelines und ohne Deploy seit Juli war jede Aussage über den Zustand von `main` ungeprüft; das erklärt auch, warum drei tote Werkzeuge 42 Scans lang unbemerkt blieben.

S0c fertig (17.09.): `report-worker/tests/golden/` mit 10 Tars (1,7 MB, ohne Screenshots, sha256 im Manifest), API-Snapshot 39 Orders (15 MB Text, bewusst unkomprimiert), `expected/junkerwerk.json`, `negative.json` (36 Einträge, 31 Befunde; MariaDB-Muster verbietet die Versionsableitung, nicht den Befund), Smoke-Test 997 grün. Nebenbefunde: GitLab-Instanz lehnt HTTP-Bodies über etwa 1 MB mit 413 ab (Push per SSH, Artefakt-Export als parallel:matrix je Order); IPv6-Hostverzeichnisse sind unter Windows nicht anlegbar (Hinweis für S1: Host-Slug statt IP als Verzeichnisname); f77ccff2 lief 46 Minuten, die drei Tage lagen zwischen Scanende und Freigabe. Merge-Reihenfolge: erst !69 (S0a, CI-Regeln), dann S0c per `git merge main` aktualisieren (kein Rebase: Session-Branches, die zwischendurch main eingemerged haben, werden gemerged, die Historie soll die Sessions abbilden, nicht linear sein), ein Konflikt in `.gitlab-ci.yml` (test-report-worker: S0a-Zeile zuerst, api-Regel darunter), MR erst danach, weil die MR-Pipeline die CI-Datei des Quellbranches nutzt.

S0b fertig (17.09., Commit 7d02167 auf `worktree-s0b-zap`, enthält S0a per Merge): Ursache siehe Abschnitt 4 „Ergebnis S0b". Tests scan-worker 778, report-worker 965, Integration 4 (zwei ZAP-Daemons, Pool, Testziel), Live-Lauf 35 Alerts, 3 aktiv, pluginId überlebt Tar und Parser. Entscheidungen DC: Staging-Nachweis nach Deploy gegen eigenes Ziel, erst dann „ZAP Active Scan" zurück auf die Methodikseite (Aufgabe S3); `run_zap_scan` (toter Code) löschen, eigener Commit; Kategorie `ssrf` bleibt leer, 40024/40046 nicht nachziehen, in Katalogdefinition als „nicht verfügbar in ZAP 2.17.0" markieren, Wiedervorlage S7; `ZAP_POOL_ENABLED` in Produktion prüfen und hier eintragen. MR für S0b erst nach Merge von !69 und `git merge main`.

Stand 17.09. abends: !69 (S0a) gemerged als `fc23b11`, !70 (S0c) gemerged als `5e8dda0` nach vollständig grüner MR-Pipeline 3060 (11 Jobs, erster Merge über den neuen Weg). 133 Fixture-Dateien unter `report-worker/tests/golden/`. S0b wartet auf `git merge main` und MR. Pipeline 3059 auf `main` mit erstem `deploy-auto` seit Juli (MinIO per Digest von quay.io, Container wird ersetzt, Volume bleibt) zum Zeitpunkt der Notiz noch offen. S1 kann starten, sobald 3059 grün ist.

S0b: MR !71 (fünf Commits, 28 Dateien) mit grüner Pipeline 3062 (11 Jobs; scan-worker 798 passed, 5 skipped, Integrationstests werden auf dem Runner sauber übersprungen). `ZAP_POOL_ENABLED` in Produktion nicht gesetzt, Compose-Default `false`: Pool nie aktiv, Worker-zu-ZAP fest 1:1, `zap-4` (1 CPU, 1,5 GB) ohne Aufgabe. Damit ist die fehlende Scanner-ID 40024 die einzige Erklärung für die 42 Fehlschläge; der Affinitätsfix ist in Produktion inaktiv, aber Voraussetzung für das Einschalten des Pools (Docstring in `zap_pool.py`). Vor dem Merge `ZAP_VERSION=2.17.0` in die Produktions-.env (dokumentiert den Pin, identisch zum Default). Abnahme S0b: nach deploy-auto ein Perimeter-Scan gegen ein eigenes Ziel mit `zap_active status=ok` und Alerts mit pluginId im Tar. Danach als eigener Schritt `ZAP_POOL_ENABLED=true`, Worker-Neustart, zweiter Scan. Nebenbefund: kein `trivy-scan-worker`-Job (Issue #6), ausgerechnet das Image mit den Scan-Werkzeugen bleibt ungescannt.

Abschluss S0b (18.09., abgenommen): MR !71 (S0b-Reparatur) und MR !72 (Poll-Timeout `ZAP_ACTIVE_SCAN_TIMEOUT_SEC=900`, auch als CI-Variable angelegt) gemerged, Deploy 3065 live, Scan-Worker auf `8173f48d`, ZAP auf 2.17.0 gepinnt. Nachweislauf Order `14272c00` gegen `dortmund-beach.com`: `zap_active status=ok`, volle Alert-Liste (1269), alter `does_not_exist` weg, ID-Filter greift (40024 gedroppt), Order sauber bis `pending_review`, 27,7 min. Zielwahl: `dortmund-beach.com` ist ein von DC freigegebenes externes Ziel außerhalb der geteilten Traefik-Instanz, also kein Rate-Limit; damit sind der zunächst erwogene Test-Hostname am Frontend-Service und jeder Umbau an `rate-limit@file` verworfen, `dortmund-beach.com` ist das Standardziel für künftige Scanner-Nachweise. Dokumentiert offen, kein Handlungsbedarf: Cap-Tiefe (`maxScanDurationInMins`, aktuell rund 12 min erreichbar) ist eine Produktentscheidung, in S1 wieder aufgreifen, sobald im Katalog steht, welche Prüfungen an ZAP Active hängen; Empfehlung Claude bei moderatem Cap belassen, die Kernbefunde kommen aus nmap, testssl und ffuf. Methodikseite „ZAP Active Scan" zurücknehmen mit Datum 18.09.2026 (Aufgabe in `spec/prompts/S3.md`). `ffuf_sensitive` läuft (S0a greift), timeoutet aber bei 180 s, eigenes Budget-Thema, nicht S0b. Exakter pluginId-Count nur per SSH/MinIO aus dem Roh-Tar abrufbar, end-to-end im Integrationstest belegt. Pool-Test (`ZAP_POOL_ENABLED=true`) ist kein Pflichtschritt mehr: die Instanz-Affinität ist in !71 abgeräumt und der Nachweis lief mit einer Instanz sauber; das Einschalten des Pools ist eine reine Durchsatzfrage, verschoben nach S3/S7.

Merge je Session: im Worktree `git push gitlab worktree-<name>`, Merge Request in GitLab (MR-Pipeline mit Build, Trivy und Tests seit S0a), nach Merge `git pull` auf `main`, Worktree beim Beenden von Claude Code löschen lassen. Hat sich `main` während der Session bewegt: `git merge main` im Worktree, kein Rebase. Nur Testsuite ohne Build: Pipeline mit Quelle api (Regel aus S0c).
