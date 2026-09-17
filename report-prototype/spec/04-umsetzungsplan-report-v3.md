# Umsetzungsplan: Report v3 dauerhaft aus der Applikation (Weg zum Livegang)

Stand 17.09.2026. Grundlage: Prototyp `report-prototype/`, Rohdaten-Analyse (`01`), Scan-Drift (`02`),
Struktur-Spec (`03`), Code-Stand `main` (letzter Report-Commit 23.07.2026), `docs/report-pipeline/`.

## 0. Ausgangslage in fünf Sätzen

1. Der v2-Renderer ist produktiv, das ValidationGate läuft im Modus `warn`
   (`docker-compose.yml:550`, `VECTISCAN_VALIDATION_LEVEL` Default `warn`): Reports mit Gate-Fehlern
   (Dubletten) werden erzeugt und landen in `pending_review`.
2. Drei Läufe auf dieselbe Infrastruktur (Junkerwerk) ergaben 4 von 22 Sachverhalten konsistent,
   6 Falschbefunde, 3 fehlende relevante Befunde, eine unsichtbare Abdeckungslücke (Hoster blockt Scanner).
3. Die Rohdaten sind über alle Läufe stabil und gut; die Fehler entstehen in der Reporter-Stufe, weil die
   KI Befunde erzeugt und Regeln sie nachträglich korrigieren, statt umgekehrt.
4. Der Prototyp zeigt das Zielbild (Struktur, Sprache, Triage ohne Eigen-Scores, Abdeckung, Screenshots),
   aber mit manueller Kuratierung.
5. Livegang heißt: Die Applikation ersetzt die manuelle Kuratierung durch ein Faktenmodell, einen
   Regelkatalog und ein blockierendes Gate. Ein Report, der das Gate nicht besteht, existiert nicht.

## 1. Leitprinzipien (Reputationsschutz, nicht verhandelbar)

1. **Beleg vor Aussage.** Jeder Befund, jede Tech-Zeile, jeder Posture-Wert zeigt auf einen Rohdaten-
   Eintrag (`evidence_ref`: Tool, Host, Zeile). Ohne Beleg keine Aussage.
2. **Keine eigenen Scores, keine Standard-Labels.** Eigene Bewertung ist Triage-Status, Dringlichkeit und
   Einstufung (Exposition kritisch/erhöht, Hygiene hoch/mittel/niedrig). CVSS nur als Fremdreferenz zu
   zitierten CVEs mit Quelle. Kein „PTES-konform", kein „KI-gestützt".
3. **Unsicherheit ist ein zulässiger Zustand.** „unbekannt", „passiv", „nicht verifiziert", „nicht geprüft"
   sind erlaubte Werte; „aktuell" und „EOL" nur mit exakter Version und Quelle.
4. **Abdeckung ist Ergebnis.** Was nicht geprüft werden konnte, steht im Report (Kapitel 2, Warnbox
   Seite 3), nicht im Log.
5. **Gate blockiert.** Level `strict` in Produktion; Order geht in `report_blocked` mit Fehlerliste im
   Admin, nie in die Auslieferung.
6. **KI formuliert, entscheidet nicht.** Existenz, Version, Titel, Kategorie, Status, Dringlichkeit,
   Einstufung kommen aus Regeln. Die KI schreibt „Was wurde gefunden" und „Auswirkung" innerhalb der
   Fakten; `claims_guard` prüft jeden Satz gegen das Faktenmodell.
7. **Ein Sachverhalt, ein Befund**, hostübergreifend konsolidiert, IDs nach Konsolidierung lückenlos.

## 2. Reputationsfallen-Register (beobachtet, mit Gegenmaßnahme)

| # | Falle | Beobachtet (Junkerwerk) | Ursache im Code | Gegenmaßnahme | Gate-Check |
|---|---|---|---|---|---|
| R1 | Falsch-EOL aus Versionsstring | „MySQL 5.5 EOL 2018" (real MariaDB 10.11 LTS), „PostgreSQL 9.6 EOL" (nmap: „or later") | `eol_detector._parse_version`, `_normalize_vendor_product` | MariaDB-Kompatibilitätspräfix strippen, Ranges/„or later" → `unbekannt`, MySQL und MariaDB getrennt | EOL nur mit exakter Version + Quelle, sonst Gate-Error |
| R2 | Produktfehlerkennung | „Exchange 2016 EOL" 9.1, real Exchange SE (OWA 15.2.2562, `x-feserver`) | `cms_fingerprint` Konfidenz 0.95 ohne Plausibilität | Exchange-Build-Tabelle (15.1 = 2016, 15.2 = 2019/SE), Header auswerten; Tech-Zeile und Befund aus derselben Quelle | consistency: Tech-Zeile ≠ Befund-Version → Error |
| R3 | SPF „fehlt" trotz SPF | multi + de; de zugleich Positivbefund „SPF korrekt" | SPF-Prüfung liest `dns_security` (kein spf-Key) statt `dns_records.spf` | Quelle korrigieren; DMARC-Befund statt SPF | Widerspruch Positivbefund ↔ Befund → Error |
| R4 | Klartext-Befund trotz TLS-Zwang | FTP „requires SSL", IMAP LOGINDISABLED, POP3 STLS | Parser ignoriert TLS-Signale | Klartext-Befund nur, wenn AUTH ohne TLS angeboten wird | Regel-Vorbedingung |
| R5 | Severity-Drift und INFO mit CVSS 4.3 | TLS 1.0/1.1: 9.1 (multi) vs. 3.1 (de) | SP-TLS-001, Score und Severity entkoppelt | Eigen-CVSS abschaffen (Prinzip 2), Einstufung je Regel fest | keine `cvss_vector`-Felder mehr zulässig |
| R6 | CVE aus Banner, Guard entfernt CVE, Befund bleibt | hu VS-001 OpenSSH 9.2p1 (Debian-Backport) | `cve_guard` säubert nur Text | Befund entfällt oder wird „Prüfpunkt", wenn die tragende CVE entfernt wird | CVE-Referenz ohne Allowlist-Eintrag → Error |
| R7 | Dubletten im PDF | Anti-CSRF doppelt (multi, hu) | Gate `warn` | Merge im Konsolidierungsschritt; Gate `strict` | titles-Check bleibt, wird blockierend |
| R8 | Interner Hinweis im Titel | „[Hinweis: exchange wird laut Scan-Inventar …]" | KI-generierter Titel | Titel ausschließlich aus `title_policy`-Templates; KI darf Titel nicht setzen | Regex `\[Hinweis`, `\{…\}` |
| R9 | Passivdaten ungekennzeichnet, Passivbefunde fehlen | Shodan-Zeilen „Port 110 unbekannt" in Tech-Tabelle; SonicWall 4433 kein Befund | `tech_table_builder` Shodan-Block ohne Flag | `source: active/passive` im Faktenmodell; Passiv-Befundklasse mit Verifikationsschritt, kein Score | Passivbefund ohne Verifikationsschritt → Error |
| R10 | Abdeckungslücke unsichtbar | Hetzner blockt Scanner nach nmap; alle Phase-2-Tools „ok" mit leerem Output | `header_check.reachable=false` wird nicht ausgewertet | Coverage je vHost (voll/teil/keine) aus reachable-Flags + leeren Outputs; Kapitel 2 + Warnbox | Coverage-Kapitel Pflicht; Report ohne Coverage → Error |
| R11 | Toolausfälle unsichtbar | zap_active API 400, ffuf Wordlist fehlt, VirusTotal ohne Key, crt.sh 404, gobuster Timeout, IPv6-nmap leer | Status `ok`/`skipped` ohne Folge | Tool-Health in Coverage; Ops-Alarm (Uptime-Kuma/Loki) bei Ausfall | Kern-Tool ausgefallen → Order `scan_incomplete` |
| R12 | „PTES-konform" | Katalog, Homepage, Subscribe, Prompts, `strategy.py:159`, `report_mapper.py:522/1041`, `generate_report.py:832/1142/1939`, CLAUDE.md | Marketing-Claim in Code und Katalog | „Externe Schwachstellenanalyse; PTES-Phasen Aufklärung, Schwachstellenanalyse, Bericht; keine Exploitation" | Textsuche im Build: `PTES-konform` verboten |
| R13 | „KI-gestützt" ohne Substanz | `prompts.py`, `report_mapper.py`, `v2_data.py`, Homepage, Datenschutzseite | Floskel | Ein Satz mit konkreter Aufgabe (Prototyp Kapitel 2.3) | Textsuche `KI-gestützt` |
| R14 | Optik: ae/ue/oe, Cover nur eine Domain | v2-PDF Junkerwerk | ReportLab-Font-Pfad, Cover-Template | Renderer v3 (WeasyPrint, Inter), Cover mit allen Zieldomains | Umlaut-Check im PDF-Text |
| R15 | Zeitraster „Tag 1-3 / Woche 1 / Monat 1" | Recommendations | KI-Freitext | Enum Unverzüglich/In Kürze/Mittelfristig/Strategisch | plan-Check erweitern |
| R16 | Falsche Host-Zuordnung in Empfehlung | „188.40.3.130-Ableger cloud.junkerwerk.de" | KI-Freitext | `claims_guard`: Host↔IP-Paare gegen Inventar prüfen | Paar nicht im Inventar → Error |
| R17 | Generischer Geschäftskontext | „Allgemeine Geschäfts-IT" | `business_context` Domain-Heuristik | Ableitung aus vHost-Titeln, Produkten, DNS (Prototyp Seite 3); ohne Beleg lieber kurz | kein Fallback-Text ohne mindestens ein beobachtetes System |
| R18 | Mehrere Domains, ein Report | Multi-Target ohne Domain-Differenzierung in Ampel/Posture | Layer-1-Aggregation domainblind | Posture je Domain; Cover und Kontext nennen alle Domains | – |

## 3. Zielarchitektur Report-Worker v3

```
Rohdaten (MinIO tar, scan_results, passive_intel)
   │
   ▼
A  Evidence Layer        reporter/evidence.py         Faktenmodell: hosts[] → services[], web[] (vhosts),
                                                       dns{}, tls{}, headers{}, screenshots[], tool_health[]
                                                       jede Zeile: source active|passive, tool, evidence_ref
   │
   ▼
B  Coverage              reporter/coverage.py (erw.)  reachable je vHost, geprüfte Ports, Toolausfälle,
                                                       IPv6, blockierte Phasen → Kapitel 2 + Warnbox
   │
   ▼
C  Regelkatalog          reporter/rules/*.py           Regeln ERZEUGEN Befunde aus Fakten (nicht mehr
                                                       KI-Befunde korrigieren); je Regel: id, Kategorie A–E,
                                                       Status, Dringlichkeit, Einstufung, Titel-Template,
                                                       Evidence-Pointer, Empfehlungs-Stufen, Verifikation
   │
   ▼
D  Konsolidierung        reporter/consolidate.py       ein Sachverhalt = ein Befund (hostübergreifend),
                                                       Positivbefunde aus Regeln, IDs, Kategorien,
                                                       Top-3-Hebel (Cluster), Maßnahmenplan
   │
   ▼
E  Text (KI, begrenzt)   reporter/narrate.py           „Was wurde gefunden", „Auswirkung", Geschäftskontext;
                                                       Eingabe = Fakten + Regeltext; claims_guard enforce
   │
   ▼
F  Gate STRICT           reporter/validation/          alle Checks aus Abschnitt 2 + Bestand; Fehler →
                                                       Order report_blocked, Admin sieht Fehlerliste
   │
   ▼
G  Render v3             reporter/pdf/v3/ (WeasyPrint) Template aus dem Prototyp, Screenshots 2×3,
                                                       Impressum unten, Seitenzahl n von N
   │
   ▼
H  Regression            tests/golden/                 8 reale Orders als Golden-Files (Sachverhalt →
                                                       erwarteter Befund/Status); CI-Pflicht
```

Was bleibt: `title_policy`, `id_renumber`, `layer1_aggregator` (Kategorien, Hebel), `befund_landschaft`,
`verification_templates`, `claims_guard`, `cve_guard`, `screenshot_pipeline`, Compliance-Module.
Was kippt: KI-Erstbefunde (`claude_client` als Befundquelle), `severity_policy` als Score-Vergeber
(wird Einstufungs-Tabelle der Regeln), ReportLab v1/v2 nach Cutover.

**Kostenwirkung:** Der Junkerwerk-Multi-Report kostete 1,94 USD KI-Anteil (`report_cost`, Opus, 18k Output-
Tokens), weil die KI den gesamten Befundsatz schreibt. Mit Regeln als Befundquelle und KI nur für
begrenzte Prosa je Befund sinkt das deutlich und wird reproduzierbar.

## 4. Arbeitspakete

Größen: S = 1 Claude-Code-Session, M = 2 bis 3, L = 4 bis 6. Reihenfolge ist Abhängigkeitsreihenfolge.

| WP | Inhalt | Größe | Abnahme |
|---|---|---|---|
| **WP0 Claims bereinigen** | R12, R13: Katalog (`catalog/packages.catalog.json` + Codegen), Homepage, Subscribe, Datenschutz, Prompts, `strategy.py`, `report_mapper.py`, `generate_report.py`, CLAUDE.md. Neue Formulierung aus Prototyp 2.3. | S | Textsuche `PTES-konform`, `KI-gestützt` leer; Pipeline grün |
| **WP1 Evidence Layer + Coverage** | Faktenmodell aus allen Parsern; `source`-Flag; reachable je vHost; Tool-Health; Coverage-Tabelle und Warnbox als Renderer-Input. R9, R10, R11. | L | Junkerwerk-Multi: Coverage zeigt Webserver „teil", IPv6 „keine", zap_active „ausgefallen" |
| **WP2 Regelkatalog v3** | Regeln erzeugen Befunde: DB/Verwaltung/Fernzugang exponiert, Passiv-Exposition, DMARC/SPF/MTA-STS, TLS-Protokolle/Cipher/HSTS/Cert-Mismatch, Header-Score, Banner/TRACE, DNSSEC/CAA, EOL (nur exakt), Lifecycle-Hinweis, Altprotokolle mit TLS-Zwang (blau). Vorbedingungen aus R1, R3, R4, R6. Bestehende ~74 Policy-Regeln als Ausgangsmaterial. | L | Golden-Files: Junkerwerk ×3 ergeben denselben Befundsatz wie der Prototyp (15 + 8) |
| **WP3 Triage statt CVSS** | Datenmodell `status/urgency/scale/level`; `cvss_*`-Felder entfernen; CVE-Referenztabelle mit NVD/ZDI-Score; Anhang A wie Prototyp. R5. | M | Gate: kein Vektor im Datensatz; Score-Mismatch-Test |
| **WP4 Konsolidierung + Plan** | Hostübergreifendes Merge, IDs, Kategorien, Top-3-Hebel, Zeitstufen-Enum (R15), Positivbefunde aus Regeln, Geschäftskontext datengetrieben (R17), Multi-Domain-Posture (R18). | M | Landschaft und Plan des Prototyps reproduziert; jeder Befund genau einmal im Plan |
| **WP5 KI-Rolle begrenzen** | `narrate.py`: Prosa je Befund und Kontext aus Fakten; Titel-Verbot (R8); `claims_guard` um Host↔IP-Paare und Versionen erweitern (R16); Temperatur 0, Cache mit Regelversion. | M | Drei Läufe → identische Titel, Kategorien, Status; Prosa-Varianz nur stilistisch |
| **WP6 Gate STRICT + Admin-Flow** | Checks aus Abschnitt 2 ergänzen (Widerspruch positiv/negativ, Passiv ohne Verifikation, EOL ohne Version, Coverage Pflicht, Umlaute, Claims-Textsuche); Level `strict`; neuer Order-Status `report_blocked` mit Fehlerliste im Admin; „Nach Fix neu generieren". | M | Junkerwerk-Multi mit Alt-Pipeline → blocked mit 6 Fehlern; mit v3 → passed |
| **WP7 Renderer v3** | `pdf/v3/` mit WeasyPrint aus `template.html.j2`; Fonts im Image; Screenshots 2×3 mit zweitem Playwright-Pass für vHosts mit `reachable=false` (R14); Cover mit allen Domains; Impressum unten; Seitenzahl n von N. ReportLab bleibt bis Cutover als Fallback. | M | PDF-Diff gegen Prototyp; Sparse-Page-Check; Umlaut-Check |
| **WP8 Golden-Files + CI** | 8 reale Orders als Fixtures (Junkerwerk ×3, secumetrix, trunk, heuel, castenow, dortmund-beach): Rohdaten eingefroren, erwarteter Befundsatz je Sachverhalt; Test-Stage in `.gitlab-ci.yml`. | M | Jeder Regel-Change läuft gegen alle Fixtures |
| **WP9 Scanner-Betrieb** | Blockade-Erkennung (reachable kippt nach nmap) + Retry über zweite Egress-IP oder gedrosseltes Profil; IPv6-nmap; zap_active reparieren; ffuf-Wordlist ins Image; VirusTotal-Key; crt.sh-Fallback; Zusatzports (4433, 8443, 10443, 4443) in die Portliste. | M | Junkerwerk-Rescan: Website mit Header/TLS-Ergebnis, IPv6 gescannt, keine Tool-Ausfälle |
| **WP10 Pilot + Cutover** | Shadow-Modus: v3 parallel zu v2 für alle neuen Orders, Vergleich im Admin; DC-Review von 5 Reports; `VECTISCAN_REPORT_LAYOUT=v3` Default; v1/v2 entfernen; Doku (`docs/report-pipeline/`) auf v3. | M | 5 Pilotreports ohne manuelle Korrektur auslieferbar |

Kritischer Pfad: WP1 → WP2 → WP4 → WP6 → WP7 → WP10. WP0, WP3, WP5, WP8, WP9 laufen parallel dazu.
WP0 zuerst, weil es Außenwirkung hat und in einer Session erledigt ist.

## 5. Definition of Done „Report-Livegang"

1. Gate `strict` in Produktion; kein Report seit Cutover mit Gate-Fehler ausgeliefert.
2. Golden-Files grün; drei Läufe auf dieselbe Infrastruktur ergeben identische Befund-IDs, Status,
   Dringlichkeiten und Titel.
3. Kein Eigen-CVSS, kein „PTES-konform", kein „KI-gestützt" im Report, im Katalog, auf der Website.
4. Abdeckung im Report ausgewiesen; Scanner-Blockade führt zu Retry oder Coverage-Eintrag, nie zu
   stillem Leerlauf.
5. Passivbefunde immer gekennzeichnet und mit Verifikationsschritt; kein EOL ohne exakte Version.
6. Renderer v3 mit echten Umlauten, allen Zieldomains auf dem Cover, Screenshots, Impressum unten.
7. Fünf Pilotreports (verschiedene Kunden) ohne manuelle Nacharbeit freigegeben.
8. Doku: `docs/report-pipeline/` auf v3, CLAUDE.md-Paketbeschreibung aktualisiert, Fallen-Register als
   Test-Checkliste in `report-worker/tests/`.

## 6. Entscheidungen, die vor WP1 fallen sollten

1. **Renderer:** WeasyPrint (Empfehlung: Prototyp 1:1 übernehmbar, HTML-Diff-Tests, Fonts kontrollierbar)
   oder ReportLab weiterführen (Portierungsaufwand für jedes Element, kein Vorteil).
2. **KI-Modell für Prosa:** Sonnet reicht, wenn Regeln die Fakten liefern; Opus nur, wenn Textqualität im
   Pilot nicht genügt. Kostenziel unter 0,50 USD je Report.
3. **Order-Status bei Gate-Fehler:** `report_blocked` (Admin behebt Regel/Datenfehler, regeneriert) statt
   `failed` (Kunde sieht Fehlschlag).
4. **Compliance-Paket:** Mapping-Anhang bleibt dem Compliance-Paket vorbehalten; Perimeter-Report ohne
   Compliance-Zeile (offen aus Spec 03).
5. **ID-Schema:** `VS-2026-NNN` beibehalten oder Kundenpräfix (offen aus Spec 03).

## 7. Nächste konkrete Schritte

1. DC: Entscheidungen 1 bis 5 aus Abschnitt 6.
2. Claude-Code-Session 1: WP0 (Claims) + Golden-File-Rohdaten aus MinIO einfrieren (WP8 Vorarbeit).
3. Claude-Code-Session 2 bis 4: WP1 Evidence Layer, gegen Junkerwerk-Multi entwickelt, Coverage sichtbar.
4. Danach WP2 mit den 15 Prototyp-Befunden als Zielsatz.
