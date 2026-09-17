# Architektur-Befund VectiScan und Plan „mit einfachen Mitteln zum optimalen Ergebnis"

Stand 17.09.2026. Intern. Grundlage: Code im Repo (Wahrheit), `docs/report-pipeline/01..13`, `docs/PIPELINE-AI-FLOW.md`, die drei Junkerwerk-Läufe (spec/01, spec/02) und der Prototyp (spec/03). Dieses Dokument ersetzt nicht spec/04 (Arbeitspakete), sondern erklärt, warum die Architektur die beobachteten Fehler zwangsläufig produziert, und leitet daraus den kleinsten Umbau ab, der das Ziel erreicht. Abschnitt 11 ordnet die Arbeitspakete aus spec/04 zu.

## 0. Kurzfassung

Der Scanner sammelt brauchbare Fakten. Der Reporter wirft diese Fakten in Prosa um, lässt eine KI daraus Befunde erfinden und repariert das Ergebnis anschließend in acht Stufen. Die Reparaturkette ist der eigentliche Fehler: Sie kann nur korrigieren, was sie erkennt, und sie erkennt nur, was die KI zufällig so formuliert hat, wie eine Regel es erwartet. Deshalb driften drei Läufe auf dieselben Rohdaten in 18 von 22 Sachverhalten, deshalb entstehen Falschbefunde (Exchange 2016, MySQL 5.5, SPF fehlt), deshalb fehlen echte Befunde (SonicWall, RD-Gateway) und deshalb kann niemand vor Auslieferung sagen, ob der Report stimmt.

Die Lösung ist keine neue Plattform. Sie besteht aus einer Umkehrung der Reihenfolge: **Fakten zuerst, Befunde aus Regeln, Text zuletzt.** Konkret: eine Faktendatei je Scan (`facts.json`), ein Regelkatalog, der daraus Befunde ableitet, eine KI, die nur noch Sätze zu fertigen Befunden schreibt, ein Gate, das blockiert, und drei Golden-Läufe, die jede Änderung gegen bekannte Wahrheit testen. Etwa 70 % des bestehenden Codes bleiben (Scanner, Parser, Policy-Regeln als Einstufungsquelle, DB, MinIO, Admin-Review, Renderer bis zur Umschaltung). Der Rest wird nicht umgebaut, sondern abgeschaltet.

## 1. Ist-Fluss mit Bruchstellen

```
SCAN-WORKER                                        REPORT-WORKER
Phase 0a passive (Shodan, WHOIS)                    Tar entpacken
Phase 0b DNS, Discovery, httpx, Scope               parser.py: 12 Tool-Parser -> Dicts       (gut)
   KI#1 Host-Strategie (Haiku)                      consolidate_findings(): Dicts -> TEXT    [B2]
Phase 1 nmap, webtech, wafw00f                      KI#5 Reporter (Opus, 37-KB-Prompt):
   KI#2 Tech-Analyse (Haiku)                           TEXT -> findings JSON mit CVSS       [B2][B3]
   KI#3 Phase-2-Config (Haiku, je Host)             qa_check (ohne Cap)                      [B3]
Phase 2 ZAP, ffuf, headers, wpscan, testssl         finding_type_mapper (Regex)              [B3]
Phase 3 correlator -> CorrelatedFinding             ai_finding_type_fallback (Haiku)         [B3]
   KI#4 Confidence-Boost (Sonnet)                   severity_policy (74 Regeln, ~95 % Override) [B3]
   -> orders.correlation_data                       cvss_consistency, business_impact        [B3]
   -> Job-Payload correlatedFindings ──X            selection Top-N, id_renumber             [B3]
_finalize: Tar nach MinIO, Job in Queue             title_policy, claims_guard               [B3]
                                                    report_mapper + _augment_for_v2 (12 Felder,
                                                       lazy, try/except, aus 3 Quellen)      [B1]
                                                    ValidationGate level=warn                [B6]
                                                    ReportLab v2 -> PDF -> MinIO -> DB
                                                    Order -> pending_review
```

X: `correlatedFindings`, `phase3Summary`, `businessImpactScore` werden in `upload.py:289-294` in den Job geschrieben und im Report-Worker nie gelesen (`grep` über `report-worker/reporter/*.py`: kein Treffer). Nur `enrichment` (CVE-Threat-Intel) kommt an.

## 2. Die Bruchstellen im Detail

### B1. Zwei Befundwelten, die sich nie treffen

Beobachtung: Der Scanner erzeugt in Phase 3 strukturierte `CorrelatedFinding`-Objekte (Tool, Host, Port, Confidence, Korroboration, FP-Marker, CVE-Enrichment; `scanner/correlation/correlator.py:61`). Der Report-Worker ignoriert sie und baut Befunde aus den rohen Tool-Ausgaben neu, als Text, per KI. Zusätzlich zieht `_augment_for_v2` zwölf Report-Felder aus drei verschiedenen Quellen (`claude_output`, `host_inventory`, `tech_profiles`), jede in eigenem try/except mit Fallback auf leer.

Wirkung: Tech-Tabelle und Befund widersprechen sich im selben PDF (Tabelle „Exchange SE Build 15.2.2562", Befund „Exchange 2016 EOL"). Positivbefund „SPF korrekt" neben Befund „SPF fehlt" (de-Lauf). Die Phase-3-Arbeit (KI#4, NVD/EPSS/KEV-Korrelation) ist für den Report weitgehend verloren; sie erscheint nur als Badge im Dashboard (`ThreatIntelBadge.tsx`).

Beleg: `docs/report-pipeline/02_data_sources.md`: „Phase-3-Ergebnisse sind nicht im Tar … Findings werden direkt aus den per-host Tool-Outputs konsolidiert."

### B2. Strukturierte Daten werden zu Prosa, damit eine KI sie wieder strukturiert

Beobachtung: `parser.consolidate_findings()` (`parser.py:848`) rendert Ports, testssl-Zeilen, Header, DNS in einen Textblock. `SYSTEM_PROMPT_PROFESSIONAL` (`prompts.py:229`, insgesamt 37 KB Promptdatei) weist die KI an, als Penetration Tester Befunde samt CVSS-Vektor und Score zu erzeugen, mit Referenztabellen, Obergrenzen, Beispielen häufiger Fehler und CVE-Warnungen. Kosten je Report 1,94 USD (Multi-Lauf, 25.418 Cache-Creation-Tokens).

Wirkung: Nichtdeterminismus an der Wurzel. Dieselbe Portliste ergibt einmal „MariaDB exponiert HIGH", einmal „PostgreSQL exponiert HIGH", einmal beides in einer Empfehlung. Die KI erkennt „requires SSL" bei FTP nicht als TLS-Zwang, schreibt „Klartext". Interne Prompt-Hinweise landen als Titel im PDF („[Hinweis: exchange wird laut Scan-Inventar …]"). Bei Ausfall eines Tools fehlt schlicht der Textabschnitt, die KI bemerkt nichts.

Der Prompt bekämpft Symptome dieses Ansatzes mit immer mehr Regeln im Prompt (Referenzwerte, „NICHT HIGH", „Lieber zu wenig CVEs"). Das sind Regeln, die als Code deterministisch wären und im Prompt probabilistisch bleiben.

### B3. Acht Reparaturstufen statt einer Herleitung

Reihenfolge nach `deterministic_pipeline.py` und `worker.py:528-594`: qa_check → finding_type_mapper (Regex auf Titel/Body) → ai_finding_type_fallback (Haiku) → severity_policy (74 Regeln, Kommentar im Code: „überschreibt sonst eh ~95 % der Findings") → cvss_consistency → business_impact → selection → id_renumber → title_policy (Templates mit `?`-Default) → qa_cap nur für SP-FALLBACK → claims_guard.

Wirkung: Jede Stufe hängt davon ab, dass die vorige die KI-Ausgabe richtig erraten hat. Der Type-Mapper erkennt FTP, XFO-Dubletten, Cert-Mismatch, Exim nicht → SP-FALLBACK (3 bis 6 je Lauf) → KI-Titel, KI-Severity, keine Policy. Der CVE-Guard entfernt eine unbelegte CVE, lässt den Befund aber mit HIGH stehen (hu VS-001). Severity 9.1 für TLS 1.0 (Policy SP-TLS-001) neben 3.1 für denselben Sachverhalt im anderen Lauf. Dubletten passieren die Selection. Das System repariert, was es nicht hätte erzeugen dürfen.

Die 74 Policy-Regeln sind wertvoll: Sie enthalten die fachliche Einstufung. Nur ihr Eingang ist falsch (KI-Titel statt Fakt).

### B4. Versionsableitung ohne Plausibilität

`eol_detector.py` parst „5.5.5-10.11.18-MariaDB" als MySQL 5.5 und „9.6.0 or later" als 9.6.0. `cms_fingerprinter.py` meldet „Exchange 2016" mit Konfidenz 0.95 gegen OWA-Build 15.2.x, obwohl 15.2 = 2019/SE und der Header `X-FEServer: EXCHANGE-SE` vorliegt. Es gibt keine Stelle, an der Version, Build und Produktfamilie gegeneinander geprüft werden, und keine Stelle, an der „unbekannt" ein zulässiges Ergebnis ist.

Wirkung: Genau die EOL-Falschbefunde, die DC als Problem Nr. 1 nennt. Sie sind reputationskritisch, weil der Kunde sie sofort widerlegen kann.

### B5. Abdeckung ist unsichtbar

Hetzner blockiert den Scanner nach nmap; alle Phase-2-Tools melden „ok" mit leerem Ergebnis. IPv6-Hosts liefern leeren nmap-Output ohne Fehlerstatus. zap_active (API 400), ffuf (Wordlist), VirusTotal (Key), crt.sh (404) fallen aus, ohne dass der Report es sagt. `waf_block_detector.py` (235 Zeilen) existiert, sein Ergebnis erreicht das Kapitel „Umfang" nicht. Der Report behauptet damit implizit vollständige Prüfung.

Wirkung: Beim Junkerwerk-Scan wurde die Website in keinem der drei Läufe auf Applikationsebene geprüft. Ein Kunde, der das bei einem späteren Vorfall erfährt, verliert das Vertrauen in alle anderen Aussagen des Reports.

### B6. Das Gate warnt und blockiert nicht

`VECTISCAN_VALIDATION_LEVEL` steht in Produktion auf `warn` (`docker-compose.yml:550`). Die sieben Checks (titles, ids, cvss, consistency, tech_table, eol, plan) laufen, ihre Errors landen in `reports.validation_warnings`, das PDF wird trotzdem gebaut und die Order geht in `pending_review`. Der Admin sieht im Review das PDF, nicht die Defektliste.

Wirkung: Die Dubletten-Errors der Junkerwerk-Läufe stehen in der DB und in keinem Prozess. Ein Gate, das nicht blockiert, ist Telemetrie, keine Qualitätssicherung.

### B7. Zusagen im Code, die der Scanner nicht einlöst

„PTES-konform" an acht Stellen (Katalog, Homepage, Prompt, Renderer, Mapper), „KI-gestützt" in Prompt, Mapper, v2_data, Homepage, Datenschutz, eigene CVSS-Vektoren an jedem Befund. Ein automatisierter Außenscan deckt drei von sieben PTES-Phasen ab; CVSS-Eigenwerte ohne Nachweis sind angreifbar; „KI-gestützt" lädt zur Frage ein, was die KI entschieden hat.

Wirkung: Reputationsfallen, die nichts mit Scanqualität zu tun haben und mit einer Textänderung verschwinden.

### B8. Fünf KI-Aufrufe mit Entscheidungsgewalt

KI#1 und KI#3 bestimmen Scan-Umfang und Tool-Konfiguration je Host, KI#2 interpretiert Tech-Profile, KI#4 boostet Confidence (nur nach oben), KI#5 erzeugt den Befundsatz, dazu Haiku-Fallback für Finding-Typen. Jeder Aufruf ist eine Stelle, an der zwei Läufe auseinanderlaufen können. Für Junkerwerk waren die Rohdaten über drei Läufe praktisch identisch; die Drift entstand fast vollständig in KI#5 und der Reparaturkette. KI#1 bis #4 sind deshalb kein akutes Problem, aber sie müssen ihre Entscheidungen protokollieren, damit Abdeckungsunterschiede erklärbar bleiben.

### Warum es so gekommen ist

KI-first war der schnellste Weg zum ersten Report: Rohdaten rein, fertiger Bericht raus. Jeder entdeckte Fehler wurde mit einer weiteren Schicht hinter der KI beantwortet (Type-Mapper, Policy, Title-Policy, QA-Cap, Guards, Gate). Das ist nachvollziehbar und hat bis hierher funktioniert. Es skaliert nicht, weil die Zahl der Reparaturregeln mit der Zahl der KI-Formulierungen wächst, nicht mit der Zahl der Sachverhalte. Sachverhalte im Perimeter-Paket gibt es etwa 30. Formulierungen unendlich viele.

## 3. Zielbild: Fakten → Regeln → Text

```
SCAN-WORKER (unverändert, plus Coverage-Protokoll)
   Tar + host_inventory + tech_profiles + correlated_findings + coverage

REPORT-WORKER v3
   1. facts.json bauen         parser.py (vorhanden) + correlated_findings + coverage
                               -> eine Datei, ein Schema, versioniert, in MinIO neben dem Tar
   2. Regelkatalog anwenden    rules/*.yaml: Fakt-Muster -> Befundtyp, Einstufung, Betroffene
                               Einstufungen aus severity_policy übernommen (Regel = Daten)
   3. Konsolidieren            ein Befund je Sachverhalt, hostübergreifend, Betroffene als Liste
                               Positivbefunde aus denselben Regeln (Muster erfüllt = positiv)
   4. Text erzeugen            Katalogtexte je Befundtyp (deterministisch)
                               KI nur für Kontextabsätze mit Wortlisten- und Längen-Gate
   5. Gate strict              blockiert; Order -> report_blocked; Admin sieht Defektliste
   6. Rendern                  Jinja + WeasyPrint (Prototyp) als v3; ReportLab v2 bleibt schaltbar
   7. Golden-Test              drei Junkerwerk-Läufe: Befundliste muss identisch sein
```

Was bleibt: alle Scanner-Phasen und Tools, `parser.py` (12 Tool-Parser), die fachlichen Einstufungen aus `severity_policy.py`, `title_policy`-Templates als Titelquelle, DB-Schema (eine JSON-Spalte kommt hinzu), MinIO, Queue, Admin-Review, Posture-Aggregation, ReportLab v2 bis zur Umschaltung.

Was abgeschaltet wird: `consolidate_findings()` als Prompt-Text, KI#5 als Befunderzeuger, `ai_finding_type_fallback`, qa_cap, cvss_consistency, Eigen-CVSS an Befunden, claims_guard (wird überflüssig, wenn die KI keine Fakten mehr schreibt), `finding_type_mapper` als Regex auf Titel (der Typ kommt aus der Regel).

Was neu ist: `facts.json` mit Schema, `rules/` als YAML, Coverage-Modell, Textkatalog, Golden-Files, Gate strict mit Order-Status.

## 4. Die einfachen Mittel im Einzelnen

### M1. facts.json (Evidence Layer)

Eine Datei je Scan mit etwa zwölf Entitäten, alle mit `source` (Tool), `observed_at`, `mode` (active/passive) und `confidence`:

```
scan        order_id, package, started, finished, scanner_egress, policy_version
target      domain(s), scope_decisions, out_of_scope[]
host        ip, family(4/6), reverse, provider(ASN), reachable, blocked_by(WAF/Provider)
fqdn        name, host_ip, http_status, title, redirect_to, screenshot_key, reachable
service     host_ip, port, proto, product, version_raw, version_norm, tls_required, auth_required
tls         fqdn:port, protocols[], ciphers_weak[], cert{cn, san[], issuer, not_after, mismatch}
http        fqdn, headers{}, csp, hsts, cookies[], forms[], login_form
dns         domain, ns[], dnssec, caa, mx[], spf{raw, all}, dmarc{raw, p}, dkim_selectors[]
software    host_ip, product, family, version_norm, build, eol{status, date, source}, evidence[]
passive     source(Shodan…), host_ip, port, product, seen_at, verified(false)
coverage    fqdn|host, phase, tool, status(ok|empty|failed|blocked|skipped), reason
threat      cve_id, cvss_nvd, epss, kev, affected_software_ref
```

Quelle: 90 % existiert in `parser.py`, `host_inventory`, `tech_profiles`, `correlated_findings`, `dns_records`, `testssl_raw_by_host`, `headers_by_host`. Neu ist nur die Zusammenführung in ein Schema und die Normalisierung der Versionen (`version_norm`, `family`, `build`) mit Plausibilitätsregeln (MariaDB-Präfix strippen, „or later" → unbekannt, Exchange-Build → Familie). Ein Fakt ohne Tool-Beleg existiert nicht.

Größe: M. Das ist das einzige Arbeitspaket, das echte Denkarbeit im Schema braucht. Alles andere hängt davon ab.

### M2. Regelkatalog

Regeln als Daten, nicht als Python-Funktionen mit Regex auf KI-Titel:

```yaml
- id: R-DB-EXPOSED
  when: service.port in [3306, 5432, 1433, 27017] and service.reachable and host.family == 4
  finding_type: db_exposed
  scale: exposure
  level: kritisch          # aus SP-DB-001 übernommen
  group_by: sachverhalt    # ein Befund für alle DB-Ports aller Hosts
  affected: "{host_ip}:{port} ({service.product})"
  positive_when: no match  # kein Positivbefund, weil Abwesenheit nicht beweisbar ist

- id: R-MAIL-DMARC-MISSING
  when: dns.mx and not dns.dmarc
  finding_type: dmarc_missing
  scale: hygiene
  level: hoch
  positive_when: dns.mx and dns.dmarc.p in [quarantine, reject]
```

Für das Perimeter-Paket reichen etwa 30 Regeln (die 15 Prototyp-Befunde plus 8 Positivbefunde plus die Sachverhalte aus der Befund-Matrix spec/02, die im Prototyp bewusst nicht auftauchen). Die 74 Policy-Regeln liefern Einstufung, Rationale, Referenzen; sie werden nicht neu geschrieben, sondern je Regel referenziert. Regeln für passive Quellen erzeugen Befunde mit `verified: false` und Pflicht-Prüfschritt.

Größe: M. Eine Regel je Stunde, inklusive Test gegen die Golden-Files.

**Ist der Katalog beherrschbar?** Die Sorge liegt nahe: unendlich viele Konfigurationen, also unendlich viele Regeln. Die Daten sagen etwas anderes.

- Drei Junkerwerk-Läufe: 37 Befunde, davon 15 verschiedene `finding_type`, 14 verschiedene `policy_id`. 11 der 37 Befunde (30 %) sind SP-FALLBACK, also Sachverhalte, für die die heutige Regel nicht greift, obwohl sie im Katalog steht (FTP, XFO-Dublette, Cert-Mismatch, Exim-Version). Der Fallback entsteht nicht, weil der Katalog den Fall nicht kennt, sondern weil der Regex den KI-Titel nicht erkennt. Regeln über Fakten hätten getroffen.
- Der Report trunk-immobilien.de (Mai 2026, anderer Kunde, anderer Hoster, anderer Stack) enthält neun Befunde aus denselben Familien: DB-Port exponiert, Server-Banner, veraltetes CMS, FTP, DMARC none, DKIM fehlt, CSP fehlt, Entwicklungsumgebung öffentlich, altes OpenSSH. Und dieselben Fehlermuster: Titel „SPF-Record fehlt" über einem DKIM-Text, Titel „WordPress-Plugin 27" (27 ist eine Theme-Version), MariaDB 5.5.68 als „MySQL" mit widersprüchlichen EOL-Daten (2018 in der Tabelle, April 2020 im Befund), ein Titel zweimal für zwei verschiedene Befunde, drei Positivbefunde mit identischem Satz.
- `severity_policy.py` ist bereits ein Katalog mit 74 Regeln, und laut Code-Kommentar deckt er ~95 % der Befunde ab. Auch der 37-KB-Prompt ist ein Katalog (Referenzwerte für DB-Port, FTP, SSH, DNS, Banner), nur probabilistisch ausgewertet. Der Katalog existiert also längst; er wird nur an der falschen Stelle angewendet.

Der Grund für die geringe Zahl: Ein Außenscan ohne Zugangsdaten kann nur eine begrenzte Menge Dinge beobachten: offene Ports und Dienste, TLS-Konfiguration und Zertifikate, HTTP-Header und Cookies, DNS- und Mail-Records, Softwareversionen, Web-Befunde aus ZAP-Templates, Passivquellen. Das sind rund 25 bis 35 Sachverhaltsfamilien. Die Kombinatorik liegt in den Parametern (welcher Host, welcher Port, welche Version), und Parameter sind Template-Variablen, keine neuen Regeln.

Was tatsächlich variiert und wie es abgefangen wird:

| Variabel | Lösung | Pflege |
|---|---|---|
| Host, Port, Produkt, Version im Text | Template-Variablen aus `facts.json` | keine |
| EOL-Daten, aktuelle Versionen | Datenfeed (endoflife.date), nicht Katalogtext | automatisch |
| CVE-Zuordnung, Scores, KEV | Datenfeed (NVD, EPSS, KEV) als Fremdreferenz | automatisch |
| Web-Befunde aus ZAP/nuclei | Werkzeug liefert eigene Beschreibung; generische Regel „Werkzeugbefund" mit Werkzeugtext als Nachweis, Einstufung aus Policy | eine Regel je neuer Familie, selten |
| Sachverhalt ohne Regel | landet als „unverarbeitete Beobachtung" im Admin-Review, nie im Kundenreport; Admin entscheidet, ob daraus eine Regel wird | eine Regel plus ein Fixture je Fall |
| Branchenkontext, Systemzweck | KI-Kontextabsatz, nicht Katalog | keine |

Erwartung: 30 Regeln zum Start, ein bis zwei neue je Kunde in den ersten zehn Kunden, danach nahe null. Belegt durch die Simulation über alle 36 Produktionsscans in spec/06 (42 Entwurfsregeln, Sättigung nach 15 Läufen, Restmenge unter einer Beobachtung je Scan, 35 belegbare Falschbefunde der KI in ausgelieferten Reports). Der Katalog wächst linear mit Sachverhalten, nicht mit Konfigurationen. Das heutige System wächst mit Formulierungen, und davon gibt es beliebig viele.

Eine sinnvolle Rolle für die KI bleibt an dieser Stelle: Im Admin-Review kann sie zu einer unverarbeiteten Beobachtung einen Regelvorschlag machen (Muster, Einstufung, Textbausteine). Der Mensch bestätigt, die Regel geht mit Fixture in den Katalog. KI schlägt vor, Katalog entscheidet.

### M3. Konsolidierung

Ein Sachverhalt = ein Befund. `group_by` in der Regel bestimmt, ob je Host, je FQDN oder global konsolidiert wird. IDs lückenlos nach Konsolidierung. Selection (Top-N) bleibt, arbeitet aber auf konsolidierten Befunden mit deterministischer Sortierung (Status, Dringlichkeit, Regel-ID). Dubletten sind damit strukturell unmöglich.

Größe: S.

### M4. Text: Katalog zuerst, KI begrenzt

Jeder Befundtyp bekommt im Katalog vier Textbausteine (Beobachtung-Template, Bedeutung, Empfehlung in Stufen, Prüfschritt). Die 15 Prototyp-Befunde sind die erste Fassung. Damit ist der Report ohne KI vollständig und korrekt.

KI (ein Aufruf, Sonnet) schreibt danach nur: Zusammenfassung Seite 1, Kontextabsatz Kapitel 1, Beobachtungssätze zu Systemen in Kapitel 3, optional Feinschliff der Bedeutungssätze. Eingabe sind fertige Befunde und Fakten, nicht Rohdaten. Ausgabe wird gegattert: keine Zahlen, die nicht in den Fakten stehen, keine CVE-IDs, keine Severity-Wörter, keine Hostnamen außerhalb der Betroffenenliste, Längenlimit je Feld. Bei Gate-Fehler bleibt der Katalogtext stehen. Kosten je Report unter 0,20 USD.

Größe: S für Katalog (Texte liegen vor), S für KI-Aufruf mit Gate.

### M5. Coverage

`coverage`-Einträge entstehen im Scanner (jeder Tool-Run kennt schon `status` in `record_tool_run`) und im Report-Worker aus leeren Ergebnissen (Tool „ok" mit 0 Zeilen bei erreichbarem Host = `empty`, bei blockiertem Host = `blocked`). `waf_block_detector` schreibt `host.blocked_by`. Kapitel 2 des Reports wird daraus generiert: Tabelle je FQDN mit voll/teil/keine und Klartext-Einschränkungen. Der Prototyp zeigt die Zielform.

Größe: S. Ohne diesen Baustein ist jeder Report eine implizite Vollständigkeitsbehauptung.

### M6. Gate strict mit Prozess

`VECTISCAN_VALIDATION_LEVEL=strict`, neuer Order-Status `report_blocked`, Admin-Ansicht zeigt die Defektliste statt des PDF. Neue Checks kommen aus dem Prototyp-Build (`build_report.py:check_data`): IDs lückenlos, Titel eindeutig, keine Platzhalter, scale/level gültig, zitierte Fremd-Scores gegen `threat`, Werkzeuge ohne Version, Plan-Referenzen vollständig, Coverage-Kapitel nicht leer, keine Tech-Zeile widerspricht einem Befund (Familie/Version aus derselben `software`-Entität).

Größe: S. Der Gate-Rahmen existiert; es fehlen Level, Status und Sichtbarkeit.

### M7. Golden-Files

Die drei Junkerwerk-Läufe (Tar, host_inventory, tech_profiles, correlated_findings) werden Fixtures. Soll-Ausgabe: die Befundliste des Prototyps (15 Befunde, 8 Positivbefunde, IDs, Einstufungen, Betroffene) als JSON. CI-Test: `facts.json` aus drei Läufen ergibt dieselbe Befundliste; Abweichung = roter Build. Jede neue Regel bekommt ihren Fall in den Golden-Files. Später kommen weitere Kunden-Läufe dazu (anonymisiert).

Größe: S. Das ist die Versicherung gegen Rückfall.

### M8. Renderer

Prototyp-Template (Jinja2 + WeasyPrint, `build/template.html.j2`) wird `report-worker/reporter/pdf/v3/`. Eingabe ist das Datenmodell aus `report_data.py`, das der Reporter v3 nun direkt füllt. ReportLab v2 bleibt unter `VECTISCAN_REPORT_LAYOUT=v2` erreichbar, bis v3 zwei Kundenreports ohne Beanstandung geliefert hat. WeasyPrint kommt als Systempaket in das Worker-Image (Fonts Inter, DejaVu Sans Mono mitliefern).

Größe: M. Layout-Arbeit ist geleistet; offen sind Paket-Varianten (webcheck, compliance, tlscompliance) und Mehrsprachigkeit, falls gewünscht.

### M9. Zusagen bereinigen

PTES-Formulierung ersetzen (Katalog, Homepage, Subscribe, Prompt, Renderer, Mapper, CLAUDE.md), „KI-gestützt" ersetzen durch „regelbasiert mit Werkzeugen X", CVSS-Eigenwerte entfernen, Datenschutzseite anpassen (KI schreibt Texte, entscheidet keine Befunde).

Größe: S. Textänderungen, kein Risiko, sofort möglich.

## 5. Was bewusst nicht gebaut wird

- Kein neuer Scanner, keine neuen Tools, keine Änderung der Phasen 0 bis 3.
- Keine neue Datenbankstruktur außer `reports.facts_key` (MinIO-Pfad) und Order-Status `report_blocked`.
- Keine Ablösung von KI#1 bis #4. Sie bekommen nur ein Entscheidungsprotokoll in `coverage`/`scan` (welcher Host warum wie gescannt wurde). Abschaltung oder Vereinfachung ist ein späteres Thema, wenn die Golden-Files Drift aus dem Scanner zeigen.
- Keine Multi-Modell-Orchestrierung, keine Agenten im Reporter. Ein KI-Aufruf für Prosa.
- Kein Umbau des Frontends außer Admin-Defektliste und neuem Status.
- Keine parallele Pflege von v2-Reparaturkette und v3. Wenn v3 auf `strict` steht und Golden-Files grün sind, wird die Reparaturkette entfernt, nicht gewartet.

## 6. Reihenfolge

Jeder Schritt hinterlässt ein lauffähiges System. Reihenfolge nach Abhängigkeit und Reputationsrisiko.

| Schritt | Inhalt | Bausteine | Größe | Ergebnis |
|---|---|---|---|---|
| 0 | Zusagen bereinigen, Gate auf strict im Staging, Golden-Fixtures ablegen | M9, M6 (Teil), M7 (Teil) | S | Keine PTES/KI-Claims mehr; Defekte sichtbar |
| 1 | facts.json mit Versions-Normalisierung und Coverage; Ausgabe zunächst nur neben dem alten Report | M1, M5 | M | Fakten pro Scan prüfbar; EOL-Falschbefunde an der Quelle abgestellt |
| 2 | Regelkatalog + Konsolidierung; Golden-Test „drei Läufe, eine Befundliste" grün | M2, M3, M7 | M | Drift 0 auf Junkerwerk; keine Dubletten; SonicWall/RD-Gateway/PostgreSQL erscheinen |
| 3 | Textkatalog + KI nur für Prosa mit Gate; Gate strict in Produktion mit `report_blocked` | M4, M6 | S | Report ohne KI korrekt; KI-Kosten unter 0,20 USD; nichts Ungeprüftes wird ausgeliefert |
| 4 | Renderer v3 aus dem Prototyp, Paketvarianten, Umschaltung | M8 | M | Kundenreport in Prototyp-Qualität aus der Applikation |
| 5 | Reparaturkette entfernen, Doku (`docs/report-pipeline`) auf v3 umschreiben | Aufräumen | S | Wartbare Pipeline mit einem Datenmodell |

Schritt 0 und 1 können sofort beginnen. Schritt 4 kann parallel zu 2 und 3 laufen, weil das Datenmodell des Prototyps schon feststeht.

## 7. Messgrößen

| Kennzahl | Ist (Junkerwerk) | Ziel |
|---|---|---|
| Sachverhalte mit gleicher Bewertung über Wiederholungsläufe | 4 von 22 | 22 von 22 (Golden-Test) |
| Falschbefunde je Report | 5 (Exchange, MySQL, SPF, FTP, IMAP/POP3) | 0 im Golden-Set; jeder neue Fall wird Regel + Fixture |
| Fehlende relevante Befunde | 3 (SonicWall, RD-Gateway, PostgreSQL im de-Lauf) | 0 im Golden-Set |
| Dubletten | 2 je Lauf | strukturell 0 |
| Abdeckungslücken im Report benannt | 0 von 7 | alle (Kapitel 2 generiert) |
| Gate-Errors, die ausgeliefert werden | alle (warn) | 0 (strict, report_blocked) |
| KI-Kosten je Report | 1,94 USD | unter 0,20 USD |
| KI-Aufrufe mit Entscheidungsgewalt im Reporter | 2 (Opus Befunde, Haiku Typen) | 0 |
| Zeit Admin-Review je Report | unbekannt, PDF-Lesen | Defektliste leer = Freigabe in Minuten |

## 8. Entscheidungen, die den Plan formen

Entschieden am 17.09.2026 (DC):

1. **Textquelle:** Katalogtexte als Grundlage, KI nur für Kontextabsätze mit Gate. Voraussetzung war die Frage nach der Katalogpflege; Antwort in M2 („Ist der Katalog beherrschbar?"). Ergänzung: KI darf im Admin-Review Regelvorschläge für unverarbeitete Beobachtungen machen.
2. **Renderer:** WeasyPrint aus dem Prototyp wird v3. ReportLab v2 bleibt per `VECTISCAN_REPORT_LAYOUT` schaltbar bis zwei Kundenreports ohne Beanstandung.
3. **Order-Status bei Gate-Fehler:** neuer Status `report_blocked`, Admin sieht Defektliste statt PDF.
5. **Scanner-KI (#1 bis #4):** belassen, Entscheidungen in `facts.json` protokollieren. Umbau erst, wenn Golden-Files Drift aus dem Scanner zeigen.

Offen:

4. **Kontextdaten des Kunden** (Branche, Mitarbeiterzahl, Systemzweck, Ansprechpartner): im Bestellprozess abfragen oder im Admin-Review nachtragen. Ohne diese Daten bleibt der Kontextabsatz Kapitel 1 generisch.
6. **ID-Schema:** `VS-<Kundenkürzel>-<Jahr>-<lfd>` wie im Prototyp (stabil über Folgeberichte, zitierbar) oder `VS-<Jahr>-<lfd>` wie bisher.

## 9. Woran man erkennt, dass die Architektur richtig ist

- Ein Befund lässt sich in unter einer Minute bis zum Tool-Output zurückverfolgen (`facts.json` → Regel → Befund).
- Ein neuer Fehlertyp kostet eine Regel und ein Fixture, keinen Prompt-Absatz.
- Zwei Läufe auf dieselbe Infrastruktur ergeben dieselbe Befundliste; Unterschiede sind Coverage-Unterschiede und stehen in Kapitel 2.
- Der Report ist ohne KI vollständig; die KI macht ihn lesbarer, nicht richtiger.
- Ein Admin gibt frei, weil die Defektliste leer ist, nicht weil das PDF gut aussieht.

## 10. Risiken des Umbaus

- **Regelkatalog zu eng:** Sachverhalte, für die es keine Regel gibt, erzeugen keinen Befund. Gegenmittel: `coverage` zeigt Tool-Findings ohne Regeltreffer als „unverarbeitete Beobachtungen" im Admin-Review (nicht im Kundenreport); daraus entstehen neue Regeln. Das ist gewollt: lieber ein fehlender Befund, den der Admin sieht, als ein erfundener, den der Kunde sieht.
- **Versions-Normalisierung unvollständig:** Neue Produkte liefern Banner, die das Schema nicht kennt. Gegenmittel: `version_norm = unbekannt` ist zulässig und erzeugt keinen EOL-Befund; EOL nur bei sicherer Familie und Version.
- **WeasyPrint im Worker-Image:** Paket- und Fontabhängigkeiten. Gegenmittel: Build im Prototyp ist reproduzierbar (Dockerfile-Zeilen liegen vor); v2 bleibt schaltbar.
- **Zeit:** Schritte 1 und 2 sind je eine konzentrierte Woche in Claude-Code-Sessions mit diesem Dokument und spec/04 als Vorgabe. Bis dahin liefert der Prototyp-Weg (manuell kuratiert) auslieferungsfähige Reports.

## 11. Zuordnung zu spec/04

| Baustein hier | Arbeitspaket spec/04 |
|---|---|
| M9 Zusagen | WP0 |
| M1 facts.json | WP1 Evidence Layer (A) |
| M5 Coverage | WP2 (B) |
| M2 Regelkatalog | WP3 (C) |
| M3 Konsolidierung | WP4 (D) |
| M4 Text | WP5 (E) |
| M6 Gate | WP6 (F) |
| M8 Renderer | WP7 (G) |
| M7 Golden-Files | WP8 (H) |
| Schritt 5 Aufräumen | WP9/WP10 |

Neu gegenüber spec/04: Bruchstelle B1 (correlated_findings werden nie gelesen) und B8 (Scanner-KI protokollieren statt umbauen), die Abgrenzung in Abschnitt 5, die Messgrößen in Abschnitt 7 und die Erkennungsmerkmale in Abschnitt 9.
