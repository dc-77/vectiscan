# 10 — Anhänge A-F

`pdf/v2/layers/appendix.py:build_appendix` (Z. 619) ruft sechs Sub-Builder in fixer Reihenfolge.

## Render-Helper (Z. 27-78)

| Helper | Zeile | Zweck |
|---|---|---|
| `_section(story, styles, title)` | 27 | H1-Section-Überschrift |
| `_subsection(story, styles, title)` | 32 | H2-Subsection-Überschrift |
| `_body(story, styles, text)` | 37 | Plain-Paragraph |
| `_table(story, styles, header, rows, col_widths)` | 42 | Formatierte Tabelle mit Header-Styling |

## A — CVSS-Tabelle + Hygiene-Skala (Z. 109)

Liest `data["layer1"]["hygiene_split"]` mit `{"cvss": [...], "hygiene": [...]}`. Fallback (Z. 116-119): wenn `layer1` fehlt, iteriert über `data["findings"]` und sortiert per `f.scale` (`"cvss"` Default).

### A.1 — CVSS v3.1 (Z. 134-156)

Tabelle mit 6 Spalten:

| Spalte | Quelle | Breite |
|---|---|---|
| ID | `external_id` oder `id` | 18mm |
| Titel | `title` | 56mm |
| Severity | `severity.upper()` | 18mm |
| Score | `cvss_score` | 14mm |
| Vektor | `cvss_vector` | 50mm |
| CWE | `cwe` | 14mm |

Wenn `cvss_findings` leer: italic "*(keine Befunde mit CVSS-Skala in diesem Report)*".

### A.2 — Hygiene-Skala (Z. 158-180)

Tabelle mit 4 Spalten:

| Spalte | Quelle | Breite |
|---|---|---|
| ID | `external_id` oder `id` | 18mm |
| Titel | `title` | 65mm |
| Hygiene-Stufe | `_hygiene_level_label(f.hygiene_level)` | 22mm |
| Begründung | `_hygiene_reason(f)` | 65mm |

`_hygiene_level_label` (Z. 80): mapped numerische Stufe (0..3) auf Label ("Beobachtung", "Hinweis", "Hardening-Lücke", "Wirksame Lücke").

`_hygiene_reason` (Z. 88): kurze Begründung pro Eintrag, gebaut aus Impact-Token + Policy-ID + Finding-Type.

## B — Service-Inventar (Z. 269)

Liest `data["service_cards"]` (aus `befund_landschaft.build_service_cards`). Returnt früh, wenn leer.

### Pre-Computation: _SERVICE_RECOMMENDATION_HINT (Z. 186)

Map `port → Empfehlungstext` mit 25 Einträgen:

| Port | Empfehlung |
|---|---|
| 21 | Klartext-FTP - SFTP einsetzen, Port schliessen |
| 23 | Telnet - nicht mehr produktiv einsetzen |
| 25 | SMTP - nur ausgehender Mailverkehr; eingehend STARTTLS pflicht |
| 53 | DNS - Open-Resolver-Check; rekursive Anfragen begrenzen |
| 80 | HTTP - auf HTTPS umstellen, 301-Redirect |
| 110/143 | POP3/IMAP - durch …S ersetzen |
| 389 | LDAP - LDAPS bzw. STARTTLS verlangen |
| 443 | HTTPS - TR-03116-Konformitaet pruefen |
| 465/587 | SMTPS/SUBMISSION |
| 993/995 | IMAPS/POP3S - aktiv |
| 1433/1521/3306/5432 | DB - intern halten oder Firewall-Regel |
| 3389 | RDP - nur ueber VPN/MFA |
| 5900 | VNC - nur ueber VPN; Klartext |
| 6379 | Redis - intern halten, Auth aktivieren |
| 8080/8443 | HTTP-Alt/HTTPS-Alt |
| 9200/11211/27017 | Elasticsearch/Memcached/MongoDB - intern halten |

### _findings_by_port_host (Z. 223)

Baut Index `(host, port) → [finding_ids]`:

- Host-Kandidaten: `vhost, fqdn, host, host_ip, ip` + erster Teil von `affected` vor dem `:`.
- Port-Kandidaten: `finding.port` + Regex `:(\d{1,5})\b` gegen `affected`.

`_service_recommendation_text(port, finding_refs)` (Z. 215): wenn finding_refs vorhanden → `"siehe VS-2026-005, VS-2026-007, …"` (max 3). Sonst Hint aus der Map oder `"—"`.

### Render (Z. 280-344)

Pro Card mit erreichbaren Ports:

- H2 mit `host_label`.
- Tabelle 4 Spalten: Port, Service, Version, Empfehlung/Querverweis. Spaltenbreiten 16/30/22/102 mm.

Hosts ohne Ports werden in `empty_hosts[]` gesammelt und als kompakte Sammel-Zeile am Ende der Sektion ausgegeben (Z. 336-342): *"Folgende Hosts haben in der externen Pruefung keine erreichbaren Ports gezeigt: \<Liste\>."* — verhindert Whitespace-Seitenfortsätze.

## C — Eingesetzte Tools + Konfidenz (Z. 376)

Liest die hardcoded Liste `reporter.report_mapper.SCAN_TOOLS` (Lazy-Import Z. 380, leer wenn Import fehlschlägt).

### _TOOL_CONFIDENCE (Z. 352)

16 Einträge:

| Tool | Konfidenz |
|---|---|
| nmap | hoch (Service-Detection mit -sV) |
| webtech | mittel-hoch (Signatur-basiert) |
| wafw00f | mittel |
| subfinder | hoch (passive) |
| crt.sh / certspotter | hoch (CT-Logs autoritativ) |
| dnsx | hoch |
| httpx | hoch |
| gobuster | mittel |
| testssl.sh | sehr hoch (autoritative TLS-Analyse) |
| ZAP Spider | mittel |
| ZAP Ajax Spider | mittel |
| ZAP Active Scan | mittel-hoch |
| ffuf | mittel |
| feroxbuster | mittel |
| wpscan | hoch (CVE-Datenbank-Match) |
| NVD/EPSS/KEV | hoch (autoritative Threat-Intel) |

`_tool_confidence(name)` (Z. 372): Default `"mittel"` bei Cache-Miss.

### Render

Tabelle 4 Spalten: Tool, Phase, Funktion, Konfidenz. Spaltenbreiten 32/22/70/46 mm. Jede Zeile kommt direkt aus einem `SCAN_TOOLS`-Eintrag.

## D — Compliance-Mapping (Z. 414)

Liest `data["findings"]` + `data["compliance_mappings"]` (siehe `11_compliance_mappings.md`).

Tabelle 6 Spalten:

| Spalte | Breite |
|---|---|
| ID | 18mm |
| Befund | 40mm (truncated auf 60 chars) |
| NIS2 / §30 BSIG | 28mm |
| BSI-Grundschutz | 25mm |
| ISO 27001 | 18mm |
| DSGVO | 35mm |

Findings ohne Mapping-Eintrag bekommen "nicht definiert" in jeder Framework-Spalte (Z. 441-446).

## E — Methodische Filterungen (Z. 487)

Liest `data["methodology_stats"]` (`filtered_count, selected_count, filter_rate_pct`) + `data["additional_findings"]`.

### Statistik-Paragraph (Z. 500-507)

```
Waehrend dieses Scans wurden <b>{total_raw} Roh-Befunde</b> von den eingesetzten
Tools erzeugt. Nach Korrelation, False-Positive-Filterung und Severity-Bewertung
verbleiben <b>{selected_count} validierte Befunde</b> (Filterrate {rate}%).
```

### E.1 — Aufschlüsselung pro Filter-Grund (Z. 516-527)

`_aggregate_filter_reasons(additional)` (Z. 469) baut `[(reason, tool, count)]`, sortiert nach Count DESC. Tabelle 3 Spalten: Filter-Grund, Tool, Anzahl (Breiten 85/40/18 mm).

`reason`-Quellen pro Eintrag: `entry["reason"]` → `entry["filter_reason"]` → "ohne Begruendung".

### E.2 — Was wurde typischerweise gefiltert? (Z. 530-548)

Statische Bullet-Liste mit 4 Kategorien:

- Doppelmeldungen über mehrere Tools.
- Generische Hinweise ohne praktische Auswirkung.
- Findings unterhalb der Bagatell-Grenze.
- False-Positives der KI-Korrelation (Phase 3 Cross-Tool-Confidence-Boost mit Sonnet 4.6).

Plus Note (Z. 544): Roh-Output auf Anforderung verfügbar, Aufbewahrung 90 Tage.

## F — Wiederholungsempfehlung + Haftung (Z. 568)

Liest `data["scope_meta"]["scan_date"]` für die Geltungsdauer.

### F.1 — Wiederholungsempfehlung (Z. 576-588)

Default: 12 Monate. Trigger-Liste `_TRIGGER_LIST` (Z. 555) mit 6 Einträgen:

1. jeder größeren Architekturänderung (neue Hosts, neue Domains, Migration);
2. jedem CMS-Major-Upgrade oder Framework-Wechsel;
3. jeder Freischaltung eines neuen extern erreichbaren Dienstes;
4. jedem Verdacht auf einen Sicherheitsvorfall;
5. Vorhandensein eines neu bekannt gewordenen CVEs in eingesetzten Komponenten;
6. Vorbereitung auf einen NIS2/BSI/ISO-Audit.

### F.2 — Geltungsdauer (Z. 590-599)

Paragraph: "Dieser Bericht bildet den Zustand vom \<scan_date\> ab. Bereits am Folgetag …".

### F.3 — Haftungsausschluss (Z. 602-613)

Vier-Punkte-Paragraph zur Erkennungs-Grenze des externen automatischen Scans (Insider-Bedrohungen, Konfigurationsfehler hinter Auth-Stufen, Zero-Day).

## Reihenfolge in `build_appendix` (Z. 619)

```python
_build_appendix_a(story, styles, data)
_build_appendix_b(story, styles, data)
_build_appendix_c(story, styles, data)
_build_appendix_d(story, styles, data)
_build_appendix_e(story, styles, data)
_build_appendix_f(story, styles, data)
```

Anhang B wird übersprungen, wenn `service_cards` leer ist (Z. 272-273). Anhang D wird übersprungen, wenn `findings` leer ist (Z. 422-423). Anhang A wird nicht übersprungen — er rendert auch dann eine Sektion mit "*(keine Befunde …)*"-Paragraph wenn nichts da ist.
