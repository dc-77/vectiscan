# Status quo — PDF-Report-Erstellung

> **⚠ ABGELOEST DURCH v2 (Stand 2026-05-13).**
> Dieses Dokument beschreibt den **Legacy-v1-Renderer**. Es war die Basis fuer
> die Fehleranalyse (`01_Fehleranalyse_und_Korrekturplan.md`) und das Neudesign
> (`02_Report_Aufbau_Neudesign.md`). Der v2-Renderer ist seit M5+M6.1
> implementiert und per ENV `VECTISCAN_REPORT_LAYOUT=v2` aktivierbar; der
> Big-Bang-Default-Flip + Legacy-Removal erfolgt nach Pilot.
> Aktueller Soll-Zustand: `references/report_structure.md` Abschnitt
> "v2-Renderer".

> **Zweck dieses Dokuments**
>
> Bestandsaufnahme vor dem Re-Design der VectiScan-PDF-Reports.
> Es beschreibt, **welche Daten ein Scan liefert**, **wie sie durch die
> Report-Pipeline laufen** und **was davon im PDF landet — und was nicht**.
>
> **Quellen**: Code-Trace mit Datei-/Zeilen-Belegen, Live-API gegen
> `scan-api.vectigal.tech`, eingebettete Screenshots aus einem realen
> Perimeter-Report (`secumetrix.de`, Order `7629dd77-…`, 2026-05-11).
>
> **Stand**: 2026-05-12 · `POLICY_VERSION=2026-05-10.1` · ABGELOEST

---

## 1 · Big Picture

```
SCAN-WORKER                          MinIO                  REPORT-WORKER                  PDF
───────────                          ─────                  ─────────────                  ───
Phase 0a passive intel               scan-rawdata/          worker.py listens on
   ├─ shodan, abuseipdb, otx          <orderId>.tar.gz       Redis queue 'report-pending'
   ├─ securitytrails                  ├─ hosts/<ip>/         │
   ├─ whois, dns_security            │  ├─ nmap.xml          ▼
   └─ passive_subdomains             │  ├─ nuclei.jsonl     1. download tar.gz
Phase 0b DNS+httpx+scope             │  ├─ testssl.json     2. parser.py        ─┐ 10 tool
  ┌─ KI #1 host_strategy ──┐         │  ├─ zap_alerts.json                      │ parser
Phase 1 tech detection     │         │  ├─ headers.json     3. claude_client     │ (nmap,
  ┌─ KI #2 cms_fingerprint │         │  ├─ httpx.json          (sonnet/opus)     │ nuclei,
  ├─ KI #3 phase2_config   │         │  ├─ wpscan.json      4. qa_check          │ testssl,
Phase 2 deep scan          │         │  └─ ... (ffuf,       5. deterministic    │ zap,
  ├─ zap, nuclei, testssl  │         │     dalfox, katana,    pipeline           │ httpx,
  ├─ wpscan, nikto, …      │         │     gobuster, …)        ├─ type_mapper    │ wpscan,
Phase 3 correlation        │         scan-screenshots/         ├─ severity_      │ headers,
  └─ KI #4 confidence ─────┘         <orderId>/                │  policy        │ gobuster,
                                     <ip>__<vhost>.png         ├─ business_     │ katana,
                                                               │  impact         │ playwright)
DB writes:                                                     └─ selection      │
  scan_results (52 rows/scan)                              6. report_mapper   ─┘
  orders.passive_intel_summary                                (paket-dispatch)
  orders.correlation_data (2000+)                          7. generate_report
  orders.business_impact_score                                (ReportLab → PDF)  ──▶ scan-reports/
  host_tech (tech-stack pro host)                          8. DB insert reports          <orderId>.pdf
                                                              + UPDATE orders.status
```

**Endzustand nach `status=delivered`** (siehe Live-API für `7629dd77`):

- 52 Zeilen in `scan_results` (Phase 0–4)
- 2185 Einträge in `orders.correlation_data` (424 valid, 1761 als FP gefiltert)
- 10 Findings + 3 positive Findings in `reports.findings_data`
- 21 PDF-Seiten in `scan-reports/<orderId>.pdf`

---

## 2 · Datenquellen am Ende eines Scans

### 2.1 · MinIO-Buckets

Definiert in `api/src/lib/minio.ts:11`, geschrieben von
`scan-worker/scanner/upload.py`:

| Bucket | Pfad | Inhalt |
|---|---|---|
| `scan-rawdata` | `<orderId>.tar.gz` | Komprimiertes Scan-Verzeichnis mit allen Tool-Outputs aller Phasen |
| `scan-screenshots` | `<orderId>/<ip>__<vhost>.png` | Pro-VHost-Screenshots seit PR-D (Mai 2026, vorher 1 pro IP) |
| `scan-reports` | `<orderId>.pdf` bzw. `<orderId>_v<n>.pdf` | Finales PDF, Regenerationen versioniert |
| `scan-authorizations` | hochgeladene Verifizierungs-Dokumente | DNS-TXT-Snapshots, File-Proofs, Meta-Tag-Proofs |

**Im `scan-rawdata.tar.gz` enthalten**:

```
<orderId>/
├── meta.json                              # Order-Meta + Paket + Targets
├── phase0/
│   ├── host-inventory.json                # Hosts + FQDNs + has_web
│   └── domain-dns.json                    # DNS Records
├── phase1/
│   └── tech-profiles.json                 # Tech-Stack pro Host
└── hosts/<ip>/
    ├── nmap.xml          ├── feroxbuster   ├── headers.json
    ├── nuclei.jsonl      ├── ffuf*.json    ├── httpx.json
    ├── testssl.json      ├── dalfox.json   ├── webtech.json
    ├── wpscan.json       ├── katana.txt    ├── wafw00f.json
    ├── nikto.json/txt    ├── zap_alerts.json
    ├── gobuster_dir.txt  ├── zap_spider_urls.json
    └── screenshots/      (lokale Playwright-Outputs)
```

### 2.2 · DB-Tabellen mit Scan-Ergebnissen

Schema-Quelle: `docs/DB-SCHEMA.sql` + alle Migrationen unter
`api/src/migrations/`.

| Tabelle | Zweck | Schlüsselspalten | Anmerkungen |
|---|---|---|---|
| `orders` | Scan-Auftrag + Aggregat-Metadaten | `status`, `passive_intel_summary` (JSONB), `correlation_data` (JSONB), `business_impact_score`, `overall_risk` | Migration 009 fügt passive_intel_summary + business_impact_score |
| `scan_targets` / `scan_target_hosts` | Multi-Target-Modell | hostname, ip, verifiziert | Migration 014 |
| `scan_target_subdomain_snapshots` | Subdomain-Cache mit TTL 24h | `all_subdomains` (TEXT[]), `tool_sources` (JSONB: crtsh/subfinder/amass/axfr) | Migration 019 |
| `scan_results` | Per-Tool-Output-Historie über alle Phasen | `phase`, `tool_name`, `raw_output`, `findings` (JSONB), `exit_code`, `duration_ms` | typisch 50–80 Zeilen pro Order; Persistierung auch der AI-Debug-Outputs (`ai_*_debug`) |
| `host_tech` | Pro-Host Tech-Stack | cms, cms_version, cms_confidence, server, waf, tech_versions | Migration 027 |
| `reports` | Finales Report-Datenmodell | `findings_data` (JSONB), `tech_profiles` (JSONB), `additional_findings` (JSONB), `policy_version`, `policy_id_distinct`, `severity_counts`, `excluded_findings`, `minio_path`, `download_token` | Migrationen 007, 011, 016, 017, 027 |
| `threat_intel_cache` | NVD/EPSS/CISA-KEV/ExploitDB Cache | `cache_key`, `cache_value` (JSONB), `source`, `expires_at` | wird vom Phase-3-Enrichment gefüllt |
| `scan_authorizations` | Domain-Ownership-Nachweise | Methode, Status, Beleg | für admin-review-Workflow |

### 2.3 · 4 KI-Outputs

Quelle: `scan-worker/scanner/ai_orchestrator.py`, `correlation/correlator.py`,
sowie die DB-Reflexion über `scan_results` (Live-API: `tool_name`-Filter).

| KI | Phase | Modell | Wo persistiert? | Was bleibt? |
|---|---|---|---|---|
| **#1 Host-Strategy** | 0b → 1 | Haiku 4.5 | `scan_results` (tool=`ai_host_strategy` + `_debug`) + Entscheidungs-Outcome in `orders.passive_intel_summary` | Vollständiges System-Prompt + JSON-Antwort (Debug) |
| **#2 CMS-Korrektur** | 1 | Haiku 4.5 | `host_tech.cms`, `host_tech.cms_version`, `host_tech.cms_confidence` | nur Final-Wert, kein Reasoning |
| **#3 Phase-2-Config** | 1 → 2 | Haiku 4.5 (mit Rule-Based-Fallback) | `scan_results` (tool=`ai_phase2_config`, `_rule_based`, `_debug`) | ZAP-Policy, spider_depth, active_categories, skip_tools |
| **#4 Cross-Tool-Confidence** | 3 | Sonnet 4.6 | Per-Entry-Confidence in `orders.correlation_data`, Aggregat in `scan_results` (tool=`phase3_correlation`) | aggregierte Scores, KEIN Pro-Entry-Reasoning-Text |

**Beobachtung secumetrix.de**: `ai_phase2_config` lief Rule-Based
(`reasoning: "[RULE-BASED] rule:wordpress-standard"`) und nicht über die KI.
Der `_debug`-Output für KI #1 enthält das vollständige System-Prompt
(≥ 3 KB Text).

### 2.4 · `passive_intel_summary` (Phase 0a)

Komplexer JSONB-Block in `orders.passive_intel_summary` mit fünf Top-Level-
Keys. Live-Auszug:

| Key | Inhalt |
|---|---|
| `dns_security` | DMARC, DKIM, SPF, MTA-STS, BIMI, DANE-TLSA, CAA, TLS-RPT, DNSSEC mit Sub-Keys wie `dnskey_count`, `nsec3_iterations`, `nsec3_rfc9276_violation` |
| `shodan_domain` | A/MX/NS/SOA-Records inkl. `last_seen`-Timestamps (Drift-Detection möglich) |
| `securitytrails` | historische Subdomain-Daten |
| `passive_subdomains` | vollständige Subdomain-Liste mit Tool-Quelle |
| `otx` | AlienVault-Pulses (Threat-Intel) |

### 2.5 · `correlation_data` (Phase 3)

`orders.correlation_data` ist die **Goldgrube** — typisch 2000+ Einträge,
davon 70–80 % deterministisch als FP gefiltert. Pro Entry:

```json
{
  "fqdn": "secumetrix.de", "host_ip": "45.157.234.103", "port": null,
  "source_tool": "header_check",   // header_check, zap_passive, nuclei, …
  "title": "Missing security header: x-frame-options",
  "severity": "low",
  "cluster_id": "security_headers_45.157.234.103",
  "confidence": 0.95,
  "is_false_positive": false, "fp_reason": "",
  "corroborating_tools": [],
  "cve_id": null,
  "enrichment": { "business_impact": 3 }
}
```

**Reale Verteilung secumetrix.de**:
- 2185 entries — 2165 von `zap_passive`, 20 von `header_check`
- Severity: 1842 low, 339 medium, 4 high
- 1761 als FP gefiltert → 424 valid → davon nur **10** ins finale `findings_data`

### 2.6 · `findings_data` (Hauptobjekt für den Report)

Geschrieben von `report-worker/reporter/worker.py:_create_report_record`
(Z. 103–153). Top-Level-Keys:

```
overall_risk           overall_description       severity_counts
findings[]             positive_findings[]       recommendations[]
audit_severity_counts  business_impact_score     policy_version
policy_id_distinct     excluded_finding_ids      exclusions
tech_profiles[]        additional_findings[]     package
```

Pro Finding-Eintrag (Live-Beispiel):

```json
{
  "id": "VS-2026-002",
  "title": "Datenbank-Port 1433 oeffentlich erreichbar auf secumetrix.de / dev.secumetrix.de",
  "severity": "HIGH", "cvss_score": "7.3",
  "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
  "cwe": "CWE-284",
  "affected": "45.157.234.103:1433 (secumetrix.de), 45.157.232.12:1433 (dev.secumetrix.de)",
  "description": "Auf beiden Windows-Servern …",
  "evidence":    "$ nmap -sV 45.157.234.103\n1433/tcp open  ms-sql-s  …",
  "impact":      "Ein extern erreichbarer Datenbankdienst …",
  "recommendation": "<b>Kurzfristig (Tage):</b> Port 1433 per Firewall sperren …",
  "finding_type":          "database_port_exposed",
  "_finding_type_source":  "pattern" /  "ai_fallback" / "manual",
  "policy_id": "SP-DB-001",
  "business_impact_score": 8.8,
  "title_vars": { "host": "secumetrix.de / dev.secumetrix.de",
                  "port": "1433", "tech": "Microsoft SQL Server" },
  "severity_provenance": {
    "policy_id": "SP-DB-001",
    "policy_version": "2026-05-10.1",
    "policy_decision": "h…",          // gekürzt in Anzeige
    "rationale": "Datenbank-Port (3306/5432/27017/6379/…) oeffentlich erreichbar - Brute-Force, Default-Creds, ungepatchte DB-CVEs …",
    "context_flags": {
      "cve_in_kev": false,    "cve_ransomware": false,  "cve_epss_high": false,
      "mx_present": true,     "auth_present": false,    "form_present": false,
      "https_in_use": true,   "state_change": false,    "is_session_path": false,
      "cookie_session": false, "inline_scripts": false
    }
  }
}
```

---

## 3 · Die Report-Pipeline (10 Stationen)

Code-Quelle: `report-worker/reporter/worker.py` Zeilen 337–638.

```
1. BullMQ pick (worker.py:739)
     └─ inputs: orderId, package, rawDataPath, hostInventory, techProfiles, enrichment, excluded
2. MinIO download + extract (worker.py:382)
3. parser.parse_scan_data (worker.py:405 → parser.py:1006)
     ├─ parse_nmap_xml          (parser.py:55)
     ├─ parse_nuclei_json       (parser.py:137)
     ├─ parse_testssl_json/raw  (parser.py:202, 254)
     ├─ parse_nikto_json        (parser.py:296)
     ├─ parse_zap_alerts_json   (parser.py:334)
     ├─ parse_headers_json      (parser.py:368)   ⚠ nur 7 Security-Header
     ├─ parse_httpx             (parser.py:511)
     ├─ parse_katana            (parser.py:525)
     ├─ parse_wpscan            (parser.py:552)
     ├─ parse_gobuster_dir      (parser.py:606)
     └─ find_playwright_screenshots (parser.py:449)
4. claude_client.call_claude (worker.py:449 → claude_client.py:644)
     ├─ model: webcheck/tlscompliance → Sonnet 4.6   16K tokens
     ├─ model: perimeter/compliance/supplychain/insurance → Opus 4.7   32K tokens
     ├─ cache key 1: content_hash (order-übergreifend)
     ├─ cache key 2: order_scope  (für regenerate)
     └─ output schema: overall_risk, findings[], positive_findings[], recommendations
5. qa_check.run_checks (worker.py:483 → qa_check.py:40-300)
     ├─ CVSS-Vektor↔Score-Konsistenz
     ├─ CWE-Format + MITRE-API
     ├─ Severity↔Score-Alignment
     ├─ Duplikat-Dedup (fuzzy)
     ├─ Required-Fields (HIGH/CRITICAL brauchen recommendation)
     └─ optional Haiku-Plausibility bei Anomalien
6. deterministic_pipeline.apply_pipeline (worker.py:503 → deterministic_pipeline.py:1)
     ├─ finding_type_mapper.classify_findings    (~20 Regex-Patterns)
     ├─ severity_policy.apply_policy             (~63 Regeln, POLICY_VERSION = "2026-05-10.1")
     ├─ business_impact.recompute_business_impact_scores
     └─ selection.select_findings (Top-N)
            Top-N: webcheck 8 · perimeter 15 · compliance 20 · supplychain 15 · insurance 15
            Min-N: webcheck 3 · perimeter  6 · compliance 10 · supplychain  6 · insurance  6
            Rest → additional_findings[]
7. report_mapper.map_to_report_data (worker.py:558 → report_mapper.py:1672)
     ├─ webcheck    → map_basic_report          (R.1698)
     ├─ perimeter   → map_professional_report   (R.1699)
     ├─ compliance  → map_nis2_report           (R.1700)
     ├─ supplychain → map_supplychain_report    (R.1701)
     ├─ insurance   → map_insurance_report      (R.1702)
     └─ tlscompliance → map_tlscompliance_report (R.1703)
8. generate_report.generate_report (worker.py:602 → generate_report.py:1610)
     ├─ Engine: ReportLab Platypus
     ├─ Branding: pdf/branding.py
     └─ Custom Flowables: pdf/__init__.py
9. MinIO upload scan-reports/<orderId>.pdf (worker.py:606)
10. DB persist reports + UPDATE orders.status (worker.py:625-638)
```

### Begleitende Hilfsmodule

| Modul | Zweck |
|---|---|
| `finding_type_mapper.py` | Regex-Klassifizierung von Findings auf interne Typen (z. B. `database_port_exposed`) |
| `ai_finding_type_fallback.py` | Haiku-basierter Fallback für Findings ohne Pattern-Match |
| `severity_policy.py` | ~63 deterministische Regeln; POLICY_VERSION via ENV `VECTISCAN_POLICY_VERSION` |
| `business_impact.py` | Paket-spezifische Gewichte (Insurance ↑ rdp_smb, Compliance ↑ encryption) |
| `selection.py` | Top-N / Min-N pro Paket, additional[] für Rest |
| `tech_table_builder.py` | Per-Host Tech-Tabelle mit EOL-Status |
| `eol_detector.py` | 388 manuelle + endoflife.date EOL-Einträge, KNOWN_VULN_BUILDS |
| `title_policy.py` | Deterministische Titel-Templates + Smart-Var-Fallback (`{host}` etc.) |
| `tr03116_checker.py` | BSI TR-03116-4 Audit über testssl-Raw |
| `posture_aggregator.py` | Subscription-weite Lifecycle-Aggregation (open / resolved / regressed) |
| `compliance/{nis2_bsig,iso27001,bsi_grundschutz,nist_csf,insurance}.py` | Paket-spezifische Compliance-Mappings |
| `cwe_reference.py` | CWE-Block für System-Prompts |
| `ai_cache.py` | Redis-Cache mit POLICY_VERSION-Bindung (Auto-Invalidate beim Bump) |
| `status_report_generator.py` | Subscription-Status-Report (Rescan-Pfad) |

---

## 4 · PDF-Sektionen — Was am Ende auf den Seiten steht

Realer Report: `secumetrix.de` · perimeter · 21 Seiten · 1.05 MB.

### Sektion 0 — Cover (Seite 1)

![Cover](assets/cover.png)

| Feld | Quelle | Anmerkung |
|---|---|---|
| Logo + Wortmarke "VECTISCAN" | static, `pdf/branding.py` | |
| "AUTOMATED SECURITY ASSESSMENT" + Titel | static + `order.domain` | |
| Paket-Badge ("PERIMETERSCAN") | `order.package` → `pdf/branding.py:PACKAGE_BADGES` | Farbe paket-abhängig (Cyan/Gold/Grün) |
| Ziel / Datum / Paket / Methodik / Scoring / Klassifizierung / Befunde | `order.*` + `findings_data.severity_counts` | „Befunde:" gibt Top-N-Counts wieder |
| Klassifizierungs-Footer | static, Cyan | dokumentierter Soll-Zustand: rot, Code: cyan — Drift gegen `references/report_structure.md` |

### Sektion 1 — Inhaltsverzeichnis (Seite 2)

![TOC](assets/toc.png)

**Beobachtung im Realreport**: Title-Drift sichtbar — zwei Findings haben
`{host}`-Platzhalter, der vom `title_policy.py:render_title_from_template`
nicht gefüllt wurde:
- "VS-2026-001 — RDP-Dienst (Port 3389) öffentlich erreichbar auf **{host}**"
- "VS-2026-004 — FTP-Dienst (Klartext) auf Produktivserver **{host}**"

Das ist ein konkreter Bug-Kandidat für die Re-Design-Phase.

### Sektion 2 — Zusammenfassung (Seite 3)

![Executive Summary](assets/executive-summary.png)

| Feld | Quelle |
|---|---|
| 1.1 Gesamtbewertung (Fließtext) | `findings_data.overall_description` (AI) |
| Gesamtrisikobewertung-Balken (HIGH) | `findings_data.overall_risk` (AI), Farbe aus `pdf/branding.py:SEVERITY_COLORS` |
| 1.2 Befundübersicht (Anzahl-Tabelle mit Punkten) | `findings_data.severity_counts` (deterministisch nach Selection) |

### Sektion 3 — Umfang & Methodik (Seiten 4–7)

| Element | Quelle |
|---|---|
| 2.1 Prüfungsumfang (Host/FQDN-Tabelle) | `tech_profiles[].ip` + `tech_profiles[].fqdns` |
| **Eingesetzte Technologien — `<ip>` (FQDNs)** (Tabelle pro Host) | `tech_profiles[].tech_rows[]` mit Spalten Technologie / Version / Kategorie / Status / EOL / CVEs |
| 2.2 Methodik (Phasen-Beschreibung) | static Text |
| 2.3 Web-Oberflächen (Screenshot pro VHost mit Caption) | `scan-screenshots/<orderId>/<ip>__<vhost>.png` + Caption aus Server-Banner |

![Scope Hosts](assets/scope-hosts.png)
![Tech Table](assets/tech-table.png)
![Methodology](assets/methodology.png)
![Screenshots Intro](assets/screenshots-intro.png)
![Screenshot Example](assets/screenshot-example.png)

**Beobachtung**: Die Tech-Tabelle zeigt 21 Einträge für IP `45.157.234.103`
mit Status durchgängig „aktuell" und leere CVE-Spalten — obwohl
`tech_profiles[].tech_rows` Felder wie `cves[]`, `is_mega_cve`, `latest_patch`,
`confidence` enthält. Diese werden im PDF **nicht angezeigt**. Auf Seite 6
sieht man bei `nginx 1.24.0` korrekt den Status "EOL" + EOL-Datum "2024-04-23"
— der Mechanismus funktioniert also, kommt aber selten zum Tragen.

### Sektion 4 — Befunde (Seiten 10–17)

Pro Finding ein gleichförmiger Block:

![Finding Example](assets/finding-example.png)

| Element | Quelle |
|---|---|
| Header-Bar mit Severity-Farbe | `pdf/__init__.py:FindingHeader` (~Z. 59–131) |
| Finding-ID + Title | `findings_data.findings[].id` + `.title` (nach `title_policy.py`) |
| CVSS-Score-Badge (rechts) | `.cvss_score` + Farbe nach Score |
| CVSS-Vektor / CWE / Affected Systems | `.cvss_vector`, `.cwe`, `.affected` |
| Beschreibung | `.description` (AI) |
| Nachweis (Monospace, grauer Hintergrund) | `.evidence` (deterministisch aus Tool-Output) |
| Geschäftsauswirkung | `.impact` (AI) |
| Empfehlung | `.recommendation` (AI, kann HTML enthalten) |
| Thumbnail (30 mm, rechts) | optional, `report_mapper.py:_attach_thumbnails` mappt erste Screenshot-Datei pro IP |
| NIS2-Badge (6 mm) | nur compliance/nis2, aus `compliance/nis2_bsig.py` |

### Sektion 5 — Positive Befunde (Seite 17 unten)

![Positive Finding](assets/positive-finding.png)

Kompakt gerendert (nur `title`, `description`, `recommendation`).
Quelle: `findings_data.positive_findings[]` (AI).

### Sektion 6 — Maßnahmenplan (Seite 19)

![Recommendations](assets/recommendations.png)

Roadmap-Tabelle mit Spalten **Zeitraum / Maßnahme / Befund-Ref. / Aufwand**.
Quelle: `findings_data.recommendations[].{timeframe, action, finding_refs, effort}`
(AI).

### Sektion 7 — Anhang A: CVSS-Referenz (Seite 20)

![Appendix CVSS](assets/appendix-cvss.png)

Tabelle aller Top-N-Findings mit ID / Title / Severity / Score / CVSS-Vektor.
Quelle: deterministisch aus `findings`.

### Sektion 8 — Anhang B: Eingesetzte Tools + Haftungsausschluss (Seite 21)

![Appendix Tools](assets/appendix-tools.png)

Tool-Tabelle (static in `report_mapper.py:SCAN_TOOLS` ca. Z. 79–96) + statischer
Disclaimer-Text.

### Paket-spezifische Zusatzsektionen

Aus `report_mapper.py:1672–1751` und den `compliance/*.py`-Modulen:

| # | Sektion | webcheck | perimeter | compliance / nis2 | supplychain | insurance | tlscompliance |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|
| 0 | Cover (Logo, Domain, Paket-Badge, Risk-Score) | ✓ | ✓ | ✓ (Gold) | ✓ | ✓ | ✓ (Grün) |
| 1 | TOC | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 2 | Executive Summary | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 2.x | NIS2-Compliance-Matrix (§30 BSIG) | – | – | ✓ | – | – | – |
| 3 | Scope + Host-Tabelle + Tech-Tabelle | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 3.3 | Web-Oberflächen (Screenshots) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 4 | Findings (Top-N) | ✓ (8) | ✓ (15) | ✓ (20) | ✓ (15) | – | ✓ |
| 4.x | Positive Findings | ✓ | ✓ | ✓ | ✓ | – | ✓ |
| 5 | TR-03116-4 Compliance | – | – | – | – | – | ✓ |
| 6 | Maßnahmenplan | ✓ | ✓ | ✓ | ✓ | – | ✓ |
| 7–9 | Insurance Questionnaire + Risk Score + Premium Actions | – | – | – | – | ✓ | – |
| 10 | NIS2 Audit Trail | – | – | ✓ | – | – | – |
| 11 | Anhänge (CVSS, Raw, Tools) | ✓ | ✓ | ✓ | ✓ | – | ✓ |
| 12–13 | Supply-Chain-Page + Compliance-Checkliste | – | – | ✓ | – | – | – |
| 14 | Compliance-Attestation | – | – | – | – | – | ✓ |
| 15 | Haftungsausschluss | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

---

## 5 · Datenfeld-Mapping pro Sektion

Pro Sektion: Quelle des Inhalts und welche Felder im Code existieren, aber
**nicht** gerendert werden.

| Sektion | Quelle | Gerendert | Vorhanden, aber nicht gerendert |
|---|---|---|---|
| Cover | `order.*` + `findings_data.severity_counts` | Paket, Domain, Risk-Counts | `business_impact_score` (8.8 bei secumetrix), `policy_version`, `correlationCount`, `passive_intel_summary.dns_security.dnssec_signed` |
| TOC | Auto-Generierung aus Sections | Section-Titel | — |
| Executive Summary | AI: `overall_description`, `overall_risk`; det.: `severity_counts` | beide | `audit_severity_counts` (pre-Selection-Werte), `policy_id_distinct`, FP-Statistik aus `correlation_data` |
| Scope Host-Tabelle | `tech_profiles[].ip` + `.fqdns` | IP + FQDNs | `vhost_results`, `redirect_data`, `ftp_service`, `mail_services`, `is_spa`, `waf`, `has_ssl`, `primary_vhost` |
| Tech-Tabelle | `tech_profiles[].tech_rows[]` | Name, Version, Kategorie, Status, EOL, CVEs | `cves[]` (Inhalt — Spalte ist leer), `is_mega_cve`, `confidence`, `latest_patch`, `source` (z. B. cms_fingerprint vs. server_banner), `vuln_name` |
| Web-Oberflächen | `scan-screenshots/` | Bild + Caption | Title aus VHost-Probe, Server-Banner, Aliases |
| Finding-Block | AI: `description`, `impact`, `recommendation`; det.: `severity`, `policy_id`, `cvss_*`, `cwe`, `affected`, `evidence` | siehe Sektion 4 | `severity_provenance.{context_flags, rationale, policy_decision}`, `business_impact_score`, `_finding_type_source`, `title_vars`, `finding_type`, `is_false_positive`, `fp_reason` |
| Positive Findings | AI: `positive_findings[]` | title + description + recommendation | — (nur Title/Desc/Rec im Schema) |
| Maßnahmenplan | AI: `recommendations[]` | timeframe, action, finding_refs, effort | — |
| Appendix A CVSS | det. aus `findings` | ID, Title, Sev, Score, Vector | — |
| Appendix B Tools | static `SCAN_TOOLS` | Tool, Beschreibung, Phase | Echte `duration_ms` / `exit_code` aus `scan_results` |
| Disclaimer | static | — | — |
| NIS2-Matrix | `compliance/nis2_bsig.py` | §30-Abdeckung pro nr1–nr10 | granulares Per-Finding-Mapping |
| TR-03116-4 | `tr03116_checker.py` aus `testssl_raw` | TR-Grades + Detail-Checks | — |

---

## 6 · Ungenutzte Daten — Hebel für das Re-Design

Sortiert nach **Datenvolumen × Aussagekraft**.

### 6.1 · Korrelations-Goldgrube (`orders.correlation_data`)

**2185 Entries bei secumetrix.de, 10 erscheinen — 99,5 % der Phase-3-Arbeit ist im PDF unsichtbar.**

| Datenpunkt | Speicherort | Heute? |
|---|---|---|
| Cluster-Bildung (`cluster_id`) | jeder Entry | nicht im Report |
| Cross-Tool-Bestätigung (`corroborating_tools`) | jeder Entry | nicht im Report |
| FP-Filter-Statistik (1761 von 2185 als FP erkannt) | aggregiert in `scan_results` (tool=`phase3_correlation`) | nicht im Report — wäre starkes Reife-Signal |
| Per-Entry Confidence | jeder Entry | nicht im Report |
| Per-Entry Business-Impact (`enrichment.business_impact`) | jeder Entry | nicht im Report |
| Per-Entry FP-Reason | jeder Entry | nicht im Report |

### 6.2 · Severity-Provenance pro Finding (`findings_data.findings[].severity_provenance`)

Existiert seit Q2/2026-Determinismus-Block, aber **rendert nirgendwo**:
- `context_flags`: 11 Flags — `cve_in_kev`, `cve_ransomware`, `cve_epss_high`, `auth_present`, `cookie_session`, `form_present`, `https_in_use`, `inline_scripts`, `is_session_path`, `mx_present`, `state_change`
- `rationale` (Klartext, Score-Begründung)
- `policy_decision`
- `policy_version` pro Finding
- `rule_references` (Verweise auf weitere zutreffende Regeln)
- `tool_severities` (Ausgangs-Severities aller meldenden Tools vor Policy-Override)

Nur der aggregierte `policy_id_distinct` taucht implizit auf (über die
einzelnen Findings). Audit-Trail-tauglicher Block für Compliance-Kunden.

### 6.3 · `passive_intel_summary` komplett unsichtbar

Im PDF fehlt jede Spur von:
- DMARC-/SPF-/DKIM-Status (obwohl in Findings teilweise zitiert wird, wird die volle Policy nirgendwo gerendert)
- MTA-STS, BIMI, DANE-TLSA, CAA, TLS-RPT
- DNSSEC mit `dnssec_signed`, `dnskey_count`, `nsec3_iterations`,
  `nsec3_rfc9276_violation`
- Shodan-Records mit `last_seen` (Drift)
- SecurityTrails-Historie
- OTX-Pulses (Threat-Intel-Hits)

→ Kandidat für eine eigene "E-Mail-Sicherheit / DNS-Hygiene"-Sektion.

### 6.4 · Tech-Profile-Tiefe

`reports.tech_profiles[].tech_rows[]` enthält bereits:
- `cves: []` mit CVE-IDs pro Komponente
- `is_mega_cve`, `latest_patch`, `confidence`, `vuln_name`, `source`
- `vhost_results`, `redirect_data`, `ftp_service`, `mail_services`, `is_spa`, `waf`

Im PDF rendert die Tech-Tabelle nur 6 Spalten und lässt `cves`, `is_mega_cve`,
`vhost_results`, `mail_services` weg.

### 6.5 · Threat-Intel-Cache

`threat_intel_cache` enthält EPSS-Scores, KEV-Flags, ExploitDB-Refs gecacht
pro CVE. Heute fließt das nur in `business_impact.py` als Multiplikator —
**das PDF zeigt weder EPSS-Score noch KEV-Markierung pro Finding**.

### 6.6 · AI-Reasoning-Texte

`scan_results.raw_output` enthält für `ai_*_debug`-Tools die vollen
System-Prompts und JSON-Antworten der vier KIs. Heute komplett unsichtbar
im PDF — Kandidat für einen optionalen Audit-/Transparenz-Anhang.

### 6.7 · Performance-Metriken

`scan_results.duration_ms` + `exit_code` pro Tool — wären eine ergonomische
"Scan-Statistik"-Sektion (52 Tool-Runs, X Stunden Gesamt-Laufzeit, Y Tools
mit Exit ≠ 0).

### 6.8 · Komplett ungenutzte Tool-Outputs

| Tool | MinIO-Pfad | Status |
|---|---|---|
| ffuf | `hosts/<ip>/ffuf*.json` | Tool läuft, kein Parser, nirgendwo gelesen |
| dalfox | `hosts/<ip>/dalfox.json` | Tool läuft (manche Pakete), kein Parser |
| wpscan vulnerable_plugins/themes Details | `hosts/<ip>/wpscan.json` | nur als Prompt-Text an Claude — keine Extraktion in Findings |
| webtech (Tiefe) | `hosts/<ip>/webtech.json` | nur top-level `technologies`, keine Versionen/Confidence in Report |
| zap_spider_urls | im Scan-Verzeichnis + `scan_results` | nicht im PDF; nur als "Discovered Endpoints" im Prompt |

### 6.9 · Visuelle Lücken im PDF

- **Keine Charts oder Diagramme** — alles ist Tabelle oder gefärbter Balken
- **Keine CVE-Hyperlinks** zu NVD/CVE.org/cve.mitre
- **Keine Severity-Bar-Chart**, keine Compliance-Heatmap
- **Keine Drift-/Trend-Sektion** für Rescans — die Daten sind in
  `posture_aggregator` vorhanden (open / resolved / regressed)
- **Keine VHost-Differenzierung** in der Tech-Tabelle, obwohl Multi-VHost-
  Modell seit Mai 2026 existiert (Migration 023)

---

## 7 · Paket-Profile

### webcheck

- **Use-Case**: Schnellscan (~15–20 Min), max 3 Hosts (`subscriptions.max_hosts`)
- **Top-N**: 8 (Min 3)
- **Modell für Report-AI**: Sonnet 4.6
- **Exklusiv**: —
- **Sektionen**: Standard ohne Compliance-Blöcke
- **Badge-Farbe**: Cyan (`pdf/branding.py:PACKAGE_BADGES`)
- **Prompt-Variante**: `prompts.py:SYSTEM_PROMPT_BASIC` (Tonfall: knapp, Hands-on)

### perimeter (= secumetrix-Referenzreport)

- **Use-Case**: Vollscan (~60–90 Min), max 15 Hosts, PTES-konform
- **Top-N**: 15 (Min 6)
- **Modell für Report-AI**: Opus 4.7
- **Exklusiv**: —
- **Sektionen**: Cover, TOC, ES, Scope+Tech, Screenshots, Findings, Positive, Maßnahmen, Anhänge, Disclaimer
- **Badge-Farbe**: Cyan
- **Prompt-Variante**: `prompts.py:SYSTEM_PROMPT_PROFESSIONAL`

### compliance / nis2

- **Use-Case**: perimeter + §30 BSIG + BSI-Grundschutz-Refs + Audit-Trail
- **Top-N**: 20 (Min 10)
- **Modell**: Opus 4.7
- **Exklusiv**:
  - NIS2-Compliance-Matrix (nach Executive Summary)
  - NIS2-Badge pro Finding (Gold) mit `§30 Abs. ? Nr. ? BSIG`-Ref aus `compliance/nis2_bsig.py:map_finding_to_bsig`
  - NIS2 Audit Trail
  - Supply-Chain-Sektion
  - Compliance-Checkliste
- **`findings_data`-Felder**: `nis2_compliance_summary`, `nis2_ref` pro Finding
- **Badge-Farbe**: Gold
- **Prompt-Variante**: `prompts.py:SYSTEM_PROMPT_NIS2`

### supplychain

- **Use-Case**: perimeter + ISO 27001 Annex A + Auftraggeber-Nachweis
- **Top-N**: 15 (Min 6)
- **Modell**: Opus 4.7
- **Exklusiv**: Third-Party-Risk, Dependency-Graph
- **Module**: `compliance/iso27001.py`, `bsi_grundschutz.py`
- **Badge-Farbe**: Cyan
- **Prompt-Variante**: `prompts.py:SYSTEM_PROMPT_SUPPLYCHAIN`

### insurance

- **Use-Case**: perimeter + Versicherungs-Fragebogen + Ransomware-Indikator
- **Top-N**: 15 (Min 6)
- **Modell**: Opus 4.7
- **Exklusiv**: Insurance Questionnaire, Risk Score, Premium Actions —
  **anstelle** der klassischen Findings-Sektion
- **`findings_data`-Felder**: `insurance.questionnaire`, `insurance.risk_score`,
  `insurance.premium_actions`
- **business_impact.py-Gewichte**: rdp_smb × 2.0, encryption × 1.3
- **Badge-Farbe**: Cyan
- **Prompt-Variante**: `prompts.py:SYSTEM_PROMPT_INSURANCE`

### tlscompliance

- **Use-Case**: BSI TR-03116-4 TLS-Audit (eigener Worker-Pfad)
- **Top-N**: kein klassisches Top-N (eigener Reporter-Flow)
- **Modell**: Sonnet 4.6
- **Exklusiv**: TR-03116-Compliance-Sektion, Compliance-Attestation
- **Modul**: `tr03116_checker.py`
- **`findings_data`-Felder**: `tr03116`-Block mit Grades pro Host
- **Badge-Farbe**: Grün
- **Prompt-Variante**: `prompts.py:SYSTEM_PROMPT_TLSCOMPLIANCE`

---

## 8 · Soll/Ist gegen `references/report_structure.md`

| Aspekt | Soll (Doku) | Ist (Code/PDF) |
|---|---|---|
| Classification-Bar | rot, 12 mm, unten | cyan, 14 mm, **am Cover unten** + oben/unten als Trennlinie (Footer) — Drift |
| Finding-ID-Schema | `{CLIENT_PREFIX}-{YEAR}-{NN}` | global `VS-{YEAR}-NNN` (`VS-2026-002`) |
| Appendix B "Raw Tool Output" | volle Raw-Outputs | nur testssl-Raw rendert; Rest fehlt |
| Title-Templates | platzhalterfrei | im Realreport sichtbar: `{host}`-Lücken (z. B. "auf {host}") |
| Logo | dunkel auf hell | nur Wortmarke "VECTISCAN", kein eigentliches Logo |

---

## 9 · Reale Zahlen aus der Live-API (Order `7629dd77` / secumetrix.de)

| Metrik | Wert |
|---|---|
| Paket | perimeter |
| Hosts | 3 |
| Phasen 0–4 in `scan_results` | 52 Zeilen |
| Eingesetzte Tools | 26 distincte `tool_name` |
| `correlation_data` Einträge | **2185** (header_check: 20, zap_passive: 2165) |
| davon FP gefiltert | 1761 (80,6 %) |
| davon valid | 424 |
| Severity in correlation | low 1842 / medium 339 / high 4 |
| Findings im PDF | 10 (Top-N=15, KI lieferte weniger) |
| Positive Findings im PDF | 3 |
| Recommendations | 8 |
| `overall_risk` | HIGH |
| `business_impact_score` | 8.8 |
| `policy_version` | 2026-05-10.1 |
| `policy_id_distinct` | 9: `SP-DB-001, SP-DISC-001, SP-DNS-005, SP-DNS-008, SP-DNS-010, SP-ENUM-001, SP-FALLBACK, SP-HDR-006, SP-JS-001` |
| `additional_findings` | 0 (Top-N nicht voll ausgeschöpft) |
| `excluded_findings` | 0 |
| `tech_profiles` Einträge | 3 (1 pro Host) |
| `passive_intel_summary` Top-Level-Keys | 5: `otx, dns_security, passive_subdomains, securitytrails, shodan_domain` |
| PDF | 21 Seiten · 1.05 MB |

---

## 10 · Kritische Code-Referenzen

Für Folge-Sessions (Claude Design / Claude Code):

| Bereich | Datei | Zeilen |
|---|---|---|
| Pipeline-Orchestrator | `report-worker/reporter/worker.py` | 337–638 |
| Alle Tool-Parser | `report-worker/reporter/parser.py` | 55–1275 |
| Paket-Prompts (5 Varianten) | `report-worker/reporter/prompts.py` | gesamtes Modul |
| Determinismus-Pipeline | `report-worker/reporter/deterministic_pipeline.py` | 1–80 |
| Severity-Policy + Version | `report-worker/reporter/severity_policy.py` | 30 (POLICY_VERSION), ~63 Regeln |
| Selection (Top-N) | `report-worker/reporter/selection.py` | 29–48 |
| Paket-Mapper-Dispatch | `report-worker/reporter/report_mapper.py` | 1672–1751 |
| Finding-Mapping pro Eintrag | `report-worker/reporter/report_mapper.py` | 155–218 |
| PDF-Engine (ReportLab) | `report-worker/reporter/generate_report.py` | 1610–Ende |
| Custom Flowables (FindingHeader etc.) | `report-worker/reporter/pdf/__init__.py` | 59–131 |
| Branding (Farben, Badges) | `report-worker/reporter/pdf/branding.py` | gesamt; Severity 45–80, Package-Badges 112–160 |
| Compliance-Module | `report-worker/reporter/compliance/{nis2_bsig,iso27001,bsi_grundschutz,nist_csf,insurance}.py` | je gesamt |
| Title-Policy / Smart-Var-Fallback | `report-worker/reporter/title_policy.py` | 30–150 |
| Tech-Table-Builder + EOL | `report-worker/reporter/tech_table_builder.py`, `eol_detector.py` | gesamt |
| Read-APIs für Reporter-Daten | `api/src/routes/orders.ts` | 354 (/), 454 (/correlation), 485 (/report), 838 (/findings), 588 (/results), 633 (/screenshot/) |
| Soll-Zustand (mit Drift) | `references/report_structure.md` | gesamt |

---

## 11 · Glossar

- **POLICY_VERSION**: Versionierung der ~63 Severity-Regeln; bei Bump werden alle AI-Caches automatisch invalidiert (`ai_cache.py`).
- **policy_id**: Stabile ID pro Severity-Regel, z. B. `SP-DB-001`.
- **finding_type**: Interner Klassifizierungstyp aus `finding_type_mapper.py` (Regex), z. B. `database_port_exposed`.
- **Top-N / Min-N**: Max- bzw. Mindest-Anzahl angezeigter Findings pro Paket (`selection.py`).
- **business_impact_score**: Pro Finding deterministisch berechnet aus Severity × Paket-Gewicht × Context-Flags; fließt nur in Selection-Sort und ins Order-Aggregat, **nicht** ins PDF.
- **additional_findings**: Findings, die nach Top-N "übrig" sind; werden in DB persistiert (`reports.additional_findings`) und im Frontend-Drilldown, aber **nicht im PDF** gezeigt.
- **VHost**: Echter virtueller Host auf einer IP (Migration 023, Mai 2026). Aliase werden per Redirect/Body-Hash dedupliziert.
