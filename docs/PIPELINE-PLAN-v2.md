# VectiScan v2 — Scan Pipeline Umsetzungsplan

## Context

VectiScan v1 hat 3 Pakete (Basic/Professional/NIS2) und eine 3-Phasen-Pipeline (Phase 0 → 1 → 2).
v2 erweitert auf 5 Pakete und 6 Phasen, mit Passive Intelligence, Threat-Intel-Enrichment,
Cross-Tool-Korrelation und 4 AI-Entscheidungspunkten. Die Spezifikation liegt in `docs/SCAN-PIPELINE-v2.md`.

**Kernänderungen:**
- 3 → 5 Pakete: webcheck, perimeter, compliance, supplychain, insurance
- 3 → 6 Phasen: +Phase 0a (Passive Intel), +Phase 3 (Correlation & Enrichment)
- 21 → 34+ Tools: +Shodan, AbuseIPDB, SecurityTrails, WHOIS, ffuf, feroxbuster, dalfox, etc.
- 2 → 4 AI-Entscheidungspunkte: +Phase-3-Priorisierung (Sonnet), +Report-QA (programmatisch+Haiku)
- Neue Subsysteme: CMS-Fingerprinting-Engine, Cross-Tool-Korrelation, FP-Filter, Business-Impact-Scoring

**Persistenter Plan:** Wird als `docs/PIPELINE-PLAN-v2.md` im Repo gespeichert.

---

## Implementierungs-Phasen

### Phase I: Foundation — DB-Migration & Paket-Umbau (Woche 1–2)

**Ziel:** Alle 5 Pakete durchgängig funktionsfähig, bestehende Daten migriert.

#### 1.1 DB-Migration (neue Migration `009_v2_packages.sql`)
- `api/src/migrations/009_v2_packages.sql`
- Package-Constraint auf orders + scan_schedules erweitern (5 Werte)
- Bestehende Daten migrieren: basic→webcheck, professional→perimeter, nis2→compliance
- Neue Spalten: `correlation_data JSONB`, `business_impact_score DECIMAL(3,1)`, `passive_intel_summary JSONB`
- Neue Tabelle: `threat_intel_cache` (wie in Spec §16.3)

#### 1.2 API: Package-Erweiterung
- `api/src/routes/orders.ts`: VALID_PACKAGES auf 5 Werte erweitern + ESTIMATED_DURATIONS
- `api/src/routes/schedules.ts`: Package-Validierung anpassen

#### 1.3 Scan-Worker: packages.py auf 5 Pakete
- `scan-worker/scanner/packages.py`: 5 PACKAGE_CONFIGs
  - webcheck: ~= basic (max 3 Hosts, Phase 0a nur WHOIS, kein nikto/nuclei-full)
  - perimeter: ~= professional (max 15 Hosts, + Phase 0a voll, + ffuf/feroxbuster/dalfox)
  - compliance: = perimeter (Report-Unterschied)
  - supplychain: = perimeter (Report-Unterschied)
  - insurance: = perimeter (Report-Unterschied)
- Neue Config-Keys: `phase0a_tools`, `phase0a_timeout`, `phase3_tools`, `phase3_timeout`

#### 1.4 Frontend: PackageSelector auf 5 Pakete
- `frontend/src/components/PackageSelector.tsx`: 5 Karten mit neuen Features
- `frontend/src/app/page.tsx`: Default-Paket auf 'perimeter' ändern

#### 1.5 Report-Worker: Mapper-Dispatch auf 5 Pakete
- `report-worker/reporter/report_mapper.py`: 5 Mapper (erstmal perimeter=compliance=supplychain=insurance als Stub)
- `report-worker/reporter/prompts.py`: 5 Prompt-Varianten (Stubs für neue)
- `report-worker/reporter/claude_client.py`: MAX_TOKENS_BY_PACKAGE auf 5 Werte

#### 1.6 Environment: Neue API-Keys
- `.env.template`: SHODAN_API_KEY, ABUSEIPDB_API_KEY, SECURITYTRAILS_API_KEY, NVD_API_KEY

**Verifikation:** Bestehende Scans laufen mit neuen Paketnamen durch. E2E-Test mit webcheck + perimeter.

---

### Phase II: Passive Intelligence — Phase 0a (Woche 3–4)

**Ziel:** Passive Intel-Sammlung vor aktivem Scan, AI-Host-Strategy bekommt reicheren Input.

#### 2.1 API-Client-Infrastruktur
- `scan-worker/scanner/passive/__init__.py`
- `scan-worker/scanner/passive/base_client.py` — Gemeinsame Basis (Rate-Limiting, Retry, Timeout)
- `scan-worker/scanner/cache.py` — Redis/DB Cache-Layer für `threat_intel_cache`

#### 2.2 Passive Intel Clients
- `scan-worker/scanner/passive/shodan_client.py` — DNS-Lookup + Host-Details pro IP
- `scan-worker/scanner/passive/abuseipdb_client.py` — IP-Reputation pro Host
- `scan-worker/scanner/passive/securitytrails_client.py` — Domain + Subdomains + DNS-History
- `scan-worker/scanner/passive/whois_client.py` — Registrar, Ablauf, DNSSEC-Status

#### 2.3 Erweiterte DNS-Security
- `scan-worker/scanner/passive/dns_security.py` — DNSSEC-Validierung, CAA, MTA-STS, DANE/TLSA
- Integration in Phase 0b (nach bestehenden dig-Checks)

#### 2.4 Phase-0a-Orchestrierung
- `scan-worker/scanner/phase0a.py` — Orchestriert alle Passive-Intel-Calls
- Einbindung in `worker.py`: Phase 0a → Phase 0b → AI Host Strategy → Phase 1 → ...

#### 2.5 AI Host Strategy Update
- `scan-worker/scanner/ai_strategy.py`: Erweiterter Input (Shodan-Ports, AbuseIPDB-Score, DNS-History)
- Neues Antwort-Format mit `scan_hints` und `priority`
- Erweiterter System-Prompt (wie in Spec §5.2)

#### 2.6 Dockerfile-Erweiterungen
- `scan-worker/Dockerfile`: whois, ldnsutils (drill), shodan Python-Lib
- `scan-worker/requirements.txt`: shodan, requests (für API-Clients)

#### 2.7 Progress-System
- `scan-worker/scanner/progress.py`: Neue Event-Typen für Phase 0a

**Verifikation:** Perimeter-Scan mit Shodan/AbuseIPDB-Daten. WebCheck nur mit WHOIS. AI Host Strategy zeigt erweiterten Kontext.

---

### Phase III: Extended Deep Scan — Neue Phase-2-Tools (Woche 5–6)

**Ziel:** CMS-Engine, ffuf, feroxbuster, dalfox integriert und AI-gesteuert.

#### 3.1 CMS-Fingerprinting-Engine
- `scan-worker/scanner/cms_fingerprinter.py` — Ersetzt CMS-Fallback-Probe in phase1.py
- 5 Methoden: webtech, Meta-Tags, Probe-Matrix, Cookies, Response-Headers
- DACH-optimiert (Shopware 5/6, TYPO3, Contao)
- Integration in `phase1.py`: `build_tech_profile()` ruft CMSFingerprinter auf

#### 3.2 Neue Tools im Scan-Worker
- ffuf-Runner in `phase2.py` (3 Modi: dir, vhost, param)
- feroxbuster-Runner in `phase2.py` (rekursiv, AI-gesteuerte Tiefe)
- dalfox-Runner in `phase2.py` (XSS auf katana-Endpoints, Dependency-Chain)

#### 3.3 Tool-Orchestrierung
- Dependency-Chain in Phase 2: feroxbuster nach gobuster/ffuf, dalfox nach katana
- Dedup-Logik: feroxbuster-Ergebnisse gegen gobuster/ffuf deduplizieren

#### 3.4 AI Phase-2-Config Update
- `ai_strategy.py`: Neue Tool-Parameter (ffuf_mode, ffuf_extensions, feroxbuster_depth, dalfox_enabled)
- CMS→nuclei-Tag-Mapping im System-Prompt
- Shodan-Service-Versionen als zusätzlicher Input

#### 3.5 Dockerfile: Neue Binaries
- `scan-worker/Dockerfile`: ffuf, feroxbuster, dalfox, SecLists-Wordlists

**Verifikation:** Perimeter-Scan mit allen neuen Tools. AI konfiguriert ffuf/feroxbuster/dalfox korrekt.

---

### Phase IV: Correlation & Enrichment — Phase 3 (Woche 7–8)

**Ziel:** Cross-Tool-Korrelation, Threat-Intel-Enrichment, FP-Reduktion, Business-Impact-Scoring.

#### 4.1 Threat-Intel-Clients
- `scan-worker/scanner/correlation/threat_intel.py`:
  - NVD-API-Client (Batch, Cache via threat_intel_cache)
  - EPSS-Client (Batch-Request)
  - CISA-KEV-Loader (lokaler Cache, 6h Refresh)
  - ExploitDB-Client (searchsploit lokal)

#### 4.2 Korrelations-Engine
- `scan-worker/scanner/correlation/correlator.py` — CrossToolCorrelator
  - CVE-Dedup, Port-Service-Korrelation, Tech-Version-Match, Cluster-Bildung
  - Confidence-Score-Berechnung (Base + Korrelations-Boost - Degrade)

#### 4.3 False-Positive-Filter
- `scan-worker/scanner/correlation/fp_filter.py` — FalsePositiveFilter
  - WAF-Filter, Version-Mismatch, CMS-Mismatch, SSL-Dedup, Header-Dedup, Info-Noise

#### 4.4 Business-Impact-Scoring
- `scan-worker/scanner/correlation/business_impact.py`
  - CVSS × EPSS × CISA KEV × Asset-Wert × Paket-Gewichtung

#### 4.5 AI Phase-3-Priorisierung (Sonnet)
- `scan-worker/scanner/ai_strategy.py`: Neuer AI-Entscheidungspunkt
  - Input: Aggregierte Finding-Summary aus Phase 2
  - Output: Priorisierte Findings mit Confidence-Scores
  - Modell: Sonnet 4 (Cross-Tool-Reasoning)

#### 4.6 Phase-3-Orchestrierung
- `scan-worker/scanner/phase3.py` — Orchestriert Korrelation + Enrichment
- Einbindung in `worker.py`: ... → Phase 2 → Phase 3 → _finalize()

#### 4.7 Dockerfile: ExploitDB
- `scan-worker/Dockerfile`: exploitdb/searchsploit installieren

#### 4.8 Daten-Persistierung
- Korrelierte Findings in `orders.correlation_data`
- Business-Impact-Score in `orders.business_impact_score`
- Enrichment-Daten (EPSS, KEV, ExploitDB) im Report-Job-Payload

**Verifikation:** Perimeter-Scan zeigt korrelierte Findings mit Confidence-Scores, EPSS-Daten, KEV-Matches.

---

### Phase V: Report-Varianten — 5 Pakete (Woche 9–10)

**Ziel:** Alle 5 Report-Varianten mit paketspezifischen Sektionen und Compliance-Mappings.

#### 5.1 Prompt-Varianten
- `report-worker/reporter/prompts.py`:
  - SYSTEM_PROMPT_WEBCHECK (einfache Sprache, Ampel, max 8 Findings)
  - SYSTEM_PROMPT_PERIMETER (PTES-konform, EPSS-Kontext, Evidence)
  - SYSTEM_PROMPT_COMPLIANCE (= Perimeter + §30 BSIG, BSI-Grundschutz)
  - SYSTEM_PROMPT_SUPPLYCHAIN (= Perimeter + ISO 27001, Auftraggeber-Nachweis)
  - SYSTEM_PROMPT_INSURANCE (= Perimeter + Fragebogen-Format, Risk-Score)

#### 5.2 Compliance-Mapping-Module
- `report-worker/reporter/compliance/__init__.py`
- `report-worker/reporter/compliance/nis2_bsig.py` — §30 BSIG (refactored aus v1)
- `report-worker/reporter/compliance/iso27001.py` — ISO 27001 Annex A
- `report-worker/reporter/compliance/bsi_grundschutz.py` — BSI-Grundschutz-Refs
- `report-worker/reporter/compliance/nist_csf.py` — NIST CSF
- `report-worker/reporter/compliance/insurance.py` — Versicherungs-Fragebogen-Generator

#### 5.3 Report-Mapper (5 Varianten)
- `report-worker/reporter/report_mapper.py`:
  - map_webcheck_report() — Ampel, vereinfacht, Mail-Security-Summary
  - map_perimeter_report() — Attack-Surface, EPSS-Top-10, Evidence
  - map_compliance_report() — NIS2-Summary, BSI-Refs, DNSSEC/MTA-STS-Sektion
  - map_supplychain_report() — ISO 27001 Mapping, Auftraggeber-Nachweis
  - map_insurance_report() — Fragebogen, Risk-Score, Ransomware-Indikator

#### 5.4 PDF-Templates
- Neue Sektionen in `report-worker/reporter/pdf/generate_report.py`
- WebCheck: "So lesen Sie diesen Bericht", Mail-Security-Ampel, Top-3-Maßnahmen
- Insurance: Fragebogen-Sektion, Risk-Score-Trend
- SupplyChain: Auftraggeber-Nachweis-Kapitel, ISO-Mapping-Tabelle

#### 5.5 Report-QA
- `report-worker/reporter/qa_check.py`:
  - Programmatische Checks: CVSS-Vektor, CWE-Validierung, Severity-Konsistenz, Duplikate
  - Haiku-Check: Nur für Anomalien (Plausibilität, CWE-Zuordnung)
  - Integration in Worker-Pipeline nach Claude-Call, vor PDF-Generierung

**Verifikation:** Jedes Paket erzeugt korrekten Report mit paketspezifischen Sektionen.

---

### Phase VI: Integration & Frontend (Woche 11–12)

**Ziel:** Frontend zeigt alle neuen Daten, E2E-Tests für alle 5 Pakete.

#### 6.1 Frontend-Updates
- PackageSelector: 5 Pakete mit Feature-Vergleichstabelle
- Scan-Detail: Phase-0a-Anzeige (Passive Intel Summary)
- Scan-Detail: Phase-3-Korrelationsdaten im Debug-Tab
- Findings-Viewer: Confidence-Score, EPSS, CISA KEV Badges
- Dashboard: Business-Impact-Score Anzeige

#### 6.2 API-Erweiterungen
- GET /api/orders/:id/events: Phase-0a und Phase-3 Events
- GET /api/orders/:id: passive_intel_summary, correlation_data, business_impact_score

#### 6.3 E2E-Tests
- 1 Scan pro Paket gegen Testdomain
- Report-Validierung: Paketspezifische Sektionen vorhanden
- Performance: Timeouts einhalten

#### 6.4 Dokumentation
- CLAUDE.md aktualisieren (5 Pakete, 6 Phasen)
- docs/SCAN-TOOLS.md aktualisieren (neue Tools)
- docs/API-SPEC.md aktualisieren

---

## Kritische Dateien (Änderungen)

| Datei | Änderungstyp |
|-------|-------------|
| `scan-worker/scanner/packages.py` | Rewrite (3→5 Pakete) |
| `scan-worker/scanner/worker.py` | Erweitert (Phase 0a + Phase 3 einbinden) |
| `scan-worker/scanner/phase0a.py` | **NEU** |
| `scan-worker/scanner/passive/*.py` | **NEU** (5 Dateien) |
| `scan-worker/scanner/cms_fingerprinter.py` | **NEU** |
| `scan-worker/scanner/phase1.py` | Erweitert (CMS-Engine) |
| `scan-worker/scanner/phase2.py` | Erweitert (ffuf, feroxbuster, dalfox) |
| `scan-worker/scanner/phase3.py` | **NEU** |
| `scan-worker/scanner/correlation/*.py` | **NEU** (4 Dateien) |
| `scan-worker/scanner/cache.py` | **NEU** |
| `scan-worker/scanner/ai_strategy.py` | Erweitert (4 AI-Punkte) |
| `scan-worker/scanner/progress.py` | Erweitert (neue Events) |
| `scan-worker/Dockerfile` | Erweitert (neue Tools) |
| `scan-worker/requirements.txt` | Erweitert (shodan, requests) |
| `report-worker/reporter/prompts.py` | Rewrite (3→5 Prompts) |
| `report-worker/reporter/report_mapper.py` | Rewrite (3→5 Mapper) |
| `report-worker/reporter/claude_client.py` | Erweitert (5 Pakete) |
| `report-worker/reporter/qa_check.py` | **NEU** |
| `report-worker/reporter/compliance/*.py` | **NEU** (6 Dateien) |
| `report-worker/reporter/pdf/generate_report.py` | Erweitert (neue Sektionen) |
| `api/src/routes/orders.ts` | Erweitert (5 Pakete) |
| `api/src/routes/schedules.ts` | Erweitert (5 Pakete) |
| `api/src/migrations/009_v2_packages.sql` | **NEU** |
| `frontend/src/components/PackageSelector.tsx` | Rewrite (5 Pakete) |
| `frontend/src/app/page.tsx` | Erweitert |
| `frontend/src/app/scan/[orderId]/page.tsx` | Erweitert (Phase 0a/3) |
| `.env.template` | Erweitert (4 neue API-Keys) |
| `docker-compose.yml` | Ggf. Ressourcen-Anpassung |

---

## Reihenfolge-Logik

```
Phase I (Foundation) ist Voraussetzung für alles.
Phase II (Passive Intel) und Phase III (Deep Scan Tools) sind unabhängig voneinander.
Phase IV (Correlation) braucht Phase II + III.
Phase V (Reports) braucht Phase IV (Enrichment-Daten für Reports).
Phase VI (Integration) braucht Phase V.
```

Phase II und III können parallelisiert werden.

---

## Einstiegspunkte für neue Sessions

Um in einer frischen Session an einem bestimmten Punkt weiterzuarbeiten:

**Phase I starten:** "Wir setzen docs/PIPELINE-PLAN-v2.md um. Starte mit Phase I: Foundation."
**Phase II starten:** "Wir setzen docs/PIPELINE-PLAN-v2.md um. Phase I ist abgeschlossen. Starte Phase II: Passive Intelligence."
**Phase III starten:** "Wir setzen docs/PIPELINE-PLAN-v2.md um. Phase I ist abgeschlossen. Starte Phase III: Extended Deep Scan."
**Phase IV starten:** "Wir setzen docs/PIPELINE-PLAN-v2.md um. Phasen I–III sind abgeschlossen. Starte Phase IV: Correlation."
**Phase V starten:** "Wir setzen docs/PIPELINE-PLAN-v2.md um. Phasen I–IV sind abgeschlossen. Starte Phase V: Reports."
**Phase VI starten:** "Wir setzen docs/PIPELINE-PLAN-v2.md um. Phasen I–V sind abgeschlossen. Starte Phase VI: Integration."

Referenz-Dokument für Details: `docs/SCAN-PIPELINE-v2.md`
