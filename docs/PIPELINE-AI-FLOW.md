# VectiScan v2 — Pipeline & KI-Entscheidungspunkte

**Stand:** 2026-05-04
**Zielgruppe:** Owner / Auditor / Entwickler
**Zweck:** Vollständiger End-to-End-Trace eines Scans inkl. aller 5 KI-Entscheidungspunkte. Jede Aussage ist im Code mit `Datei:Zeile` verifiziert.

> Diese Doku ist die KI-Flow-Referenz. Architektur-Übersicht steht in
> `docs/architecture.md`, Tool-Konfig/Timeouts in `docs/SCAN-TOOLS.md`,
> Determinismus-Block in `docs/deterministic/`.

---

## 0. Pipeline auf einen Blick

```
┌──────────────────┐
│  ORDER (queue)   │  scan-pending
└────────┬─────────┘
         ▼
┌──────────────────────────────────────────────────────────────┐
│  scan-worker/scanner/worker.py:_process_job (Z. 175)         │
└────────┬─────────────────────────────────────────────────────┘
         ▼
   PHASE 0a  ── passive_intel ────────────────  (Shodan, AbuseIPDB,
   (optional)   phase0a.py:24                    SecurityTrails, WHOIS,
                                                 DNS-Security)
         ▼
   PHASE 0b  ── DNS + Discovery + Probe + Scope
                phase0.py:1174
                ├─ crt.sh + certspotter
                ├─ subfinder, amass
                ├─ subdomain_snapshot (TTL 24h)   [Migration 019]
                ├─ dnsx
                ├─ httpx + Playwright
                ├─ merge_and_group   ← FQDN→IP-Dedup (phase0.py:834)
                └─ scope.enforce_scope
         ▼
  ┌─────────────────────────────────────────┐
  │  ◀━━ KI #1  Host-Strategy  (Haiku 4.5)  │  ai_strategy.py:255
  │  ──────────────────────────────────────│  cache: ki1_host_strategy / 7d
  │  + Hard-Override _enforce_scan_for_     │  override Z. 326 (heuel.com-Fix)
  │    live_web_hosts                       │
  └─────────────────────────────────────────┘
         ▼
   PHASE 1  ── Tech-Detection (parallel, max 3 Hosts)
                phase1.py:522
                nmap → httpx → Playwright (Wappalyzer-Lite)
                → cms_fingerprinter → wafw00f → gowitness
         ▼
  ┌─────────────────────────────────────────┐
  │  ◀━━ KI #2  Tech-Analysis (Haiku 4.5)   │  ai_strategy.py:421
  │  ──────────────────────────────────────│  cache: ki2_tech_analysis / 30d
  │  CMS-False-Positive-Korrektur, SPA-Det  │
  └─────────────────────────────────────────┘
  ┌─────────────────────────────────────────┐
  │  ◀━━ KI #3  Phase-2-Config (Haiku 4.5)  │  ai_strategy.py:564
  │  ──────────────────────────────────────│  cache: ki3_phase2_config / 7d
  │  PRO HOST: ZAP-Policy + skip_tools etc. │  per-host scope
  └─────────────────────────────────────────┘
         ▼
   PHASE 2  ── Deep-Scan (parallel, max 3 Hosts; sequenziell bei WAF)
                phase2.py:999
                Stage 1: testssl, nikto, headers
                Stage 2: ZAP, ffuf/feroxbuster, wpscan, dalfox
                Stage 3: katana, nuclei
         ▼
   PHASE 3  ── Correlation + Threat-Intel + FP-Filter
                phase3.py:65
                extract → correlate → NVD/EPSS/KEV/ExploitDB
                → FP-Filter → BusinessImpact
                  ▲
                  │ irgendwo dazwischen (Sonnet 4.6):
  ┌───────────────┴─────────────────────────┐
  │  ◀━━ KI #4  Cross-Tool-Confidence       │  ai_strategy.py:745
  │  ──────────────────────────────────────│  cache: ki4_phase3 / 1d
  │  + Extended Thinking 8K                 │  optional Tool-Use-Loop
  └─────────────────────────────────────────┘
         ▼
  FINALIZE ── _finalize() (worker.py:829)
              tar.gz → MinIO scan-rawdata
              Screenshots → MinIO scan-screenshots
              Redis-Push: report-pending
         ▼
┌──────────────────────────────────────────────────────────────┐
│  REPORT-WORKER  report-worker/reporter/worker.py:329          │
└────────┬─────────────────────────────────────────────────────┘
         ▼
   1. _download_rawdata (worker.py:214) ← MinIO scan-rawdata
   2. parser.parse_scan_data
   3. ◀━━ KI #5 Reporter (Sonnet/Opus)  ──────  claude_client.py:593
                                                 cache: reporter_v1 / 1d
                                                 cache_control: ephemeral
                                                 Extended Thinking 12K (Opus)
   4. finding_type_mapper.annotate_finding_types  (deterministisch)
   5. severity_policy.apply_policy  (63 Regeln, Z. 1012)
      └─ überschreibt KI-Severities, setzt policy_id + provenance
   6. business_impact.recompute (Z. 182)
   7. selection.select_findings (Z. 188)  ← Top-N je Paket
   8. qa_check.run_qa_checks (Z. 584)  ← optional 1× Haiku
   9. report_mapper.map_to_report_data + Compliance-Module
  10. generate_report.py (ReportLab) → PDF
  11. MinIO scan-reports + DB reports-Insert + Order-Status
  12. posture_aggregator.aggregate_into_posture (Z. 174)
```

### Die 5 KI-Calls — Inhaltsverzeichnis

| # | Datei : Zeile | Modell | Zweck | Cache-Namespace | TTL |
|---|---|---|---|---|---|
| 1 | `scan-worker/scanner/ai_strategy.py:255` | Haiku 4.5 | Host-Strategy (scan/skip) | `ki1_host_strategy` | 7d |
| 2 | `scan-worker/scanner/ai_strategy.py:421` | Haiku 4.5 | CMS-/Tech-Korrektur | `ki2_tech_analysis` | 30d |
| 3 | `scan-worker/scanner/ai_strategy.py:564` | Haiku 4.5 | Phase-2-Config (per Host) | `ki3_phase2_config` | 7d |
| 4 | `scan-worker/scanner/ai_strategy.py:745` | Sonnet 4.6 | Cross-Tool-Confidence | `ki4_phase3` | 1d |
| 5 | `report-worker/reporter/claude_client.py:593` | Sonnet 4.6 / Opus 4.6 | Report-Generierung | `reporter_v1` | 1d |

Phase 0a ist optional (passive intel kann disabled sein), Phase 0b ist Pflicht.

---

## 1. Phase 0a — Passive Intelligence (optional)

| Eigenschaft | Wert |
|---|---|
| Einstieg | `scan-worker/scanner/phase0a.py:24` `run_phase0a()` |
| Parallelisierung | ThreadPool, max 5 |
| Persistenz | `orders.passive_intel_summary` (PostgreSQL) |
| KI-Entscheidung | **keine** |

### Tools

| Tool | Was es liefert | Warum es für die KIs relevant ist |
|---|---|---|
| WHOIS | Registrar, Ablaufdatum, Kontakte | KI #1 (Host-Strategy) sieht Domain-Alter & Kontakte → Priorisierung |
| Shodan | Offene Ports, Service-Versionen, Banner (max 15 IPs) | KI #1 priorisiert Hosts mit veralteten Versionen / exponierten Mgmt-Ports; KI #3 nutzt Banner für ZAP-Policy |
| AbuseIPDB | IP-Reputation 0-100 (max 15 IPs) | KI #1: hoher Score → Prio 1 (möglicherweise kompromittiert) |
| SecurityTrails | DNS-Historie, Subdomains | Gleicht mit CT-Logs ab → Discovery-Vollständigkeit |
| DNS-Security | DNSSEC, CAA, DANE, MTA-STS, SPF/DMARC | Reporter-Findings (DKIM/SPF/DMARC), KI #5 nutzt für Compliance-Mapping |

---

## 2. Phase 0b — DNS + Subdomain-Discovery + Web-Probing + Scope

| Eigenschaft | Wert |
|---|---|
| Einstieg | `scan-worker/scanner/phase0.py:1174` `run_phase0()` |
| Output | `host_inventory` mit `hosts[].web_probe`, `dns_findings`, `discovery_health` |
| KI-Entscheidung | **keine** |

### Subschritte (Reihenfolge)

1. **CT-Logs**
   - `run_crtsh()` — 3-Stufen-Self-Retry (5 s, 15 s, 30 s Backoff; Timeout 60 s)
   - Fallback: `certspotter` wenn crt.sh leer
2. **Subdomain-Discovery**
   - `subfinder -d <domain>`
   - `amass -d <domain>` (über Tool-Runner)
3. **Subdomain-Snapshot** (Migration 019, TTL 24 h)
   - `subdomain_snapshot.py` — speichert die Discovery-Ergebnisse pro Domain
   - **Bei Cache-Hit:** nachfolgende Scans innerhalb 24 h verwenden den Snapshot (Log: *"SKIPPED: Subdomain-Snapshot vom … wiederverwendet — N Subdomains aus vorherigem Lauf"*)
   - Re-Enumeration nur via `POST /api/admin/targets/<host_id>/restart-precheck`
4. **DNS-Resolution** (`dnsx` batch-Aufruf): A / AAAA / CNAME pro FQDN
5. **Web-Probing** (`httpx` + Playwright): pro FQDN parallel HTTP/HTTPS-Probe
   - Erfasste Felder: `has_web`, `status`, `final_url`, `title`, Response-Header, Tech-Signal (Cookies, Scripts)
6. **Dedup** — `merge_and_group()` (`phase0.py:834`)
   - Gruppiert FQDNs nach IP → Host-Aggregation
   - **Wichtige Klarstellung:** Subdomain-Anzahl ≠ Anzahl unique IP-Hosts. Beispiel heuel.com (Mai 2026): 28 Subdomains → 5 unique IPs (mehrere FQDNs teilen sich Hetzner-Mailserver, Cloudflare-Edge, Azure-Frontdoor)
7. **Scope-Enforcement** — `scope.enforce_scope()` (Multi-Target: `enumerate` / `scoped` / `ip_only`)

---

## 3. KI #1 — Host-Strategy (Haiku 4.5)

| Eigenschaft | Wert |
|---|---|
| Datei : Zeile | `scan-worker/scanner/ai_strategy.py:255` `plan_host_strategy()` |
| Modell | `claude-haiku-4-5-20251001` |
| Temperature / max_tokens | 0.0 / 8192 |
| System-Prompt | `HOST_STRATEGY_SYSTEM` ab `ai_strategy.py:184` (~1.2 K Tokens) |
| Cache | namespace `ki1_host_strategy`, TTL **7 d**, order-scope (byte-identisch bei Re-Scan) |
| Fallback | scan ALL hosts mit Begründung (`ai_strategy.py` ~Z. 298) |

### Input pro Host

- `ip`, `fqdns[]`
- `web_probe` — `has_web`, `status`, `title`, `final_url`, `web_fqdn`
- `passive_intel` — Shodan-Ports/Services, AbuseIPDB-Score, DNSSEC, Whois-Expiration
- `dns_findings` — dangling-CNAME-Risiken

### Output

```json
{
  "hosts": [
    {"ip": "...", "action": "scan|skip", "priority": 1,
     "reasoning": "...", "scan_hints": {...}}
  ],
  "strategy_notes": "...",
  "passive_intel_summary": "..."
}
```

### Hard-Override `_enforce_scan_for_live_web_hosts()` — `ai_strategy.py:326`

> Eingebaut **2026-05-04** nach dem heuel.com-Bug.

Wenn die KI einen Host auf `skip` setzt, aber **alle drei** Bedingungen erfüllt sind:
- `web_probe.has_web == True`
- `web_probe.status ∈ {200, 201, 202, 204, 301, 302, 401, 403, 405}`
- `urlparse(web_probe.final_url).hostname == web_probe.web_fqdn` (Host antwortet selbst — kein externer Redirect)

→ wird `action` zwangsweise auf `scan` gesetzt. Verhindert False-Negatives bei:
- **Cloudflare-WAF-403** (z. B. `online.heuel.com`) — die KI sah „Just a moment…" und entschied skip
- **„Title=Redirector"-Pages** (z. B. `ose.heuel.com` auf Azure) — die KI dachte, es sei ein reiner Redirector

Echte externe Redirects (z. B. IPv6 → andere Subdomain) bleiben korrekt skip.

---

## 4. Phase 1 — Tech-Detection (parallel, max 3 Hosts)

| Eigenschaft | Wert |
|---|---|
| Einstieg | `scan-worker/scanner/phase1.py:522` `run_phase1()` |
| Parallelisierung | ThreadPool, max 3 Hosts gleichzeitig (`worker.py:429`) |
| Output | `tech_profile` pro Host (server, cms, cms_version, cms_confidence, waf, technologies, redirect_data, has_web) |
| KI-Entscheidung | **keine in Phase 1 selbst** — Daten-Sammlung für KI #2 + #3 |

### Tools (Reihenfolge)

1. **nmap** — `nmap -p- --script=ssl-cert -oX` (Full-Port + SSL-Cert)
2. **httpx** — `-silent -no-color -json` (Status, Header, Title, Body)
3. **Playwright** + Wappalyzer-Lite-Patterns
   - Cookies, Scripts, Meta-Tags, Body-Classes
   - Erkennt: Next.js, React, Vue, Angular, Node.js, PHP, IIS, CMS (WordPress, Drupal, TYPO3, Joomla, Shopware, Magento), Vercel/CF/CloudFront/Azure/Fastly/Nginx/Apache
4. **CMSFingerprinter** (`scanner/cms_fingerprinter.py`)
   - Probe-Matrix per Default **OFF** seit dew21.de-Bug (env `CMS_PROBE_MATRIX_ENABLED`)
   - Strenge Patterns für Magento (`Mage.Cookies`, `/skin/frontend/`) + Craft (`Craft\s?CMS`, `craftcms.com`, `/cpresources/`)
5. **wafw00f** — `wafw00f -a` (CF, AWS WAF, ModSecurity, …)
6. **gowitness** — Screenshot pro Host

---

## 5. KI #2 — Tech-Analysis / CMS-Korrektur (Haiku 4.5)

| Eigenschaft | Wert |
|---|---|
| Datei : Zeile | `scan-worker/scanner/ai_strategy.py:421` `plan_tech_analysis()` |
| Modell | `claude-haiku-4-5-20251001` |
| Temperature / max_tokens | 0.0 / 8192 |
| Cache | namespace `ki2_tech_analysis`, TTL **30 d** (CMS-Detection ist stabil) |
| Fallback | `{}` (Phase-1-Daten unkorrigiert weiterverwendet) |

### Input

- `tech_profiles` aus Phase 1
- `redirect_data` pro FQDN (HTTP-Header, HTML-Meta-Tags, Title, Body-Snippets)
- CMS-Path-Probe-Ergebnisse

### Was die KI korrigiert

- **CMS-False-Positives** (z. B. „WordPress erkannt, aber `/wp-login.php` = 404" → CMS=null)
- **Tech-Stack-Versionen** (Meta-Tags vs. Response-Header vs. Server-Header)
- **SPA-Detection** (Next.js, Nuxt, React)

### Output

```json
{
  "hosts": {
    "<ip>": {
      "cms": "...|null",
      "cms_version": "...",
      "cms_confidence": "high|medium|low",
      "is_spa": true,
      "reasoning": "..."
    }
  }
}
```

---

## 6. KI #3 — Phase-2-Config (Haiku 4.5, **pro Host**)

| Eigenschaft | Wert |
|---|---|
| Datei : Zeile | `scan-worker/scanner/ai_strategy.py:564` `plan_phase2_config()` |
| Modell | `claude-haiku-4-5-20251001` |
| Temperature / max_tokens | 0.0 / 8192 |
| Cache | namespace `ki3_phase2_config`, TTL **7 d**, **per-host** (`host_scope=ip`) |
| Fallback | Default-Config (standard ZAP, kein AJAX, alle Tools) |

> **Wichtig:** Wird PRO Host einzeln aufgerufen. Eine Order mit 3 Hosts = 3 Cache-Einträge.

### Input pro Host

- Tech-Profile (cms, server, waf, technologies)
- CMS-Details (cms_fingerprint confidence)
- Shodan Service-Versionen (aus Phase 0a)
- Package (perimeter / compliance / insurance / webcheck)

### Was die KI konfiguriert

| Feld | Werte |
|---|---|
| `zap_scan_policy` | `waf-safe` / `standard` / `aggressive` |
| `zap_spider_max_depth` | 3–10 |
| `zap_ajax_spider_enabled` | bool (für SPAs) |
| `zap_active_categories` | `[sqli, xss, lfi, ssrf, cmdi, path_traversal, …]` |
| `zap_rate_req_per_sec` | 20–150 (WAF-Empfindlichkeit) |
| `zap_threads` | 1–20 |
| `zap_spider_delay_ms` | int |
| `skip_tools` | `[]` oder `[wpscan, nikto, …]` |
| `focus_areas` | `[api_security, cms_plugins, ssl, header_security]` |

---

## 7. Phase 2 — Deep-Scan (parallel, max 3 Hosts)

| Eigenschaft | Wert |
|---|---|
| Einstieg | `scan-worker/scanner/phase2.py:999` `run_phase2()` |
| Parallelisierung | ThreadPool, max 3 Hosts; pro Host parallel oder sequenziell laut `should_parallelize_stage2()` (`phase2.py:45`) |

### Stages

| Stage | Tools | Anmerkung |
|---|---|---|
| 1 — statisch | testssl.sh, nikto, headers | immer parallel |
| 2 — dynamisch | ZAP (Spider + AJAX-Spider + Active Scan), ffuf / feroxbuster (Wordlist), wpscan (wenn CMS=WordPress), dalfox (XSS) | parallel oder sequenziell wenn WAF erkannt |
| 3 — Enrichment | katana (Crawler), nuclei (Templates) | optional |

**ZAP Pool-Mode:** ZAP-Instanzen aus Redis-Pool leasen (Heartbeat-basiert). Details: `docs/SCAN-TOOLS.md`.

**Output:** `phase2_result` mit `tools_run[]` + `findings[]` pro Tool.

---

## 8. KI #4 — Cross-Tool-Confidence (Sonnet 4.6)

| Eigenschaft | Wert |
|---|---|
| Datei : Zeile | `scan-worker/scanner/ai_strategy.py:745` `plan_phase3_prioritization()` |
| Modell | `claude-sonnet-4-6` |
| Temperature / max_tokens | 0.0 (1.0 wenn Thinking) / 24576 |
| Extended Thinking | budget 8192 (M3 produktiv) |
| Cache | namespace `ki4_phase3`, TTL **1 d**, order-scope |
| Fallback | leere `confidence_scores[]` (Phase 3 läuft programmatisch weiter) |

### Input (begrenzt auf 100 Findings)

- `findings_summary` — `tool, title, severity, cve, confidence, host, port, also_found_by`
- `tech_profiles` (für Version-Cross-Check)
- WAF-Status

### Was die KI entscheidet

- **Confidence-Boost** wenn mehrere Tools korroborieren
- **False-Positive-Detection** bei Tech-Mismatch (z. B. „WP-Plugin-XSS aber CMS=null")

> **Severity-Hoheit:** Die KI ändert die Severity NICHT — sie liegt beim Phase-3-FP-Filter und der Reporter-Severity-Policy.

### Tool-Use-Loop (opt-in via `KI4_USE_TOOLS=true`)

| Tool | Zweck |
|---|---|
| `lookup_cve(cve_id)` | NVD / CVSS / KEV-Status |
| `lookup_epss(cve_id)` | Exploit-Probability (0.0 – 1.0) |
| `get_finding_corroboration(host, finding_type)` | andere Tools die dasselbe melden |

---

## 9. Phase 3 — Correlation + Threat-Intel + FP-Filter

| Eigenschaft | Wert |
|---|---|
| Einstieg | `scan-worker/scanner/phase3.py:65` `run_phase3()` |

### Schritte

1. **`extract_findings(phase2_results)`** — Parse ZAP / nikto / wpscan / ffuf / testssl / dalfox JSON in einheitliches Format
2. **`CrossToolCorrelator.correlate()`** — gruppiert nach `(host, port, vuln-type)`, berechnet `corroborating[]`
3. **Threat-Intel-Enrichment**
   - **NVD** (`NVDClient.lookup_batch(cve_ids, max=50)`) — CWE, CVSS-v3.1-Score, Severity
   - **EPSS** — Exploit-Probability nächste 30 Tage
   - **CISA-KEV** — Known Exploited Vulnerability
   - **ExploitDB** (optional) — öffentliche PoC-Verfügbarkeit
4. **`FalsePositiveFilter.filter()`** — Regeln:
   - WAF-Single-Tool-FP
   - Version-Mismatch (z. B. „WP 3.5 CVE, aber Seite läuft 6.0")
   - CMS-Mismatch
   - SSL-Dedup (Multi-Host-Cert)
   - Header-Dedup (Load-Balancer)
   - Info-Noise (CVSS < 2.5 ohne CMS-Context)
5. **KI #4 Cross-Tool-Confidence** (siehe oben)
6. **Business-Impact-Scoring**
   - Basis: CVSS-Score (oder Severity→CVSS-Map)
   - EPSS-Boost: > 0.7 → Confidence + 0.2
   - CISA-KEV-Boost: gelistet → Priorität ↑↑
   - Package-Weights (insurance: RDP/SMB ×2.0; compliance: Encryption ×1.5; …)
   - Ransom-Ports (3389, 445, 5900) → Special-Weight
   - Final 0–10 pro Finding + Order-Score

### Output

```json
{
  "correlated_findings": [...],
  "enrichment": {"nvd": {...}, "epss": {...}, "kev_list": [...]},
  "business_impact_score": 7.3,
  "phase3_summary": {
    "total_findings": 42, "valid_findings": 35, "false_positives": 7,
    "severity_counts": {"critical": 2, "high": 8, "medium": 25},
    "cves_enriched": 12, "cisa_kev_matches": 2
  }
}
```

---

## 10. Finalize + Übergabe an Reporter

`_finalize()` (`scan-worker/scanner/worker.py:829`):

1. `pack_results()` → tar.gz nach MinIO-Bucket `scan-rawdata`
2. Screenshots → MinIO-Bucket `scan-screenshots` (`{order_id}/{safe_fqdn}.png`)
3. `enqueue_report_job()` → Redis `report-pending`
4. DB-Updates:
   - `orders.passive_intel_summary` (nach Phase 0a)
   - `orders.correlation_data` (nach Phase 3)
   - `orders.business_impact_score`
   - `orders.performance_metrics`
   - `orders.status` ← `complete`

---

## 11. Report-Worker — Datenladung + Determinismus-Pipeline

| Eigenschaft | Wert |
|---|---|
| Einstieg | `report-worker/reporter/worker.py:329` `process_job()` |

### Schritte (in dieser Reihenfolge)

1. **MinIO-Download** — `_download_rawdata()` (`worker.py:214`)
2. **`parser.parse_scan_data()`** — normalisiert + dedupliziert Tool-Outputs
3. **KI #5 Reporter-Call** (siehe nächster Abschnitt) — generiert Findings-JSON
4. **`finding_type_mapper.annotate_finding_types()`** (`finding_type_mapper.py:335`)
   - 40+ Regex-Patterns setzen `finding_type`
   - **Deterministisch, kein KI-Call**
5. **`severity_policy.apply_policy()`** (`severity_policy.py:1012`)
   - **63 Regeln** in `severity_policy.py`, kalibriert gegen Rapid7 / Acunetix
   - Überschreibt KI-Severities deterministisch, setzt `policy_id` + `severity_provenance`
   - `POLICY_VERSION = "2026-04-30.1"` (env `VECTISCAN_POLICY_VERSION`, Z. 30)
   - Kategorien: SP-HDR-* (Header), SP-CSP-*, SP-CORS-*, SP-TLS-*, SP-DNS-*, SP-EXP-*, SP-FALLBACK
6. **`business_impact.recompute()`** (`business_impact.py:182`)
   - Re-rechnet Score nach Policy-Anwendung: `severity_weight × cvss_score × package_modifier × host_factor`
7. **`selection.select_findings()`** (`selection.py:188`) — Top-N pro Paket:

| Paket | Top-N |
|---|---|
| webcheck | 8 |
| perimeter | 15 |
| compliance | 20 |
| supplychain | 15 |
| insurance | 15 |

   - Stable-Sort, Tiebreaker `finding_id`
   - `additional[]` für „Weitere Befunde"-Anhang

> **Determinismus-Hoheit:** Severity der Findings im PDF kommt NICHT direkt aus
> der KI, sondern aus der Severity-Policy. Die KI liefert
> Title / Description / Recommendation; die Policy bestimmt den Schweregrad.

---

## 12. KI #5 — Reporter (Sonnet 4.6 / Opus 4.6)

| Eigenschaft | Wert |
|---|---|
| Datei : Zeile | `report-worker/reporter/claude_client.py:593` `call_claude()` |
| Cache | namespace `reporter_v1`, TTL **1 d**, order-scope (`regenerate-report` ist byte-identisch) |
| Temperature | 0.0 (oder 1.0 wenn Thinking) |

### Modell paketabhängig

| Paket | Modell | max_tokens |
|---|---|---|
| `webcheck`, `basic`, `tlscompliance` | `claude-sonnet-4-6` | 16 384 |
| `perimeter`, `professional`, `compliance`, `nis2`, `supplychain`, `insurance` | `claude-opus-4-6` | 32 000 |

### 5 System-Prompt-Varianten — `report-worker/reporter/prompts.py`

| Variante | Datei : Zeile | Größe |
|---|---|---|
| `SYSTEM_PROMPT_BASIC` | `prompts.py:10` | ~7 K Tokens |
| `SYSTEM_PROMPT_PROFESSIONAL` | `prompts.py:95` | ~13 K Tokens |
| `SYSTEM_PROMPT_NIS2` | `prompts.py:245` | PROFESSIONAL + ~3 K NIS2 |
| `SYSTEM_PROMPT_SUPPLYCHAIN` | `prompts.py:313` | PROFESSIONAL + ~2 K ISO27001 |
| `SYSTEM_PROMPT_INSURANCE` | `prompts.py:356` | PROFESSIONAL + ~2 K Versicherung |
| `SYSTEM_PROMPT_TLSCOMPLIANCE` | `prompts.py:410` | ~4 K eigenständig |

Selektor: `get_system_prompt()` (`prompts.py:484`)

### User-Prompt — 2-Block-Struktur (M2 Prompt-Cache)

| Block | Inhalt | Caching |
|---|---|---|
| 1 (Prefix) | host_inventory + tech_profiles (~8–15 K Chars) | `cache_control: ephemeral` ab ≥ 8 K Chars |
| 2 (Variable) | consolidated_findings (gekappt 120 K Chars) + Instruktionen | nicht gecacht |

### Extended Thinking

- Nur Opus + max_tokens ≥ 16 K
- Budget: 12 K Tokens
- Anwendung: Findings-Priorisierung, Recommendation-Selektion

### Prompt Caching (M1)

- System-Prompt mit `cache_control=ephemeral` wenn ≥ 8 K Chars (Reporter)
- Scanner-KIs analog wenn ≥ 1.5 K Chars
- TTL Anthropic-default 5 min, Cache-Read = 0.1× Base-Preis

### Fallback

5x Retry mit Exponential Backoff:
- RateLimitError: 10 / 20 / 40 / 80 / 120 s
- APITimeoutError: 5 s
- JSONDecodeError: 3 s + Cache-Invalidate
- APIStatusError retryable (429, 500, 502, 503, 529)

### Output-Schema

```json
{
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "overall_description": "...",
  "findings": [{"id": "VS-2026-001", "title": "...", "severity": "...",
                "cvss_score": "7.5", "cvss_vector": "...", "cwe": "CWE-284",
                "affected": "host:port", "description": "...", "impact": "...",
                "recommendation": "..."}],
  "positive_findings": [...],
  "recommendations": [...]
}
```

Plus paketspezifische Felder (z. B. NIS2 §30-Mapping).

---

## 13. Reporter — QA, Mapping, PDF, DB

### `qa_check.run_qa_checks()` — `qa_check.py:584`

8 Checks (6 deterministisch, 2 optional Haiku):

| # | Check | Was geprüft |
|---|---|---|
| 1 | CVSS-Vector ↔ Score | Berechnet Score aus Vektor, Toleranz ±0.1 |
| 2 | CVSS → Severity | Score-zu-Severity-Mapping plausibel? |
| 3 | CWE-Format | Pattern `CWE-\d{1,4}` |
| 4 | CWE-MITRE-Existence | optional API-Lookup |
| 5 | Duplicate-Detection | Fuzzy-Match (Levenshtein) |
| 6 | Required-Fields | HIGH/CRITICAL → Recommendation MUSS vorhanden sein |
| 7 | Plausibility | Optional Haiku-Review wenn Issues |
| 8 | Halluzination | erfundene CVEs, unmögliche CVSS-Kombinationen |

Output: `QAReport` mit `quality_score` (0–100), `auto_fixes_applied`, `manual_review_needed`.

### `report_mapper.map_to_report_data()`

- Sortiert Findings (CRITICAL → INFO)
- HTML-Escape für ReportLab
- **Compliance-Mapping** (lazy import nach Paket):
  - `compliance/nis2_bsig.py` — §30 BSIG (nr1–nr10), Coverage-Quote
  - `compliance/iso27001.py` — Annex A Controls (A.5–A.18)
  - `compliance/bsi_grundschutz.py` — Module
  - `compliance/nist_csf.py` — Identify / Protect / Detect / Respond / Recover
  - `compliance/insurance.py` — Versicherungs-Fragebogen, Ransom-Port-Multiplier
- Severity-Counts, Recommendation-Clustering nach Timeframe
- Screenshot-Embedding aus `host_screenshots[ip]`

### PDF-Generierung — `generate_report.py`

- **Library:** ReportLab (NICHT weasyprint)
- Custom Flowables: `FindingHeader`, `SeverityBadge`, `HorizontalLine`
- Branding aus `reporter/pdf/branding.py` (Farben, Fonts, Logo) — nicht hardcoden
- Sektionen: Cover → Executive Summary → Findings Detail → Positive Findings → Recommendations → Compliance (paketabhängig) → Appendix → Additional Findings

### MinIO + DB

- Upload Bucket `scan-reports` → `{order_id}.pdf` (oder `{order_id}_v{n}.pdf` bei Regeneration)
- DB `reports`-Tabelle:
  - `findings_data` (JSONB)
  - `policy_version` (TEXT)
  - `policy_id_distinct` (TEXT[])
  - `severity_counts` (Trigger-gesetzt)
  - `version`, `superseded_by`
- Order-Status: `pending_review` (initial) oder `report_complete`

### `posture_aggregator.aggregate_into_posture()` — `posture_aggregator.py:174`

- Akkumuliert Findings über die Subscription-Lebensdauer in `consolidated_findings`
- Lifecycle: `open` / `resolved` / `regressed` / `risk_accepted`
- `posture_score`, `trend_direction` („improving" / „stable" / „degrading")
- Audit-Trail in `scan_finding_observations`
- Update `subscription_posture`, Insert `posture_history`-Snapshot
- Mit `conn.rollback()`-Recovery seit Commit `dc528d2` (verhindert hängende Reports bei SQL-Exception)

---

## 14. Cache + Cost-Tracking — Querschnitt

### Cache-Verhalten

| KI | Namespace | TTL | Order-Scope | Host-Scope | Hit-Rate (geschätzt) |
|---|---|---|---|---|---|
| #1 | `ki1_host_strategy` | 7 d | ja | nein | 50–80 % |
| #2 | `ki2_tech_analysis` | 30 d | ja | nein | 60–90 % |
| #3 | `ki3_phase2_config` | 7 d | ja | **ja** (per IP) | 70–95 % |
| #4 | `ki4_phase3` | 1 d | ja | nein | 40–60 % |
| #5 | `reporter_v1` | 1 d | ja | nein | 80–99 % bei `regenerate-report` |

**POLICY_VERSION** ist Teil aller Cache-Keys (`scan-worker/scanner/ai_cache.py:35`,
`report-worker/reporter/ai_cache.py:22`) → ein Bump invalidiert alles automatisch.

**Cache-Modi:**
- **Order-Scope-Mode** (M1): Hash = `(namespace, order_scope, host_scope?, model, policy_version, cache_version)` — Re-Scans derselben Order treffen garantiert Cache
- **Input-Hash-Mode** (M2): SHA256 von `(namespace, model, system, messages, tools, temperature, max_tokens)` — wenn `order_scope=None`

### Cost-Persistierung

- Modul: `scan-worker/scanner/ai_cost_persist.py` + `report-worker/reporter/ai_cost_persist.py`
- Tabelle `ai_call_costs` (Migration `022_ai_call_costs.sql`)
- Felder: `order_id`, `ki_step`, `model`, `input_tokens`, `output_tokens`, `cache_creation_tokens`, `cache_read_tokens`, `thinking_tokens`, `total_cost_usd`, `cache_hit`, `duration_ms`
- Zusätzlich `*_debug` als `scan_results.tool_name` mit System-Prompt + User-Prompt + Raw-Response für Audit

### Pricing (Mai 2026, USD pro 1 M Tokens)

| Modell | Input | Output | Cache-Read | Cache-Write |
|---|---|---|---|---|
| Haiku 4.5 | 1.00 | 5.00 | 0.10 | 1.25 |
| Sonnet 4.6 | 3.00 | 15.00 | 0.30 | 3.75 |
| Opus 4.6 | 15.00 | 75.00 | 1.50 | 18.75 |

Cache-Read = 0.1× Base, Cache-Write = 1.25× Base.

### Geschätzte Kosten pro Order (Vollscan Perimeter)

| Schritt | Modell | Input | Output | Kosten |
|---|---|---|---|---|
| KI #1 | Haiku | ~3 K | ~1 K | $0.008 |
| KI #2 | Haiku | ~5 K | ~1 K | $0.010 |
| KI #3 (× 3 Hosts) | Haiku | ~3 K each | ~1 K each | $0.024 |
| KI #4 | Sonnet | ~15 K | ~5 K | $0.120 |
| KI #5 | Opus | ~30 K | ~8 K | $1.050 |
| QA optional | Haiku | ~2 K | ~1 K | $0.007 |
| **Gesamt** | | | | **~$1.20** |

Bei `regenerate-report`: KI #5 Cache-Hit → Kosten ~$0.20.

---

## 15. Bekannte KI-Schwächen + Override-Patterns

Dieser Abschnitt ist die Brücke zur nächsten Optimierungsrunde — hier ist
dokumentiert, **wo wir der KI heute schon nicht mehr trauen**:

| Pattern | Datei | Auslöser |
|---|---|---|
| **KI #1 Skip-Override** für Live-Web-Hosts | `ai_strategy.py:326` `_enforce_scan_for_live_web_hosts` | heuel.com Mai 2026 — KI hat `ose.heuel.com` (Title=Redirector, 200 OK) und `online.heuel.com` (CF-WAF-403) fälschlich geskippt |
| **CMS-Probe-Matrix per Default OFF** | `cms_fingerprinter.py` env `CMS_PROBE_MATRIX_ENABLED` | dew21.de Mai 2026 — `(?i)mage` hat „image" gematcht, falscher Magento-Treffer; Wappalyzer-Lite via Playwright ist redundant zuverlässiger |
| **Severity-Policy überschreibt KI-Severities** | `severity_policy.py` (63 Regeln) | Determinismus-Block Q2/2026 — KI darf Title/Description schreiben, aber nicht den Schweregrad bestimmen |
| **Phase-3-FP-Filter vor KI #4** | `phase3.py` `FalsePositiveFilter` | KI #4 sieht schon vorgefilterte Findings → kürzere Prompts, weniger FP-Reasoning |
| **Subdomain-Snapshot (TTL 24 h)** | Migration 019 `scan-worker/scanner/subdomain_snapshot.py` | Eliminiert externe Drift bei wiederholten Scans innerhalb 24 h — Re-Enumeration nur via Admin-API |
| **Posture-Aggregator conn.rollback()** | `posture_aggregator.py` + `worker.py` (Commit `dc528d2`) | Order 9ac8ea7f Mai 2026 — SQL-Exception im Aggregator versetzte conn in `InFailedSqlTransaction` → Reporter hing in `report_generating` |

---

## 16. Querverweise

- Architektur-Übersicht: `docs/architecture.md`
- v2-Pipeline-Spec: `docs/SCAN-PIPELINE-v2.md`
- Tool-Konfig + Timeouts + Output-Format: `docs/SCAN-TOOLS.md`
- Determinismus-Block (Spec): `docs/deterministic/`
- API-Spec: `docs/API-SPEC.md`
- DB-Schema: `docs/DB-SCHEMA.sql`
- Report-Layout: `references/report_structure.md`
