# Scan-Optimierung — Implementierungs-Changelog

**Stand:** 2026-05-08
**Quelle:** Audit `docs/scan-flow/Scan-Optimierung.md` (42 Findings)
**Status:** 41/42 deployed (P0-P3 + P4a), 1 deferred (P4b: nuclei + katana)

---

## Übersicht

| Paket | Pipeline | Findings | POLICY_VERSION | Migrations | Branch-Range |
|---|---|---|---|---|---|
| P0 Foundation | 2411 ✓ | 9 | unverändert | — | `pre-p0-foundation..28d36d3` |
| P1 Quick-Wins | 2412 ✓ | 17 | unverändert | — | `pre-p1-quickwins..6c448d2` |
| P2 Maintained-Listen-Sync | 2414 ✓ | 4 | → `2026-05-08.1` | — | `pre-p2-sync..1480b8b` |
| P3 Mail-Security & Discovery | 2415 ✓ | 7 | → `2026-05-09.1` → `2026-05-10.1` | 026 (Shodan Pre-Warm) | `pre-p3-mail-discovery..23d33de` |
| P4a Phase-1/KI-Coverage | 2416 ✓ | 4 | unverändert | — | `pre-p4a-phase1-ki..edfb770` |
| P4b nuclei + katana | — | 1 (deferred) | (POLICY_VERSION-Bump erwartet) | — | — |

**Aktuelle POLICY_VERSION:** `2026-05-10.1` (in `severity_policy.py`, `report-worker/ai_cache.py`, `scan-worker/ai_cache.py`).

**Gesamt-Test-Suite:** 1133 grün (579 report-worker + 525 scan-worker, 1 skip + 29 scripts). API 89 grün. Frontend TS-compile clean.

**Rollback-Tags:** `pre-p0-foundation`, `pre-p1-quickwins`, `pre-p2-sync`, `pre-p3-mail-discovery`, `pre-p4a-phase1-ki`. Pro Tag: `git reset --hard <tag>` setzt main auf den Stand VOR dem Paket zurück.

---

## P0 — Foundation (Determinismus-Hygiene)

**Commit:** `pre-p0-foundation..28d36d3` (Pipeline 2411 success).
**Zweck:** Bug-Charakter, kein Severity-Drift. Solide Basis für alle weiteren Pakete.

### F-XS-003 — Sync-Helper-Lib + Pilot-Refactor `sync-eol-data.py`

**Commit:** `85d31b3`
**Geändert:**
- NEU `scripts/_sync_lib.py` — Helper-Bibliothek mit `fetch_with_retry`, `atomic_write_python_module`, `has_git_changes`, `commit_and_push_if_changed`, `validate_min_entries`, `SyncValidationError`.
- NEU `scripts/_sync_commit.py` — CLI-Wrapper für GitLab-Jobs.
- MOD `scripts/sync-eol-data.py` — refaktoriert auf neue Lib (Output-Format byte-identisch zu vor dem Refactor).
- MOD `.gitlab-ci.yml` — neuer YAML-Anchor `.sync-job-template`, `eol-data-sync`-Job nutzt Template + backwards-kompatibler `EOL_SYNC` ODER neuer `SYNC_ENABLED`-Trigger.
- NEU `scripts/tests/_sync_lib.py` — 7 Tests.

**Erwartetes Verhalten:**
- `sync-eol-data.py` produziert identisches Output wie vor Refactor (Hash-Vergleich über `eol_data_generated.py`).
- Sync-Helper-Library ist als Pilot bereit für die drei neuen Sync-Skripte (P2).

**Test:**
```bash
# Sanity: existierender EOL-Sync läuft weiter durch
cd C:/BS-Consulting/Projekte/Coding/vectiscan
python scripts/sync-eol-data.py --dry-run
# Erwartung: ~25 Produkte gefetched, kein Crash
```

**Risiko:** keiner. Bei Lib-Bug fallen alle Sync-Skripte aus, daher Test-Coverage auf Lib selbst.

---

### F-XS-001 — Output-Normalizer für 4 Phase-2-Tools

**Commit:** `33770ee`
**Geändert:**
- MOD `scan-worker/scanner/output_normalizer.py` — 4 neue Funktionen + Dict-Einträge:
  - `normalize_testssl` — strippt Run-Metadata + IDs
  - `normalize_ffuf` — strippt time/commandline/config-Felder, sortiert results by url
  - `normalize_katana` — strippt timestamps + Cookies, sortiert
  - `normalize_feroxbuster` — strippt timestamp/response_time/wildcard
- NEU `scan-worker/tests/test_output_normalizer_fxs001.py` — 15 Tests.

**Erwartetes Verhalten:**
- Cache-Hit-Quote bei Re-Scans steigt deutlich (TLSCompliance ~80%+, Perimeter ~50%).
- `scan_results.raw_output` für die 4 Tools enthält keine Run-spezifischen Felder mehr.
- KI #5 Reporter content_hash ist stabil bei identischen Server-Antworten.

**Test:**
```bash
# Re-Scan einer bestehenden Order. Vorher in DB checken: ai_call_costs.cache_hit
# Nach 2 Re-Scans sollten ki1_host_strategy / ki2_tech_analysis / ki3_phase2_config /
# ki4_phase3 / reporter_v1 alle Cache-Hits zeigen — vorher waren testssl-getriebene
# Re-Scans Cache-Miss.
```

**Risiko:** einmaliger Cache-Miss nach Rollout (alte Hashes invalid).

---

### F-XS-002 — Cache-Symmetrie KI #2 + KI #3

**Commit:** `31f3d07`
**Geändert:**
- MOD `scan-worker/scanner/ai_strategy.py` — `plan_tech_analysis` (KI #2) und `plan_phase2_config` (KI #3) übergeben jetzt `content_hash` an `_call_haiku` (analog KI #1).
- NEU `scan-worker/tests/test_ai_strategy_cache.py` — 4 Tests.

**Erwartetes Verhalten:**
- KI #2 + KI #3 Cache-Hits **Order-übergreifend** bei identischen Tech-Profilen (vorher nur Order-Scope).
- Re-Scans verschiedener Orders mit gleichem Tech-Stack treffen denselben Cache-Eintrag.

**Test:**
```bash
# Zwei Orders auf ähnlichen Tech-Stacks (z.B. zwei WordPress-Seiten ohne WAF).
# Erwartung: zweiter Order trifft KI #3 Cache → keine Haiku-Kosten für Phase-2-Config.
# Verifikation in DB: SELECT model, SUM(cost_usd) FROM ai_call_costs WHERE order_id = '...' AND ki_step = 'ki3_phase2_config';
```

**Risiko:** Cache-Volumen +~30% Redis-Keys (vernachlässigbar).

---

### F-RPT-002 — `selection.consolidate` mit `STABLE_TITLE_VARS`

**Commit:** `22edf02`
**Geändert:**
- MOD `report-worker/reporter/selection.py` — neue Konstante `STABLE_TITLE_VARS = ("port", "tech", "version", "plugin", "library", "directive", "selector")`. `_normalized_evidence_hash` nimmt `title_vars`-Beitrag auf.
- MOD `report-worker/tests/test_selection.py` — 4 neue Tests.

**Erwartetes Verhalten:**
- EOL-Findings mit unterschiedlichen Tech (z.B. PHP 5.6 vs Python 2.7) konsolidieren NICHT mehr falsch zu einem Eintrag.
- DB-Port-Findings (3306 vs 5432) bleiben getrennt.
- WordPress-Plugin-Vulns (Slider-Revolution vs WPBakery) bleiben getrennt.

**Test:**
```bash
# Re-Scan eines Hosts mit mehreren EOL-Software-Versionen.
# Vorher: ein Finding "(N Hosts betroffen)" mit nur einer Tech.
# Nachher: pro Tech/Version separates Finding.
# Im PDF: Anzahl EOL-Findings sollte steigen bei Multi-Tech-Hosts.
```

**Risiko:** Determinismus-Drift einmalig 1-2 Re-Scans (Migration 024 Score ändert sich), danach stabil.

---

### F-RPT-007 — `eol_detector.merge_into_claude_findings` Host-Resolution + Version-Recovery

**Commit:** `95882db`
**Geändert:**
- MOD `report-worker/reporter/eol_detector.py` — neuer optionaler `tech_profiles=None`-Parameter; Host-Resolution via FQDN↔IP-Mapping aus `tech_profiles[].fqdns[0]`; Version-Recovery aus Title-Regex wenn `title_vars.version` fehlt.
- MOD `report-worker/reporter/deterministic_pipeline.py` — Caller passt `tech_profiles` durch.
- MOD `report-worker/tests/test_eol_detector.py` — 4 neue Tests.

**Erwartetes Verhalten:**
- Keine Doppel-EOL-Findings mehr bei FQDN-basierten Scans (Mehrheit der Customer-Orders).
- Claude-Finding "Apache 2.2 ist EOL auf example.com" + EOL-Detector-Finding (mit host_ip + fqdn) → 1 merged Finding mit `_deterministic_source` Marker.

**Test:**
```bash
# Scan einer Domain mit veralteter Software (Apache 2.2 / PHP 7.x / etc.).
# PDF-Report sollte pro EOL-Tech NUR EINEN Eintrag zeigen, nicht zwei.
```

**Risiko:** Determinismus-Drift einmalig (consolidation_groups ändert sich), danach stabil.

---

### F-RPT-003 — `business_impact._classify_finding` policy_id-Mapping

**Commit:** `0e061d3`
**Geändert:**
- MOD `report-worker/reporter/business_impact.py` — neue Konstante `POLICY_ID_TO_CATEGORIES` (~63 Einträge). `_classify_finding` ersetzt englische Keyword-Suche durch policy_id-Lookup.
- MOD `RANSOMWARE_PORTS` — Telnet 23 + VNC alt 5800 ergänzt (CISA-KEV-relevant).
- MOD `report-worker/tests/test_business_impact.py` — 5 neue Tests inkl. Cross-Check-Test (jeder policy_id muss in Mapping sein).

**Erwartetes Verhalten:**
- DACH-Reports (deutsche Narratives) bekommen jetzt korrekt Insurance/Compliance/SupplyChain-Multipliers.
- Vorher fielen viele Findings durch das englische Keyword-Raster → niedrige business_impact_scores → falsche Top-N-Reihenfolge.

**Test:**
```bash
# Insurance-Paket-Scan vorher/nachher Vergleich:
# - Top-N-Reihenfolge im PDF ändert sich (mehr Diversität, mehr CRITICAL/HIGH oben)
# - business_impact_score-Verteilung verschiebt sich nach oben
# - SQL: SELECT severity, AVG(business_impact_score) FROM consolidated_findings GROUP BY severity;
```

**Risiko:** Score-Drift einmalig 1-2 Re-Scans, dann stabil. Top-N-Reihenfolge ändert sich (gewünschtes Verhalten).

---

### F-RPT-005 — QA-Check `_check_severity_evidence` nach severity_policy verschieben

**Commit:** `82c820a`
**Geändert:**
- MOD `report-worker/reporter/qa_check.py` — `run_qa_checks` bekommt `apply_severity_cap=True`-Default-Parameter.
- MOD `report-worker/reporter/worker.py` — Worker ruft erst mit `apply_severity_cap=False` auf, dann nach `apply_deterministic_pipeline` neuer Helper-Aufruf der Cap NUR auf `policy_id="SP-FALLBACK"`-Findings anwendet. Gecappte Findings bekommen `_qa_cap_applied=True`-Flag.
- MOD `report-worker/tests/test_worker.py` — 3 neue Tests in `TestQASeverityCapOrder`.

**Erwartetes Verhalten:**
- Audit-Log enthält keine wirkungslosen `severity_capped`-Events mehr für Findings mit policy_id (~95% der Findings).
- `severity_provenance.tool_severities` zeigt jetzt KI-Original-Severity (vorher QA-modifiziert).
- Forensik-Diff (`scripts/diff-orders.py`) liefert vollständigeres Bild.

**Test:**
```bash
# Reporter-Worker-Logs nach einem Scan:
# - Vorher: viele "severity_capped" Events trotz finaler HIGH-Severity (verwirrend)
# - Nachher: "severity_capped" nur bei SP-FALLBACK-Findings
# - severity_provenance.tool_severities = KI-Original (z.B. "high"), nicht "medium"
```

**Risiko:** keiner. Determinismus unverändert, FP-Rate für SP-FALLBACK unverändert.

---

### F-RPT-006 — `claude_client.call_claude` Truncation-Fix

**Commit:** `75c764d`
**Geändert:**
- MOD `report-worker/reporter/claude_client.py` — Helper `_truncate_consolidated_findings` extrahiert. `MAX_FINDINGS_CHARS` 120K → 150K. `per_host_cap` wird jetzt tatsächlich angewendet (war dead code).
- MOD `report-worker/tests/test_claude_client.py` — 3 neue Tests.

**Erwartetes Verhalten:**
- Bei Multi-Host-Scans (>10 Hosts) bekommen jetzt ALLE Hosts ihren fairen Anteil im KI-Prompt (statt erste Hosts voll, letzte abgeschnitten).
- KI-Narratives im PDF sind für letzte Hosts vollständig (vorher fehlten KI-Beschreibungen für 5+ letzte Hosts bei großen Scans).

**Test:**
```bash
# Compliance-Paket mit >10 Hosts.
# PDF prüfen: alle Hosts sollten KI-formulierte Beschreibungen haben (nicht nur die ersten).
# Falls input >150K bytes: log.warning "consolidated_findings_truncated" weiterhin sichtbar.
```

**Risiko:** KI-Input-Kosten +25% (~$0.11/Report) bei großen Scans.

---

### F-RPT-004 — `finding_type_mapper` AI-Fallback ThreadPool

**Commit:** `50e6a67`
**Geändert:**
- MOD `report-worker/reporter/finding_type_mapper.py` — AI-Fallback-Loop sequenziell → `ThreadPoolExecutor(max_workers=5)` mit per-Future-Timeout 10s.
- NEU `report-worker/tests/test_finding_type_mapper_parallel.py` — 2 Tests (Parallel-Verifikation + Timeout-Isolation).

**Erwartetes Verhalten:**
- Cold-Cache-Szenarien (neue Customer-Reports, POLICY_VERSION-Bumps) deutlich schneller (5-60s → 1-3s).
- Bei warmem Cache marginal.

**Test:**
```bash
# Reporter-Run nach POLICY_VERSION-Bump (Cache-Invalidierung).
# Log-Event "ai_fallback_unavailable" sollte selten kommen.
# Reporter-Latenz für AI-Fallback-Zeile sollte unter 5s bleiben statt 5-60s.
```

**Risiko:** Rate-Limit bei Tier-1 nicht erreicht (max_workers=5 × 1s = 5 req/s, Limit 50 RPM = 0.83 req/s steady-state — SDK-Backoff kompensiert).

---

## P1 — Quick-Wins

**Commit:** `pre-p1-quickwins..6c448d2` (Pipeline 2412 success).
**Zweck:** XS-Aufwand-Findings parallelisierbar, gebündelt nach Phase.

### Bundle A — Pre-Check + Phase 0a (5 Findings, Commit `8b554d1`)

#### F-PRE-002 — DNS-Resolution parallel
- MOD `scan-worker/scanner/common/dns_utils.py` — `resolve_all` ThreadPoolExecutor max_workers=5 (5 Record-Typen parallel).
- **Erwartet:** Pre-Check-Worst-Case 25s → 5s bei langsamen Authoritative-NS.

#### F-PRE-004 — nmap_light Performance-Flags
- MOD `scan-worker/scanner/common/nmap_utils.py` — `--max-retries 2 --host-timeout 30s -n --open` ergänzt.
- **Erwartet:** CIDR-Worst-Case mit DROP-Firewall 180s → ~30s.

#### F-PRE-005 — nmap_light 57-Port-Liste
- MOD `scan-worker/scanner/common/nmap_utils.py` — neue Konstante `PRECHECK_PORTS` mit 57 kuratierten Ports (S1 RCE + S2 KMU-Mgmt + S3 Industrial).
- **Erwartet:** Live-Detection für Hosts auf Custom-Ports (vorher nur Top-10 = 80/443/22/...). Mehr `is_live=true` im Admin-Review.

#### F-P0A-001 — Phase 0a Inner-Parallelization
- MOD `scan-worker/scanner/phase0a.py` — Shodan/AbuseIPDB IP-Loop ThreadPool max_workers=3 + ENV-Override `PASSIVE_INTEL_CONCURRENCY`. SecurityTrails 3-Calls parallel.
- **Erwartet:** Phase-0a-Gesamtzeit ~75s → ~15s.

#### F-P0A-005 — phase0a_ip_cap konfigurierbar
- MOD `scan-worker/scanner/packages.py` — neuer Config-Key `phase0a_ip_cap` (perimeter/compliance/supplychain 25, insurance 50). ENV-Override `PHASE0A_IP_CAP`.
- **Erwartet:** Bei Multi-IP-Targets (CIDR, Multi-Subdomain) mehr Coverage.

**Test:**
```bash
# Pre-Check eines /24-CIDR-Targets:
# - Vorher: Top-10-Ports nur, langsam bei langsamen NS
# - Nachher: 57 Ports gescannt, schneller, mehr is_live=true Hosts im Review
```

---

### Bundle B — Phase 0b (4 Findings, Commit `9818850`)

#### F-P0B-002 — subfinder explizite Sources
- MOD `scan-worker/scanner/phase0.py` — `-all` durch `-sources <Free-Provider-Liste>` ersetzt.
- **Erwartet:** Audit-fähig, keine Default-Drift bei subfinder-Updates.

#### F-P0B-005 — CDN-Edge-Dedup rdns-Suffix-Match
- MOD `scan-worker/scanner/phase0.py` — `merge_and_group()` rdns-Suffix-Match VOR IP-Range-Prüfung. Zentraler `rdns_provider_patterns`-Helper.
- MOD `scan-worker/scanner/precheck/saas_heuristic.py` — Helper geteilt.
- **Erwartet:** Fastly/Akamai-Edges werden korrekt dedupliziert (vorher als getrennte IPs).

#### F-P0B-007 — Multi-VHost-Probe batch httpx
- MOD `scan-worker/scanner/phase0.py` — subprocess-pro-FQDN durch batch `httpx -l <file> -threads 30` mit NDJSON-Parser ersetzt.
- **Erwartet:** Multi-VHost-Probe ~50s → ~5-10s.

#### F-P0B-008 — CT-Discovery parallel
- MOD `scan-worker/scanner/phase0.py` — crt.sh + certspotter parallel via ThreadPoolExecutor + Set-Vereinigung statt Fallback.
- **Erwartet:** Frische CT-Issuances zuverlässig (kein crt.sh-Outage-Bottleneck mehr).

**Test:**
```bash
# Phase-0b-Diskovery für eine Domain mit vielen CT-Einträgen + mehreren Subdomains.
# Erwartung: schneller, mehr Subdomains entdeckt (CT-Doppel-Coverage), CDN-IPs als ein Host.
```

---

### Bundle C — Phase 1 + Phase 2 + Upload (3 Findings, Commit `874c665`)

#### F-PH1-002 — wafw00f-VHost-Loop parallel
- MOD `scan-worker/scanner/phase1.py` — ThreadPoolExecutor max_workers=5.
- **Erwartet:** Multi-VHost-Hosts wafw00f-Phase ~20s → ~4s.

#### F-PH2-001 — ffuf_sensitive Wordlist raft-medium → raft-small
- MOD `scan-worker/scanner/phase2.py` — Wordlist-Pfad-Konstante geändert (17.5k → 10k Einträge).
- **Erwartet:** ffuf-Phase ~70s/VHost schneller, kein Hard-Cap-Hit. Coverage-Verlust <2%.

#### F-PH9-001 — Screenshots-Upload parallel
- MOD `scan-worker/scanner/upload.py` — Screenshots-Upload ThreadPoolExecutor max_workers=10. Bucket-Existence-Check als Module-Level-Cache.
- **Erwartet:** Upload-Phase ~5s/Scan schneller.

**Test:**
```bash
# Perimeter-Scan einer Domain mit 5+ VHosts.
# Erwartung: gesamte Phase-2-Laufzeit reduziert, kein ffuf-Hard-Cap-Hit im Log.
```

---

### Bundle D — KI #4 + Phase 3 (2 Findings, Commit `71faa97`)

#### F-KI4-001 — KI #4 Severity-Pre-Sort + Cap 100→150
- MOD `scan-worker/scanner/ai_strategy.py` — vor `summary_truncated[:100]` Severity-priorisierte Sortierung (CRITICAL > HIGH > MEDIUM + KEV-Boost). Cap 150.
- **Erwartet:** Kritische Findings landen zuverlässig im KI-Prompt statt zufällig abgeschnitten zu werden.

#### F-PH3-001 — NVD-Lookup parallel + max_lookups
- MOD `scan-worker/scanner/correlation/threat_intel.py` — ThreadPoolExecutor (max_workers dynamisch: 2 ohne API-Key, 8 mit Key). Exponential-Backoff bei 429.
- MOD `scan-worker/scanner/phase3.py` — `max_lookups` 50 → 100 (perimeter), webcheck 5 → 10. ENV-Override `NVD_MAX_LOOKUPS`.
- **Erwartet:** Phase-3-Laufzeit bei vielen CVE-Findings deutlich schneller. Coverage-Erweiterung.

**Test:**
```bash
# Scan einer Site mit vielen CVE-Treffern (z.B. veraltete WordPress-Plugins).
# Erwartung: KI #4 enthält alle CRITICAL-Findings (auch bei >100 Findings),
# Phase-3-Threat-Intel deckt mehr CVEs ab.
```

---

### Bundle E — KI #1 + KI #3 (3 Findings, Commit `92eec98`)

#### F-KI1-001 — `scan_hints` aus HOST_STRATEGY_SCHEMA entfernt
- MOD `scan-worker/scanner/ai_strategy.py` — `scan_hints`-Feld aus Schema + System-Prompt entfernt (toter Output).
- **Erwartet:** Marginal kürzerer KI-Output, keine Verhaltensänderung.

#### F-KI1-002 — Hard-Override für Mailserver-Hosts
- MOD `scan-worker/scanner/ai_strategy.py` — neuer Helper `_enforce_scan_for_mailservers`. Hosts mit MX-Record-Match ODER offenen Mail-Ports (25/465/587/110/143/993/995) bekommen `action=scan` auch wenn KI "skip" sagte. Reasoning enthält `[HARD-OVERRIDE: MX-Record|Mail-Port N]`.
- **Erwartet:** Mail-Security-Compliance-Drift bei KI-Fehlentscheidung verhindert.

#### F-KI3-001 — KI #3 Host-Iteration ThreadPool
- MOD `scan-worker/scanner/worker.py` — sequenzielle Loop durch `ThreadPoolExecutor(max_workers=min(5, len(targets)))` ersetzt. Rule-Engine-Pre-Gate bleibt.
- **Erwartet:** Bei vielen Hosts ohne Rule-Match 30-45s → 6-9s.

**Test:**
```bash
# Scan-Plan-Phase: Order mit Mail-Hosts (mit MX-Record).
# Logs prüfen: "ai_host_strategy_complete overridden_to_scan=N" wenn KI Mailserver skippen wollte.
# Multi-Host-Order: Phase-1-Phase-2-Übergangszeit reduziert.
```

---

## P2 — Maintained-Listen-Sync

**Commit:** `pre-p2-sync..1480b8b` (Pipeline 2414 success).
**Zweck:** Sync-Pipelines auf Basis F-XS-003-Helper-Lib. POLICY_VERSION-Bump → `2026-05-08.1`.

### F-PRE-001 — Parking-Pattern DACH + Provider + Redirect-Allowlist (Commit `968a249`)

**Geändert:**
- MOD `scan-worker/scanner/common/http_utils.py` — `_PARKING_PATTERNS` von 14 auf 30 erweitert (5 deutsche Marker, 4 expired/maintenance, 7 Provider-Tokens). Neue `_PARKING_REDIRECT_HOSTS`-Allowlist (10 Domains). `is_parking_page` mit optionalem `final_url`-Parameter.
- NEU `scan-worker/tests/test_http_utils.py` — 10 Tests.

**Erwartetes Verhalten:**
- DACH-Parking-Hosts ("Diese Domain steht zum Verkauf", "Wartungsarbeiten") werden erkannt.
- Redirect-zu-Landing-Page-Variante (Domain → parkingpage.namecheap.com) wird erkannt.
- Eingesparte Phase-1-Tools-Calls + KI #1-Calls auf toten Hosts.

**Test:**
```bash
# Pre-Check einer geparkten DE-Domain (sedoparking.com-Listing oder "Diese Domain steht zum Verkauf").
# Logs: "is_parking=true" → Phase 0b/1 wird übersprungen für diesen Host.
```

---

### F-PRE-003 — cloud-ranges-sync (Commit `80b69c5`)

**Geändert:**
- NEU `scripts/sync-cloud-ranges.py` — Sync-Skript für 9 Provider via `_sync_lib`. Quellen: AWS/GCP/Cloudflare/Fastly/DigitalOcean/OVH/IONOS/STRATO/Hetzner-Online (RIPEstat-ASNs).
- NEU `scan-worker/data/__init__.py` + `scan-worker/data/cloud_ranges_generated.py` (wird beim ersten Sync gefüllt).
- MOD `scan-worker/scanner/precheck/saas_heuristic.py` — `_GENERATED_RANGES`-Loader analog `eol_data_generated`-Pattern. Manual `_STATIC_RANGES` gewinnt bei Kollision.
- MOD `scan-worker/Dockerfile` — `COPY data/` für Container.
- MOD `.gitlab-ci.yml` — Job `cloud-ranges-sync`.
- NEU `scripts/tests/test_sync_cloud_ranges.py` — 6 Tests.

**Erwartetes Verhalten:**
- Initial: keine Generated-Ranges (Datei leer bis erster Sync-Run). `_STATIC_RANGES` greift weiter.
- Nach Sync-Job-Run: ~150 Ranges für 9 Provider, KI #1 sieht IONOS/STRATO/OVH/DigitalOcean/etc. korrekt klassifiziert.
- CDN-Dedup für Fastly/Akamai-Edges greift.

**Test:**
```bash
# 1. Sync auslösen: GitLab-Job cloud-ranges-sync via web-Trigger ODER lokal:
python scripts/sync-cloud-ranges.py --dry-run
# 2. Pre-Check eines DE-Hosts (IONOS/STRATO/Hetzner-IP):
# - Vorher: cloud_provider=null
# - Nachher: cloud_provider="ionos" (oder ähnlich)
```

**Risiko:** Azure übersprungen (rotierende SAS-Tokens) — nicht-blocker.

---

### F-P0B-006 — takeover-list-sync (Commit `8a83dfc`)

**Geändert:**
- NEU `scripts/sync-takeover-list.py` — Sync gegen EdOverflow's `can-i-take-over-xyz/fingerprints.json`. Filter `vulnerable=true`. Stdlib `json` (kein pyyaml-Dep nötig).
- MOD `scan-worker/scanner/phase0.py` — `_build_takeover_indicators`-Loader. `_TAKEOVER_POSSIBLE_COMBINED` kombiniert Manual + Generated (Manual gewinnt). `_classify_dangling_cname` nutzt Combined-Liste.
- MOD `.gitlab-ci.yml` — Job `takeover-list-sync`.
- NEU `scripts/tests/test_sync_takeover_list.py` — 9 Tests.

**Erwartetes Verhalten:**
- Initial: hardcoded Takeover-Set greift. Nach Sync ~35 vulnerable Services aus EdOverflow.
- CRITICAL-Severity bei Statuspage/Webflow/Tilda/Heroku/AWS-S3/GitHub-Pages/...-Takeovers.

**Test:**
```bash
python scripts/sync-takeover-list.py --dry-run
# Erwartung: ~35 Services vulnerable
# Live-Test: Domain mit dangling CNAME auf herokuapp.com → Phase-0b sollte takeover_possible=true setzen
```

---

### F-RPT-001 — KNOWN_VULN_BUILDS +15 Manual + OSV-Sync + Range-Matcher (Commit `6df74bd`)

**POLICY_VERSION-Bump:** `2026-04-30.1` → `2026-05-08.1`.

**Geändert:**
- MOD `report-worker/reporter/eol_detector.py` — KNOWN_VULN_BUILDS_MANUAL von 5 auf 20 Einträge erweitert (Apache 2.4.55, nginx 1.23.0, Confluence 8.5.1, GitLab 16.7.1, TeamCity 2023.11.3, PHP 8.3.7, Citrix Bleed, MOVEit, FortiOS, Ivanti, ScreenConnect, WS_FTP, Exchange CU13, vCenter 7.0u3o). Neue `_version_in_range`-Funktion mit `<=`/`>=`/`<`/`>`-Operatoren. Loader-Union mit `KNOWN_VULN_BUILDS_GENERATED`.
- NEU `scripts/sync-known-vuln-builds.py` — OSV-API-Sync mit CISA-KEV + CVSS≥9.0-Filter.
- MOD `report-worker/reporter/severity_policy.py` — POLICY_VERSION-Bump.
- MOD `report-worker/reporter/ai_cache.py` + `scan-worker/scanner/ai_cache.py` — POLICY_VERSION-Bump.
- MOD `.gitlab-ci.yml` — Job `known-vuln-builds-sync`.
- MOD `report-worker/tests/test_eol_detector.py` — 5 neue Tests.
- NEU `scripts/tests/test_sync_known_vuln_builds.py` — 7 Tests.

**Erwartetes Verhalten:**
- Banner-Match bei modernen Mega-Schwachstellen (2022-2026) erzeugt deterministisches Pflicht-Finding mit CRITICAL-Severity + CVE-Listing.
- POLICY_VERSION-Bump invalidiert AI-Cache → erste Re-Scans sind Cache-Miss.
- Range-Matcher unterstützt OSV-Output-Schema (`<=2.4.55`, `>=1.23.0`).

**Test:**
```bash
# Test mit Citrix-Bleed-Banner (CVE-2023-4966):
# Tech-Profile: cms="Citrix NetScaler", cms_version="13.1-49"
# Erwartung: Pflicht-Finding mit CRITICAL, CVE-2023-4966 als cve_id
# OSV-Sync (manuell, Live):
python scripts/sync-known-vuln-builds.py --dry-run
# Erwartung: 15+ Server-Software-CVEs gefiltert
```

**Risiko:** POLICY_VERSION-Bump → einmaliger Cache-Miss-Hit auf alle KI-Calls.

---

## P3 — Mail-Security & Discovery-Tiefe

**Commit:** `pre-p3-mail-discovery..23d33de` (Pipeline 2415 success).
**Zweck:** Mail-Security-Coverage + Phase-0a-Threat-Intel-Erweiterung + Discovery-Cleanup. POLICY_VERSION 2× gebumpt → `2026-05-09.1` → `2026-05-10.1`. Migration 026.

### Bundle A — Mail-Security (Commit `ae5fa74`)

**POLICY_VERSION-Bump:** `2026-05-08.1` → `2026-05-09.1`.

#### F-P0A-002 — Mail-Security-Parsers + 4 SP-DNS-Regeln
- NEU `scan-worker/scanner/passive/mail_security_parsers.py` — TLS-RPT (RFC 8460), BIMI (RFC 9091), DMARC-Detail-Parser (p/sp/pct/rua/ruf/aspf/adkim/fo), NSEC3-Iterations (RFC 9276).
- MOD `scan-worker/scanner/passive/dns_security.py` — `check_dnssec` um NSEC3-Felder erweitert. `run_all_dns_security` ruft `check_tls_rpt` + `check_dmarc_policy` (alle Pakete) + `check_bimi` (Perimeter+) auf.
- MOD `scan-worker/scanner/phase0a.py` — Marker `tlsrpt_present`, `dmarc_p`, `dmarc_pct`, `nsec3_rfc9276_violation` in `passive_intel_summary` für KI #1.
- MOD `scan-worker/scanner/phase0.py` — DMARC-raw-Detection durch strukturierten Parser ersetzt.
- MOD `report-worker/reporter/severity_policy.py` — neue Regeln SP-DNS-011 (TLS-RPT LOW), SP-DNS-012 (BIMI INFO), SP-DNS-013 (DMARC pct<100 MEDIUM), SP-DNS-014 (NSEC3 LOW). `extract_context_flags` setzt `dmarc_pct_partial`/`nsec3_iterations_nonzero`.
- MOD `report-worker/reporter/title_policy.py` — 4 neue Templates.
- MOD `report-worker/reporter/business_impact.py` — POLICY_ID_TO_CATEGORIES.
- MOD `report-worker/reporter/ai_finding_type_fallback.py` — FINDING_TYPE_CATALOG.
- MOD `report-worker/reporter/finding_type_mapper.py` — 4 neue Regex-Patterns.
- NEU `scan-worker/tests/test_mail_security_parsers.py` — 21 Tests.

**Erwartet:** Compliance-Pakete bekommen TLS-RPT/BIMI/DMARC-Detail/NSEC3-Findings. SP-DNS-013 (DMARC pct<100) ist häufiger Insurance-Marker.

#### F-P0B-001 — DKIM-Selektoren parallel + Coverage
- MOD `scan-worker/scanner/phase0.py` — DKIM-Probe ThreadPoolExecutor max_workers=10. Selektor-Liste auf ~57 dedup. Einträge erweitert (SES, Postmark, Mailgun, Mailjet, Brevo, Zoho, IONOS, STRATO, T-Online, GMX, Google, M365).
- NEU `scan-worker/tests/test_dkim_parallel.py` — 3 Tests.

**Erwartet:** False-positive "DKIM missing"-Klasse bei DE-Customers behoben (erkennt jetzt `selector1.dkim` für M365 + alle gängigen DACH-Provider).

**Test:**
```bash
# Mail-Security-Scan einer Domain mit DMARC pct=50.
# Erwartung: SP-DNS-013-Finding mit MEDIUM-Severity.
# DKIM-Test: Domain mit IONOS-DKIM (selector1) → DKIM-Record erkannt, kein "missing"-Finding.
```

---

### Bundle B1 — Phase-0a +URLhaus +GreyNoise +OTX +VirusTotal (Commit `5a7d87e`)

**POLICY_VERSION-Bump:** `2026-05-09.1` → `2026-05-10.1`.

**F-P0A-003** — 4 neue Threat-Intel-Clients + SP-URLHAUS-001:
- NEU `scan-worker/scanner/passive/urlhaus_client.py` — abuse.ch, kein Key nötig, optional `URLHAUS_API_KEY`.
- NEU `scan-worker/scanner/passive/greynoise_client.py` — Community-Tier ohne Key, `GREYNOISE_API_KEY` für Premium.
- NEU `scan-worker/scanner/passive/otx_client.py` — AlienVault, Free 10 req/s.
- NEU `scan-worker/scanner/passive/virustotal_client.py` — `VIRUSTOTAL_API_KEY` nötig (Free 4 req/min).
- MOD `scan-worker/scanner/passive/base_client.py` — `_post()` für form-encoded URLhaus-Calls.
- MOD `scan-worker/scanner/phase0a.py` — 4 neue `_run_*`-Helper, in `top_level_tools`-Liste für parallele Ausführung. Marker in `build_passive_intel_for_ai`.
- MOD `scan-worker/scanner/packages.py` — Tools in `_PERIMETER_BASE.phase0a_tools` und `webcheck` (URLhaus + OTX, Free-Tier).
- MOD `report-worker/reporter/severity_policy.py` — SP-URLHAUS-001 CRITICAL CVSS 10.0.
- MOD `report-worker/reporter/title_policy.py` + `business_impact.py` + `ai_finding_type_fallback.py` + `finding_type_mapper.py`.
- NEU 4× `scan-worker/tests/test_<client>.py` (24 Tests) + `report-worker/tests/test_urlhaus_policy.py` (8 Tests).

**Bonus-Fix:** pre-existing `severity_policy.extract_context_flags` Bug (evidence als String) defensiv gepatcht — 9 deterministic-pipeline-Tests wieder grün.

**Erwartet:**
- Phase-0a-Output enthält neue Felder: `urlhaus.compromised`, `greynoise.classification`, `otx.pulse_count`, `virustotal.malicious`.
- KI #5 sieht das automatisch und generiert ggf. Finding.
- Bei URLhaus-Compromise-Treffer → SP-URLHAUS-001 CRITICAL via finding_type-Mapper.

**Test:**
```bash
# Test-Domain mit bekanntem URLhaus-Listing (z.B. von urlhaus.abuse.ch live abrufen).
# Erwartung: passive_intel_summary.urlhaus.compromised=true → Finding mit CRITICAL.
# ENV-Variablen setzen: GREYNOISE_API_KEY, VIRUSTOTAL_API_KEY (optional, sonst graceful skip).
```

---

### Bundle B2 — Phase-0a Subdomain-Reuse + Shodan Pre-Warm (Commit `36587de`)

**Migration 026:** `orders.pre_warm_requested` (BOOLEAN) + `subscriptions.shodan_scan_request` (JSONB).

#### F-P0A-004 — Phase-0a-Subdomains an Phase 0b durchreichen
- MOD `scan-worker/scanner/phase0a.py` — `run_phase0a` returnt zusätzlich `passive_subdomains`.
- MOD `scan-worker/scanner/phase0.py` — `run_phase0` mit `seed_subdomains`-Param. SecurityTrails-Doppelcall (`run_securitytrails_subdomains`) entfernt.
- MOD `scan-worker/scanner/worker.py` — Wiring.
- NEU `scan-worker/tests/test_phase0a_passive_seed.py` — 4 Tests.

**Erwartet:** Phase 0b ~15s schneller (SecurityTrails-API-Tier-Verbrauch halbiert). Mehr Subdomains entdeckt (Shodan-Subdomain-Liste neu eingespeist).

#### F-P0A-006 — Shodan on-demand Pre-Warm
- NEU `scan-worker/scanner/shodan_prewarm.py` — Helper `maybe_trigger_prewarm(order_id)`.
- MOD `scan-worker/scanner/passive/shodan_client.py` — `request_scan(ips)`-Methode. POST `/shodan/scan`, Cap 50 IPs.
- MOD `scan-worker/scanner/worker.py` — Trigger nach `set_scan_started` (= nach Authorization-Upload).
- NEU `api/src/migrations/026_shodan_pre_warm.sql` + Hook in `api/src/lib/db.ts::initDb()`.
- MOD `api/src/routes/orders.ts` — `pre_warm_shodan: boolean` Field.
- MOD `frontend/src/lib/api.ts` — `createOrder` mit `preWarmShodan`-Param.
- NEU `scan-worker/tests/test_shodan_prewarm.py` — 11 Tests.

**Erwartet:**
- Subscription-Pfad: default-on. Pro Re-Scan ~50 IPs an Shodan zur on-demand-Aktualisierung gemeldet → frischere Daten in Phase 0a.
- One-Off-Order: opt-in via API-Field `pre_warm_shodan`. **Frontend-UI-Toggle deferred** — Customer kann's aktuell nur via direktem API-Call setzen.

**Test:**
```bash
# Subscription-Re-Scan: Logs sollten "shodan_prewarm_triggered" enthalten.
# DB-Check: SELECT shodan_scan_request FROM subscriptions WHERE id = '...';
# Erwartung: JSONB mit scan_id, requested_at, ips[].
# One-Off-Test: POST /api/orders mit { pre_warm_shodan: true } → orders.pre_warm_requested=true.
```

**Risiko:** Shodan Freelancer ~5000 Scan-Credits/mo Budget — ~1500 erwartet bei 30 Subscriptions/mo.

---

### Bundle C — Discovery-Cleanup (Commit `2649035`)

#### F-P0B-003 — amass v5 entfernen
- MOD `scan-worker/scanner/phase0.py` — `run_amass`-Funktion + Aufruf entfernt.
- MOD `scan-worker/Dockerfile` — amass-Install-Block entfernt.
- MOD `scan-worker/scanner/packages.py` — `amass` aus `_PERIMETER_BASE.phase0b_tools`.
- MOD `scan-worker/scanner/{worker,diagnose}.py` — Tool-Version-Listen bereinigt.

**Erwartet:** Phase-0b-Worst-Case -300s (amass-Hard-Cap), Image -50MB. <5% Subdomain-Coverage-Verlust.

#### F-P0B-004 — gobuster_dns Wordlist 30k
- MOD `scan-worker/Dockerfile` — Build-Time-Merge-Block (SecLists-20k + bitquark Top-10k + n0kovo-small) → `/opt/wordlists/dns-merged-30k.txt`.
- MOD `scan-worker/scanner/phase0.py` — `GOBUSTER_DNS_WORDLIST_PATH`-Konstante. `--threads 30 --timeout 3s`.

**Erwartet:** Bessere Coverage moderner SaaS-/DevOps-Patterns. Phase-0b-Wordlist von ~5k auf 30k erweitert.

**Test:**
```bash
# Phase-0b-Discovery für eine größere Domain:
# - Vorher: amass timeoutet bei großen Domains (300s)
# - Nachher: gobuster-DNS findet mehr Subdomains via 30k-Wordlist, schneller insgesamt
```

---

## P4a — Phase-1/KI-Coverage

**Commit:** `pre-p4a-phase1-ki..edfb770` (Pipeline 2416 success).
**Zweck:** CMS-Detection-Coverage + KI-Schemas + Screenshot-Pipeline. Kein POLICY_VERSION-Bump.

### F-PH1-001 — CMS-Fingerprinter +10 CMS DACH/Hosted (Commit `b0a17f1`)

**Geändert:**
- MOD `scan-worker/scanner/cms_fingerprinter.py` — 10 neue CMS-Patterns: Pimcore, Sulu, Plone, SilverStripe, Statamic (DACH/Open-Source) + Webflow, Shopify, HubSpot, Wix, Squarespace (Hosted). Erweitert `PROBE_MATRIX`, `COOKIE_CMS_MAP`, `META_GENERATOR_PATTERNS`, `HEADER_CMS_PATTERNS`. Neue `BODY_REF_PATTERNS`-Tabelle für Hosted-CMS (Static-CDN-URLs, JS-Globals, data-Attribute). Hosted-CMS bekommen keine Active-Path-Probes (403/429-Risk). Probe-Cap 20 → 25.
- MOD `scan-worker/scanner/phase1.py` — `CMSFingerprinter(max_requests=25)`.
- NEU `scan-worker/tests/test_cms_fingerprinter.py` — 30 Tests.

**Erwartetes Verhalten:**
- DACH-Customer-Reports erkennen jetzt Pimcore/Sulu/Plone/SilverStripe/Statamic.
- Hosted-CMS (Webflow/Shopify/HubSpot/Wix/Squarespace) werden klassifiziert → KI #3 Rule-Engine kann sie als "skip_deep_scan" behandeln.

**Test:**
```bash
# Phase-1-Scan einer Pimcore- oder Sulu-Site:
# Erwartung: tech_profile.cms = "Pimcore" mit confidence ≥ 0.85
# Phase-1-Scan einer Webflow-Site:
# Erwartung: tech_profile.cms = "Webflow", keine Active-Path-Probes
```

---

### F-KI2-001 + F-KI3-002 — KI-Schema + Rule-Engine (Commit `182401f`)

**F-KI2-001 — KI #2 Schema DACH-CMS:**
- MOD `scan-worker/scanner/ai_strategy.py` — `TECH_ANALYSIS_SCHEMA`: `cms` als String (kein Enum, akzeptiert neue CMS-Strings). System-Prompt: "Phase-1-Detection mit Confidence ≥0.85 ist Wahrheit". DACH-Indikatoren im Prompt: Pimcore, Sulu, Plone, Craft, Statamic. Hosted-CMS-Hinweis: action=skip oder priority=99.

**F-KI3-002 — KI #3 Rule-Engine:**
- MOD `scan-worker/scanner/phase2_config_rules.py` — Generic-CMS-Set erweitert (Pimcore, Sulu, Plone, SilverStripe, Statamic, Drupal, Joomla, TYPO3, Craft, Ghost). Neuer **Hosted-CMS-Branch** (Webflow/Shopify/HubSpot/Wix/Squarespace → "skip_deep_scan, only_screenshots"). Neuer **Static-Hoster-Branch** (cloudflare/vercel/netlify/github-pages/s3 + open_ports == [80,443] → "minimal scan").
- MOD `scan-worker/tests/test_phase2_config_rules.py` — 7 neue Tests.
- NEU `scan-worker/tests/test_ai_strategy_tech_analysis.py` — 7 Tests.

**Erwartetes Verhalten:**
- Hosted-CMS-Hosts: kein Active-Phase-2-Scan mehr (KI-Cost-Reduktion + sinnvolle Behandlung — hosted Plattformen haben keine änderbare Server-Konfig).
- Static-Hoster (Vercel/Netlify/Cloudflare-Pages): nur Headers+TLS-Check.

**Test:**
```bash
# Scan einer Shopify-Site:
# Erwartung: KI #3 Rule-Engine matcht "skip_deep_scan, only_screenshots" → kein nuclei/ffuf-Run.
# Scan einer reinen Vercel-Site:
# Erwartung: minimal scan, no fuzzing.
```

---

### F-PH1-003 — Screenshot-Pipeline (Commit `be0ad38`)

**Geändert:**
- MOD `scan-worker/scanner/tools/redirect_probe.py` — `_take_screenshot` nutzt `full_page=True, animations="disabled"`. Neuer `_sanitize_vhost`-Helper. Neuer `_cap_screenshot_height` (Pillow-basierter 4096px-Cap, optional Dep, graceful fallback).
- MOD `scan-worker/scanner/upload.py` — MinIO-Key: `<order_id>/<ip>__<vhost>.png` — pro VHost eigener Screenshot, keine Kollision auf shared IPs.
- MOD `scan-worker/requirements.txt` — `Pillow>=11.0.0`.
- MOD `report-worker/reporter/parser.py` — `host_screenshots_per_vhost` Dict-Schema: `{ip: [{vhost, path}, ...]}`. Backwards-kompatibel zu Legacy-Schema. `find_gowitness_screenshots` → `find_playwright_screenshots` (Backwards-Compat-Alias).
- MOD `report-worker/reporter/report_mapper.py` — `_build_screenshot_data` produziert 1 PDF-Entry pro primary VHost mit Label `<fqdn> (Screenshot)`. Cap `_MAX_SCREENSHOTS_PER_HOST_IN_PDF=5`.
- MOD `report-worker/reporter/worker.py` — präferiert `host_screenshots_per_vhost` wenn vorhanden.
- MOD `frontend/src/lib/toolLabels.ts` — `playwright_screenshot` DE+EN, `gowitness` als Legacy-Alias.
- NEU `scan-worker/tests/test_redirect_probe_screenshot.py` (4 Tests) + `report-worker/tests/test_screenshot_data.py` (4 Tests).

**Erwartetes Verhalten:**
- PDF zeigt pro primary VHost einen full-page-Screenshot (vorher: nur 1 Viewport-Screenshot pro IP).
- Multi-VHost-Hosts (z.B. `example.com` + `mail.example.com` auf gleicher IP): beide mit eigenem Screenshot.
- Bei extrem langen Pages: Pillow-Cap auf 4096px Höhe (PDF-Layout bleibt intakt).

**Test:**
```bash
# Scan einer Domain mit mehreren VHosts auf gleicher IP.
# PDF prüfen: pro VHost ein Screenshot mit Label "<fqdn> (Screenshot)".
# Sehr lange Page (Single-Page-Apps): Screenshot sollte auf 4096px gekappt sein.
```

**Risiko:** PDF-Größe +3-5MB bei Multi-VHost-Hosts. Phase-1 +5-10s/Host.

---

## Übergreifende Prüfungen

### POLICY_VERSION-Effekte

POLICY_VERSION ist jetzt `2026-05-10.1`. Cache-Invalidierung erwartet:
- Erste Re-Scans nach Deployment: alle KI-Calls Cache-Miss (höhere Kosten ~$0.50-1/Scan einmalig).
- Determinismus-KPI (`subscription_posture.determinism_score`, Migration 024): erwartet 1-2 niedrige Werte direkt nach Bump, dann zurück auf hohem Niveau.

```sql
-- Determinismus-KPI prüfen
SELECT subscription_id, determinism_score, last_3_orders
FROM subscription_posture
ORDER BY updated_at DESC LIMIT 10;
```

### KI-Kosten-Erwartung

Nach Deployment + 1-2 Cache-Warmup-Cycles:
- KI #2 + KI #3 (Haiku): Cache-Hit-Quote bei Re-Scans steigt deutlich (F-XS-002).
- KI #4 (Sonnet): Cap 100→150 + KEV-Pre-Sort → bessere Reasoning-Qualität, gleiche Kosten.
- KI #5 (Sonnet/Opus): Truncation-Cap 150K → +25% Input-Tokens bei großen Scans (~$0.11/Report).

```sql
-- Kosten-Trend über die nächsten Scans
SELECT model, ki_step, AVG(cost_usd), COUNT(*)
FROM ai_call_costs
WHERE created_at > NOW() - INTERVAL '7 days'
GROUP BY model, ki_step
ORDER BY AVG(cost_usd) DESC;
```

### Cache-Wirksamkeit (F-XS-001 + F-XS-002)

```sql
-- Cache-Hit-Quote pro KI-Step
SELECT ki_step,
       SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END)::float / COUNT(*) AS hit_rate,
       COUNT(*) AS total_calls
FROM ai_call_costs
WHERE created_at > NOW() - INTERVAL '7 days'
GROUP BY ki_step;
```

Erwartete Hit-Rates nach 1 Woche Betrieb:
- `reporter_v1`: 60-80% (TLSCompliance höher dank F-XS-001)
- `ki1_host_strategy`: 50-70% (war schon vorher gut)
- `ki2_tech_analysis`: **NEU** ~40-60% (vorher 0% Order-übergreifend)
- `ki3_phase2_config`: **NEU** ~30-50% (vorher 0% Order-übergreifend)
- `ki4_phase3`: 30-50%
- `reporter_v1_finding_type_fallback`: 80%+ (TTL 30 Tage)

### Smoke-Tests pro Paket

**P0 Smoke:**
```bash
python scripts/sync-eol-data.py --dry-run                   # F-XS-003
python -m pytest scan-worker/tests/test_output_normalizer_fxs001.py -v   # F-XS-001
python -m pytest scan-worker/tests/test_ai_strategy_cache.py -v          # F-XS-002
python -m pytest report-worker/tests/test_selection.py -v -k "consolidate"   # F-RPT-002
```

**P1 Smoke:**
```bash
python -m pytest scan-worker/tests/test_dns_utils_parallel.py -v          # F-PRE-002
python -m pytest scan-worker/tests/test_nmap_utils_precheck.py -v         # F-PRE-005
python -m pytest scan-worker/tests/test_dkim_parallel.py -v               # F-P0B-001 (kommt aber aus P3)
```

**P2 Smoke:**
```bash
python scripts/sync-cloud-ranges.py --dry-run                # F-PRE-003
python scripts/sync-takeover-list.py --dry-run               # F-P0B-006
python scripts/sync-known-vuln-builds.py --dry-run           # F-RPT-001
```

**P3 Smoke:**
```bash
python -m pytest scan-worker/tests/test_mail_security_parsers.py -v       # F-P0A-002
python -m pytest scan-worker/tests/test_urlhaus_client.py scan-worker/tests/test_otx_client.py -v   # F-P0A-003
# Migration 026 verifizieren:
psql ... -c "\d orders" | grep pre_warm_requested
psql ... -c "\d subscriptions" | grep shodan_scan_request
```

**P4a Smoke:**
```bash
python -m pytest scan-worker/tests/test_cms_fingerprinter.py -v -k "pimcore or shopify or webflow"   # F-PH1-001
python -m pytest scan-worker/tests/test_phase2_config_rules.py -v -k "hosted or static"              # F-KI3-002
python -m pytest scan-worker/tests/test_redirect_probe_screenshot.py -v                              # F-PH1-003
```

### End-to-End-Validierung

Empfohlener Test-Ablauf nach Smoke-Tests:
1. **Test-Order anlegen** (z.B. `heuel.com` oder ähnliche Customer-Test-Domain) — Perimeter-Paket.
2. **Pre-Check beobachten:** Logs sollten 57-Port-nmap, parallele DNS, DACH-Parking-Erkennung zeigen.
3. **Phase 0a beobachten:** Logs sollten neue Clients (URLhaus/GreyNoise/OTX/VirusTotal) zeigen, Phase-0a-Gesamtzeit ~15s.
4. **Phase 0b beobachten:** kein amass mehr, batch-httpx, parallele CT-Discovery, paralleler DKIM-Probe.
5. **KI #1/2/3:** Cache-Hits beobachten (zweiter Re-Scan derselben Order).
6. **Phase 2/3:** ohne nuclei (P4b deferred), aber NVD parallel, KI #4 mit korrekter Severity-Reihenfolge.
7. **Reporter (KI #5):** kein Truncation bei <150K Input, alle KI-Narratives für alle Hosts.
8. **PDF-Report:** keine Doppel-EOL-Findings, korrekte Konsolidierung, Multi-VHost-Screenshots, neue SP-DNS-011..014 + SP-URLHAUS-001-Findings (falls zutreffend).

### Deferred / Bekannte Open-Items

1. **P4b: F-PH2-002** — nuclei + katana als Phase-2-Stage 3. ~3 Tage Aufwand. POLICY_VERSION-Bump erwartet wegen Severity-Flut. Nikto + dalfox bleiben in Anhang A des Audit-Docs deferred.

2. **F-P0A-006 Frontend-UI-Toggle** — Customer kann `pre_warm_shodan: true` aktuell nur via direktem API-Call setzen. Order-Form-Component (`frontend/src/app/scan/page.tsx`) braucht Checkbox + Customer-Hinweis (24-48h Wartezeit). Backend ist komplett bereit.

3. **F-PRE-003 Azure Cloud-Ranges** — übersprungen wegen rotierender SAS-Tokens. Kann manuell zu `_STATIC_RANGES` ergänzt werden.

4. **`docs/PIPELINE-AI-FLOW.md` + `docs/SCAN-PIPELINE-DETAIL.md`** — bestehende Doku reflektiert noch Pre-P0-State (5 Pakete statt 6, alte Phase-0a-Tools-Liste etc.). Aktualisierung als Folge-PR sinnvoll.

5. **CLAUDE.md** — die Memory-/Konventionen-Datei sollte auf neue POLICY_VERSION + neue Phase-0a-Tools (URLhaus/GreyNoise/OTX/VirusTotal) + neue Sync-Pipelines + neue SP-Regeln aktualisiert werden.

---

## Rollback-Anweisungen

Falls ein Paket Probleme zeigt, hier die Rollback-Pfade:

### Komplettes Rollback auf Pre-Audit-Stand:
```bash
git reset --hard pre-p0-foundation
git push gitlab feat/p0-foundation:main --force-with-lease   # gefährlich: bestätigt mit User!
```

### Einzelnes Paket rollbacken:
```bash
# Beispiel: P3 zurücknehmen (POLICY_VERSION + Migration 026 betroffen!)
git reset --hard pre-p3-mail-discovery
# Migration 026 muss manuell zurückgerollt werden (Spalten droppen)
psql -c "ALTER TABLE orders DROP COLUMN pre_warm_requested;"
psql -c "ALTER TABLE subscriptions DROP COLUMN shodan_scan_request;"
git push gitlab HEAD:main --force-with-lease
```

### Einzelnen Commit rückgängig machen:
```bash
git revert <commit-hash>
git push gitlab HEAD:main
```

---

**Ende des Changelogs.** Generiert 2026-05-08, Stand nach P4a-Deployment (Pipeline 2416).
