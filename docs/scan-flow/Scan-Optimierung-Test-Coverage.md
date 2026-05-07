# Scan-Optimierung — Test-Coverage-Matrix

**Zweck:** Welche Scan-Konfigurationen decken welche Findings ab. Empfehlung für Test-Session nach P0-P4a-Deployment.

**Stand:** 2026-05-08 (alle 41 Findings deployed bis P4a, F-PH2-002 als P4b deferred).

---

## Matrix: Scan-Typ → Findings

### Scan 1 — TLSCompliance auf TLS-fähiger Domain
**Target-Vorschlag:** beliebige Customer-Domain mit HTTPS, `package=tlscompliance`.
**Laufzeit:** ~5-10 min.
**Hits:**
- F-XS-001 — testssl-Normalizer (Cache-Stabilität)
- F-XS-002 — KI #1 + KI #2 + KI #3 sind ja `skip_ai_decisions=True` für TLSCompliance, daher kein Hit hier — aber Reporter content_hash wird stabil
- POLICY_VERSION-Bump-Cache-Invalidation (alle SP-TLS-*-Findings)

**Was prüfen:**
- `ai_call_costs.cache_hit` für Reporter (zweiter Run derselben Order = Cache-Hit erwartet)
- TR-03116-Findings-Anzahl unverändert vs Vor-Deployment

---

### Scan 2 — Perimeter auf FQDN-Domain (DACH)
**Target-Vorschlag:** Customer-Test-Domain mit ~3-10 Subdomains, deutschem CMS-Setup, IONOS/STRATO/Hetzner-Hosting.
**Laufzeit:** ~60-90 min.
**Hits (große Hit-Rate):**
- F-PRE-001 — Parking-Pattern-Detection (falls eine Subdomain geparkt ist)
- F-PRE-002 — DNS-Resolution parallel (Pre-Check)
- F-PRE-003 — Cloud-Provider-Detection (IONOS/STRATO/Hetzner sollten erkannt werden — sofern `cloud-ranges-sync`-Job vorher manuell getriggert wurde)
- F-PRE-004 — nmap-Light-Flags
- F-PRE-005 — 57-Port-Liste (mehr `is_live=true`-Hosts)
- F-P0A-001 — Phase-0a parallel (Logs: Gesamtzeit ~15s statt ~75s)
- F-P0A-002 — Mail-Security-Parser (TLS-RPT/BIMI/DMARC-Detail/NSEC3)
- F-P0A-003 — URLhaus/GreyNoise/OTX (Free-Tier ohne Keys reicht)
- F-P0A-004 — Phase-0a-Subdomain-Reuse in Phase 0b
- F-P0A-005 — phase0a_ip_cap=25 für perimeter
- F-P0B-001 — DKIM-Selektoren parallel + DACH-Provider erkannt
- F-P0B-002 — subfinder explizite Sources
- F-P0B-003 — kein amass mehr (Logs: "amass" sollte nicht auftauchen)
- F-P0B-004 — gobuster_dns 30k-Wordlist (mehr Subdomains)
- F-P0B-005 — CDN-Edge-Dedup (falls Cloudflare/Fastly im Spiel)
- F-P0B-006 — Subdomain-Takeover-Liste (35+ Services aus EdOverflow)
- F-P0B-007 — batch httpx (Logs: Multi-VHost-Probe ~5-10s statt 50s)
- F-P0B-008 — CT-Discovery parallel
- F-KI1-001 — `scan_hints` weg
- F-KI1-002 — Mailserver-Hard-Override (falls KI Mail-Hosts skippen will)
- F-KI3-001 — KI #3 ThreadPool
- F-PH1-001 — CMS-Fingerprinter (falls Pimcore/Sulu/Plone im Spiel)
- F-PH1-002 — wafw00f parallel
- F-PH1-003 — Screenshot-Pipeline (full_page + per VHost)
- F-PH2-001 — ffuf raft-small (kein Hard-Cap-Hit)
- F-PH3-001 — NVD-Lookup parallel
- F-KI4-001 — KI #4 Pre-Sort (Logs: stop_reason != max_tokens)
- F-RPT-001 — KNOWN_VULN_BUILDS (falls EOL-Banner-Match)
- F-RPT-002 — Konsolidierungs-Hash (keine falschen Tech/Plugin-Merges)
- F-RPT-003 — Business-Impact (deutsche Narratives bekommen Boost)
- F-RPT-004 — AI-Fallback parallel
- F-RPT-005 — QA-Cap nach severity_policy
- F-RPT-006 — Truncation Cap 150K
- F-RPT-007 — EOL-Merge-Dedup
- F-PH9-001 — Upload parallel
- F-XS-001/002/003 — alle Foundation-Effekte greifen

**Was prüfen:**
- PDF-Output: alle erwarteten Sektionen, keine Doppel-EOL-Findings, korrekte Konsolidierung mit Multi-Host-Annotation, Per-VHost-Screenshots
- Logs: keine `consolidated_findings_truncated`-Warnung bei <150K Input
- DB: `severity_provenance.tool_severities` zeigt KI-Original (nicht QA-modifiziert)
- Determinismus-Score (`subscription_posture.determinism_score`) niedrig direkt nach POLICY_VERSION-Bump, dann hoch

---

### Scan 3 — Perimeter Re-Scan derselben Order
**Target-Vorschlag:** Scan 2 nochmal triggern (regenerate-report) ODER neue Order auf demselben Target.
**Laufzeit:** ~30-50 min (sollte schneller sein als Scan 2 dank Cache).
**Hits (Cache-Wirksamkeit):**
- F-XS-001 — Output-Normalizer → Reporter content_hash stabil
- F-XS-002 — KI #2 + KI #3 Cache-Hits Order-übergreifend (wenn andere Order auf gleichem Tech)

**Was prüfen:**
- `ai_call_costs.cache_hit=true` für reporter_v1, ki1_host_strategy, ki2_tech_analysis, ki3_phase2_config
- Gesamt-Reporter-Kosten ~10-30% von Scan 2

---

### Scan 4 — Insurance-Paket auf Domain mit EOL-Software
**Target-Vorschlag:** Domain mit absichtlich veralteter Software (PHP 7.x, Apache 2.2, OpenSSL 1.0) ODER Customer mit echter EOL-Tech.
**Laufzeit:** ~60-90 min.
**Hits:**
- F-RPT-001 — KNOWN_VULN_BUILDS Mega-Schwachstellen-Match (CVE-Listing direkt im Finding)
- F-RPT-003 — Insurance-Multipliers für EOL/Database/Default-Login → höhere business_impact_scores
- F-PH3-001 — NVD-Lookup für CVE-Mapping
- F-P0A-006 — wenn Subscription: Shodan Pre-Warm (falls Subscription-Order)

**Was prüfen:**
- PDF: SP-EOL-001..004 mit korrekten Templates, CRITICAL bei KNOWN_VULN_BUILDS-Match
- Top-N-Reihenfolge bei Insurance: EOL/DB/Default-Login zuerst
- Migration 026: `subscriptions.shodan_scan_request` befüllt nach Re-Scan

---

### Scan 5 — Multi-VHost-Host (shared IP)
**Target-Vorschlag:** Domain mit mehreren VHosts auf gleicher IP (z.B. example.com + mail.example.com + shop.example.com auf 1.2.3.4).
**Laufzeit:** Perimeter ~60 min.
**Hits:**
- F-RPT-002 — Konsolidierung mit `STABLE_TITLE_VARS` (verschiedene Tech pro VHost bleiben getrennt)
- F-RPT-007 — Merge-Dedup mit Host-Resolution (KI-Findings ohne host_ip + EOL-Detector-Findings → 1 Finding pro Tech/Version)
- F-PH1-003 — Screenshot pro primary VHost (≥2 Screenshots pro IP im PDF)

**Was prüfen:**
- PDF: pro VHost separater Screenshot mit Label `<fqdn> (Screenshot)`
- Konsolidierung: bei Multi-Tech (verschiedene EOL-Versions) → mehrere Findings mit korrekten title_vars statt 1 falsch gemergt
- consolidated_findings.vhost-Spalte korrekt befüllt

---

### Scan 6 — Hosted-CMS-Domain
**Target-Vorschlag:** Webflow / Shopify / HubSpot / Wix / Squarespace-gehostete Site (öffentliche Demo-Site reicht).
**Laufzeit:** Perimeter ~30 min (sollte deutlich kürzer sein dank Hosted-Branch-Skip).
**Hits:**
- F-PH1-001 — CMS-Fingerprinter erkennt Hosted-CMS (kein Active-Path-Probe)
- F-KI3-002 — Rule-Engine Hosted-CMS-Branch (skip_deep_scan, only_screenshots)
- F-KI2-001 — KI #2 Hinweis "kein Server-Side-Scan-Wert"

**Was prüfen:**
- Logs: `phase2_config_rule_based reason="hosted-cms-skip"` (oder ähnlich)
- Phase 2 läuft NICHT (kein nuclei/ffuf/feroxbuster auf Webflow)
- PDF: minimaler Findings-Set, nur Screenshot + Headers

---

### Scan 7 — Compliance/Compliance auf Multi-IP-Target (>10 Hosts)
**Target-Vorschlag:** /28 oder /29 CIDR mit echten Hosts (Customer-Test-Setup oder Lab).
**Laufzeit:** Compliance ~90 min.
**Hits:**
- F-RPT-006 — Truncation Cap 150K + per_host_cap (ALLE Hosts haben KI-Narrative im PDF)
- F-PH3-001 — NVD-Lookup parallel (Cap 100 statt 50)
- F-KI4-001 — KI #4 Pre-Sort (alle CRITICAL erreichen Sonnet)
- F-XS-001 — Output-Normalizer auf 4 Tools (testssl-Cache stabil bei Re-Scans)

**Was prüfen:**
- PDF: pro Host (auch der letzte alphabetisch) hat `description`, `recommendation`, `impact` befüllt (KI-Narrative vorhanden)
- Logs: `consolidated_findings_truncated` nur falls echt >150K bytes
- KI #4: severity-priorisierte Reihenfolge im Prompt

---

## Empfohlene Reihenfolge

**Wenn du nur 1-2 Scans laufen lässt:**
1. **Scan 2 (Perimeter FQDN-DACH)** — größte Hit-Rate, deckt 70% der Findings.
2. **Scan 5 (Multi-VHost)** — deckt die fragilsten Konsolidierungs-Pfade ab.

**Wenn du Zeit hast:**
- Scan 2 + Re-Scan (Scan 3) — Cache-Wirksamkeit ist der Determinismus-Hauptbeleg
- Plus Scan 4 (Insurance + EOL) für Severity-Verifikation
- Plus Scan 6 (Hosted-CMS) für Rule-Engine-Branch

**Optional aber wertvoll:**
- Scan 1 (TLSCompliance) — 5-10 min, separater Pfad
- Scan 7 (Compliance >10 Hosts) — Truncation-Test

---

## Vorbereitung pro Scan

**Vor jedem Scan-Set:**
1. Sync-Jobs einmal manuell triggern (P2 Sync-Pipelines), damit `cloud_ranges_generated.py`, `takeover_data_generated.py`, `known_vuln_builds_generated.py` befüllt sind:
   - GitLab-UI → web-Pipeline triggern → `cloud-ranges-sync`/`takeover-list-sync`/`known-vuln-builds-sync`-Jobs manuell startten
   - ODER lokal: `python scripts/sync-cloud-ranges.py` etc.
2. Optional ENV-Variablen setzen (für volle Test-Coverage):
   - `GREYNOISE_API_KEY` — Premium-Tier (sonst Free-Tier)
   - `VIRUSTOTAL_API_KEY` — sonst graceful skip
   - `URLHAUS_API_KEY` — optional
3. Baseline-Snapshot ziehen (siehe `scripts/ops-baseline-snapshot.py` + GitLab-Job `ops-baseline-snapshot`).

**Nach jedem Scan:**
1. PDF-Report runterladen + visuell checken
2. DB-Queries laufen lassen (siehe Smoke-Tests in Changelog)
3. `ai_call_costs.cache_hit` für den Order prüfen
4. Wenn auffällig: relevantes Finding in Audit-Doc nachschlagen

---

## Stop-Bedingungen

**Was ist ein "echtes Problem":**
- Pipeline-Builds rot
- Reporter wirft Exception
- Severity-Drift bei einem Finding-Typ wo wir keinen Bump erwarten (außer F-RPT-003 Top-N-Reihenfolge — das ist gewünscht)
- Cache-Hit-Quote sinkt nach Re-Scan auf 0% (sollte steigen)

**Was ist normal:**
- Erste Re-Scans nach POLICY_VERSION-Bump = Cache-Miss (höhere Kosten einmalig)
- Determinismus-Score 1-2 niedrige Werte direkt nach Bump
- Top-N-Reihenfolge ändert sich (F-RPT-003 + F-RPT-002 wirken)
- KI-Narrative-Texte nicht byte-identisch zu Vor-Deployment (KI ist nicht-deterministisch trotz temperature=0.0)

**Was ist Edge-Case-Tuning (kein Blocker):**
- Einzelner Finding mit unerwartetem Title-Template-`?` → F-PH1-001 + F-PH1-002 Smart-Var-Fallback Edge-Case
- Hosted-CMS wurde nicht erkannt → BODY_REF_PATTERNS evtl. zu eng
- DKIM-Selektor fehlt → einfach in F-P0B-001-Liste ergänzen

---

## Output-Sammlung

Für die spätere Test-Session bereitstellen:
- 1× PDF-Report pro Scan-Set
- DB-Snapshot (Baseline vorher + Stand nachher)
- Reporter-Worker-Logs des Scans
- `ai_call_costs`-Auszug für die Order
- Falls Bug: Order-ID + Logs + relevanter PDF-Abschnitt
