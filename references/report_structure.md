# Pentest Report Structure Reference

> **Stand 2026-05-13**: Dieses Dokument beschreibt den **Legacy-v1-Renderer**.
> Der neue v2-Renderer (3-Schichten-Architektur, Hygiene-Skala neben CVSS,
> Threat-Intel + Verifikations-Schritte pro Befund, 6 Anhaenge A-F) ist seit
> M5+M6.1 (2026-05-13) implementiert und per ENV-Flag
> `VECTISCAN_REPORT_LAYOUT=v2` aktivierbar (Big-Bang-Default-Flip steht
> nach Pilot-Phase aus). Spec fuer v2: `docs/report-erstellung/02_Report_Aufbau_Neudesign.md`.
> Code-Tree: `report-worker/reporter/pdf/v2/`.

## Table of Contents
1. [PDF Layout Specifications](#pdf-layout)
2. [Color Scheme](#colors)
3. [Page Templates](#page-templates)
4. [Content Section Details](#content-sections)
5. [Finding Template](#finding-template)
6. [CVSS Scoring Guide](#cvss-guide)
7. [Common Findings Library](#common-findings)
8. [Localization](#localization)
9. [v2-Renderer (M1-M6 Redesign) — Kurzueberblick](#v2-renderer)

---

## PDF Layout Specifications <a name="pdf-layout"></a>

- **Page size**: A4 (210 × 297 mm)
- **Margins**: 20mm left/right, 22mm top, 20mm bottom
- **Body font**: Helvetica 9.5pt, leading 14pt
- **Heading font**: Helvetica-Bold 18pt (section), 13pt (subsection)
- **Evidence font**: Courier 7.5pt on light gray background (#edf2f7)
- **Table header font**: Helvetica-Bold 8pt, white on dark navy
- **Finding header**: 18mm tall colored bar with white text, CVSS badge on right

## Color Scheme <a name="colors"></a>

```python
PRIMARY       = "#1a1a2e"   # Deep navy — headers, table headers, page bars
SECONDARY     = "#16213e"   # Dark blue — secondary backgrounds
ACCENT        = "#0f3460"   # Medium blue — subsection titles, links
LIGHT_ACCENT  = "#e2e8f0"   # Light gray-blue — table borders, dividers
TEXT_COLOR     = "#2d3748"   # Dark gray — body text
MUTED         = "#718096"   # Muted gray — footer text, labels
BG_LIGHT      = "#f7fafc"   # Near-white — alternating table rows

# Severity colors
CRITICAL = "#c53030"   # Red
HIGH     = "#dd6b20"   # Orange
MEDIUM   = "#d69e2e"   # Gold/yellow
LOW      = "#38a169"   # Green
INFO     = "#3182ce"   # Blue
```

## Page Templates <a name="page-templates"></a>

### Cover Page
- Full dark navy (#1a1a2e) background
- 8mm accent stripe on left edge (#0f3460)
- Decorative geometric overlay on right third
- Content positioned at ~50mm from top: subtitle, title, horizontal rule, metadata table
- Red classification bar at bottom (12mm): "KLASSIFIZIERUNG: VERTRAULICH" or "CLASSIFICATION: CONFIDENTIAL"

### Normal Pages
- Dark navy header bar (14mm) with report title left and target right
- Thin accent line below header
- Footer: classification + date left, page number right
- Light divider line above footer

## Content Section Details <a name="content-sections"></a>

### 1. Cover Page
Required metadata fields:
- Target (domain + IP)
- Report date
- Methodology (PTES / OWASP / custom)
- Scoring system (CVSS v3.1)
- Classification level
- Finding count summary

### 2. Table of Contents
- Two levels: sections (bold, 10pt) and subsections (muted, 9pt, indented 10mm)
- List all findings by ID and short title under section 3

### 3. Executive Summary

**3.1 Overall Assessment**
- 2-3 paragraphs max
- What was tested, what was found (high level), what's the overall posture
- Mention both negative and positive findings

**3.2 Risk Distribution**
Table with columns: Severity | Count | Finding IDs
One row per severity level (Critical through Informational)

**3.3 Key Recommendations**
Table with columns: Priority | Measure | Timeframe
Top 5-6 actions ranked by severity

**Overall Risk Box**
- Colored box showing overall risk level (Critical/High/Medium/Low)
- 1-2 sentence summary below it

### 4. Scope & Methodology

**4.1 Scope**
Table format with rows: Test period, Method, Target IP, Reverse DNS, Platform, Exclusions

**4.2 Methodology**
- Reference the standard used (PTES, OWASP, etc.)
- List phases performed and not performed
- Mention scoring system

**4.3 Limitations**
- External only / no internal access
- Point-in-time assessment
- No active exploitation (if applicable)
- Recommendation for regular retesting

**PCI-DSS/GDPR Note** (if applicable)
- Blue info box if the target processes payments or personal data

### 5. Findings
See Finding Template below

### 6. Recommendations
Consolidated remediation roadmap table:
- Columns: Timeframe | Measure | Finding Reference | Effort
- Ordered by priority (most urgent first)
- Include concrete effort estimates

### 7. Appendix A — CVSS Vector Table
Table: ID | Finding | Score | Severity | Vector String

### 8. Appendix B — Raw Tool Output
- Include relevant excerpts from scan tools
- Use monospace/evidence formatting
- Don't dump entire outputs — curate the relevant parts

### 9. Appendix C — Tools
Table: Tool | Version | Purpose

### Final Element: Disclaimer
Gray info box at the end: point-in-time assessment, no guarantee, recommend regular testing

## Finding Template <a name="finding-template"></a>

Each finding consists of these visual elements in order:

```
┌─────────────────────────────────────────────────────────┐
│ [COLOR BAR - 18mm tall, severity-colored]               │
│  FST-YYYY-NNN                            ┌──────────┐  │
│  Finding Title                           │ CVSS v3.1│  │
│                                          │   8.6    │  │
│                                          └──────────┘  │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│ CVSS-Vector: ...    │ CWE: CWE-XXX │ Affected: ...     │
└─────────────────────────────────────────────────────────┘

**Beschreibung / Description**
Factual description of what was found. No opinions, no alarmism.

**Nachweis / Evidence**
┌─ monospace on gray background ──────────────────────────┐
│ $ tool-command                                          │
│ actual output from the tool                             │
└─────────────────────────────────────────────────────────┘

**Geschäftsauswirkung / Business Impact**
What could happen. Tied to business context (data loss, compliance, etc.)

**Empfehlung / Recommendation**
**Short-term (X days):** Specific steps.
**Medium-term:** Strategic improvements.
```

### Finding ID Convention
- Format: `{CLIENT_PREFIX}-{YEAR}-{SEQUENTIAL_NUMBER}`
- Example: FST-2026-001, ACME-2026-001
- Derive prefix from client name (3-4 chars)

### CWE Mapping for Common Findings
| Finding Type | CWE |
|---|---|
| Missing access control | CWE-284 |
| Insufficient credential protection | CWE-522 |
| Cleartext transmission | CWE-319 |
| Improper restriction of brute force | CWE-307 |
| Information exposure | CWE-200 |
| Missing encryption | CWE-311 |
| Use of default credentials | CWE-798 |
| Unrestricted upload | CWE-434 |
| Missing authentication | CWE-306 |

## CVSS v3.1 Scoring Guide <a name="cvss-guide"></a>

### Scoring Principles

1. **Score what you proved, not what you imagine**
   - If you proved the port is open but auth works → score the exposure, not the theoretical breach
   - If you proved default credentials work → score full compromise

2. **Scope Change (S:C) requires evidence**
   - S:C means the vulnerable component impacts OTHER components (different authorization scope)
   - Example: XSS in a subdomain that can steal cookies for the main domain = S:C
   - Example: Exposed DB on same server as web app = S:U (same authorization scope)

3. **Attack Complexity (AC)**
   - AC:L = attacker can repeat the attack at will with no special conditions
   - AC:H = requires specific conditions (race conditions, MITM position, non-default config)

4. **Common CVSS Vectors**

| Scenario | Vector | Score |
|---|---|---|
| Unauthenticated remote code execution | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | 10.0 |
| Remote DB access, no auth | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |
| Remote DB access, auth required | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L | 8.6 |
| Exposed service, brute-forceable | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N | 6.5 |
| Service without rate limiting | AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N | 3.7 |
| Information disclosure (passive) | AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N | 3.1 |

## Common Findings Library <a name="common-findings"></a>

These are frequently encountered findings with pre-validated descriptions. Adapt as needed.

### Exposed Database Port
- Typical services: MySQL/MariaDB (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379)
- Key question: Does the service require authentication? Check nmap output for "unauthorized" vs "allowed"
- If auth works: HIGH (7.0-8.6)
- If no auth or default creds: CRITICAL (9.0-10.0)

### Exposed Mail Services on Production Server
- Services: SMTP (25/465/587), IMAP (143/993), POP3 (110/995)
- Issue: Service isolation violation, increased attack surface
- Typical score: MEDIUM (5.0-6.5)
- Recommendation: Migrate to dedicated mail server or managed service

### Legacy/Unnecessary Services
- Services: FTP (21), Telnet (23), rsh/rlogin, NFS
- Key question: Is the service actually needed?
- FTP with SSL: MEDIUM (4.0-5.5)
- FTP without SSL: HIGH (7.0-7.5)
- Telnet: HIGH (7.5-8.0)

### SSH Configuration Issues
- Missing brute-force protection: LOW (3.0-4.0)
- Password auth enabled (no key-only): LOW-MEDIUM (3.5-5.0)
- Outdated SSH version with known CVEs: Score based on specific CVE

### Information Disclosure
- robots.txt revealing admin paths: LOW (2.0-3.5)
- Server version banners: LOW (2.0-3.0)
- SSL certificate SANs revealing domains: LOW (2.0-3.0)
- Directory listing enabled: MEDIUM (4.0-5.0)
- Stack traces in error pages: MEDIUM (4.0-5.5)

### Missing Security Headers
- No HSTS: LOW (3.0-3.5)
- No X-Frame-Options: LOW (2.5-3.5)
- No CSP: LOW-MEDIUM (3.0-4.5)
- No X-Content-Type-Options: LOW (2.0-3.0)

### Positive Findings (always include!)
- HSTS with includeSubDomains and long max-age
- X-Frame-Options: deny
- Strong CSP
- TLS 1.2+ only
- Certificate transparency
- Proper CORS configuration

## Localization <a name="localization"></a>

### German Labels
| English | German |
|---|---|
| Executive Summary | Managementzusammenfassung |
| Scope & Methodology | Umfang und Methodik |
| Findings | Befunde |
| Recommendations | Empfehlungen |
| Description | Beschreibung |
| Evidence | Nachweis |
| Business Impact | Geschäftsauswirkung |
| Recommendation | Empfehlung |
| Affected Systems | Betroffene Systeme |
| Overall Risk Assessment | Gesamtrisikobewertung |
| Severity | Schweregrad |
| Appendix | Anhang |
| Tools Used | Eingesetzte Werkzeuge |
| Confidential | Vertraulich |
| Disclaimer | Haftungsausschluss |
| Cover classification | KLASSIFIZIERUNG: VERTRAULICH — NUR FÜR AUTORISIERTE EMPFÄNGER |

### English Labels
| Label | Text |
|---|---|
| Cover classification | CLASSIFICATION: CONFIDENTIAL — AUTHORIZED RECIPIENTS ONLY |
| Overall Risk Assessment | Overall Risk Assessment |
| Disclaimer | This report represents the security posture at the time of testing... |

---

## v2-Renderer (M1-M6 Redesign) <a name="v2-renderer"></a>

> Kompletter Master-Plan: `~/.claude/plans/ich-m-chte-gerne-das-iterative-nova.md`
> Design-Spec: `docs/report-erstellung/02_Report_Aufbau_Neudesign.md`
> Fehleranalyse: `docs/report-erstellung/01_Fehleranalyse_und_Korrekturplan.md`

### Aktivierung
ENV-Variable im `report-worker`-Container:
```yaml
VECTISCAN_REPORT_LAYOUT: v2   # Default bleibt v1 bis Big-Bang-Cutover
```
Code-Pfad: `report-worker/reporter/worker.py:667-682`.

### 3-Schichten-Architektur

| Schicht | Zielgruppe | Code-Pfad | Inhalt |
|---|---|---|---|
| **1 Frontpage** (S. 2) | Geschaeftsfuehrer | `pdf/v2/layers/frontpage.py` | Risiko-Ampel (5 Buckets) + Top-3-Hebel (kombinierte Massnahmen) + Compliance-Indikatoren |
| **2 Strategie** (S. 3-9) | IT-Verantwortlicher | `pdf/v2/layers/strategy.py` | Geschaeftskontext, Methodik mit konkreten KI-Modellen, Tech-Tabelle v2 mit Patch-Status + Top-CVE, Service-Karte, Posture-Indikatoren, Befund-Landschaft, Screenshots (dedupliziert) |
| **3 Befund-Details** (S. 11+) | Administrator/Dienstleister | `pdf/v2/layers/findings.py` | 7-Sektionen-Body pro Befund: WAS / NACHWEIS / THREAT INTEL (CVE+EPSS+KEV) / GESCHAEFTSAUSWIRKUNG / EMPFEHLUNG / VERIFIKATION / INTERNE REFERENZ |
| **Anhang A-F** | Audit / Versicherung | `pdf/v2/layers/appendix.py` | A.1 CVSS · A.2 Hygiene-Skala · B Service-Inventar · C Tools mit Konfidenz · D Compliance-Mapping NIS2/BSI/ISO/DSGVO · E methodische Filterungen · F Wiederholungs-Trigger + Haftungsausschluss |

### Daten-Aggregatoren (Single-Source-of-Truth pro Schicht)

| Modul | Liefert |
|---|---|
| `reporter/layer1_aggregator.py` | `risk_ampel`, `top_hebel`, `overall_level`, `hygiene_split` |
| `reporter/business_context.py` | Branchencluster + Datenarten-Annahme |
| `reporter/v2_data.py` | `scope_meta`, `methodology_stats`, `compliance_indicators`, `tech_table_v2` |
| `reporter/befund_landschaft.py` | Kategorisierung + Service-Cards |
| `reporter/posture_v2.py` | 4 Posture-Indikatoren (Mail/Web/DNS/TLS) |
| `reporter/verification_templates.py` | Pro policy_id Verifikations-Befehl (Top-15 gepflegt) |
| `reporter/compliance_mappings.py` | NIS2/BSI/ISO/DSGVO pro Befund |
| `reporter/screenshot_pipeline.py` | Body-Hash-Dedup + Cap max. 2 |

### Hygiene-Skala vs CVSS

Befunde tragen ein neues Feld `scale`:
- `scale: "cvss"` (Default): ausnutzbare Schwachstelle mit CVSS v3.1-Vektor, Anhang A.1.
- `scale: "hygiene"`: Best-Practice-Abweichung ohne ausnutzbaren Vektor (HSTS fehlt, Cookie-Flags, CSP). Anhang A.2 mit `hygiene_level: "low|medium|high"`. **Kein** CVSS-Score.

### Severity-zu-Prioritaet-Mapping

| Severity | Prioritaet |
|---|---|
| CRITICAL / HIGH | Unverzueglich (24-72h) |
| MEDIUM | In Kuerze (1-2 Wochen) |
| LOW | Mittelfristig (naechster Patch-/Release-Zyklus) |
| INFO | Strategisch (laufendes Quartal) |

### Threat-Intel-Sichtbarkeit

Quellen pro Befund (Reihenfolge mit Fallback):
1. `finding["cves"]` — `list[str]` oder `list[{cve_id, epss_score, kev}]`
2. `finding["cve_id"]` + `finding["threat_intel"]` mit `epss_score` / `in_kev`
3. `finding["enrichment"]` mit `cisa_kev` (struct) / `epss.epss` (struct)
4. `finding["correlation_data"]` (merge)

Sortierung: KEV-Eintraege zuerst, dann EPSS DESC, Top-3 angezeigt.

### POLICY_VERSION

Default: `2026-06-01.1` (`reporter/severity_policy.py:30`).
Override via ENV: `VECTISCAN_POLICY_VERSION`. Audit-Trail-Feld in `reports.policy_version`.