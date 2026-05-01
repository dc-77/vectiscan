# VectiScan Q2/2026 Determinismus — Bewertung & Vergleich

**Stand:** 2026-05-01
**Datenbasis:** Live-Pull von `scan-api.vectigal.tech` (Test-Account
`daniel.czischke@vectigal.gmbh`, Admin-Rolle). Externe Baseline:
[`202604 - Securess Report Summary.pdf`](./202604%20-%20Securess%20Report%20Summary.pdf)
(Rapid7 InsightAppSec Output für `securess.de`, 39h Crawl + 645k Attacks,
1 URL).

---

## 1. Was ist „Q2/2026 Determinismus"?

Drei zusammengehörige Änderungen sind seit Ende April 2026 in Prod (Tags
`a19acb4` → `eb65d0b`):

1. **Severity-Policy** (`report-worker/reporter/severity_policy.py`) mit
   ~45 kalibrierten Regeln. Jede Severity hat eine `policy_id`
   (z.B. `SP-DNS-008` für „kein DKIM"), `cvss_vector`, `rationale` und
   `references` (CWE/OWASP/BSI).
2. **AI-Cache + temperature=0** in allen 5 KI-Calls (3× Haiku, 1× Sonnet
   Phase 3, 1× Sonnet Reporter). Reproduzierbarkeit, Kostenreduktion auf
   Re-Scans.
3. **Top-N Selection** pro Paket (WebCheck 8 / Perimeter 15 / Compliance 20)
   mit Stable-Sort + Konsolidierung über Hosts.

Plus zwei Bug-Fixes nach erstem Live-Test:

- **Migration 018** — Trigger las falschen JSONB-Pfad
  (`findings_data` statt `findings_data->'findings'`) → `severity_counts`
  war überall null. Backfill via `UPDATE reports SET findings_data = findings_data`.
- **finding_type_mapper deutsch-Patterns** — Mapper traf die deutschen
  Claude-Title-Strings nur in 1/14 Fällen, jetzt 14/14. Zusätzlich
  5 neue Regeln (SP-DNS-010 dmarc_p_quarantine, SP-WP-001/002 Plugin-Vulns,
  SP-ENUM-001 User-Enumeration, SP-SSH-001 Brute-Force-Hardening).

---

## 2. Wirkungsmessung — vorher/nachher

### SP-FALLBACK-Rate (Quote der Findings ohne echte Policy-Regel)

| Zeitpunkt | Reports | SP-FALLBACK | Echte Policy-Hits | Bemerkung |
|---|---:|---:|---:|---|
| **2026-04-30 11:43** (alte Reports, vor Mapper-Fix) | 6 | **100%** | ~2-3 pro Report | Audit-Job 10285 |
| **2026-05-01** (heuel.com perimeter, nach Mapper-Fix) | 1 | **45%** (5/11) | **6/11** | Order `1de5b28f` |

**Interpretation:** Ein einziger Push (Commit `eb65d0b`) hat die Mapper-
Trefferquote auf einem repräsentativen Real-Scan **mehr als verdoppelt**.
SP-FALLBACK-Reduzierung ist nicht 0%, weil der Reporter (Claude) Findings
extrahiert, die nicht in unseren ~45 Policy-Regeln vertreten sind
(z.B. „Cross-Domain-Fehlkonfiguration", „Verwundbare JavaScript-Bibliothek",
„Private IP-Adressen in öffentlichen Antworten"). Diese 5 Pattern lassen
sich jederzeit nachziehen.

### Severity-Verteilung — heuel.com (Perimeter, 13 Hosts, 11 Findings)

| Severity | Count | Anteil |
|---|---:|---:|
| Critical | 0 | 0% |
| High | 0 | 0% |
| Medium | 3 | 27% |
| Low | 4 | 36% |
| Info | 4 | 36% |

**Severity-Policy-Coverage:** 6 distinct policies aktiv —
`SP-CSP-001`, `SP-CSRF-001`, `SP-DNS-005`, `SP-DNS-008`,
**`SP-DNS-010`** (neue Regel, dmarc_p_quarantine), `SP-FALLBACK`.

**Determinismus-Werte messbar:**
- `policy_version: 2026-04-30.1` ist gesetzt
- `audit_severity_counts` aus DB-Trigger (Migration 018) matcht den
  vom Reporter geschriebenen Wert exakt
- `policy_id_distinct` als sortiertes Array verfügbar

---

## 3. VectiScan vs. Securess Rapid7-Report — Detail-Vergleich

### Quantitativ

| | Rapid7 (extern) | VectiScan POST-Q2 |
|---|---|---|
| **Total Findings** | 335 (alle unkuratiert) | 11 (heuel) / 12 (dortmund-beach perimeter) — kuratiert |
| **Critical** | 0 | 0 |
| **High** | 0 | 0–2 |
| **Medium** | **0** | 3–3 |
| **Low** | 46 (14%) | 4–6 |
| **Info** | 289 (86% Noise) | 4–1 |
| **Crawl-Dauer** | 39 h | ~22 min (heuel mit 13 Hosts) |
| **Attacks** | 645.000 | ~3.000 |
| **Hosts gescannt** | 1 (`www.securess.de`) | 13 (heuel) bzw. 1–12 |
| **DNS/Mail-Security** | 0 Checks | DKIM/SPF/DMARC/dnssec/MTA-STS |

### Was Rapid7 findet, was VectiScan verfehlt (5 Beispiele)

| Rapid7-Finding | VectiScan | Lücke |
|---|---|---|
| Form Re-Submission (PRG-Pattern) × 33 | 0 | ZAP active-scan zu konservativ im waf-safe-Modus |
| JavaScript Strict-Mode-Defizite × 5 | 0 | Statische JS-Analyse fehlt |
| Browser Cache Directives × 1 | 0 | Cache-Control-Check fehlt |
| Web Beacons × 2 (Tracker Detection) | 0 | Privacy-Scanner fehlt |
| Subresource Integrity × 2 | 0 | SRI-Check fehlt |

### Was VectiScan findet, was Rapid7 verfehlt (5 Beispiele)

| VectiScan-Finding | Rapid7 | Begründung |
|---|---|---|
| Exchange 2016 EOL auf `owa.securess.de` | 0 | Rapid7 scant nur `www`, sieht keine Subdomains |
| DKIM fehlt bei DMARC `reject` | 0 | DAST hat keine DNS-Layer |
| SPF Softfail (`~all`) | 0 | gleicher Grund |
| Mailserver-Ports SMTP/IMAP/POP3 öffentlich | 0 | DAST scant nicht network-layer |
| `enterpriseregistration.heuel.com` Microsoft-Service erkannt + sauber geskippt | (n.a.) | Nur VectiScan reasoned über Subdomain-Kategorien |

**Strategisches Fazit:** Wir konkurrieren NICHT mit Rapid7's AppSec-
Tiefe (DAST mit 645k Attacks ist eine andere Waffenklasse). Wir bedienen
**Breite + Business-Context + Compliance** — DNS, Mail, Infrastruktur,
mehrere Hosts, deutsche Analyst-Sprache, NIS2/ISO27001-Mapping. Rapid7
Customer + VectiScan Customer überlappen kaum.

---

## 4. „Coole Daten" die wir haben (und die externe Tools nicht haben)

Alle folgenden Daten werden **bereits gesammelt und persistiert** —
sind aber aktuell nur im Admin-Debug-Tab sichtbar. Belege aus dem heuel.com-
Scan (`/api/orders/1de5b28f-…/events`):

### 4.1 AI-Host-Targeting mit Reasoning
Pro Host eine begründete Scan-/Skip-Entscheidung mit Priority. Beispiel:

```
[P1] scan  217.72.203.132 (heuel.com)
       → Basisdomain heuel.com mit Web-Content (Logistics-Unternehmen);
         höchste Priorität für Perimeter-Scan.

[P2] scan  5.7.192.178 (rcmh1.heuel.com)
       → Spezial-Hardware (Hikvision IP-Kamera, STARFACE PBX) mit
         ungewöhnlichen Ports; IoT/Telekommunikations-Geräte erfordern
         Sicherheitsprüfung.

[skip] enterpriseenrollment.heuel.com
       → Microsoft Azure-Host; Redirect zu Microsoft Intune Admin Center
         → Skip (Microsoft-Enrollment-Service, kein eigener Content).
```

### 4.2 Phase-2-Config-Erklärungen (ZAP-Strategie pro Host)
Jeder Host bekommt eine eigene ZAP-Konfiguration mit Begründung:

```
217.72.203.132 (heuel.com):
   policy=standard, skip=[]
   → NEOS CMS mit Preact/JavaScript-Framework erkannt
     (Preact.js, runtime.js, bundled JS-Chunks). AJAX Spider aktiviert
     für SPA-ähnliche Interaktionen. Keine WAF erkannt → standard
     policy mit vollem Rate.

20.79.218.75 (dta-kemper.heuel.com):
   policy=passive-only, skip=[feroxbuster]
   → Host zeigt minimale Web-Präsenz: 8 von 9 FQDNs retournieren 403.
     feroxbuster bringt keinen Mehrwert.
```

### 4.3 Globale Strategie-Notiz
```
"Perimeter-Scan für Logistics-Unternehmen mit hybrider Infrastruktur
 (On-Prem + Microsoft 365). Priorität 1: Basisdomain + kritische
 Mailserver mit vielen offenen Ports. Priorität 2: Multi-Purpose-Hosts
 und IoT/Telekommunikations-Geräte. ..."
```

### 4.4 Threat-Intel-Anreicherung
Pro Finding:
- KEV-Status (CISA Known Exploited Vulnerabilities)
- EPSS-Score (Exploit Probability)
- NVD CVSS + CWE-Refs
- ExploitDB-Verweise

### 4.5 Business-Impact-Score
Numerischer Score 0–10 pro Finding, kombiniert aus:
`CVSS × EPSS × KEV × Asset-Wert × Package-Weight × Confidence`.
Sortier-Schlüssel für Top-N-Selection.

### 4.6 Severity-Provenance pro Finding
```json
{
  "policy_id": "SP-DNS-010",
  "policy_decision": "low",
  "policy_version": "2026-04-30.1",
  "tool_severities": {"reporter_claude": "low"},
  "context_flags": {"mx_present": true, "dns_records.dmarc_p": "quarantine"},
  "rationale": "DMARC mit p=quarantine — Mail wird nur in Spam verschoben,
                nicht abgewiesen; teilweise Durchsetzung",
  "rule_references": ["CWE-290"]
}
```

### 4.7 KI-Kosten pro Order
- Total USD pro Order (Beispiel heuel: **$1.0255** für 6 KI-Calls)
- Breakdown nach Step + Modell + Tokens
- Cache-Hit-Rate (sinkt Re-Scan-Kosten auf ~30%)

### 4.8 Compliance-Mapping (paketabhängig)
- WebCheck/Perimeter: nur CWE/OWASP
- Compliance: §30 BSIG + BSI-Grundschutz-Refs
- SupplyChain: ISO 27001 Annex A
- Insurance: Versicherungs-Fragebogen + Ransomware-Indikator

### 4.9 Positive Findings + Recommendations mit Effort
- 2 positive Findings pro Report (z.B. „DMARC reject", „TLS überall")
- 9 Recommendations mit Timeframe (Sofort / Woche 1 / Monat 1) + Effort-
  Estimate

---

## 5. Empfohlene Visualisierung im Frontend

Der nächste Schritt (Plan
[`schau-diir-mal-die-wild-dawn.md`](../../../Users/danie/.claude/plans/schau-diir-mal-die-wild-dawn.md))
führt diese Daten in einen neuen **Modern-View** auf
`/scan/[orderId]` ein:

| Komponente | Daten-Quelle | Wert für User |
|---|---|---|
| `SeverityDonut` | `audit_severity_counts` | Auf einen Blick Verteilung |
| `PolicyCoverage` | `policy_id_distinct` | Determinismus-/Audit-Wert |
| `HostMap` | `events.aiStrategy.hosts[]` | Targeting-Reasoning sichtbar |
| `ScanStoryTimeline` | `events.aiStrategy + events.toolOutputs` | Erzählung des Scans |
| `ThreatIntelBadge` (in Findings) | `enrichment.kev/epss/nvd` | Drohungs-Kontext per Finding |
| `AICostsCollapsible` | `events.costs` | Transparenz |

Der bisherige „Hacker-View" mit CRT/Matrix/Glitch bleibt als Legacy
über Toggle erreichbar.

---

## 6. Offene Punkte

- **5 weitere Mapper-Patterns** für SP-FALLBACK-Reduzierung von 45% auf
  ~20%: Session-IDs in URL, JS-Library-Vuln, Cross-Domain-Konfiguration,
  Private-IP-Disclosure, Dangling-DNS.
- **DB-weiter Audit** mit `ops-findings-audit` Job nach den nächsten
  3-5 Test-Scans, um Trend zu validieren.
- **Reproducibility-Test**: 2× Scan derselben Domain → identische
  `policy_id_distinct` + `severity_counts` (≤ ±0.01 business_impact_score).
  Aktuell nur einzelner Scan beobachtet.

---

**Verantwortlich:** Daniel Czischke
**Quellen:**
- Live-API `scan-api.vectigal.tech`, Order `1de5b28f` (heuel.com Perimeter)
- DB-Audit `ops-findings-audit` Pipeline-Jobs 10285, 10299
- Externe Baseline: `docs/analyse/202604 - Securess Report Summary.pdf`
- Wettbewerbsanalyse: `docs/analyse/Wettbewerbsanalyse-Rapid7-vs-VectiScan.md`
