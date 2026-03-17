# VectiScan — Architektur-Referenz

## Scan-Architektur: Phase-First Model

Der Scan-Worker verwendet eine Phase-First-Architektur: Alle Hosts durchlaufen
Phase 1, bevor Phase 2 beginnt. Zwischen den Phasen trifft Haiku KI-Entscheidungen.

```
Phase 0: DNS-Reconnaissance (alle Tools)
    │
    ├── crt.sh, subfinder, [amass, gobuster dns, AXFR]*
    ├── DNS Records (SPF, DMARC, DKIM, MX, NS)
    ├── dnsx Validierung + IP-Gruppierung
    └── Web Probe (httpx: HTTP-Check pro Host)
    │
    ▼
AI Host Strategy (Haiku)
    │ Entscheidet: scan/skip pro Host, Priorität, Begründung
    │ Persistiert in: scan_results (ai_host_strategy)
    │ Gepusht via: WebSocket (ai_strategy Event)
    │
    ▼
Phase 1: Tech Detection — ALLE Hosts sequenziell
    │
    ├── nmap (Port-Scan, Service Detection)
    ├── webtech (Technologie-Erkennung, HTTPS first)
    ├── wafw00f (WAF-Erkennung)
    └── CMS-Fallback (wp-login.php Probe wenn webtech nichts findet)
    │
    ▼
AI Phase 2 Config (Haiku, pro Host)
    │ Konfiguriert: nuclei_tags, nikto_tuning, gobuster_wordlist, skip_tools
    │ Persistiert in: scan_results (ai_phase2_config)
    │ Gepusht via: WebSocket (ai_config Event)
    │
    ▼
Phase 2: Deep Scan — ALLE Hosts sequenziell
    │
    ├── testssl.sh (nur bei has_ssl=true)
    ├── nikto (AI-adaptive Tuning)
    ├── nuclei (AI-adaptive Tags, Performance-Flags)
    ├── gobuster dir (AI-adaptive Wordlist)
    ├── gowitness (Screenshot)
    ├── HTTP Headers (Security-Header-Analyse)
    ├── httpx (HTTP-Probing, Tech-Detection)
    ├── katana (Web-Crawler)
    └── wpscan (nur bei CMS=WordPress)
    │
    ▼
Finalize: Pack tar.gz → MinIO Upload → Report-Job enqueuen

* Tools je nach Paket — Basic hat nur crtsh, subfinder, dnsx
```

---

## Web Probe in Phase 0

Nach der DNS-Validierung und Host-Gruppierung wird ein schneller HTTP-Check
pro Host durchgeführt (httpx, ~1-5s pro FQDN):

- `has_web=true`: HTTP-Content vorhanden, Status 2xx-4xx -> voller Web-Scan
- `has_web=false`: Kein HTTP-Content -> nur Port-Scan + SSL

Die Web-Probe-Daten werden im Host-Inventar gespeichert und der AI Host Strategy
als Input mitgegeben. Wenn eine funktionierende FQDN gefunden wird, wird sie
in Phase 1/2 als primäre FQDN verwendet.

---

## FQDN-Priorisierung

Innerhalb jedes Hosts werden FQDNs nach Scan-Relevanz sortiert:

| Priorität | FQDN-Typ | Beispiel |
|---|---|---|
| 0 | Basisdomain | `example.com` |
| 1 | www-Subdomain | `www.example.com` |
| 5 | Sonstige Subdomains | `shop.example.com`, `dev.example.com` |
| 9 | Mail-FQDNs | `mail.example.com`, `mx.example.com` |

Die erste FQDN in der Liste wird als `primary_fqdn` für Phase 1/2 Tools verwendet.

Hosts werden ebenfalls priorisiert:
- Basisdomain-Host zuerst
- www-Subdomain-Host
- Sonstige Web-Hosts
- Mail/Autodiscover-Hosts zuletzt

---

## AI-Orchestrierung

### Host Strategy (nach Phase 0)

**Modell:** `claude-haiku-4-5-20251001`

Haiku erhält das Host-Inventar mit Web-Probe-Daten und entscheidet:
- `scan`: Host wird in Phase 1+2 gescannt
- `skip`: Host wird übersprungen (z.B. Parking-Pages, CDN-Nodes, Autodiscover)

**Fallback:** Bei API-Fehler werden alle Hosts gescannt.

### Phase 2 Config (nach Phase 1, pro Host)

Haiku erhält das Tech-Profile eines Hosts und konfiguriert:
- **nuclei_tags**: Technologie-spezifische Template-Tags (max 5-7)
- **nuclei_exclude_tags**: Tags die ausgeschlossen werden (z.B. `dos`, `fuzz` bei WAF)
- **nikto_tuning**: Relevante Scan-Kategorien (1-9, 0)
- **gobuster_wordlist**: Passende Wordlist (`common`, `wordpress`, `api`, `cms`)
- **skip_tools**: Tools die übersprungen werden können (nur für API-Hosts/Mailserver)

**Override:** Auf der Basisdomain und www-Subdomain ist `skip_tools` immer leer.

---

## WebSocket Event Replay

Clients, die sich spät verbinden, erhalten automatisch alle bisherigen Events:

1. **hosts_discovered**: Entdeckte Hosts aus dem Host-Inventar
2. **ai_strategy**: Die AI-Host-Strategie (scan/skip Entscheidungen)
3. **ai_config**: AI Phase-2-Konfigurationen pro Host
4. **tool_output**: Zusammenfassungen aller bisherigen Tool-Ergebnisse (max 50)

Die Events werden aus zwei Quellen rekonstruiert:
- `orders.discovered_hosts` (JSONB) für Host-Discovery
- `scan_results` Tabelle für AI-Entscheidungen und Tool-Outputs

---

## Event-Persistenz

AI-Entscheidungen werden in der `scan_results` Tabelle gespeichert:

| tool_name | phase | Inhalt |
|---|---|---|
| `ai_host_strategy` | 0 | JSON mit hosts[], strategy_notes |
| `ai_host_skip` | 0 | Skip-Begründung pro Host |
| `ai_phase2_config` | 1 | JSON mit nuclei_tags, wordlist, etc. |
| `web_probe` | 0 | JSON mit has_web, status, title pro Host |

Dies ermöglicht:
- Event-Replay für WebSocket Late-Joining
- Scan-Detail-Seite (`/scan/[orderId]`) mit Debug-Mode
- `/api/orders/:id/events` Endpoint

---

## CWE-Validierung + CVSS-Score-Capping

Der Report-Worker hat eine Post-Processing-Pipeline:

1. **CWE-Validierung**: `cwe_reference.py` enthält eine Referenztabelle gültiger CWE-IDs.
   Ungültige CWE-Zuordnungen von Claude werden korrigiert.
2. **CVSS-Score-Capping**: Strenge Obergrenzen verhindern überhöhte Scores:
   - Information Disclosure: max LOW (3.5)
   - Fehlende Security Headers: max MEDIUM (5.5)
   - SSH mit Key-Auth: INFO (0.0)
   - DNS-Records: max MEDIUM (5.5)
3. **Score-Vektor-Konsistenz**: Der numerische CVSS-Score muss zum Vektor passen.

Die Regeln sind in den drei Prompt-Varianten (`prompts.py`) kodiert.

---

## Scheduled Scans Architecture

### Scheduler Tick Loop

Der API-Server startet beim Boot einen Scheduler (`lib/scheduler.ts`), der alle 60 Sekunden:

1. `scan_schedules` abfragt: `WHERE enabled = true AND next_scan_at <= NOW()`
2. Row-Level-Lock (`FOR UPDATE SKIP LOCKED`) gegen Doppelverarbeitung
3. Für jede fällige Schedule:
   - Order direkt im Status `queued` erstellen (Verifikation überspringen)
   - Scan-Job in Redis-Queue enqueuen
   - `next_scan_at` berechnen (weekly: +7d, monthly: +1M, quarterly: +3M)
   - `once`-Schedules werden deaktiviert (`enabled = false`)

### Voraussetzung

Eine Schedule kann nur für Domains erstellt werden, die der Kunde zuvor
verifiziert hat (mind. eine Order mit `verified_at IS NOT NULL`).

---

## Queue-System (Redis + BullMQ)

**Zwei Queues:**

| Queue | Produzent | Konsument | Payload |
|---|---|---|---|
| `scan-pending` | Backend-API / Scheduler | Scan-Worker | `{ orderId, targetDomain, package }` |
| `report-pending` | Scan-Worker | Report-Worker | `{ orderId, rawDataPath, hostInventory, techProfiles[], package }` |

**Redis Pub/Sub:** Kanal `scan:{orderId}` für WebSocket-Events.

---

## Object Storage (MinIO)

| Bucket | Inhalt | Retention |
|---|---|---|
| `scan-rawdata` | Rohdaten der Scans (tar.gz) | 90 Tage |
| `scan-reports` | Fertige PDF-Berichte | 365 Tage |
| `scan-logs` | Scan-Execution-Logs | 30 Tage |

---

## Report-Pipeline

### Drei Prompt-Varianten

| Paket | Prompt | Besonderheiten |
|---|---|---|
| Basic | `SYSTEM_PROMPT_BASIC` | Max 5-8 Findings, Management-tauglich, kein Fachjargon |
| Professional | `SYSTEM_PROMPT_PROFESSIONAL` | PTES-Standard, vollständige CVSS-Vektoren, Evidence-Blöcke |
| NIS2 | `SYSTEM_PROMPT_NIS2` | = Professional + §30 BSIG-Mapping, Compliance-Summary, Lieferketten-Zusammenfassung |

Alle Prompts enthalten:
- Strenge CVSS-Obergrenzen
- CWE-Referenztabelle (inline)
- Häufig falsch bewertete Findings mit korrekten Scores
- Deutsche Ausgabe

### Report-Worker Dateien

```
report-worker/reporter/
├── worker.py              ← BullMQ Consumer, Orchestrierung
├── parser.py              ← Tool-Output-Parser (JSON/XML → Findings)
├── claude_client.py       ← Claude API Aufruf + JSON-Parsing
├── prompts.py             ← Drei Prompt-Varianten (Basic, Pro, NIS2)
├── report_mapper.py       ← Claude-Output → report_data Dict (drei Mapper)
├── cwe_reference.py       ← CWE-Validierung + CVSS-Capping
└── generate_report.py     ← PDF-Engine (pentest-report-generator Skill)
```

### Claude-Output → report_data Mapping

Der Claude-API-Aufruf liefert JSON mit `findings[]`, `positive_findings[]` und
`recommendations[]`. Die Finding-Felder (id, title, severity, cvss_score,
cvss_vector, cwe, affected, description, evidence, impact, recommendation)
mappen 1:1 auf die report_data-Struktur des PDF-Skills.

NIS2-Findings haben zusätzlich ein `nis2_ref`-Feld (`§30 Abs. 2 Nr. X BSIG`).
Der NIS2-Report enthält außerdem `nis2_compliance_summary` und `supply_chain_summary`.

---

## Sicherheit des Scan-Workers

- Container läuft als Non-Root-User (`scanner`)
- Persistent-Worker, der nach jedem Job /tmp aufräumt
- Minimales Base-Image (Debian-Slim)
- Kein Volume-Mount auf Host-Dateisystem
- Resource-Limits (CPU, RAM)
- **Keine aktive Exploitation** — nur Scanning und Enumeration
- Alle Tool-Aufrufe werden in `scan_results` geloggt
- Cancellation-Check: Worker prüft regelmäßig DB-Status, bricht bei `cancelled` ab
- Tool-Versionen werden bei Scan-Start erfasst und in `meta.json` geschrieben
