# VectiScan — Architektur-Referenz (Stand: 2026-04-21)

Hochlevel-Architektur. Detaillierte Pipeline-Doku in `SCAN-PIPELINE-DETAIL.md`.

---

## Systemtopologie

```
                       ┌─────────────────────────┐
   internes Netz ──→   │ Traefik v3.6 (DMZ host) │
                       └────────┬────────────────┘
                                │ scan.vectigal.tech
                                │ scan-api.vectigal.tech
                                ▼
              ┌─────────────────────────────────────────────────┐
              │              Docker-Compose Stack               │
              │                                                 │
              │  ┌──────────┐   ┌──────────┐                   │
              │  │ frontend │──▶│   api    │──▶ postgres ◀──┐  │
              │  │ Next.js  │   │ Fastify  │──▶ redis    ◀──┤  │
              │  └──────────┘   └────┬─────┘──▶ minio    ◀──┤  │
              │                      │                       │  │
              │             ┌────────┴─────────┐             │  │
              │             ▼                  ▼             │  │
              │     ┌───────────────┐  ┌───────────────┐    │  │
              │     │ scan-worker-1 │  │ scan-worker-2 │────┤  │
              │     │   + zap-1     │  │   + zap-2     │    │  │
              │     └───────┬───────┘  └───────┬───────┘    │  │
              │             └──────┬───────────┘             │  │
              │                    ▼                         │  │
              │             ┌─────────────┐                  │  │
              │             │report-worker│──────────────────┘  │
              │             └─────────────┘                     │
              └──────────────────────────────────────────────────┘
```

Frontend und API hängen in `proxy-net` (Traefik) und `vectiscan-internal`.
Alle anderen Services nur in `vectiscan-internal`. Scan-Worker brauchen
Internet-Outbound (NAT über `ens192`, Docker `iptables=false`).

---

## Scan-Pipeline (6 Phasen, 4 KI-Punkte)

```
Redis Queue: scan-pending
    │
    ▼
worker.py::_process_job(order_id, domain, package)
    │
    ├── Phase 0a: Passive Intelligence
    │     WHOIS, Shodan, AbuseIPDB, SecurityTrails,
    │     DNSSEC/CAA/MTA-STS/DANE  (parallel)
    │
    ├── Phase 0b: DNS-Reconnaissance
    │     crt.sh, subfinder, amass, gobuster_dns, AXFR, dnsx
    │     + Web-Probe (httpx pro FQDN)              (parallel, 6 Worker)
    │
    ├── KI #1: Host Strategy (Haiku)
    │     scan/skip pro Host, Priorität, scan_hints
    │
    ├── Phase 1: Tech Detection                     (parallel, max 3 Hosts)
    │     nmap, Playwright-webtech, wafw00f, CMSFingerprinter
    │
    ├── KI #2: Tech Analysis (Haiku)
    │     CMS-Korrektur basierend auf Redirect-Daten
    │
    ├── KI #3: Phase-2-Config (Haiku, pro Host)
    │     ZAP-Policy/Spider-Tiefe/Active-Kategorien/ffuf-Modus/skip_tools
    │
    ├── Phase 2: Deep Scan       (parallel max 3 Hosts; max 1 wenn ZAP läuft)
    │     ├── Stage 1 Discovery: ZAP Spider, testssl, Headers, httpx
    │     ├── Stage 2 Deep:      ZAP Active, ffuf, feroxbuster, wpscan
    │     └── Stage 3 Alerts:    ZAP-Pscan-Queue leeren, Alerts mappen
    │
    ├── KI #4: Phase-3-Priorisierung (Sonnet, nur bei >5 Findings)
    │     Konfidenz-Scoring, Cross-Tool-Korrelation, FP-Erkennung
    │
    ├── Phase 3: Correlation & Enrichment
    │     ├── Cross-Tool-Korrelation (CrossToolCorrelator)
    │     ├── FP-Filter (6 Regeln: WAF, Version, CMS, SSL/Header-Dedup, Noise)
    │     ├── Threat-Intel: NVD, EPSS, CISA KEV, ExploitDB (parallel, 4 Worker)
    │     └── Business-Impact-Score (CVSS × EPSS × KEV × Asset × Paket)
    │
    └── Finalize
          ├── tar.gz packen → MinIO scan-rawdata/<orderId>.tar.gz
          ├── Report-Job in Redis-Queue (report-pending)
          └── Status → pending_review (Admin-Review-Workflow)
```

TLSCompliance-Paket (`skip_ai_decisions=True`) überspringt KI #1, #2 und #3
sowie Phase 3 — es nutzt nur DNS-Recon, nmap auf TLS-Ports, testssl und
Headers, und einen dedizierten TR-03116-4-Pfad im Report-Worker.

---

## KI-Modelle und Einsatz

| Punkt | Modell | Einsatz | Token-Budget |
|---|---|---|---|
| Host Strategy | `claude-haiku-4-5-20251001` | Pattern-Matching: scan/skip | 8.192 |
| Tech Analysis | `claude-haiku-4-5-20251001` | CMS-Korrektur per Redirect-Daten | 8.192 |
| Phase-2-Config | `claude-haiku-4-5-20251001` | ZAP-Policy + ffuf-Modus pro Host | 8.192 |
| Phase-3-Priorisierung | `claude-sonnet-4-6` | Cross-Tool-Reasoning, FP-Erkennung | 16.384 |
| Report-Generierung | `claude-sonnet-4-6` | Komplexe Analyse, Prosa, Compliance | paketabhängig |
| Report-QA | `claude-haiku-4-5-20251001` | Plausibilität nur bei Anomalien | klein |

Alle KI-Calls werden über `_save_ai_debug()` in `scan_results` gespeichert:
System-Prompt vollständig, User-Prompt bis 10 KB, Raw-Response, Cost-Dict.
Cap auf 50 KB pro Eintrag.

---

## Order-Status-Flow

```
verification_pending
        │
        ▼ POST /api/verify/check (verified) oder /api/verify/manual
       queued
        │
        ▼ scan-worker pickup
      scanning ─→ passive_intel ─→ dns_recon
        │           │                │
        │           ▼                ▼
        │      scan_phase1 ─→ scan_phase2 ─→ scan_phase3
        │                              │
        │                              ▼
        └────────────────────────→ scan_complete
                                       │
                                       ▼ report-worker (Claude-Analyse)
                                 pending_review  ←── Admin-Review
                                       │
                          ┌────────────┼─────────────┐
                          ▼ approve    ▼ reject      ▼ regenerate
                  report_generating  rejected   report_generating
                          │                          │
                          ▼                          ▼
                  report_complete             report_complete (v+1)

   cancelled (von jedem aktiven Status)
   failed    (von jedem Status, bei Worker-Fehler)
   delivered (Folge-Status nach Versand, nicht aktiv im Pipeline-Code)
```

Customer sieht nur `report_complete`, `delivered`, `report_generating` und
`pending_review` über `GET /api/orders/:id`. Alle anderen Status sind
admin-only.

---

## Web-Probe in Phase 0b

Pro FQDN (max 3 pro Host) wird `httpx -u <fqdn> -json -silent
-follow-redirects -status-code -title -timeout 5` ausgeführt.

- `has_web=true`: HTTP-Content vorhanden → voller Web-Scan
- `has_web=false`: kein HTTP-Content → nur Port-Scan + SSL
- Parking-Page-Patterns werden erkannt (Froxlor, Plesk, cPanel, "domain not
  configured", "default web page" etc.) und als skipping-Signal an die KI
  übergeben

Die Web-Probe-Daten landen im Host-Inventar und werden der KI Host
Strategy als Input mitgegeben. Wenn eine antwortende FQDN gefunden wird,
wird sie zur primären FQDN für Phase 1/2.

---

## FQDN- und Host-Priorisierung

| Priorität | FQDN-Typ | Beispiel |
|---|---|---|
| 0 | Basisdomain | `example.com` |
| 1 | www-Subdomain | `www.example.com` |
| 5 | Sonstige Subdomains | `shop.example.com` |
| 9 | Mail-FQDNs | `mail.*`, `mx.*`, `smtp.*`, `imap.*`, `autodiscover.*` |

Hosts werden in derselben Logik priorisiert. **Override:** Auf Basisdomain
und `www.<domain>` ist `skip_tools` der KI immer leer (Basisdomain wird
immer vollständig gescannt).

---

## Admin-Review-Workflow

1. Scan-Worker beendet Phase 3 → Status `scan_complete`, Job in
   `report-pending`-Queue
2. Report-Worker führt Claude-Analyse + QA durch, schreibt `findings_data`
   in `reports`, setzt Status auf `pending_review` (kein PDF!)
3. Admin sieht Pending-Review-Queue (`GET /api/admin/pending-reviews`),
   prüft die Findings und kann FPs ausschließen (`POST
   /api/orders/:id/findings/:findingId/exclude`)
4. Admin **approved** (`POST /api/admin/orders/:id/approve`):
   Status → `report_generating`, Report-Worker erstellt PDF inkl.
   Excluded-Filter, Status → `report_complete`
5. Admin **rejected** (`POST /api/admin/orders/:id/reject`):
   Status → `rejected` mit `review_notes`

Kunden können nach Approve den Report über die Detail-Seite herunterladen
oder per Deep-Link teilen.

---

## Subscription-Workflow

- Kunde erstellt Abo (`POST /api/subscriptions`) — Stripe gemockt, Status
  geht direkt auf `active`
- Domains landen mit Status `pending_approval`
- Admin sieht Queue (`GET /api/admin/pending-domains`), gibt jede Domain
  manuell frei (`POST /api/admin/subscription-domains/:id/approve`) oder
  lehnt sie ab
- Freigegebene Domains landen automatisch im persistierten
  `verified_domains`-Bestand des Kunden (90 Tage Gültigkeit), sodass
  Folge-Orders die Verifikation überspringen
- Customer kann pro Abo Re-Scans anstoßen (`POST
  /api/subscriptions/:id/rescan`), bis das Kontingent (`max_rescans`)
  erschöpft ist. **Admin-Re-Scans** über denselben Endpoint überspringen
  Quota-Check und -Inkrement; Audit-Log markiert `triggeredBy: 'admin'`.

### Order-zu-Abo-Linking
- `POST /api/orders` (`api/src/routes/orders.ts`) prüft bei jeder neuen
  Order: existiert für den Customer ein aktives Abo, dessen
  `subscription_domains` die Ziel-Domain mit Status `verified` und
  `enabled=true` enthält? → `subscription_id` wird automatisch gesetzt.
- Der Subscription-Scheduler (`api/src/lib/scheduler.ts`) setzt
  `subscription_id` ohnehin direkt beim INSERT.
- Der Re-Scan-Endpoint (`POST /api/subscriptions/:id/rescan`) setzt
  zusätzlich `is_rescan = true`.
- Folge: Das Dashboard kann Orders zuverlässig nach Abo gruppieren —
  auch dann, wenn der Customer den Re-Scan manuell über `/api/orders`
  statt über den Subscription-Endpoint anstößt. Alt-Orders ohne
  `subscription_id` bleiben unverknüpft und erscheinen als
  Einzelscan-Domain-Gruppen.

---

## WebSocket Event Replay

Verbindungs-Endpoint: `GET /ws?orderId=<uuid>` (auch `?scanId=` für
Backward-Compat).

Bei Connect sendet der Server `connected` und replayt aus zwei Quellen:

- `orders.discovered_hosts` (JSONB) → `hosts_discovered`-Event
- `scan_results` Tabelle:
  - `tool_name=ai_host_strategy` → `ai_strategy`-Event
  - `tool_name=ai_phase2_config` (pro Host) → `ai_config`-Events
  - Alle übrigen Tools (max 50) → `tool_output`-Events

Live-Events (vom Scan-Worker via Redis-Pub/Sub):

```
{ "type": "status",          "orderId": "uuid", "status": "..." }
{ "type": "progress",        "orderId": "uuid", "phase": "...", "tool": "...", "host": "..." }
{ "type": "hosts_discovered","orderId": "uuid", "hosts": [...], "hostsTotal": 3 }
{ "type": "ai_strategy",     "orderId": "uuid", "strategy": {...} }
{ "type": "ai_config",       "orderId": "uuid", "ip": "...", "config": {...} }
{ "type": "tool_output",     "orderId": "uuid", "tool": "nuclei", "host": "...", "summary": "..." }
{ "type": "phase3_complete", "summary": {...} }
```

Pub/Sub-Kanal: `scan:events:<orderId>`.

---

## Queue-System (Redis + BullMQ)

| Queue | Producer | Consumer | Payload |
|---|---|---|---|
| `scan-pending` | API / Scheduler / Subscriptions | Scan-Worker | `{orderId, targetDomain, package}` |
| `report-pending` | Scan-Worker (auto), API (regenerate/requeue/approve) | Report-Worker | `{orderId, rawDataPath, hostInventory, techProfiles, package, enrichment?, correlatedFindings?, businessImpactScore?, excludedFindings?, approved?, regenerate?}` |
| `diagnose-pending` | API (`POST /api/admin/diagnose`) | Scan-Worker | `{requestId, probe?}` |

Alle drei Queues werden via `BLPOP` konsumiert. Diagnose-Result wird unter
`diagnose:result:<requestId>` (TTL 5 Min) abgelegt und vom API gepollt.

---

## Object Storage (MinIO)

| Bucket | Inhalt | Retention |
|---|---|---|
| `scan-rawdata` | tar.gz aller Scans | 90 Tage |
| `scan-reports` | PDF-Reports (versioniert) | 365 Tage |
| `scan-debug` | Claude-Prompts/Responses pro Order (JSON) | 30 Tage |

Versionierte Reports liegen unter `<orderId>.pdf` (v1) bzw.
`<orderId>_v<n>.pdf`. Die Datenbank-Spalte `reports.version` und
`reports.superseded_by` halten die Reihenfolge.

---

## CWE/CVSS-Validierung

Pipeline im Report-Worker:

1. **`validate_cwe_mappings()`** — `cwe_reference.py` enthält die lokale
   Whitelist gültiger CWE-IDs; ungültige Zuordnungen werden geloggt
   (optional korrigiert via MITRE-CWE-API-Client `cwe_api_client.py`)
2. **`validate_cvss_scores()`** — Berechnet CVSS-3.1-Score aus dem Vektor
   (8 Pflichtmetriken), korrigiert Divergenzen >0.1
3. **`cap_implausible_scores()`** — Strenge Obergrenzen aus den Prompts:
   - Information Disclosure: max LOW (3.5)
   - Banner: max INFO (2.5)
   - Fehlende Security-Headers: max MEDIUM (5.5)
   - DNS-Records: max MEDIUM (5.5)
   - SSH mit Key-Auth: INFO (0.0)
4. **`run_qa_checks()`** — Programmatische Konsistenz-Checks (Severity ↔
   Score, doppelte IDs, fehlende Felder); Haiku-Plausibilität nur bei
   Anomalien

Trailing-Commas in Claude-Antworten werden per Regex bereinigt;
JSON-Parse-Fehler werden bis zu 3× retried (mit 3 s Pause).

---

## Sicherheit des Scan-Workers

- Container läuft als Non-Root-User (`scanner`)
- Persistent-Worker, der nach jedem Job `/tmp/scan-<orderId>` aufräumt
- Minimales Base-Image (`debian:bookworm-slim`)
- Kein Volume-Mount auf das Host-Dateisystem
- Resource-Limits (2 CPU, 2 GB RAM pro Worker)
- **Keine aktive Exploitation** — nur Scanning und Enumeration
- Cancellation-Check: Worker prüft regelmäßig `orders.status` → bei
  `cancelled` wird der Scan beendet (`ScanCancelled`)
- Tool-Versionen werden bei Scan-Start erfasst und in `meta.json` und
  vom Report-Worker in den Audit-Trail (Compliance/SupplyChain) übernommen
- ZAP läuft pro Worker als separater Daemon (zap-1, zap-2) auf
  `vectiscan-internal`, kein externer Port
- Subprocess-Cleanup: `start_new_session=True` + SIGKILL der gesamten
  Prozessgruppe bei Timeout
