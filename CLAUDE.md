# VectiScan v2

## Was ist VectiScan?
Automatisierte Security-Scan-Plattform mit fünf Paketen (WebCheck, Perimeter, Compliance, SupplyChain, Insurance).
Internes Tool hinter Traefik (internal-only). Benutzer registrieren sich, erstellen
Scan-Orders, verifizieren ihre Domain, und erhalten einen PDF-Report.

## Zielumgebung
- Server: vectigal-docker02 (Debian 13, 192.168.8.44, DMZ)
- Reverse Proxy: Traefik v3.6 (Auto-Discovery über Labels)
- Registry: ghcr.io/dc-77/vectiscan
- CI/CD: GitLab Runner auf vectigal-docker02 (Shell Executor, Tag: vectigal)
- Zugriff: nur internes Netzwerk (Traefik-Middleware: internal-only@file)
- DNS: *.vectigal.tech zeigt auf den Server
- SSL: Let's Encrypt HTTP-01 pro Subdomain (Traefik-Default, kein Label nötig)

WICHTIG — Subdomain-Kollision vermeiden:
Die Gutachten-KI belegt bereits api.vectigal.tech. VectiScan nutzt deshalb:
- scan.vectigal.tech → Frontend (Next.js, Port 3000)
- scan-api.vectigal.tech → Backend API (Fastify, Port 4000)

## Tech-Stack
| Komponente      | Technologie                                          |
|-----------------|------------------------------------------------------|
| Frontend        | Next.js 15 (App Router), Tailwind CSS                |
| Backend-API     | Node.js, Fastify, TypeScript                         |
| Datenbank       | PostgreSQL 16.4-alpine                               |
| Queue           | Redis 7.4-alpine + BullMQ                           |
| Scan-Worker     | Python 3.12, debian:bookworm-slim Base               |
| Report-Worker   | Python 3.12, Claude API, pentest-report-generator Skill |
| Object Storage  | MinIO (S3-kompatibel)                                |

## Repo-Struktur
Mono-Repo mit vier Diensten: frontend/, api/, scan-worker/, report-worker/.
Jeder Dienst hat ein eigenes Dockerfile. Die docker-compose.yml im Root
definiert alle Container. Docs liegen unter docs/.

## Konventionen
- TypeScript strict mode für Frontend und API
- Python Type Hints für Worker
- Alle Environment-Variablen über .env (nie hardcoded)
- API-Responses immer als JSON mit konsistentem Format:
  { "success": true, "data": {...} } oder { "success": false, "error": "..." }
- Logging: strukturiertes JSON-Logging (pino für Node, structlog für Python)
- Docker: Multi-Stage Builds, Non-Root User in allen Images
- Alle Scan-Tool-Outputs als JSON (wo möglich), gespeichert unter
  /tmp/scan-<orderId>/ mit der Verzeichnisstruktur aus docs/SCAN-TOOLS.md

## Netzwerk-Architektur
- proxy-net: Traefik ↔ Frontend, API (über Traefik erreichbar, internal-only)
- vectiscan-internal: Alle Container untereinander
- Frontend und API hängen in beiden Netzwerken
- Alles andere nur in vectiscan-internal
- Scan-Worker braucht Internet-Outbound (NAT über ens192, Docker iptables=false)

## Traefik-Labels (Muster für VectiScan)
Frontend:
  traefik.enable=true
  traefik.http.routers.vectiscan-web.rule=Host(`scan.vectigal.tech`)
  traefik.http.routers.vectiscan-web.middlewares=security-headers@file,rate-limit@file,internal-only@file
  traefik.http.services.vectiscan-web.loadbalancer.server.port=3000

API:
  traefik.enable=true
  traefik.http.routers.vectiscan-api.rule=Host(`scan-api.vectigal.tech`)
  traefik.http.routers.vectiscan-api.middlewares=security-headers@file,rate-limit@file,internal-only@file
  traefik.http.services.vectiscan-api.loadbalancer.server.port=4000
  traefik.http.services.vectiscan-api.loadbalancer.healthcheck.path=/health
  traefik.http.services.vectiscan-api.loadbalancer.healthcheck.interval=15s

SSL-Zertifikate werden automatisch per Let's Encrypt HTTP-01 gezogen.
Kein certresolver-Label nötig — das ist der Traefik-Default.

## Authentication
- JWT-basierte Auth (Register, Login, Password-Reset)
- Zwei Rollen: `customer` (sieht eigene Orders) und `admin` (sieht alles)
- Middleware: `requireAuth` (JWT prüfen), `requireAdmin` (Admin-Rolle prüfen)
- Report-Download: Auth via JWT oder Download-Token (für E-Mail-Links)

## API-Endpoints
Siehe docs/API-SPEC.md für vollständige Spezifikation.

### Orders (Multi-Target)
- POST /api/orders           → Neue Order anlegen
  (Body: `{ package, targets: [{raw_input, exclusions?}, ...] }`, max 10 Zeilen,
   max 1 CIDR, /24 minimaler Prefix)
- POST /api/orders/validate-targets → Live-Validierung pro Zeile
- GET  /api/orders           → Order-Liste (Admin: alle, Kunde: eigene)
- GET  /api/orders/:id       → Status + Live-Fortschritt
- DELETE /api/orders/:id     → Soft-Cancel oder Hard-Delete (?permanent=true)
- GET  /api/orders/:id/report → PDF-Download (Auth via JWT oder Download-Token)
- GET  /api/orders/:id/results → Raw Scan-Results pro Tool
- GET  /api/orders/:id/events → AI-Strategie, AI-Configs, Tool-Outputs (Event Replay)
- GET  /api/orders/:id/findings → Strukturierte Befunde aus dem Report

### Auth
- POST /api/auth/register, POST /api/auth/login, GET /api/auth/me
- POST /api/auth/forgot-password, POST /api/auth/reset-password
- PUT  /api/auth/password

### Admin
- GET /api/admin/users, PUT /api/admin/users/:id/role, DELETE /api/admin/users/:id
- GET /api/admin/stats
- GET /api/admin/review/queue → Orders/Subscriptions mit `pending_target_review`
- GET /api/admin/review/:type/:id → Detail inkl. Pre-Check-Hosts + Authorizations
- PUT /api/admin/targets/:targetId → Policy/Exclusions editieren
- POST /api/admin/targets/:targetId/approve|reject|restart-precheck
- POST /api/admin/orders/:id/release → Scan nach Freigabe aller Targets starten
- POST /api/admin/orders/:id/authorizations → Multipart-Upload (PDF/JPG/PNG)
- POST /api/admin/subscriptions/:id/authorizations
- DELETE /api/admin/authorizations/:id

### Subscriptions
- POST /api/subscriptions → Abo anlegen mit `targets[]`
- GET /api/subscriptions → Liste (Kunde: eigene, Admin: alle) inkl. Target-Stati
- POST /api/subscriptions/:id/targets → Target nachtraeglich anhaengen
- DELETE /api/subscriptions/:id/targets/:targetId → Target entfernen
- POST /api/subscriptions/:id/rescan → Ad-hoc Re-Scan (optional nur ein Target)

### Schedules
- GET /api/schedules, POST /api/schedules, GET /api/schedules/:id
- PUT /api/schedules/:id, DELETE /api/schedules/:id

### Verification (optional im Multi-Target-Flow)
- POST /api/verify/check → verifiziert ein scan_target (nur FQDN-Typen),
  beschleunigt Admin-Entscheidung, Ergebnis im 90-Tage-Cache `verified_domains`
- GET /api/verify/status/:orderId → Verify-Status pro FQDN-Target der Order
- (`POST /api/verify/manual` entfernt — ersetzt durch Admin-Approve-Flow)

### WebSocket
- GET /ws?orderId=<uuid> → Real-Time Progress mit Event-Replay

### Health
- GET /health → Health-Check für Traefik

## Datenbank
Siehe docs/DB-SCHEMA.sql für das vollständige Schema.
Basis-Tabellen: customers, users, orders, scan_results, reports, audit_log, scan_schedules.
Multi-Target-Tabellen (Migration 014): scan_targets, scan_target_hosts,
scan_run_targets, scan_authorizations. Die alte subscription_domains ist gedropt.

## Multi-Target-Flow
1. POST /api/orders mit `targets[]` legt Order mit Status `precheck_running` an
   und befüllt `scan_targets`. Job wird in Redis-Queue `precheck-pending` gelegt.
2. precheck-worker-1/-2 (separate Container, gleiches Image, anderer Entrypoint
   `scanner.precheck_worker`) validiert pro Target: DNS, httpx, nmap-Top-10,
   Cloud-Provider-Heuristik. Schreibt `scan_target_hosts`.
3. Nach Abschluss: Order-Status → `pending_target_review`. Admin sieht Review
   unter `/admin/review/[orderId]`, kann pro Target approve/reject/update und
   Scan-Authorizations (PDF) hochladen.
4. `POST /api/admin/orders/:id/release` setzt Status `queued` und enqueued
   `scan-pending` mit `{orderId, package}`. `scan_run_targets` wird als
   Snapshot angelegt.
5. Scan-Worker liest Targets aus DB, führt Phase 0b pro Policy (enumerate/
   scoped/ip_only) aus, merget Inventar, wendet Scope-Enforcement an
   (`scanner/scope.py`), läuft dann wie bisher Phase 1-3 durch.

Four Target-Typen: `fqdn_root`, `fqdn_specific`, `ipv4`, `cidr`.
Drei Discovery-Policies: `enumerate`, `scoped`, `ip_only`.
Limits: 10 Eingabezeilen pro Auftrag, 1 CIDR, /24 kleinster Prefix, 50 lebende
Hosts maximal (`subscriptions.max_hosts`, Default 50).

## Scan-Worker
6-Phasen-Architektur mit 4 AI-Entscheidungspunkten:
1. Phase 0a: Passive Intelligence (Shodan, AbuseIPDB, SecurityTrails, WHOIS)
2. Phase 0b: DNS-Reconnaissance + Web-Probe (httpx), pro Target policy-aware;
   danach `scope.enforce_scope()` verwirft out-of-scope Hosts und wendet
   Exclusions an.
3. AI Host Strategy (Haiku): scan/skip pro Host, Priorität, scan_hints
4. Phase 1: Tech-Detection (nmap, webtech, wafw00f, CMS-Fingerprinting-Engine)
5. AI Phase-2-Config (Haiku): nuclei-Tags, Wordlists, ffuf-Modus, feroxbuster-Tiefe, dalfox
6. Phase 2: Deep-Scan (testssl, nikto, nuclei, gobuster, ffuf, feroxbuster, katana, dalfox, gowitness, headers, httpx, wpscan)
7. AI Phase-3-Priorisierung (Sonnet): Cross-Tool-Korrelation, FP-Erkennung
8. Phase 3: Correlation & Enrichment (NVD, EPSS, CISA KEV, ExploitDB, Cross-Tool-Korrelation, FP-Filter, Business-Impact-Scoring)

Tool-Konfiguration und Timeouts: siehe docs/SCAN-TOOLS.md
Max Hosts: WebCheck 3, Perimeter+ 15. Gesamt-Timeout: WebCheck 20 Min, Perimeter+ 120 Min.

## Report-Worker
1. Rohdaten aus MinIO laden (scan-rawdata/<orderId>.tar.gz)
2. Tool-Outputs parsen und strukturieren (parser.py)
3. Claude API aufrufen (claude_client.py, Sonnet 4.6, JSON-Output, deutscher Text)
   - Fünf Prompt-Varianten: WebCheck, Perimeter, Compliance, SupplyChain, Insurance (prompts.py)
4. Report-QA: Programmatische Checks (CVSS, CWE, Severity, Duplikate) + Haiku-Plausibilität (qa_check.py)
5. CWE-Validierung + CVSS-Score-Capping (cwe_reference.py, claude_client.py)
6. Claude-Output auf report_data-Struktur mappen (report_mapper.py, 5 Mapper)
7. PDF generieren via generate_report() aus dem Skill (generate_report.py)
8. PDF nach MinIO hochladen (scan-reports/<orderId>.pdf)
9. Findings-Daten in reports.findings_data speichern (Dashboard)
10. Order-Status auf report_complete setzen

Compliance-Module (report-worker/reporter/compliance/):
- nis2_bsig.py — §30 BSIG Mapping
- iso27001.py — ISO 27001 Annex A
- bsi_grundschutz.py — BSI IT-Grundschutz
- nist_csf.py — NIST CSF 2.0
- insurance.py — Versicherungs-Fragebogen-Generator

## Frontend-Seiten
- `/` — Landing, Order erstellen mit Package-Selector
- `/scan` — Multi-Target Order-Form (Package + TargetInput-Komponente)
- `/login` — Login
- `/forgot-password`, `/reset-password` — Passwort-Reset-Flow
- `/dashboard` — Order-Liste, Findings-Viewer, Severity-Bars
- `/scan/[orderId]` — Scan-Detail mit Live-Progress, AI Intelligence Panel, Debug-Mode
- `/verify/[orderId]` — Domain-Verifizierung (DNS-TXT, File, Meta-Tag) — optional
- `/schedules` — Zeitplan-Verwaltung (CRUD)
- `/profile` — Passwort ändern
- `/admin` — Benutzerverwaltung, System-Statistiken
- `/admin/review` — Liste Orders/Subscriptions mit pending Target-Review
- `/admin/review/[orderId]` — Target-Review mit Policy-Editor + Auth-Upload
- `/admin/review/subscription/[subId]` — analoge Review-Seite für Subscriptions

## CI/CD
Multi-Image-Build nach dem Muster aus dem Betriebshandbuch (Beispiel C: Gutachten-KI).
Variable BASE_IMAGE statt IMAGE. Vier parallele Build-Jobs:
build-frontend, build-api, build-scan-worker, build-report-worker.
Trivy-Scan-Stage zwischen Build und Deploy (--severity CRITICAL, --ignore-unfixed).
Deploy-Sleep: 15 Sekunden (7 Container brauchen Zeit für Healthchecks).

## Arbeitsweise
- Am Ende jeder abgeschlossenen Aufgabe: Kontext-Auslastung ausgeben (geschätzter %-Wert)

## Wichtige Referenz-Dokumente
- docs/PROTOTYPE-SCOPE.md — Feature-Scope
- docs/API-SPEC.md — API-Spezifikation
- docs/DB-SCHEMA.sql — Datenbankschema
- docs/SCAN-TOOLS.md — Alle Scan-Tools mit Argumenten, Paketen und Output-Format
- docs/architecture.md — Architektur inkl. AI-Orchestrierung und Event-System
- docs/STRUCTURE.md — Verzeichnisstruktur
- docs/SCAN-PIPELINE-v2.md — v2 Pipeline-Spezifikation (6 Phasen, 5 Pakete, 4 AI-Punkte)
- docs/PIPELINE-PLAN-v2.md — Umsetzungsplan v2 (Phasen I–VI)
- references/report_structure.md — PDF-Layout-Referenz (Farbschema, Sektionen, Finding-Template)

## Fünf Pakete (WebCheck, Perimeter, Compliance, SupplyChain, Insurance)
- WebCheck: Schnellscan (~15–20 Min), Website + Mail-Security, max 3 Hosts, einfache Sprache
- Perimeter: Vollscan (~60–90 Min), alle Tools, max 15 Hosts, PTES-konform
- Compliance: = Perimeter-Scan + §30 BSIG-Mapping, BSI-Grundschutz-Refs, Audit-Trail
- SupplyChain: = Perimeter-Scan + ISO 27001 Annex A Mapping, Auftraggeber-Nachweis
- Insurance: = Perimeter-Scan + Versicherungs-Fragebogen, Risk-Score, Ransomware-Indikator

Legacy-Aliase: basic→webcheck, professional→perimeter, nis2→compliance

Das Paket wird bei POST /api/orders mitgegeben und steuert:
- Scan-Worker: Welche Tools laufen, Timeouts, Max-Hosts (scanner/packages.py)
- Phase 3: Enrichment-Tiefe (WebCheck: nur KEV+NVD, Perimeter+: vollständig)
- Claude-Prompt: Fünf Varianten (reporter/prompts.py)
- Report-Mapper: Fünf Mapper-Funktionen (reporter/report_mapper.py)
- Compliance-Module: Paketspezifische Mappings (reporter/compliance/)
- PDF-Engine: Paketspezifische Sektionen + Branding (reporter/pdf/generate_report.py)

Branding: Alle Farben kommen aus reporter/pdf/branding.py (VectiScan CI). NICHT hardcoden.

## AI-Modelle
- Haiku 4.5 (`claude-haiku-4-5-20251001`): Host Strategy, Phase-2-Config, Report-QA
- Sonnet 4.6 (`claude-sonnet-4-6`): Phase-3-Priorisierung, Report-Generierung
