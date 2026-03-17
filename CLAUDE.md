# VectiScan — Prototyp

## Was ist VectiScan?
Automatisierte Security-Scan-Plattform mit drei Paketen (Basic, Professional, NIS2).
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

### Orders
- POST /api/orders           → Neue Order anlegen (Body: { domain, package? })
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

### Schedules
- GET /api/schedules, POST /api/schedules, GET /api/schedules/:id
- PUT /api/schedules/:id, DELETE /api/schedules/:id

### Verification
- POST /api/verify/check, POST /api/verify/manual, GET /api/verify/status/:orderId

### WebSocket
- GET /ws?orderId=<uuid> → Real-Time Progress mit Event-Replay

### Health
- GET /health → Health-Check für Traefik

## Datenbank
Siehe docs/DB-SCHEMA.sql für das vollständige Schema.
Sieben Tabellen: customers, users, orders, scan_results, reports, audit_log, scan_schedules.

## Scan-Worker
Phase-First-Architektur mit AI-Orchestrierung:
1. Phase 0: DNS-Reconnaissance + Web-Probe (httpx)
2. AI Host Strategy: Haiku entscheidet scan/skip pro Host
3. Phase 1: Tech-Detection alle Hosts sequenziell (nmap, webtech, wafw00f)
4. AI Phase 2 Config: Haiku konfiguriert Tools pro Host
5. Phase 2: Deep-Scan alle Hosts sequenziell (testssl, nikto, nuclei, gobuster, etc.)

Tool-Konfiguration und Timeouts: siehe docs/SCAN-TOOLS.md
Max Hosts: Basic 5, Pro/NIS2 10. Gesamt-Timeout: Basic 15 Min, Pro/NIS2 120 Min.

## Report-Worker
1. Rohdaten aus MinIO laden (scan-rawdata/<orderId>.tar.gz)
2. Tool-Outputs parsen und strukturieren (parser.py)
3. Claude API aufrufen (claude_client.py, Sonnet, JSON-Output, deutscher Text)
   - Drei Prompt-Varianten: Basic, Professional, NIS2 (prompts.py)
4. CWE-Validierung + CVSS-Score-Capping (cwe_reference.py)
5. Claude-Output auf report_data-Struktur mappen (report_mapper.py)
6. PDF generieren via generate_report() aus dem Skill (generate_report.py)
7. PDF nach MinIO hochladen (scan-reports/<orderId>.pdf)
8. Findings-Daten in reports.findings_data speichern (Dashboard)
9. Order-Status auf report_complete setzen

## Frontend-Seiten
- `/` — Landing, Order erstellen mit Package-Selector
- `/login` — Login
- `/forgot-password`, `/reset-password` — Passwort-Reset-Flow
- `/dashboard` — Order-Liste, Findings-Viewer, Severity-Bars
- `/scan/[orderId]` — Scan-Detail mit Live-Progress, AI Intelligence Panel, Debug-Mode
- `/verify/[orderId]` — Domain-Verifizierung (DNS-TXT, File, Meta-Tag)
- `/schedules` — Zeitplan-Verwaltung (CRUD)
- `/profile` — Passwort ändern
- `/admin` — Benutzerverwaltung, System-Statistiken

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
- references/report_structure.md — PDF-Layout-Referenz (Farbschema, Sektionen, Finding-Template)

## Drei Pakete (Basic, Professional, NIS2)
Die drei Pakete sind implementiert:
- Basic: Schnellscan (~10 Min), weniger Tools, kompakter Report, max 5 Hosts
- Professional: Vollscan (~45 Min), alle Tools, max 10 Hosts
- NIS2 Compliance: Gleicher Scan wie Pro, Report mit §30 BSIG-Mapping, Audit-Trail, Lieferketten-1-Seiter

Das Paket wird bei POST /api/orders mitgegeben und steuert:
- Scan-Worker: Welche Tools laufen (scanner/packages.py)
- Claude-Prompt: Drei Varianten (reporter/prompts.py)
- Report-Mapper: Drei Mapper-Funktionen (reporter/report_mapper.py)
- PDF-Engine: NIS2-Sections + Branding (reporter/pdf/generate_report.py)

Branding: Alle Farben kommen aus reporter/pdf/branding.py (VectiScan CI). NICHT hardcoden.
