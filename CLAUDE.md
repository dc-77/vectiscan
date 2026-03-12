# VectiScan — Prototyp

## Was ist VectiScan?
Automatisierte Security-Scan-Plattform. Der Prototyp ist ein internes Tool zum
Testen der Scanner- und Report-Pipeline. Kein Zahlungsflow, keine Domain-Verifizierung,
kein E-Mail-Versand. Nur: Domain eingeben → Scannen → PDF-Report herunterladen.

## Zielumgebung
- Server: vectigal-docker02 (Debian 13, 192.168.8.44, DMZ)
- Reverse Proxy: Traefik v3.6 (Auto-Discovery über Labels)
- Registry: git-extern.bergersysteme.com:5050
- CI/CD: GitLab Runner auf vectigal-docker02 (Shell Executor, Tag: vectigal)
- Zugriff: nur internes Netzwerk (Traefik-Middleware: internal-only@file)
- DNS: *.vectigal.tech zeigt auf den Server
- SSL: Let's Encrypt HTTP-01 pro Subdomain (Traefik-Default, kein Label nötig)

WICHTIG — Subdomain-Kollision vermeiden:
Die Gutachten-KI belegt bereits api.vectigal.tech. VectiScan nutzt deshalb:
- scan.vectigal.tech → Frontend (Next.js, Port 3000)
- scan-api.vectigal.tech → Backend API (Fastify, Port 4000)

## Tech-Stack
| Komponente      | Technologie                            |
|-----------------|----------------------------------------|
| Frontend        | Next.js 15 (App Router), Tailwind CSS  |
| Backend-API     | Node.js, Fastify, TypeScript           |
| Datenbank       | PostgreSQL 16.4-alpine                 |
| Queue           | Redis 7.4-alpine + BullMQ             |
| Scan-Worker     | Python 3.12, debian:bookworm-slim Base |
| Report-Worker   | Python 3.12, ReportLab, Claude API     |
| Object Storage  | MinIO (S3-kompatibel)                  |

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
  /tmp/scan-<scanId>/ mit der Verzeichnisstruktur aus docs/SCAN-TOOLS.md

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

## API-Endpoints (Prototyp)
Siehe docs/API-SPEC.md für Details.
- POST /api/scans           → Neuen Scan starten (Body: { domain })
- GET  /api/scans/:id       → Status + Fortschritt abrufen
- GET  /api/scans/:id/report → Download-URL für PDF
- GET  /health              → Health-Check für Traefik

## Datenbank
Siehe docs/DB-SCHEMA.sql für das vollständige Schema.
Drei Tabellen: scans, scan_results, reports.
Kein customers-Table, keine Zahlungsfelder.

## Scan-Worker
Drei-Phasen-Modell:
- Phase 0: DNS-Reconnaissance (subfinder, amass, gobuster dns, crt.sh, dnsx)
- Phase 1: Technologie-Erkennung pro Host (nmap, webtech, wafw00f)
- Phase 2: Tiefer Scan pro Host (testssl.sh, nikto, nuclei, gobuster dir, gowitness)
Tool-Konfiguration und Timeouts: siehe docs/SCAN-TOOLS.md
Max 10 Hosts, Gesamt-Timeout 120 Minuten.
Hosts werden sequenziell gescannt (kein paralleles Scanning im Prototyp).

## Report-Worker
1. Rohdaten aus MinIO laden (scan-rawdata/<scanId>.tar.gz)
2. Tool-Outputs parsen und strukturieren
3. Claude API aufrufen (Sonnet, JSON-Output, deutscher Text)
4. PDF mit ReportLab generieren
5. PDF nach MinIO hochladen (scan-reports/<scanId>.pdf)
6. Scan-Status auf report_complete setzen
Prompt-Struktur und Output-Format: siehe docs/architecture.md Abschnitt 11.

## CI/CD
Multi-Image-Build nach dem Muster aus dem Betriebshandbuch (Beispiel C: Gutachten-KI).
Variable BASE_IMAGE statt IMAGE. Vier parallele Build-Jobs:
build-frontend, build-api, build-scan-worker, build-report-worker.
Trivy-Scan-Stage zwischen Build und Deploy (--severity CRITICAL, --ignore-unfixed).
Deploy-Sleep: 15 Sekunden (7 Container brauchen Zeit für Healthchecks).

## Wichtige Referenz-Dokumente
- docs/PROTOTYPE-SCOPE.md — Was ist im Prototyp drin, was nicht
- docs/API-SPEC.md — API-Spezifikation
- docs/DB-SCHEMA.sql — Datenbankschema
- docs/SCAN-TOOLS.md — Alle Scan-Tools mit Argumenten und Output-Format
- docs/architecture.md — Architektur-Auszüge aus der Gesamtplanung