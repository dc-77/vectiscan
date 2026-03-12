# VectiScan Prototyp — Scope

## Ziel
Validierung der Scanner-Pipeline und Report-Generierung in einem internen Tool.
Kein produktiver Betrieb, kein Kundenzugang.

## Im Scope

### Frontend
- Single-Page-App unter scan.vectigal.tech (internal-only)
- Domain-Eingabefeld mit Start-Button
- Live-Fortschrittsanzeige:
  - Aktuelle Phase (DNS-Recon / Phase 1 / Phase 2 / Report)
  - Aktuelles Tool (z.B. "nmap läuft auf 88.99.35.112")
  - Entdeckte Hosts (Liste aus Phase 0)
  - Fortschrittsbalken (Host X von Y)
- Download-Button für fertigen PDF-Report
- Fehleranzeige bei fehlgeschlagenen Scans
- Polling alle 3 Sekunden gegen GET /api/scans/:id

### Backend-API
- POST /api/scans — Domain annehmen, Scan-Job in Queue schreiben
- GET /api/scans/:id — Scan-Status mit Fortschrittsdetails
- GET /api/scans/:id/report — Pre-Signed MinIO URL für PDF-Download
- GET /health — Health-Check für Traefik
- Input-Validierung: Domain-Format prüfen (kein Schema, kein Pfad, nur FQDN)
- Kein Auth, kein Rate-Limiting (internes Tool)

### Scan-Worker
- Vollständiges Drei-Phasen-Modell (Phase 0 + Phase 1 + Phase 2)
- Alle Tools aus der Architekturplanung (außer CMS-spezifische: wpscan, joomscan)
- Fortschritts-Updates in Redis (Phase, aktuelles Tool, aktueller Host)
- Rohdaten-Upload nach MinIO als tar.gz
- Timeouts pro Tool wie in docs/SCAN-TOOLS.md definiert

### Report-Worker
- Claude API Integration (Sonnet) mit dem Prompt aus der Architekturplanung
- PDF-Generierung mit ReportLab
- Upload nach MinIO
- Status-Update in PostgreSQL

### Infrastruktur
- docker-compose.yml für vectigal-docker02
- GitLab CI/CD Pipeline (Multi-Image-Build nach Betriebshandbuch Beispiel C)
- Trivy-Scan zwischen Build und Deploy
- PostgreSQL, Redis, MinIO als Container im Projekt-Netzwerk
- Subdomains: scan.vectigal.tech (Frontend), scan-api.vectigal.tech (API)
- Beide mit internal-only@file Middleware (nur internes Netzwerk)
- SSL-Zertifikate automatisch per Let's Encrypt HTTP-01 (Traefik-Default)

## Nicht im Scope
- Domain-Verifizierung (DNS-TXT, File, Meta-Tag)
- Stripe / Zahlungsflow
- E-Mail-Versand (Resend)
- Kunden-Tabelle / Accounts
- Rate-Limiting auf API-Endpoints
- NIS2-Compliance-Mapping im Report
- CMS-spezifische Scanner (WPScan, Joomscan, Droopescan)
- WebSocket (Polling reicht)
- Fallback-Report-Generator (ohne Claude API)
- Mehrere Scan-Worker parallel