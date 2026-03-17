# VectiScan — Scope

## Ziel
Automatisierte Security-Scan-Plattform mit drei Paketen (Basic, Professional, NIS2).
Internes Tool hinter Traefik (internal-only), kein öffentlicher Zugang.

## Implementiert

### Authentication & Benutzerverwaltung
- Registrierung, Login, Passwort-Reset per E-Mail
- JWT-basierte Authentifizierung
- Zwei Rollen: `customer` und `admin`
- Kunden-Tabelle mit Zuordnung zu Benutzer-Accounts
- Ownership-Checks: Kunden sehen nur eigene Orders

### Admin Panel
- Benutzerliste mit Rollenverwaltung
- Benutzer erstellen/löschen
- System-Statistiken (User, Orders, Status-Breakdown)

### Frontend
- Next.js 15 App unter scan.vectigal.tech (internal-only)
- **Login/Register-Seiten** mit JWT-Verwaltung
- **Dashboard** mit Order-Liste, Severity-Bars, Risk-Badges
- **Findings-Viewer** mit Severity-Filter und Detailansicht
- **Recommendations-Viewer** (aus Claude-Daten)
- **Scan-Detail-Seite** (`/scan/[orderId]`) mit:
  - Live-Fortschrittsanzeige via WebSocket
  - AI Intelligence Panel (Radar-Topologie, Host-Discovery-Matrix, AI-Decision-Feed, Metrics-Grid)
  - Terminal-Ansicht mit Tool-Outputs
  - Debug-Mode für technische Details
- **Verifizierungsseite** (`/verify/[orderId]`) mit DNS-TXT, File, Meta-Tag Anweisungen
- **Package-Selector** (Basic, Professional, NIS2) beim Order-Erstellen
- **Profilseite** mit Passwort-Änderung
- **Zeitplan-Verwaltung** (`/schedules`) mit CRUD
- **Admin-Seite** (`/admin`) mit Benutzerverwaltung und Statistiken
- **Passwort-Reset-Flow** (`/forgot-password`, `/reset-password`)
- App Header mit Navigation und Benutzer-Menü

### Backend-API
- `POST /api/orders` — Order anlegen mit Paket-Auswahl und Verifikations-Token
- `GET /api/orders` — Order-Liste (Admin: alle, Kunde: eigene)
- `GET /api/orders/:id` — Status mit Live-Fortschritt aus Redis
- `DELETE /api/orders/:id` — Soft-Cancel oder Admin-Hard-Delete
- `GET /api/orders/:id/report` — PDF-Stream (Auth via JWT oder Download-Token)
- `GET /api/orders/:id/results` — Raw Scan-Results pro Tool
- `GET /api/orders/:id/events` — AI-Strategie, AI-Configs, Tool-Outputs (Event Replay)
- `GET /api/orders/:id/findings` — Strukturierte Befunde aus dem Report
- Auth-Endpoints: Register, Login, Me, Forgot-Password, Reset-Password, Change-Password
- Admin-Endpoints: User-Liste, Rolle ändern, User löschen, System-Statistiken
- Schedule-Endpoints: CRUD für wiederkehrende Scans
- Verifikations-Endpoints: Check (DNS/File/Meta), Manual-Bypass, Status
- WebSocket: Real-Time Progress mit Event-Replay für Late-Joining Clients
- Input-Validierung, Ownership-Checks, Audit-Log
- Backward-Compatibility Redirects von `/api/scans` zu `/api/orders`

### Domain-Verifizierung
- Drei Methoden: DNS-TXT-Record, File-Upload, Meta-Tag
- Manueller Bypass für Prototyp-/Entwicklungszwecke
- Verifizierung löst automatisch den Scan aus

### Drei Scan-Pakete
- **Basic**: Schnellscan (~10 Min), weniger Tools, Top-100 Ports, max 5 Hosts
- **Professional**: Vollscan (~45 Min), alle Tools, Top-1000 Ports, max 10 Hosts
- **NIS2 Compliance**: Gleicher Scan wie Pro, Report mit §30 BSIG-Mapping, Compliance-Summary, Lieferketten-Zusammenfassung

### Scan-Worker
- Drei-Phasen-Modell (Phase 0 + Phase 1 + Phase 2)
- **AI-Orchestrierung**: Haiku entscheidet Host-Strategie und Tool-Konfiguration
- **Web Probe**: httpx-Check in Phase 0, um Web-Content zu erkennen
- **FQDN-Priorisierung**: Basisdomain first, Mail last
- **CMS-Fallback-Erkennung**: wp-login.php Probe wenn webtech nichts findet
- **Nuclei Performance-Flags**: -no-interactsh, -timeout 5, Severity je nach Paket
- **WPScan**: CMS-adaptive WordPress-Scans (nur wenn WordPress erkannt)
- **katana**: Web-Crawler für Endpoint-Discovery
- Fortschritts-Updates via Redis Pub/Sub
- Rohdaten-Upload nach MinIO als tar.gz
- Tool-Versionen werden bei Scan-Start erfasst
- Cancellation-Check: Worker prüft regelmäßig, ob Order abgebrochen wurde

### Report-Worker
- Drei Prompt-Varianten (Basic, Professional, NIS2) via `prompts.py`
- CWE-Validierung und CVSS-Score-Capping Pipeline
- Drei Mapper-Funktionen via `report_mapper.py`
- PDF-Generierung mit VectiScan-Branding (`branding.py`)
- NIS2: §30 BSIG-Mapping, Compliance-Summary, Lieferketten-1-Seiter
- Claude API Integration (Sonnet)
- Findings-Daten werden in `reports.findings_data` gespeichert (Dashboard)

### Wiederkehrende Scans
- Zeitplan-Typen: wöchentlich, monatlich, quartalsweise, einmalig
- Scheduler-Tick-Loop (60s Intervall) im API-Server
- Row-Level-Locking (`FOR UPDATE SKIP LOCKED`) gegen Doppelverarbeitung
- Domain muss zuvor verifiziert worden sein
- Automatische Order-Erstellung mit Status `queued` (überspringt Verifikation)
- `once`-Schedules werden nach Ausführung deaktiviert

### WebSocket Real-Time Progress
- `/ws?orderId=<uuid>` für Live-Updates
- Redis Pub/Sub als Transportschicht
- Event-Replay für late-joining Clients (Host-Discovery, AI-Strategie, AI-Configs, Tool-Outputs)
- Events werden in `scan_results` persistiert

### Infrastruktur
- docker-compose.yml für vectigal-docker02
- GitLab CI/CD Pipeline (Multi-Image-Build, Trivy-Scan)
- PostgreSQL, Redis, MinIO als Container
- Subdomains: scan.vectigal.tech (Frontend), scan-api.vectigal.tech (API)
- SSL via Let's Encrypt HTTP-01

## Nicht im Scope
- Stripe / Zahlungsflow
- E-Mail-Versand (Resend) — vorbereitet aber nicht aktiv
- Öffentlicher Zugang (nur internes Netzwerk)
- Parallele Scan-Worker (Hosts werden sequenziell gescannt)
- Fallback-Report-Generator (ohne Claude API)
- CMS-spezifische Scanner für Joomla, Drupal (nur WordPress via WPScan)
