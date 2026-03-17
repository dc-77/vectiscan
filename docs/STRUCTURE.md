# VectiScan — Verzeichnisstruktur

```
vectiscan/
├── CLAUDE.md                              ← Projektkontext für Claude Code
├── docker-compose.yml                     ← Gesamtes Projekt (Produktion)
├── docker-compose.dev.yml                 ← Lokale Entwicklung
├── .env.template
├── .gitlab-ci.yml
│
├── docs/
│   ├── API-SPEC.md                        ← API-Endpoints mit Request/Response
│   ├── DB-SCHEMA.sql                      ← SQL-Schema (vollständig)
│   ├── SCAN-TOOLS.md                      ← Tool-Liste mit Argumenten und Paketen
│   ├── PROTOTYPE-SCOPE.md                 ← Feature-Scope
│   ├── STRUCTURE.md                       ← Diese Datei
│   └── architecture.md                    ← Architektur-Referenz
│
├── references/
│   └── report_structure.md                ← PDF-Layout-Referenz aus dem Skill
│
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       └── app/
│           ├── page.tsx                   ← Landing / Order erstellen
│           ├── login/page.tsx             ← Login
│           ├── forgot-password/page.tsx   ← Passwort vergessen
│           ├── reset-password/page.tsx    ← Passwort zurücksetzen
│           ├── dashboard/page.tsx         ← Order-Liste, Findings, Severity-Bars
│           ├── admin/page.tsx             ← Benutzerverwaltung, System-Stats
│           ├── profile/page.tsx           ← Passwort ändern
│           ├── schedules/page.tsx         ← Zeitplan-Verwaltung (CRUD)
│           ├── scan/[orderId]/page.tsx    ← Scan-Detail mit Debug-Mode
│           ├── verify/[orderId]/page.tsx  ← Domain-Verifizierung
│           ├── components/
│           │   ├── AppHeader.tsx           ← Navigation, Benutzer-Menü
│           │   ├── PackageSelector.tsx     ← Basic/Pro/NIS2 Auswahl
│           │   ├── HostList.tsx            ← Entdeckte Hosts
│           │   ├── ScanProgress.tsx        ← Fortschrittsanzeige
│           │   ├── ScanError.tsx           ← Fehleranzeige
│           │   ├── ReportDownload.tsx      ← PDF-Download-Button
│           │   ├── SeverityBar.tsx         ← Severity-Farbbalken
│           │   ├── SeverityCounts.tsx      ← Severity-Zähler
│           │   ├── FindingsViewer.tsx      ← Finding-Liste mit Filter
│           │   ├── RecommendationsViewer.tsx ← Empfehlungen
│           │   ├── ScanIntelligence.tsx    ← AI Intelligence Panel (Container)
│           │   ├── VectiScanLogo.tsx       ← Logo-Komponente
│           │   ├── intelligence/
│           │   │   ├── RadarTopology.tsx    ← Host-Netzwerk-Visualisierung
│           │   │   ├── MetricsGrid.tsx     ← Scan-Metriken
│           │   │   ├── AiDecisionFeed.tsx  ← AI-Entscheidungen Live-Feed
│           │   │   ├── HostDiscoveryMatrix.tsx ← Host-Entdeckungs-Matrix
│           │   │   └── DataStream.tsx      ← Daten-Stream-Animation
│           │   └── terminal/
│           │       ├── ScanTerminal.tsx    ← Terminal-Emulation
│           │       ├── ToolProgress.tsx    ← Tool-Fortschritt
│           │       ├── TerminalLine.tsx    ← Terminal-Zeile
│           │       ├── NoiseMatrix.tsx     ← Hintergrund-Animation
│           │       └── ScrambleText.tsx    ← Text-Scramble-Effekt
│           └── hooks/
│               └── useWebSocket.ts        ← WebSocket-Hook mit Auto-Reconnect
│
├── api/
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       ├── server.ts                      ← Fastify-Server, Route-Registrierung
│       ├── routes/
│       │   ├── orders.ts                  ← Order CRUD, Report-Download, Events, Findings
│       │   ├── auth.ts                    ← Register, Login, Me, Password-Reset, Admin
│       │   ├── schedules.ts               ← Schedule CRUD
│       │   ├── verify.ts                  ← Domain-Verifizierung
│       │   └── ws.ts                      ← WebSocket mit Event-Replay
│       ├── middleware/
│       │   ├── requireAuth.ts             ← JWT-Verifizierung
│       │   └── requireAdmin.ts            ← Admin-Rolle prüfen
│       ├── services/
│       │   └── VerificationService.ts     ← DNS-TXT, File, Meta-Tag Check
│       ├── lib/
│       │   ├── db.ts                      ← PostgreSQL-Client (pg)
│       │   ├── queue.ts                   ← Redis/BullMQ, Pub/Sub
│       │   ├── minio.ts                   ← MinIO-Client
│       │   ├── auth.ts                    ← Password-Hashing, JWT-Sign/Verify
│       │   ├── audit.ts                   ← Audit-Log-Schreiber
│       │   ├── validate.ts                ← Domain-Validierung
│       │   ├── email.ts                   ← E-Mail-Versand (vorbereitet)
│       │   ├── ws-manager.ts              ← WebSocket Subscribe/Unsubscribe/Publish
│       │   └── scheduler.ts               ← Tick-Loop für wiederkehrende Scans
│       └── migrations/
│           ├── 002_add_package.sql
│           ├── 003_mvp_schema.sql         ← customers, orders, scan_results, reports, audit_log
│           ├── 004_add_manual_verification.sql
│           ├── 005_users.sql              ← users Tabelle
│           ├── 006_password_reset.sql     ← reset_token Felder
│           ├── 007_report_findings_data.sql ← findings_data JSONB in reports
│           └── 008_scan_schedules.sql     ← scan_schedules Tabelle
│
├── scan-worker/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── scanner/
│       ├── __init__.py
│       ├── __main__.py                    ← Entry-Point
│       ├── worker.py                      ← Job-Consumer, Drei-Phasen-Orchestrierung
│       ├── packages.py                    ← Paket-Konfiguration (Basic/Pro/NIS2)
│       ├── phase0.py                      ← DNS-Recon, Web-Probe, Host-Inventar
│       ├── phase1.py                      ← Tech-Detection (nmap, webtech, wafw00f)
│       ├── phase2.py                      ← Deep-Scan (testssl, nikto, nuclei, etc.)
│       ├── ai_strategy.py                 ← Haiku Host-Strategy + Phase-2-Config
│       ├── tools.py                       ← Tool-Runner mit Timeout, Logging, DB-Persistenz
│       ├── progress.py                    ← Redis Pub/Sub, DB-Fortschritt
│       └── upload.py                      ← tar.gz packen, MinIO upload, Report-Job enqueuen
│
└── report-worker/
    ├── Dockerfile
    ├── requirements.txt
    └── reporter/
        ├── __init__.py
        ├── __main__.py                    ← Entry-Point
        ├── worker.py                      ← BullMQ Consumer, Orchestrierung
        ├── parser.py                      ← Tool-Output-Parser (JSON/XML → Findings)
        ├── claude_client.py               ← Claude API Aufruf + JSON-Parsing
        ├── prompts.py                     ← Drei Prompt-Varianten (Basic/Pro/NIS2)
        ├── report_mapper.py               ← Claude-Output → report_data (drei Mapper)
        ├── cwe_reference.py               ← CWE-Validierung + CVSS-Capping
        └── generate_report.py             ← PDF-Engine (pentest-report-generator Skill)
```
