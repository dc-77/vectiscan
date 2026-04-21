# VectiScan — Verzeichnisstruktur (Stand: 2026-04-21)

Mono-Repo mit vier Diensten: `frontend/`, `api/`, `scan-worker/`,
`report-worker/`. Pro Dienst eigenes Dockerfile. `docker-compose.yml` im
Root definiert alle Container. Docs unter `docs/`.

```
vectiscan/
├── CLAUDE.md                              ← Projektkontext für Claude Code
├── KNOWN-ISSUES.md                        ← Bekannte Probleme (Root, Stand der v1)
├── PACKAGE-COMPARISON.md                  ← Paketvergleich (Root, Stand der v1)
├── plan.md                                ← Historischer Auth-Plan
├── docker-compose.yml                     ← Produktion (9 Container)
├── docker-compose.dev.yml                 ← Lokale Entwicklung
├── .env.template                          ← Alle erforderlichen Env-Vars
├── .gitlab-ci.yml                         ← Multi-Image-Build + Trivy + Deploy
│
├── docs/
│   ├── API-SPEC.md                        ← Vollständige API-Spezifikation
│   ├── DB-SCHEMA.sql                      ← Schema (Migrationen 003–013)
│   ├── PROTOTYPE-SCOPE.md                 ← Status quo (was implementiert ist)
│   ├── SCAN-PIPELINE-DETAIL.md            ← 6-Phasen-Pipeline im Detail
│   ├── SCAN-TOOLS.md                      ← Tools, Pakete, KI-Prompts
│   ├── STRUCTURE.md                       ← Diese Datei
│   ├── architecture.md                    ← Architektur-Referenz
│   ├── VectiScan_Master_Plan.md           ← UX-Audit + Sprint-Plan (April)
│   ├── review-todo.md                     ← Offene Punkte aus alten Plänen
│   └── brand.html                         ← Visuelle Brand-Referenz
│
├── references/
│   └── report_structure.md                ← PDF-Layout-Referenz
│
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       ├── app/
│       │   ├── layout.tsx
│       │   ├── globals.css
│       │   ├── page.tsx                   ← Landing (mit OrderId-Redirect)
│       │   ├── login/page.tsx
│       │   ├── register/page.tsx          ← Redirect-Stub auf /login?tab=register
│       │   ├── forgot-password/page.tsx
│       │   ├── reset-password/page.tsx
│       │   ├── welcome/page.tsx           ← Onboarding-Flow für Neukunden
│       │   ├── dashboard/page.tsx         ← Security-Cockpit + Scan-Liste
│       │   ├── scan/page.tsx              ← Wizard für neue Orders
│       │   ├── scan/[orderId]/page.tsx    ← Live-Detail
│       │   ├── scans/[groupKey]/page.tsx  ← Gruppen-Detail (Abo oder Domain)
│       │   ├── verify/[orderId]/page.tsx
│       │   ├── schedules/page.tsx
│       │   ├── subscribe/page.tsx         ← Abo-Wizard
│       │   ├── pricing/page.tsx
│       │   ├── profile/page.tsx
│       │   ├── admin/page.tsx
│       │   ├── impressum/page.tsx
│       │   └── datenschutz/page.tsx
│       ├── components/
│       │   ├── AppHeader.tsx              ← Hamburger + Notification-Placeholder
│       │   ├── Toast.tsx                  ← In-App-Feedback-System
│       │   ├── PackageSelector.tsx        ← 6 Paket-Karten
│       │   ├── HostList.tsx
│       │   ├── ScanProgress.tsx
│       │   ├── ScanError.tsx
│       │   ├── ReportDownload.tsx
│       │   ├── SeverityBar.tsx
│       │   ├── SeverityCounts.tsx
│       │   ├── FindingsViewer.tsx
│       │   ├── RecommendationsViewer.tsx
│       │   ├── ScanIntelligence.tsx
│       │   ├── VectiScanLogo.tsx
│       │   ├── intelligence/
│       │   │   ├── RadarTopology.tsx
│       │   │   ├── MetricsGrid.tsx
│       │   │   ├── AiDecisionFeed.tsx
│       │   │   ├── HostDiscoveryMatrix.tsx
│       │   │   ├── DataStream.tsx
│       │   │   ├── PacketStream.tsx
│       │   │   └── constants.ts
│       │   └── terminal/
│       │       ├── ScanTerminal.tsx
│       │       ├── ToolProgress.tsx
│       │       ├── TerminalLine.tsx
│       │       ├── NoiseMatrix.tsx
│       │       ├── ScrambleText.tsx
│       │       ├── ToolWatermark.tsx
│       │       ├── ActiveOperations.tsx
│       │       └── useTerminalFeed.ts
│       ├── hooks/
│       │   └── useWebSocket.ts            ← Auto-Reconnect-Hook
│       └── lib/
│           ├── api.ts                     ← API-Client mit Bearer-Header
│           ├── auth.ts                    ← Token-Management, isAdmin/isLoggedIn
│           ├── grouping.ts                ← groupOrders() für Dashboard-Karten
│           ├── toolLabels.ts              ← Tool-Name-Mapping (CEO-tauglich)
│           └── utils.ts                   ← STATUS_LABELS, formatDuration, …
│
├── api/
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       ├── server.ts                      ← Fastify-Boot, Route-Registrierung
│       ├── routes/
│       │   ├── health.ts                  ← GET /health
│       │   ├── auth.ts                    ← Auth + Admin-Endpoints + AI-Costs + Diagnose
│       │   ├── orders.ts                  ← Orders + Findings + Diff + Versions + Approve/Reject
│       │   ├── verify.ts                  ← Domain-Verifizierung
│       │   ├── schedules.ts               ← Wiederkehrende Scans
│       │   ├── subscriptions.ts           ← Abo-Workflow + Domain-Approval
│       │   └── ws.ts                      ← WebSocket mit Event-Replay
│       ├── middleware/
│       │   ├── requireAuth.ts             ← JWT-Verifizierung
│       │   └── requireAdmin.ts            ← Admin-Rolle prüfen
│       ├── services/
│       │   └── VerificationService.ts     ← DNS-TXT, File, Meta-Tag Check
│       ├── lib/
│       │   ├── db.ts                      ← PostgreSQL-Client + Migrations-Runner
│       │   ├── queue.ts                   ← Redis/BullMQ + Pub/Sub
│       │   ├── minio.ts                   ← MinIO-Client + Bucket-Init
│       │   ├── auth.ts                    ← Bcrypt + JWT (HS256)
│       │   ├── audit.ts                   ← Audit-Log-Schreiber
│       │   ├── validate.ts                ← Domain/IP/CIDR/Subnet-Validierung
│       │   ├── email.ts                   ← Resend-Client (Password-Reset)
│       │   ├── ws-manager.ts              ← WebSocket Subscribe/Publish
│       │   └── scheduler.ts               ← Tick-Loop für Schedules
│       └── migrations/
│           ├── 002_add_package.sql
│           ├── 003_mvp_schema.sql         ← customers, orders, scan_results, reports, audit_log
│           ├── 004_add_manual_verification.sql
│           ├── 005_users.sql
│           ├── 006_password_reset.sql
│           ├── 007_report_findings_data.sql
│           ├── 008_scan_schedules.sql
│           ├── 009_v2_packages.sql        ← 5 Pakete + threat_intel_cache + neue Spalten
│           ├── 010_verified_domains.sql   ← Persistente Domain-Verifizierung (90 d)
│           ├── 011_finding_exclusions_report_versioning.sql
│           ├── 012_subscriptions_review_workflow.sql
│           └── 013_company_name.sql
│
├── scan-worker/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── scanner/
│       ├── __init__.py
│       ├── __main__.py
│       ├── worker.py                      ← Job-Consumer + Orchestrierung
│       ├── packages.py                    ← 6 Paket-Konfigurationen
│       ├── phase0a.py                     ← Passive Intelligence
│       ├── phase0.py                      ← DNS-Reconnaissance + Web-Probe
│       ├── phase1.py                      ← Tech-Detection + CMS-Fingerprint
│       ├── phase2.py                      ← Deep Scan (3-Stage-Pipeline)
│       ├── phase3.py                      ← Correlation + Enrichment
│       ├── ai_strategy.py                 ← 4 KI-Entscheidungspunkte
│       ├── cms_fingerprinter.py           ← 5-Methoden-Erkennungsengine
│       ├── progress.py                    ← Redis-Pub/Sub + DB-Fortschritt
│       ├── upload.py                      ← tar.gz packen, MinIO upload, Report-Job
│       ├── diagnose.py                    ← Tool/Env/Probe-Diagnose
│       ├── passive/
│       │   ├── base_client.py
│       │   ├── shodan_client.py
│       │   ├── abuseipdb_client.py
│       │   ├── securitytrails_client.py
│       │   ├── whois_client.py
│       │   └── dns_security.py            ← DNSSEC, CAA, MTA-STS, DANE/TLSA
│       ├── correlation/
│       │   ├── correlator.py              ← Cross-Tool-Korrelation
│       │   ├── fp_filter.py               ← 6 FP-Regeln
│       │   ├── threat_intel.py            ← NVD, EPSS, CISA KEV, ExploitDB
│       │   └── business_impact.py         ← CVSS × EPSS × KEV × Asset × Paket
│       └── tools/
│           ├── __init__.py                ← Subprocess-Runner mit Timeout/Cleanup
│           ├── zap_client.py              ← ZAP-REST-API-Client
│           ├── zap_mapper.py              ← ZAP-Alert → Finding
│           └── redirect_probe.py          ← Playwright-basierte Redirect-Probe
│
└── report-worker/
    ├── Dockerfile
    ├── requirements.txt
    └── reporter/
        ├── __init__.py
        ├── __main__.py
        ├── worker.py                      ← BullMQ-Consumer + Orchestrierung
        ├── parser.py                      ← Tool-Output-Parser → Findings
        ├── claude_client.py               ← Claude API + JSON-Parsing + Retry
        ├── prompts.py                     ← 5 Prompt-Varianten
        ├── report_mapper.py               ← Claude-Output → report_data (5 Mapper)
        ├── qa_check.py                    ← Programmatische QA + Haiku-Plausibilität
        ├── cwe_reference.py               ← Lokale CWE-Tabelle + CVSS-Capping
        ├── cwe_api_client.py              ← Optionaler MITRE-CWE-API-Client
        ├── tr03116_checker.py             ← BSI TR-03116-4 für TLSCompliance
        ├── generate_report.py             ← PDF-Engine (pentest-report-generator-Skill)
        ├── compliance/
        │   ├── nis2_bsig.py
        │   ├── iso27001.py
        │   ├── bsi_grundschutz.py
        │   ├── nist_csf.py
        │   └── insurance.py
        └── pdf/
            ├── __init__.py
            └── branding.py                ← Zentrale Farben/Logos
```
