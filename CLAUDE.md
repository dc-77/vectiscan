# VectiScan v2

## Was ist VectiScan?
Automatisierte Security-Scan-Plattform mit fünf Paketen
(WebCheck, Perimeter, Compliance, SupplyChain, Insurance).
Internes Tool hinter Traefik (internal-only). User registrieren sich, legen
Multi-Target-Scan-Orders an, Admin reviewt Targets, danach läuft der Scan
und der Customer bekommt einen PDF-Report.

## Zielumgebung
- Server: vectigal-docker02 (Debian 13, 192.168.8.44, DMZ)
- Reverse Proxy: Traefik v3.6 (Auto-Discovery via Labels, Let's-Encrypt-Default)
- Registry: ghcr.io/dc-77/vectiscan
- CI/CD: GitLab `git-extern.bergersysteme.com/vectigal/vectiscan`,
  Runner mit Tag `vectigal` (Shell Executor) auf vectigal-docker02
- Zugriff nur internes Netz (Traefik-Middleware `internal-only@file`)
- DNS: `*.vectigal.tech` zeigt auf den Server

**Subdomain-Kollision** — die Gutachten-KI belegt schon `api.vectigal.tech`.
VectiScan nutzt deshalb:
- `scan.vectigal.tech` → Frontend (Next.js, Port 3000)
- `scan-api.vectigal.tech` → Backend API (Fastify, Port 4000)

## Tech-Stack
| Komponente      | Technologie |
|-----------------|------------------------------------------------------|
| Frontend        | Next.js 15 (App Router), Tailwind CSS                |
| Backend-API     | Node.js, Fastify, TypeScript                         |
| Datenbank       | PostgreSQL 16.4-alpine                               |
| Queue           | Redis 7.4-alpine + BullMQ                            |
| Scan-Worker     | Python 3.12, debian:bookworm-slim Base               |
| Report-Worker   | Python 3.12, Claude API, pentest-report-generator    |
| Object Storage  | MinIO (S3-kompatibel)                                |

## Repo-Struktur
Mono-Repo mit vier Diensten: `frontend/`, `api/`, `scan-worker/`, `report-worker/`.
Jeder Dienst hat ein eigenes Dockerfile. `docker-compose.yml` im Root
definiert alle Container (inkl. precheck-worker-1/2 als zweiter
scan-worker-Image-Variant). Docs in `docs/`.

## Konventionen
- TypeScript strict mode (Frontend + API), Python Type Hints (Worker)
- Alle Env-Variablen via `.env`, nie hardcoded
- API-Responses: `{ "success": true, "data": {...} }` oder
  `{ "success": false, "error": "..." }`
- Logging: strukturiertes JSON (pino in Node, structlog in Python)
- Docker: Multi-Stage, Non-Root User
- Scan-Tool-Outputs als JSON wo möglich, gespeichert unter
  `/tmp/scan-<orderId>/` (Layout in `docs/SCAN-TOOLS.md`)

## Netzwerk-Architektur
- `proxy-net`: Traefik ↔ frontend, api
- `vectiscan-internal`: alle Container untereinander
- frontend + api hängen in beiden Netzen, alles andere nur internal
- Scan-Worker braucht Internet-Outbound (NAT via ens192, `iptables=false`)

## Authentication
- JWT-Auth (Register, Login, Password-Reset). Zwei Rollen: `customer`, `admin`.
- Middleware: `requireAuth`, `requireAdmin`.
- Report-Download: JWT oder Download-Token (für E-Mail-Links).

## API + DB
- API-Endpoints vollständig in `docs/API-SPEC.md`. Highlights:
  Multi-Target Orders, Subscriptions, Schedules, Verification, Admin-Review,
  WebSocket `/ws?orderId=` mit Event-Replay.
- DB-Schema: `docs/DB-SCHEMA.sql`. Migrations in `api/src/migrations/` werden
  beim API-Start idempotent über `information_schema`-Existence-Checks
  in `api/src/lib/db.ts::initDb()` angewendet (keine `migrations`-Versionstabelle).

## Multi-Target-Flow (Kurz)
1. POST `/api/orders` mit `targets[]` → Status `precheck_running`,
   Job in Redis-Queue `precheck-pending`.
2. precheck-worker prüft DNS/httpx/nmap-Top-10/Cloud-Provider, schreibt
   `scan_target_hosts`. Status → `pending_target_review`.
3. Admin reviewt unter `/admin/review/[orderId]`, lädt scan_authorizations
   hoch, ruft `release` auf → `scan-pending`-Queue.
4. Scan-Worker: Phase 0b policy-aware, `scope.enforce_scope()`,
   dann Phase 1–3.

Target-Typen: `fqdn_root`, `fqdn_specific`, `ipv4`, `cidr`.
Discovery-Policies: `enumerate`, `scoped`, `ip_only`.
Limits: 10 Eingabezeilen, 1 CIDR (≥/24), 50 lebende Hosts (`subscriptions.max_hosts`).

## Scan-Worker (6 Phasen, 4 KI-Punkte)
0a Passive Intel (Shodan/AbuseIPDB/SecurityTrails/WHOIS) →
0b DNS+httpx+Scope →
**KI #1 Host-Strategy (Haiku)** →
1 Tech-Detection (nmap, webtech, wafw00f, CMS-Fingerprint) →
**KI #2 CMS-Korrektur (Haiku) + KI #3 Phase-2-Config (Haiku)** →
2 Deep-Scan (testssl, nikto, nuclei, gobuster, ffuf, feroxbuster, katana,
dalfox, gowitness, headers, httpx, wpscan) →
**KI #4 Cross-Tool-Confidence (Sonnet, nur Confidence-Boost)** →
3 Correlation + Threat-Intel (NVD, EPSS, CISA-KEV, ExploitDB) +
deterministischer FP-Filter + Business-Impact.

Tool-Konfig/Timeouts: `docs/SCAN-TOOLS.md`. Max-Hosts: WebCheck 3, Perimeter+ 15.

## Report-Worker
1. Rohdaten aus MinIO laden
2. parser.py + Claude API (claude_client.py, JSON, deutsch, 5 Prompt-Varianten)
3. QA-Checks (qa_check.py)
4. **Determinismus-Pipeline** (Q2/2026): finding_type_mapper →
   severity_policy.apply_policy → business_impact.recompute → selection.select_findings
   (siehe Block unten)
5. report_mapper.py → PDF (generate_report.py) → MinIO (`scan-reports/`)
6. `reports.findings_data` + `policy_version` + `policy_id_distinct` in DB
7. Order-Status auf `report_complete` (oder `pending_review`)

Compliance-Module unter `report-worker/reporter/compliance/`:
nis2_bsig, iso27001, bsi_grundschutz, nist_csf, insurance.

## Determinismus-Block (Q2/2026)
Spec: `docs/deterministic/`. Stand: produktiv ab Migration 016/017.
- **Severity-Policy** (`reporter/severity_policy.py`, ~40 Regeln,
  `POLICY_VERSION` aus ENV/Default `2026-04-30.1`) ueberschreibt Tool-Severities
  deterministisch; jede Severity bekommt `policy_id` + `severity_provenance`.
- **Selection** (`reporter/selection.py`) konsolidiert über Hosts und wählt
  Top-N pro Paket: WebCheck 8, Perimeter 15, Compliance 20, SupplyChain 15,
  Insurance 15. Stable-Sort mit `finding_id` als Tiebreaker.
- **AI-Cache** (`scan-worker/scanner/ai_cache.py`,
  `report-worker/reporter/ai_cache.py`) — alle 5 KI-Calls laufen mit
  `temperature=0.0` durch Redis-Cache; Hash inkl. `POLICY_VERSION` (Auto-
  Invalidate bei Bump). Namespaces: `ki1_host_strategy`, `ki2_tech_analysis`,
  `ki3_phase2_config`, `ki4_phase3`, `reporter_v1`.
- **DB-Audit** (Migration 016): `reports.policy_version`,
  `reports.policy_id_distinct`, `reports.severity_counts` (Trigger).
- **Cleanup-Skript**: `scripts/cleanup-prod.sh` plus manueller GitLab-Job
  `cleanup-prod` (siehe `.gitlab-ci.yml`, geschützt durch
  `CLEANUP_CONFIRM=vectiscan-prod`).

## CI/CD
- 4 parallele Build-Jobs (`frontend`, `api`, `scan-worker`, `report-worker`)
- Trivy-Scan-Stage (`--severity CRITICAL --ignore-unfixed`)
- Test-Stage pro Service
- Deploy: `deploy-auto` (main automatisch) + `deploy-manual` (web manual)
- `cleanup-prod`: Big-Bang Wipe als manueller Job, braucht
  `CLEANUP_CONFIRM=vectiscan-prod` als Pipeline-Variable
- Build dauert 15–20 Min — Push nicht ungefragt auslösen
  (siehe Memory `feedback_push_workflow.md`)

## GitLab-API (für Pipeline-Inspect/Trigger)
Helper-Script: `bash /c/Users/danie/.claude/projects/C--BS-Consulting-Projekte-Coding-vectiscan/gitlab-api.sh <cmd>`.
Subcommands: `pipelines [N]`, `pipeline <ID>`, `job <ID>`, `trace <ID>`,
`play <JOB_ID>`, `trigger <REF> [VAR=val]`, `raw <PATH>`.
Token in `/c/Users/danie/.claude/secrets/gitlab-vectiscan.token`,
URL/Project in `/c/Users/danie/.claude/projects/.../gitlab.config`.
Pfade nur in POSIX-Form (Git Bash). Details: Memory `reference_gitlab_api.md`.

## Fünf Pakete
| Paket | Eigenschaft |
|---|---|
| WebCheck | Schnellscan (~15–20 Min), Website + Mail-Security, max 3 Hosts |
| Perimeter | Vollscan (~60–90 Min), alle Tools, max 15 Hosts, PTES-konform |
| Compliance | Perimeter + §30 BSIG, BSI-Grundschutz-Refs, Audit-Trail |
| SupplyChain | Perimeter + ISO 27001 Annex A, Auftraggeber-Nachweis |
| Insurance | Perimeter + Versicherungs-Fragebogen, Ransomware-Indikator |

Legacy-Aliase: `basic→webcheck`, `professional→perimeter`, `nis2→compliance`.

Paket steuert: Scan-Tools/Timeouts (`scanner/packages.py`),
Phase-3-Enrichment-Tiefe, Claude-Prompt-Variante (`reporter/prompts.py`),
Report-Mapper, Compliance-Module, PDF-Sektionen, Top-N (`selection.py`).

Branding-Farben aus `reporter/pdf/branding.py` — nicht hardcoden.

## AI-Modelle
- Haiku 4.5 (`claude-haiku-4-5-20251001`): KI #1 Host-Strategy,
  KI #2 CMS-Korrektur, KI #3 Phase-2-Config, Report-QA
- Sonnet 4.6 (`claude-sonnet-4-6`): KI #4 Cross-Tool-Confidence,
  Report-Generierung

## Arbeitsweise
- Am Ende jeder abgeschlossenen Aufgabe: Kontext-Auslastung ausgeben (%-Wert)
- Push nur auf explizite Anfrage (Build dauert 15–20 Min)

## Wichtige Referenz-Dokumente
- `docs/API-SPEC.md` — vollständige API-Spec (alle Endpoints)
- `docs/DB-SCHEMA.sql` — Datenbankschema
- `docs/SCAN-TOOLS.md` — Tool-Konfig, Timeouts, Output-Format
- `docs/architecture.md` — Architektur inkl. AI-Orchestrierung und Event-System
- `docs/SCAN-PIPELINE-v2.md` — v2 Pipeline-Spec
- `docs/deterministic/` — Q2/2026 Determinismus-Block
  (00-OVERVIEW, 01-cleanup, 02-severity-policy, 03-ai-determinism,
  04-deterministic-selection, 05-schema-migrations, 99-CUTOVER)
- `references/report_structure.md` — PDF-Layout
