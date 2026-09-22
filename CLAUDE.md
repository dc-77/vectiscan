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
| Report-Worker   | Python 3.12, Prüfkatalog, WeasyPrint, Claude API      |
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

## Report-Worker (v3, seit S6)
**Kein Befund ohne Fakt aus einem Werkzeug.** Ein Sprachmodell schreibt Prosa und
recherchiert den Kundenkontext; es entscheidet weder über Befunde noch über deren
Einstufung und vergibt keine CVSS-Werte.

1. Rohdaten aus MinIO laden
2. **Fakten** (`reporter/facts/`) → `facts.json`, ein Schema, `FACTS_SCHEMA_VERSION`
3. **Prüfkatalog** (`reporter/catalog/`) → 73 Prüfungen als YAML, ein Ergebnis je
   Prüfung und Gruppe (`fail`/`pass`/`not_testable`/`not_applicable`), `CATALOG_VERSION`
4. **Reportdaten** (`reporter/v3/`) → Sachverhalte, Kapitel, Maßnahmenplan, Anhänge;
   zwei KI-Aufrufe (Prosa, Recherche) mit Wort- und Längen-Gate
5. **Renderer** (`reporter/pdf/v3/`, Jinja2 + WeasyPrint) → PDF → MinIO (`scan-reports/`)
6. **Gate** (`reporter/gate/`) → Defektliste in `orders.report_defects`; unter `strict`
   hält ein Fehler den Bericht auf, Order → `report_blocked`
7. `reports.findings_data` (aus den Katalogbefunden, `reporter/v3/dashboard.py`),
   `policy_version` = `Katalog <v> / Fakten <v>`, `policy_id_distinct` = die Regeln
8. Order-Status auf `pending_review`; `report_complete` nur nach Admin-Freigabe

Drei Schalter, gelesen in `reporter/engine.py`, ein unbekannter Wert ist ein Startfehler:

| Variable | Werte | Vorgabe |
|---|---|---|
| `VECTISCAN_REPORT_ENGINE` | `catalog`, `legacy` | `catalog` |
| `VECTISCAN_REPORT_LAYOUT` | `v3`, `v2`, `v1` | `v3` |
| `VECTISCAN_VALIDATION_LEVEL` | `strict`, `warn`, `off` | `strict` |

`catalog` mit `v2`/`v1` ist eine Fehlkonfiguration. Der alte Weg (KI#5 mit
Reparaturkette, `severity_policy`, `finding_type_mapper`, `cvss_consistency`,
`claims_guard`, `title_policy`, ReportLab) bleibt eine Release lang über
`engine=legacy` erreichbar und kostet dort rund 1,85 USD je Bericht; der
Katalogweg liegt bei rund 0,54 USD. Details: `docs/report-pipeline/`,
alte Doku unter `docs/archive/report-pipeline-v2/`.

**Eine Abbildungstabelle** (`reporter/v3/levels.py`) verbindet Einstufung,
Dringlichkeit, Ampelfarbe und Dashboard-Stufe. Rot und „Unverzüglich" nur bei
Exposition kritisch oder aktivem Nachweis (`active_proof_when` im Katalog: ZAP mit
Risiko und Konfidenz High, testssl-Schwachstelle aus der harten Liste).

**Freigabe:** nur `POST /api/admin/orders/:id/approve` setzt `approved`. Eine
Ausschlussliste ist keine Freigabe, und `regenerate-report` verlangt Admin-Rechte;
erst `report_complete` löst die Fertig-Mail aus (`api/src/lib/ws-manager.ts`).

Compliance-Module unter `report-worker/reporter/compliance/`:
nis2_bsig, iso27001, bsi_grundschutz, nist_csf, insurance (noch am Legacy-Weg,
Paketvarianten des Katalogs kommen mit S7).

## Determinismus-Block (Q2/2026, nur noch Legacy-Weg)
Spec: `docs/deterministic/`. Gilt für `VECTISCAN_REPORT_ENGINE=legacy` und
verschwindet mit diesem Weg. Der Katalogweg braucht nichts davon: seine Befunde
entstehen aus Regeln über Fakten, nicht aus einer KI-Ausgabe, die repariert wird.
- **Severity-Policy** (`reporter/severity_policy.py`, `POLICY_VERSION` aus ENV)
  überschreibt Tool-Severities; im Katalogweg kommt die Einstufung aus der Prüfung.
- **Selection** (`reporter/selection.py`) Top-N pro Paket.
- **CVE-Guard** (`reporter/cve_guard.py`, VEC-377) gegen halluzinierte CVE-IDs.
  Im Katalogweg zitiert nur, was in `facts.threats` steht.
- **AI-Cache** (`scan-worker/scanner/ai_cache.py`, `report-worker/reporter/ai_cache.py`)
  mit `temperature=0.0`. Die Scanner-KI (#1 bis #4) bleibt unverändert;
  `reporter_v1` ist der Legacy-Namensraum, `reporter_v3` der aktuelle.
- **DB-Audit** (Migration 016): `reports.policy_version`, `policy_id_distinct`,
  `severity_counts` (Trigger) — beide Wege schreiben dieselben Spalten.
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
| Perimeter | Vollscan (~60–90 Min), alle Tools, max 15 Hosts, externe Schwachstellenanalyse |
| Compliance | Perimeter + §30 BSIG, BSI-Grundschutz-Refs, Audit-Trail |
| SupplyChain | Perimeter + ISO 27001 Annex A, Auftraggeber-Nachweis |
| Insurance | Perimeter + Versicherungs-Fragebogen, Ransomware-Indikator |

Legacy-Aliase: `basic→webcheck`, `professional→perimeter`, `nis2→compliance`.

**Kanonischer Paket-Katalog (SSoT, VEC-289):** Einzige Wahrheit ist
`catalog/packages.catalog.json` (key, Marketing-Name, Sellability, Preis,
Host-Limit, Top-N, Stripe-Key, Compliance-Modul). `node scripts/gen-catalog.js`
generiert daraus je ein TS-Modul pro Service (`api/src/lib/catalog.generated.ts`,
`frontend/src/lib/catalog.generated.ts` — getrennte Docker-Build-Kontexte, daher
Codegen statt geteiltem Modul). Nur die JSON editieren, dann regenerieren +
committen. Drift-Guard: `api/src/__tests__/catalog.parity.test.ts` (erzwingt
Generate==SSoT und SSoT==DB-CHECK-Constraints). Keine hartkodierten Paketlisten
oder Anzeige-Namen/Preise mehr — alle Consumer (Homepage/Pricing/subscribe/
PackageSelector/schedules/DemoRequestForm + Backend-Validierung) lesen aus dem
Katalog. `tlscompliance` ist NICHT im Kunden-Katalog (v1, vgl. VEC-284).

Paket steuert: Scan-Tools/Timeouts (`scanner/packages.py`),
Phase-3-Enrichment-Tiefe, Claude-Prompt-Variante (`reporter/prompts.py`),
Report-Mapper, Compliance-Module, PDF-Sektionen, Top-N (`selection.py`).

Branding-Farben aus `reporter/pdf/branding.py` — nicht hardcoden.

## AI-Modelle
- Haiku 4.5 (`claude-haiku-4-5-20251001`): KI #1 Host-Strategy,
  KI #2 CMS-Korrektur, KI #3 Phase-2-Config, Report-QA
- Sonnet 4.6 (`claude-sonnet-4-6`): KI #4 Cross-Tool-Confidence
- Opus 5 (`claude-opus-5`): die zwei KI-Aufrufe des Reports, Prosa
  (`reporter/v3/prose.py`) und Recherche des Kundenkontexts
  (`reporter/v3/research.py`). Beide schreiben nur Text; ohne Zugangsschlüssel
  steht der Bericht vollständig aus Katalogtexten.

## Arbeitsweise
- Am Ende jeder abgeschlossenen Aufgabe: Kontext-Auslastung ausgeben (%-Wert)
- Push nur auf explizite Anfrage (Build dauert 15–20 Min)

## Wichtige Referenz-Dokumente
- `docs/API-SPEC.md` — vollständige API-Spec (alle Endpoints)
- `docs/DB-SCHEMA.sql` — Datenbankschema
- `docs/SCAN-TOOLS.md` — Tool-Konfig, Timeouts, Output-Format
- `docs/architecture.md` — Architektur inkl. AI-Orchestrierung und Event-System
- `docs/SCAN-PIPELINE-v2.md` — v2 Pipeline-Spec
- `docs/PIPELINE-AI-FLOW.md` — vollständiger End-to-End-Trace inkl. aller 5 KI-Entscheidungen, Cache-Verhalten, bekannte Override-Patterns
- `docs/report-pipeline/` — Report-Pipeline v3: die fünf Schritte, die drei
  Schalter, Versionen, Kosten, Golden-Fixtures, Freigabeweg
- `report-prototype/spec/05` bis `08` — Architektur-Befund, Katalog-Simulation,
  Sitzungsplan S0a bis S7 und das Gegenlesen der ersten v3-Berichte
- `docs/archive/report-pipeline-v2/` — der Weg bis S6 (KI-erzeugte Befunde,
  Reparaturkette, ReportLab); gilt noch für `VECTISCAN_REPORT_ENGINE=legacy`
- `docs/deterministic/` — Q2/2026 Determinismus-Block, nur noch Legacy-Weg
  (00-OVERVIEW, 01-cleanup, 02-severity-policy, 03-ai-determinism,
  04-deterministic-selection, 05-schema-migrations, 99-CUTOVER)
- `MONITORING.md` — Monitoring/Logging/Alerting-Runbook (Uptime-Kuma,
  Loki+Promtail, Grafana, Resend-Alerts) — A5/VEC-85
- `OFFSITE-BACKUP-EVAL.md` — Off-Site-Backup-Bewertung + Empfehlung
- `docs/archive/report_structure.md` — PDF-Layout des Legacy-v1-Renderers (Historie)
- `docs/CRM-KEY-ROTATION.md` — Twenty-CRM Key-Rotation-Runbook (VEC-398).
  **Policy: API-Only, kein Direkt-DB-Zugriff/Schema-Poking auf Twenty.**
  Lead-Sync via REST (`api/src/lib/crm.ts`). Key-Rotation = Token manuell in
  Twenty-UI erzeugen → CI-Var via `ops-rotate-crm-api-key` setzen. Einzige
  sanktionierte DB-Ausnahme: einmaliges First-Admin-Bootstrap (VEC-324/326).
