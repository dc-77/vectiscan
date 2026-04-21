# VectiScan — Status quo (Stand: 2026-04-21)

Internes Tool hinter Traefik (`internal-only@file`), kein öffentlicher Zugang.
Sechs Pakete (WebCheck, Perimeter, Compliance, SupplyChain, Insurance,
TLSCompliance), 6-stufige Scan-Pipeline mit 4 KI-Entscheidungspunkten,
Subscription-Verwaltung und Admin-Review-Workflow.

Diese Datei beschreibt was tatsächlich implementiert ist. Detaillierte
Pipeline-Doku siehe `SCAN-PIPELINE-DETAIL.md`. Endpoints siehe `API-SPEC.md`.
Datenbank siehe `DB-SCHEMA.sql`.

---

## Implementierte Features

### Authentifizierung & Benutzerverwaltung
- Registrierung mit optionalem Firmenname (`customers.company_name`)
- Login, Passwort-Reset per E-Mail (Resend), Passwort-Änderung
- JWT-basierte Authentifizierung (HS256), `Authorization: Bearer <token>`
- Zwei Rollen: `customer` und `admin`
- Customer-Tabelle 1:n mit Users; Admins haben kein zugeordnetes Customer-Record
- Ownership-Checks: Kunden sehen nur eigene Orders, Admins sehen alles

### Admin-Funktionen
- Benutzerliste mit Rollenverwaltung (`PUT /api/admin/users/:id/role`)
- Benutzer löschen (`DELETE /api/admin/users/:id`)
- System-Statistiken (Users, Orders, Status-Breakdown, AI-Kosten in USD)
- Diagnose-Endpoint, der den Scan-Worker probt (Tools, Probedomain)
- Pending-Reviews-Queue mit Approve/Reject
- Pending-Domains-Queue (für Subscription-Workflow)
- Report-Re-Queue für gescheiterte Reports

### Domain-Verifizierung
- Drei Methoden: DNS-TXT (`_vectiscan-verify.<domain>`), File
  (`/.well-known/vectiscan-verify.txt`), Meta-Tag
- Manueller Bypass für Prototyp/Entwicklung (`POST /api/verify/manual`)
- Persistente `verified_domains` Tabelle: Verifizierung gilt 90 Tage,
  Order auf bereits verifizierter Domain überspringt die Verifikation
- Auflistung der verifizierten Domains pro User (`GET /api/auth/verified-domains`)

### Sechs Scan-Pakete
| Paket | Zweck | Dauer | Hosts | Kern-Tools |
|---|---|---|---|---|
| **WebCheck** | "Ist meine Website sicher?" | ~15–20 Min | 3 | DNS-Recon, ZAP-Spider+Passive, testssl, Headers, wpscan |
| **Perimeter** | "Wie sieht die Angriffsfläche aus?" | ~60–90 Min | 15 | + Shodan/AbuseIPDB/SecurityTrails, ZAP-Active, ffuf, feroxbuster, Threat-Intel |
| **Compliance** | "Erfüllen wir NIS2?" | ~65–95 Min | 15 | = Perimeter + §30 BSIG-Mapping + BSI-Grundschutz + Audit-Trail |
| **SupplyChain** | "Nachweis für NIS2-Auftraggeber" | ~65–95 Min | 15 | = Perimeter + ISO 27001 Annex-A-Mapping + Lieferketten-Sektion |
| **Insurance** | "Cyberversicherungs-Nachweis" | ~65–95 Min | 15 | = Perimeter + Versicherungsfragebogen + Ransomware-Indikator |
| **TLSCompliance** | "BSI TR-03116-4-Audit" | ~5–10 Min | 15 | nur DNS-Recon + nmap (TLS-Ports) + testssl + Headers, kein KI-Routing |

Compliance, SupplyChain und Insurance teilen die identische Scan-Konfiguration
mit Perimeter — sie unterscheiden sich nur im Report (Prompt + Mapper +
PDF-Sektionen).

Legacy-Aliase (Migration und API): `basic→webcheck`, `professional→perimeter`,
`nis2→compliance`.

### Subscription-Workflow
- Jahres-Abos (`subscriptions` Tabelle), Stripe-Integration vorbereitet aber
  gemockt — Abo geht direkt in `active`
- Bis zu 30 Domains pro Abo (`subscription_domains`)
- Re-Scan-Kontingent (`max_rescans`, `rescans_used`), Customer kann Re-Scan
  anstoßen (`POST /api/subscriptions/:id/rescan`)
- **Admin-Re-Scans verbrauchen kein Kontingent**: `rescans_used` wird nur
  hochgezählt, wenn `user.role !== 'admin'`. Quota-Check wird für Admins
  übersprungen. Audit-Log enthält `triggeredBy: 'admin'|'customer'`.
- **Order-zu-Abo-Auto-Linking**: `POST /api/orders` schlägt nach, ob der
  Customer ein aktives Abo hat, dessen `subscription_domains` die Domain mit
  Status `verified` und `enabled=true` enthält — wenn ja, bekommt die neue
  Order automatisch die `subscription_id`. Das gilt für Customer- und
  Admin-Orders. Manuell vom Scheduler erzeugte Re-Scans setzen
  `subscription_id` ebenfalls automatisch (`scheduler.ts`).
- Domain-Hinzufügen erfordert Admin-Freigabe (`pending_approval` →
  `verified` oder `rejected`)
- Report-E-Mail-Empfänger pro Abo (`report_emails TEXT[]`)
- Scan-Intervall: weekly / monthly / quarterly

### Scan-Pipeline (Scan-Worker)
6 Phasen mit 4 KI-Entscheidungspunkten — Details in `SCAN-PIPELINE-DETAIL.md`.

1. **Phase 0a Passive Intelligence** (parallel): WHOIS, Shodan, AbuseIPDB,
   SecurityTrails, DNSSEC, CAA, MTA-STS, DANE/TLSA
2. **Phase 0b DNS-Reconnaissance** (parallel, 6 Worker): crt.sh, subfinder,
   amass, gobuster_dns, AXFR, dnsx + httpx Web-Probe pro FQDN
3. **KI Host Strategy** (Haiku): scan/skip pro Host, Priorität, scan_hints
4. **Phase 1 Tech Detection** (parallel, 3 Hosts): nmap, Playwright-webtech,
   wafw00f, CMS-Fingerprinting-Engine (5 Methoden)
5. **KI Tech Analysis** (Haiku): CMS-Korrektur basierend auf Redirect-Daten
6. **KI Phase-2-Config** (Haiku, pro Host): ZAP-Policy, Spider-Tiefe, Active-
   Kategorien, ffuf-Modus, feroxbuster-Tiefe, skip_tools
7. **Phase 2 Deep Scan** (parallel, 3 Hosts; 1 wenn ZAP): ZAP Spider/Active/
   Passive, testssl, Headers, httpx, ffuf, feroxbuster, wpscan
8. **KI Phase-3-Priorisierung** (Sonnet, nur >5 Findings): Konfidenz-Scoring,
   FP-Erkennung
9. **Phase 3 Correlation & Enrichment**: Cross-Tool-Korrelation,
   FP-Filter (6 Regeln), NVD/EPSS/CISA-KEV/ExploitDB, Business-Impact-Scoring

ZAP läuft als dedizierter Daemon pro Worker (zap-1, zap-2 in
docker-compose.yml). Jeder Scan bekommt einen eigenen ZAP-Kontext
(`ctx-{order_id[:8]}-{ip}`) und eine Custom Scan Policy.

### Admin-Review-Workflow
- Nach Scan-Ende: Status `pending_review`
- Report-Worker generiert findings_data (Claude-Analyse), kein PDF
- Admin sieht alle pending Reviews (`GET /api/admin/pending-reviews`),
  kann Findings als FP markieren und dann **approve** oder **reject**
- Bei Approve: Status → `report_generating`, Report-Worker erstellt PDF mit
  ggf. ausgeschlossenen Findings, Status → `report_complete`

### Report-Worker
- 5 Prompt-Varianten (`prompts.py`): WebCheck, Perimeter, Compliance,
  SupplyChain, Insurance + dedizierter TLS-Compliance-Pfad
- 5 Mapper-Funktionen (`report_mapper.py`)
- Compliance-Module unter `reporter/compliance/`:
  `nis2_bsig.py`, `iso27001.py`, `bsi_grundschutz.py`, `nist_csf.py`,
  `insurance.py`
- TR-03116-4-Checker (`tr03116_checker.py`) für TLSCompliance-Pfad
- Report-QA (`qa_check.py`): programmatische Checks (CVSS-Vektor,
  CWE-Format, Severity, Duplikate) + optional Haiku-Plausibilität
- CWE-Validierung über lokale Referenztabelle (`cwe_reference.py`) und
  optionalen MITRE-CWE-API-Client (`cwe_api_client.py`)
- PDF-Generierung über `generate_report.py` mit zentralem Branding
  (`reporter/pdf/branding.py`)
- Report-Versionierung: bei Regenerate (Findings ausschließen) wird ein
  neuer `reports`-Datensatz erstellt, alter wird via `superseded_by` markiert
- Findings-Daten landen in `reports.findings_data` (JSONB), Excluded-IDs in
  `reports.excluded_findings`
- Claude-Debug-JSON wird best-effort in MinIO unter `scan-debug/` abgelegt
- AI-Kosten werden pro Job in `scan_results` (tool_name=`report_cost`)
  persistiert

### Wiederkehrende Scans
- `scan_schedules` Tabelle, Intervall: weekly / monthly / quarterly / once
- Tick-Loop alle 60s im API-Server (`lib/scheduler.ts`)
- Row-Level-Locking (`FOR UPDATE SKIP LOCKED`) gegen Doppelverarbeitung
- Verifizierung wird übersprungen, da Domain bereits in `verified_domains`
  liegen muss
- `once` deaktiviert sich nach Ausführung selbst

### Frontend
- Next.js 15 App Router, Tailwind CSS, Dark-Theme als Default
- Brand-konformes Redesign mit Cursor-Glow, Reveal-Animationen, Hamburger
  und Mobile-First-Layout
- Seiten:
  - `/` Landing mit OrderId-Redirect, eingeloggte User → `/dashboard`
  - `/login` Login + Tabbed Register mit Firmenname und AGB-Checkbox
  - `/register` (Redirect-Stub auf `/login?tab=register`)
  - `/forgot-password`, `/reset-password`
  - `/welcome` Onboarding-Flow für Neukunden
  - `/dashboard` Security-Cockpit (Risk-Gauge + Top-3-Findings) +
    Gruppen-Karten je Abo bzw. je Domain (für Einzelscans), mit Pagination
    + Suche + Filter
  - `/scans/[groupKey]` Gruppen-Detail (Mini-Cockpit, Subscription-Steckbrief
    mit Re-Scan-Buttons, Liste der enthaltenen Scans). `groupKey` ist
    `sub:<uuid>` für Abo-Gruppen oder `dom:<domain>` für Einzelscan-Gruppen.
  - `/scan?orderId=…` Wizard für neue Orders, `/scan/[orderId]` Live-Detail
  - `/verify/[orderId]` Domain-Verifizierungs-Seite
  - `/schedules` CRUD für Zeitpläne
  - `/subscribe` Abo-Wizard, `/pricing` öffentliche Preisseite
  - `/profile` Passwort + Firmenprofil + verifizierte Domains
  - `/admin` Benutzer + System-Stats + AI-Kosten + Pending-Reviews +
    Pending-Domains
  - `/impressum`, `/datenschutz`
- Komponenten:
  - `AppHeader` mit Hamburger und Notification-Bell-Placeholder
  - `Toast` System für In-App-Feedback
  - `PackageSelector` mit 6 Paketen
  - `FindingsViewer`, `RecommendationsViewer`, `SeverityBar`, `SeverityCounts`
  - `ScanProgress`, `ScanError`, `ReportDownload`, `HostList`
  - `ScanIntelligence` (Container) mit `intelligence/RadarTopology`,
    `MetricsGrid`, `AiDecisionFeed`, `HostDiscoveryMatrix`, `DataStream`,
    `PacketStream`
  - `terminal/ScanTerminal` mit `ToolProgress`, `TerminalLine`,
    `NoiseMatrix`, `ScrambleText`, `ToolWatermark`, `ActiveOperations`,
    `useTerminalFeed`
- WebSocket-Hook (`hooks/useWebSocket.ts`) mit Auto-Reconnect

### WebSocket Real-Time Progress
- `/ws?orderId=<uuid>` (auch `?scanId=` für Backward-Compat)
- Redis Pub/Sub als Transportschicht
- Event-Replay für late-joining Clients (Hosts, AI-Strategy, AI-Configs,
  Tool-Outputs der letzten 50)

### Scan-Vergleich (Diff) und Report-Sharing
- `GET /api/orders/:id/diff?compare=<otherId>` liefert neue/behobene/
  unveränderte Findings
- Report-Download via JWT (`Authorization` Header oder `?token=`) **oder**
  über `?download_token=` (zeitlich begrenzter Deep-Link für E-Mail-Versand
  an IT-Team, 30 Tage Gültigkeit)
- `download_count` und `expires_at` in `reports`

### Infrastruktur
- `docker-compose.yml`: frontend, api, scan-worker-1 + zap-1, scan-worker-2
  + zap-2, report-worker, postgres, redis, minio (9 Container)
- GitLab-CI/CD: 4 parallele Build-Jobs, Trivy-Scan-Stage, Deploy-Sleep 15s
- PostgreSQL 16.4-alpine, Redis 7.4-alpine, MinIO latest, ZAP zaproxy/zap-stable
- Subdomains: `scan.vectigal.tech` (Frontend) und `scan-api.vectigal.tech`
  (API), beide internal-only
- SSL via Let's Encrypt HTTP-01 (Traefik-Default)

### MinIO-Buckets
| Bucket | Inhalt | Erstellt durch |
|---|---|---|
| `scan-rawdata` | tar.gz pro Order | Scan-Worker |
| `scan-reports` | PDF-Reports (versioniert) | Report-Worker |
| `scan-debug` | Claude-Prompts/Responses pro Order | Report-Worker |

---

## Bewusst nicht im Scope

- **Stripe-Integration**: vorbereitet (`stripe_subscription_id`,
  `stripe_price_id`, `paid_at`, `amount_cents`), aber Subscription geht
  direkt auf `active` ohne Zahlungsabwicklung
- **E-Mail-Versand für Reports**: Resend ist eingerichtet (Password-Reset
  funktioniert), aber Report-E-Mails werden noch nicht aktiv versendet —
  Manueller Download oder Deep-Link via UI
- **Öffentlicher Zugang**: Traefik-Middleware `internal-only@file` blockt
  alle Zugriffe von außerhalb des internen Netzwerks
- **Benachrichtigungs-Center mit Glocke**: Placeholder im AppHeader,
  Backend nicht angebunden
- **Multi-Methode Domain-Verifizierung jenseits DNS/File/Meta**:
  E-Mail-an-Admin-Methode aus dem Master Plan ist nicht implementiert
- **CMS-spezifische Scanner für Joomla, Drupal, TYPO3**: nur WordPress
  via WPScan; CMS-Erkennung deckt 13 Systeme ab, aktive Scans nur für WP
