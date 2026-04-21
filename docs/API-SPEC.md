# VectiScan — API Specification (Stand: 2026-04-21)

Base URL: `https://scan-api.vectigal.tech` (internal-only via Traefik)

Antwortformat:
```json
{ "success": true, "data": {...} }
{ "success": false, "error": "..." }
```

Auth: `Authorization: Bearer <jwt>`. Manche Endpoints akzeptieren `?token=`
(JWT) oder `?download_token=` (Report-Deep-Link).

UUID-Format: `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`.

---

## Health

### GET /health
Health-Check für Traefik. Kein Auth.

```json
{ "status": "ok" }
```

---

## Authentication

### POST /api/auth/register
**Body:** `{ "email": "user@example.com", "password": "min8chars", "companyName": "Acme GmbH" }`
(`companyName` optional)

**201:** `{ token, user: { id, email, role: "customer" } }`
**Errors:** 400 (E-Mail/Passwort), 409 (E-Mail vergeben)

### POST /api/auth/login
**Body:** `{ "email", "password" }`
**200:** `{ token, user: { id, email, role } }`
**Errors:** 400 (fehlend), 401 (ungültig)

### GET /api/auth/me
**Auth required.** Liefert `{ id, email, role, customerId }`.

### POST /api/auth/forgot-password
Liefert immer 200 (Enumeration-Schutz). E-Mail mit Reset-Link wird per Resend
versendet (1 h Gültigkeit).

### POST /api/auth/reset-password
**Body:** `{ "token", "password" }` → loggt User direkt ein (`{ token, user }`).

### PUT /api/auth/password
**Auth required.** Body: `{ currentPassword, newPassword }`.

### GET /api/auth/verified-domains
**Auth required.** Listet alle nicht abgelaufenen Domain-Verifizierungen
des aktuellen Customers (`{ domains: [{ domain, verification_method,
verified_at, expires_at }] }`).

---

## Admin

Alle Admin-Endpoints: **Auth + Admin-Rolle**.

### GET /api/admin/users
Listet alle User mit `orderCount`.

### PUT /api/admin/users/:id/role
Body: `{ "role": "admin" | "customer" }`. Eigene Rolle nicht änderbar.

### DELETE /api/admin/users/:id
Eigener Account nicht löschbar.

### GET /api/admin/stats
```json
{
  "users": { "total": 5, "admins": 1 },
  "orders": { "total": 42, "today": 3, "byStatus": { "report_complete": 30, ... } }
}
```

### GET /api/admin/ai-costs
Aggregiert AI-Kosten aus `scan_results` (tool_name=`report_cost`):
```json
{
  "total_cost_usd": 12.34,
  "cost_by_model": { "claude-sonnet-4-6": { "count": 12, "total_usd": 11.20 }, ... },
  "cost_by_package": { "perimeter": { "count": 10, "total_usd": 9.5 }, ... },
  "recent_reports": [{ "orderId", "domain", "package", "cost_usd", "model", "createdAt" }]
}
```

### POST /api/admin/diagnose
**Body:** `{ "probe": "example.com" }` (optional). Triggert Scan-Worker-
Diagnose über Redis-Queue `diagnose-pending`. Pollt bis 30 s (60 s mit
probe).

**504** bei Timeout. Erfolgs-Response: `{ environment, tools, probe }`.

### GET /api/admin/pending-reviews
Listet alle Orders mit Status `pending_review` (Admin-Approval-Queue).

```json
{
  "reviews": [
    { "id", "domain", "package", "status", "customerEmail",
      "createdAt", "scanFinishedAt", "businessImpactScore", "severityCounts" }
  ]
}
```

### POST /api/admin/orders/:id/approve
Setzt Order auf `approved`, lädt ausgeschlossene Findings, enqueued Report-
Job mit `approved=true` (Worker generiert PDF und setzt `report_complete`).

### POST /api/admin/orders/:id/reject
Body: `{ "reason": "..." }`. Setzt Order auf `rejected` mit `review_notes`.

### POST /api/orders/:id/requeue-report
**Admin only.** Lädt host_inventory + tech_profiles + phase3-Daten aus
`scan_results`, setzt Status auf `scan_complete` und enqueued einen neuen
Report-Job. Für gescheiterte Reports.

### GET /api/admin/pending-domains
Subscription-Domains, die auf Admin-Freigabe warten.

### POST /api/admin/subscription-domains/:id/approve
Setzt Domain auf `verified` (Status für Re-Scans freigeschaltet).

### POST /api/admin/subscription-domains/:id/reject
Setzt Domain auf `rejected`.

---

## Orders

### POST /api/orders
**Auth required.** Body: `{ "domain": "example.com|1.2.3.4|10.0.0.0/24", "package": "perimeter" }`.

`package` optional (Default `perimeter`). Erlaubt: `webcheck`, `perimeter`,
`compliance`, `supplychain`, `insurance`, `tlscompliance`.

`domain` darf FQDN, IPv4, CIDR oder Subnetz-Maske sein
(siehe `api/src/lib/validate.ts`).

Wenn die Domain bereits verifiziert ist (`verified_domains` für diesen
Customer, nicht abgelaufen), startet die Order direkt mit Status `queued`
und wird sofort enqueued — sonst `verification_pending` mit Token.

**Auto-Linking zu Abos:** Hat der Customer ein aktives Abo, dessen
`subscription_domains` die Domain mit Status `verified` und `enabled=true`
enthält, wird die neue Order automatisch mit `subscription_id` verknüpft
und im Dashboard unter dem entsprechenden Abo-Paket gruppiert. Das
Audit-Log enthält `details.linkedToSubscription = true` und
`details.subscriptionId`.

**201:**
```json
{
  "id", "domain", "status", "package", "verificationToken",
  "verificationInstructions": { "dns_txt", "file", "meta_tag" }
}
```

### GET /api/orders
**Auth required.** Admins sehen alle Orders, Kunden nur eigene.

Liefert pro Order u.a. `id, domain, email, package, status, hasReport,
hostsTotal, hostsCompleted, currentTool, currentHost, startedAt, finishedAt,
createdAt, overallRisk, severityCounts, businessImpactScore,
subscriptionId, isRescan`.

`subscriptionId` ist gesetzt, wenn die Order zu einem Abo gehört (entweder
über `POST /api/subscriptions/:id/rescan`, den Scheduler oder das
Auto-Linking in `POST /api/orders`).

### POST /api/scans
Backwards-Compat: 307 Redirect → `/api/orders`.

### GET /api/orders/dashboard-summary
**Auth required.** Aggregiertes Security-Cockpit-Snapshot:

```json
{
  "domains": 5, "totalScans": 42, "totalFindings": 18,
  "criticalCount": 1, "highCount": 4, "overallRisk": "HIGH",
  "topFindings": [
    { "domain", "title", "severity", "cvss", "orderId" }
  ]
}
```

Berücksichtigt nur Orders mit Status `report_complete`, `delivered`,
`pending_review`. Top-3 Findings nach Severity + CVSS.

### GET /api/orders/:id
**Auth required + Ownership.** Customers sehen nur Orders mit Status
`report_complete`, `delivered`, `report_generating`, `pending_review`.

```json
{
  "id", "domain", "status", "package", "customerId", "estimatedDuration",
  "progress": { "phase", "currentTool", "currentHost", "hostsTotal",
                "hostsCompleted", "discoveredHosts", "toolOutput",
                "lastCompletedTool" },
  "startedAt", "finishedAt", "error", "hasReport",
  "overallRisk", "severityCounts",
  "passiveIntelSummary", "correlationData", "businessImpactScore"
}
```

### DELETE /api/orders/:id
**Auth required + Ownership.**

- Ohne `?permanent=true`: Soft-Cancel (Status → `cancelled`). Erlaubt von
  jedem aktiven Status.
- Mit `?permanent=true`: **Admin only.** Hard-Delete inkl. scan_results,
  reports, audit_log, MinIO-Objekte.

### GET /api/orders/:id/report
Auth via JWT (`Authorization`-Header oder `?token=…`) **oder**
`?download_token=…` (Deep-Link aus E-Mail, kein Login).

Optional `?version=N` für eine bestimmte Report-Version (sonst neueste).

**Response:** Binary PDF, `Content-Disposition: attachment; filename="vectiscan-<domain>-<package>-<YYYY-MM-DD>-<HHMM>-v<N>.pdf"`.

**Errors:** 401, 403 (ungültiges Token), 404 (Report fehlt), 410 (Token abgelaufen).

### GET /api/orders/:id/results
Raw Scan-Results pro Tool. **Kein Auth** (Debug-Endpoint, intern).

### GET /api/orders/:id/events
**Auth required + Ownership.** Event-Replay für Scan-Detail-Seite:

```json
{
  "aiStrategy": {...}, "aiConfigs": { "<ip>": {...} },
  "aiDebug": { "host_strategy": {...}, "phase2_config": { "<ip>": {...} } },
  "toolOutputs": [{ "tool", "host", "summary", "ts" }],
  "discoveredHosts": [...], "error": null,
  "falsePositives": { "count", "by_reason", "details" },
  "claudeDebug": {...}|null,   // nur Admin: aus MinIO scan-debug/
  "costs": { "total_usd": 0.12, "breakdown": [{ "step", "model", "tokens", "cost_usd" }] }|null
}
```

### GET /api/orders/:id/findings
**Auth required + Ownership.** Strukturierte Befunde aus dem aktuellen Report:

```json
{
  "overall_risk", "overall_description", "severity_counts",
  "findings": [...], "positive_findings": [...], "recommendations": [...],
  "excluded_finding_ids": [...],
  "exclusions": [{ "finding_id", "reason", "created_at" }]
}
```

### GET /api/orders/:id/diff?compare=<otherOrderId>
**Auth required + Ownership beider Orders.**

```json
{
  "current":  { "orderId", "domain", "date", "findingsCount" },
  "previous": { "orderId", "domain", "date", "findingsCount" },
  "newFindings":      [{ "title", "severity", "cvss_score" }],
  "resolvedFindings": [{ "title", "severity", "cvss_score" }],
  "unchangedCount": 7,
  "summary": "2 neue, 3 behobene, 7 unveränderte Befunde"
}
```

Vergleich erfolgt titelbasiert (case-insensitive).

### GET /api/orders/:id/report-versions
**Auth required + Ownership.**

```json
{
  "versions": [
    { "version", "createdAt", "findingsCount", "excludedCount",
      "excludedFindings", "fileSizeBytes", "isCurrent" }
  ]
}
```

### POST /api/orders/:id/findings/:findingId/exclude
**Auth required + Ownership.** Body: `{ "reason"?: "..." }`. Markiert
Finding als FP für die nächste Report-Generierung.

### DELETE /api/orders/:id/findings/:findingId/exclude
**Auth required + Ownership.** Hebt Exclusion auf.

### POST /api/orders/:id/regenerate-report
**Auth required + Ownership.** Erzeugt neuen Report mit aktuell
ausgeschlossenen Findings (Version +1). Erlaubt für Status `report_complete`,
`completed`, `failed`, `report_generating`, `cancelled`.

---

## Verification

### POST /api/verify/check
Body: `{ "orderId": "uuid" }`. Prüft DNS-TXT/File/Meta-Tag. Bei Erfolg:
- `orders.status = 'queued'`, `verified_at = NOW()`
- Domain wird in `verified_domains` persistiert (90 Tage)
- Scan-Job wird in `scan-pending` enqueued

**Response:** `{ verified: true, method: "dns_txt" }` oder `{ verified: false }`.

### POST /api/verify/manual
**Prototyp/Entwicklung only.** Body: `{ "orderId" }`. Markiert sofort als
verifiziert (Methode `manual`), enqueued Scan-Job.

### GET /api/verify/status/:orderId
```json
{ "verified": false, "method": null, "token": "...", "domain": "..." }
```

---

## Schedules

Alle Schedule-Endpoints: **Auth required.** Customer sieht nur eigene.

### GET /api/schedules
Liefert alle Schedules (Admin sieht alle).

### POST /api/schedules
Body: `{ "domain", "package", "scheduleType": "weekly|monthly|quarterly|once",
"scheduledAt"?: "ISO-Date (für 'once')" }`.

Domain muss zuvor verifiziert worden sein.

### GET /api/schedules/:id
Liefert Schedule + die 10 letzten Orders für die Domain.

### PUT /api/schedules/:id
Body (alles optional): `{ package, scheduleType, scheduledAt, enabled }`.

### DELETE /api/schedules/:id
Löscht Schedule.

---

## Subscriptions

Alle Subscription-Endpoints: **Auth required**. Stripe-Integration vorbereitet
aber gemockt — Abos gehen direkt auf `active`.

### POST /api/subscriptions
Body: `{ "package", "scanInterval": "weekly|monthly|quarterly",
"domains": ["..."], "reportEmails"?: [...] }`.

Max 30 Domains pro Abo, alle landen mit `pending_approval`. Default-Empfänger
ist die User-E-Mail.

**201:**
```json
{
  "id", "package", "status": "active", "scanInterval",
  "domains": [{ "domain", "status": "pending_approval" }],
  "expiresAt",
  "message": "Abo erstellt. Domains warten auf Admin-Freigabe."
}
```

### GET /api/subscriptions
Liefert Abos + alle Subscription-Domains. Customer sieht eigene, Admin alle.

### POST /api/subscriptions/:id/domains
Body: `{ "domain": "..." }`. Fügt Domain zum Abo hinzu (Status
`pending_approval`). Prüft `max_domains`-Quote.

### POST /api/subscriptions/:id/rescan
Body: `{ "domain": "..." }`. Erzeugt Re-Scan-Order (`is_rescan=true`,
`subscription_id` gesetzt). Domain muss `verified` und `enabled` sein.

- **Customer-Trigger** (`user.role === 'customer'`): Quote (`max_rescans`)
  wird geprüft, `rescans_used` wird hochgezählt. Bei erschöpftem Kontingent
  → 409.
- **Admin-Trigger** (`user.role === 'admin'`): Quote-Check wird übersprungen,
  `rescans_used` bleibt unverändert. Response-Message: „Admin-Re-Scan
  gestartet (Kontingent unverändert)." Audit-Log enthält
  `details.triggeredBy = 'admin'`.

---

## WebSocket

### GET /ws?orderId=<uuid>
Liefert Live-Progress. Auch `?scanId=` (Backward-Compat).

**Connect:** Server sendet `connected` und replayt persistierte Events
(`hosts_discovered`, `ai_strategy`, `ai_config`, `tool_output`).

**Event-Typen:**
```json
{ "type": "connected",          "orderId", "timestamp" }
{ "type": "status",             "orderId", "status", "error"? }
{ "type": "progress",           "orderId", "phase", "tool", "host" }
{ "type": "hosts_discovered",   "orderId", "hosts": [...], "hostsTotal": 3 }
{ "type": "ai_strategy",        "orderId", "strategy": {...} }
{ "type": "ai_config",          "orderId", "ip", "config": {...} }
{ "type": "tool_output",        "orderId", "tool", "host", "summary" }
{ "type": "phase3_complete",    "summary": {...} }
```

Pub/Sub-Kanal im Backend: `scan:events:<orderId>`.

---

## Order Status Flow

```
verification_pending
   │
   ▼ (verify/check oder verify/manual)
queued ─→ scanning ─→ passive_intel ─→ dns_recon
   │                                       │
   │                                       ▼
   │                                  scan_phase1 ─→ scan_phase2 ─→ scan_phase3
   │                                                                     │
   │                                                                     ▼
   │                                                              scan_complete
   │                                                                     │
   │                                                                     ▼ (report-worker generiert findings_data)
   │                                                              pending_review ←── Admin-Review
   │                                                                     │
   │                                                       ┌─────────────┼──────────────┐
   │                                                       ▼ approve     ▼ reject       ▼ regenerate
   │                                              report_generating   rejected     report_generating
   │                                                       │                            │
   │                                                       ▼                            ▼
   │                                              report_complete                report_complete (v+1)
   │
   └─────────────────────────────────→ cancelled / failed / delivered
```

Customer sieht in `GET /api/orders/:id` nur `report_complete`, `delivered`,
`report_generating`, `pending_review` — alles andere wirft 403.

---

## Backwards-Compat

| Alt | Neu | Code |
|-----|-----|------|
| `POST /api/scans` | `POST /api/orders` | 307 |
| `GET /api/scans/:id` | `GET /api/orders/:id` | 301 |
| `GET /api/scans/:id/report` | `GET /api/orders/:id/report` | 301 |
| `DELETE /api/scans/:id` | `DELETE /api/orders/:id` | 307 |

Legacy-Paketnamen bei `POST /api/orders`: `basic→webcheck`,
`professional→perimeter`, `nis2→compliance` (im Scan-Worker via
`packages.resolve_package` aufgelöst).
