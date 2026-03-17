# VectiScan — API Specification

Base URL: `https://scan-api.vectigal.tech`

All responses follow the format:
```json
{ "success": true, "data": {...} }
{ "success": false, "error": "..." }
```

Auth: Bearer JWT token in `Authorization: Bearer <token>` header.

---

## Health

### GET /health

Health-Check for Traefik. No auth required.

**Response:**
```json
{ "status": "ok" }
```

---

## Authentication

### POST /api/auth/register

Create a new user account. No auth required.

**Request Body:**
```json
{ "email": "user@example.com", "password": "min8chars" }
```

**Response (201):**
```json
{
  "success": true,
  "data": {
    "token": "jwt...",
    "user": { "id": "uuid", "email": "user@example.com", "role": "customer" }
  }
}
```

**Errors:** 400 (invalid email, short password), 409 (email exists)

### POST /api/auth/login

Authenticate and receive a JWT. No auth required.

**Request Body:**
```json
{ "email": "user@example.com", "password": "..." }
```

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "jwt...",
    "user": { "id": "uuid", "email": "user@example.com", "role": "customer" }
  }
}
```

**Errors:** 400 (missing fields), 401 (invalid credentials)

### GET /api/auth/me

Return the authenticated user's profile. **Auth required.**

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "uuid",
    "email": "user@example.com",
    "role": "customer",
    "customerId": "uuid"
  }
}
```

### POST /api/auth/forgot-password

Request a password reset email. No auth required. Always returns 200 to prevent user enumeration.

**Request Body:**
```json
{ "email": "user@example.com" }
```

**Response:**
```json
{
  "success": true,
  "data": { "message": "Falls ein Konto mit dieser E-Mail existiert, wurde ein Reset-Link gesendet." }
}
```

### POST /api/auth/reset-password

Reset password using a token from the reset email. No auth required. Returns JWT so the user is logged in immediately.

**Request Body:**
```json
{ "token": "reset-uuid", "password": "newPassword" }
```

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "jwt...",
    "user": { "id": "uuid", "email": "user@example.com", "role": "customer" }
  }
}
```

**Errors:** 400 (invalid/expired token, short password)

### PUT /api/auth/password

Change own password while authenticated. **Auth required.**

**Request Body:**
```json
{ "currentPassword": "old", "newPassword": "new" }
```

**Response:**
```json
{ "success": true, "data": { "message": "Passwort geändert." } }
```

**Errors:** 400 (missing fields, short password), 401 (wrong current password)

---

## Admin

All admin endpoints require **Auth + admin role**.

### GET /api/admin/users

List all users with order counts.

**Response:**
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": "uuid",
        "email": "user@example.com",
        "role": "customer",
        "customerId": "uuid",
        "orderCount": 3,
        "createdAt": "2026-03-01T12:00:00.000Z"
      }
    ]
  }
}
```

### PUT /api/admin/users/:id/role

Change a user's role. Cannot change own role.

**Request Body:**
```json
{ "role": "admin" }
```

Role must be `customer` or `admin`.

**Response:**
```json
{ "success": true, "data": { "id": "uuid", "email": "...", "role": "admin" } }
```

### DELETE /api/admin/users/:id

Delete a user. Cannot delete self.

**Response:**
```json
{ "success": true, "data": null }
```

### GET /api/admin/stats

System statistics.

**Response:**
```json
{
  "success": true,
  "data": {
    "users": { "total": 5, "admins": 1 },
    "orders": {
      "total": 42,
      "today": 3,
      "byStatus": { "report_complete": 30, "scanning": 2, "cancelled": 5 }
    }
  }
}
```

---

## Orders

### POST /api/orders

Create a new scan order. **Auth required.** The order starts in `verification_pending` status.

**Request Body:**
```json
{ "domain": "example.com", "package": "professional" }
```

`package` is optional (default: `professional`). Valid values: `basic`, `professional`, `nis2`.

**Response (201):**
```json
{
  "success": true,
  "data": {
    "id": "uuid",
    "domain": "example.com",
    "status": "verification_pending",
    "package": "professional",
    "verificationToken": "random-token",
    "verificationInstructions": {
      "dns_txt": "Create a TXT record at _vectiscan-verify.example.com with value: random-token",
      "file": "Place a file at https://example.com/.well-known/vectiscan-verify.txt containing: random-token",
      "meta_tag": "Add <meta name=\"vectiscan-verify\" content=\"random-token\"> to your homepage"
    }
  }
}
```

### GET /api/orders

List orders. **Auth required.** Admins see all orders, customers see only their own.

**Response:**
```json
{
  "success": true,
  "data": {
    "orders": [
      {
        "id": "uuid",
        "domain": "example.com",
        "email": "user@example.com",
        "package": "professional",
        "status": "report_complete",
        "hasReport": true,
        "error": null,
        "hostsTotal": 3,
        "hostsCompleted": 3,
        "currentTool": null,
        "currentHost": null,
        "startedAt": "2026-03-01T12:00:00.000Z",
        "finishedAt": "2026-03-01T12:45:00.000Z",
        "createdAt": "2026-03-01T11:59:00.000Z",
        "overallRisk": "MEDIUM",
        "severityCounts": { "HIGH": 1, "MEDIUM": 3, "LOW": 2, "INFO": 4 }
      }
    ]
  }
}
```

### GET /api/orders/:id

Get order details with live progress. **Auth required** (ownership check).

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "uuid",
    "domain": "example.com",
    "status": "scanning",
    "package": "professional",
    "customerId": "uuid",
    "estimatedDuration": "~45 Minuten",
    "progress": {
      "phase": "scan_phase2",
      "currentTool": "nuclei",
      "currentHost": "88.99.35.112",
      "hostsTotal": 3,
      "hostsCompleted": 1,
      "discoveredHosts": [],
      "toolOutput": "3 findings (1 high, 2 medium)",
      "lastCompletedTool": "nikto"
    },
    "startedAt": "2026-03-01T12:00:00.000Z",
    "finishedAt": null,
    "error": null,
    "hasReport": false
  }
}
```

### DELETE /api/orders/:id

Cancel or permanently delete an order. **Auth required** (ownership check).

- **Without `?permanent=true`**: Soft cancel. Sets status to `cancelled`. Works on orders in `verification_pending`, `verified`, `created`, `queued`, `scanning`, `dns_recon`, `scan_phase1`, `scan_phase2`, `scan_complete`, `report_generating`.
- **With `?permanent=true`** (admin only): Hard delete. Removes order, scan_results, reports, audit_log entries, and MinIO objects.

**Response:**
```json
{ "success": true, "data": null }
```

**Errors:** 409 (cannot cancel in current status), 403 (permanent delete requires admin)

### GET /api/orders/:id/report

Download PDF report. Auth via JWT (header or `?token=` query param) or via `?download_token=` (for email links, no login needed).

**Response:** Binary PDF stream with `Content-Type: application/pdf` and `Content-Disposition: attachment; filename="vectiscan-example.com-2026-03-14.pdf"`.

**Errors:** 401 (no auth), 403 (invalid download token), 404 (report not ready), 410 (download link expired)

### GET /api/orders/:id/results

Raw scan results per tool. No auth required (debug endpoint).

**Response:**
```json
{
  "success": true,
  "data": {
    "results": [
      {
        "id": "uuid",
        "hostIp": "88.99.35.112",
        "phase": 2,
        "toolName": "nuclei",
        "rawOutput": "...",
        "exitCode": 0,
        "durationMs": 45000,
        "createdAt": "2026-03-01T12:30:00.000Z"
      }
    ]
  }
}
```

### GET /api/orders/:id/events

Event replay for scan detail page. **Auth required** (ownership check). Returns AI strategy decisions, AI phase2 configs, and tool output summaries.

**Response:**
```json
{
  "success": true,
  "data": {
    "aiStrategy": {
      "hosts": [
        { "ip": "88.99.35.112", "action": "scan", "priority": 1, "reasoning": "..." }
      ],
      "strategy_notes": "..."
    },
    "aiConfigs": {
      "88.99.35.112": {
        "nuclei_tags": ["wordpress", "exposure"],
        "gobuster_wordlist": "wordpress",
        "reasoning": "..."
      }
    },
    "toolOutputs": [
      { "tool": "nmap", "host": "88.99.35.112", "summary": "...", "ts": "..." }
    ],
    "discoveredHosts": [],
    "error": null
  }
}
```

### GET /api/orders/:id/findings

Structured findings from the Claude-processed report. **Auth required** (ownership check).

**Response:**
```json
{
  "success": true,
  "data": {
    "overall_risk": "MEDIUM",
    "overall_description": "...",
    "severity_counts": { "HIGH": 1, "MEDIUM": 3, "LOW": 2, "INFO": 4 },
    "findings": [...],
    "positive_findings": [...],
    "recommendations": [...]
  }
}
```

---

## Verification

### POST /api/verify/check

Check domain verification (DNS TXT, file, or meta tag). If verified, the scan is automatically enqueued.

**Request Body:**
```json
{ "orderId": "uuid" }
```

**Response:**
```json
{ "success": true, "data": { "verified": true, "method": "dns_txt" } }
```

or:
```json
{ "success": true, "data": { "verified": false } }
```

### POST /api/verify/manual

Skip verification (prototype/development only). Immediately marks the order as verified and enqueues the scan.

**Request Body:**
```json
{ "orderId": "uuid" }
```

**Response:**
```json
{ "success": true, "data": { "verified": true, "method": "manual" } }
```

### GET /api/verify/status/:orderId

Check verification status and get the verification token/instructions.

**Response:**
```json
{
  "success": true,
  "data": {
    "verified": false,
    "method": null,
    "token": "random-token",
    "domain": "example.com"
  }
}
```

---

## Schedules

All schedule endpoints require **Auth**. Customers see only their own schedules, admins see all.

### GET /api/schedules

List all schedules.

**Response:**
```json
{
  "success": true,
  "data": {
    "schedules": [
      {
        "id": "uuid",
        "domain": "example.com",
        "package": "professional",
        "scheduleType": "monthly",
        "scheduleLabel": "Monatlich",
        "scheduledAt": null,
        "enabled": true,
        "lastScanAt": "2026-02-15T08:00:00.000Z",
        "nextScanAt": "2026-03-15T08:00:00.000Z",
        "lastOrderId": "uuid",
        "createdAt": "2026-01-15T10:00:00.000Z"
      }
    ]
  }
}
```

### POST /api/schedules

Create a new schedule. The domain must have been verified by this customer in a previous order.

**Request Body:**
```json
{
  "domain": "example.com",
  "package": "professional",
  "scheduleType": "monthly",
  "scheduledAt": "2026-04-01T08:00:00.000Z"
}
```

`scheduleType`: `weekly`, `monthly`, `quarterly`, `once`. For `once`, `scheduledAt` is required.

**Response (201):**
```json
{ "success": true, "data": { "id": "uuid" } }
```

### GET /api/schedules/:id

Schedule details including the 10 most recent orders for this domain.

**Response:**
```json
{
  "success": true,
  "data": {
    "schedule": { "id": "uuid", "domain": "...", "..." : "..." },
    "recentOrders": [
      { "id": "uuid", "status": "report_complete", "startedAt": "...", "finishedAt": "...", "createdAt": "..." }
    ]
  }
}
```

### PUT /api/schedules/:id

Update schedule properties.

**Request Body** (all optional):
```json
{
  "package": "nis2",
  "scheduleType": "quarterly",
  "scheduledAt": "2026-07-01T08:00:00.000Z",
  "enabled": false
}
```

**Response:**
```json
{ "success": true }
```

### DELETE /api/schedules/:id

Delete a schedule.

**Response:**
```json
{ "success": true }
```

---

## WebSocket

### GET /ws?orderId=<uuid>

Real-time progress events via WebSocket. Also accepts `?scanId=` for backward compatibility.

**Connection:** On connect, the server sends a `connected` event and replays persisted events (discovered hosts, AI strategy, AI configs, tool outputs) for late-joining clients.

**Event types:**
```json
{ "type": "connected", "orderId": "uuid", "timestamp": "..." }
{ "type": "hosts_discovered", "orderId": "uuid", "hosts": [...], "hostsTotal": 3 }
{ "type": "ai_strategy", "orderId": "uuid", "strategy": {...} }
{ "type": "ai_config", "orderId": "uuid", "ip": "...", "config": {...} }
{ "type": "tool_output", "orderId": "uuid", "tool": "nuclei", "host": "...", "summary": "..." }
{ "type": "status", "orderId": "uuid", "status": "scanning" }
{ "type": "progress", "orderId": "uuid", "phase": "scan_phase2", "tool": "nikto", "host": "..." }
```

---

## Order Status Flow

```
verification_pending → queued → scanning → dns_recon → scan_phase1 → scan_phase2 → scan_complete → report_generating → report_complete
                                                                                                                      → failed
                     → cancelled (from any running status)
```

## Backward Compatibility

Legacy `/api/scans` endpoints redirect to `/api/orders`:
- `POST /api/scans` → 307 → `POST /api/orders`
- `GET /api/scans/:id` → 301 → `GET /api/orders/:id`
- `GET /api/scans/:id/report` → 301 → `GET /api/orders/:id/report`
- `DELETE /api/scans/:id` → 307 → `DELETE /api/orders/:id`
