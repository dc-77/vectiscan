# VectiScan Prototyp — API-Spezifikation

Base-URL: https://scan-api.vectigal.tech (internal-only)
Interner Port: 4000

---

## POST /api/scans

Neuen Scan starten.

**Request:**
```json
{
  "domain": "beispiel.de"
}
```

**Validierung:**
- domain: Pflichtfeld, gültiger FQDN (kein http://, kein Pfad, kein Port)
- Regex: /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/

**Response 201:**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "domain": "beispiel.de",
    "status": "created",
    "createdAt": "2026-03-12T14:30:00Z"
  }
}
```

---

## GET /api/scans/:id

Scan-Status und Fortschritt abrufen.

**Response 200:**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-...",
    "domain": "beispiel.de",
    "status": "scan_phase2",
    "progress": {
      "phase": "phase2",
      "currentTool": "nikto",
      "currentHost": "88.99.35.112",
      "hostsTotal": 3,
      "hostsCompleted": 1,
      "discoveredHosts": [
        {
          "ip": "88.99.35.112",
          "fqdns": ["beispiel.de", "www.beispiel.de"],
          "status": "completed"
        },
        {
          "ip": "88.99.35.113",
          "fqdns": ["mail.beispiel.de"],
          "status": "scanning"
        },
        {
          "ip": "88.99.35.114",
          "fqdns": ["dev.beispiel.de"],
          "status": "pending"
        }
      ]
    },
    "startedAt": "2026-03-12T14:30:05Z",
    "finishedAt": null,
    "error": null,
    "hasReport": false
  }
}
```

**Status-Werte (in Reihenfolge):**
created → dns_recon → scan_phase1 → scan_phase2 → scan_complete →
report_generating → report_complete | failed

---

## GET /api/scans/:id/report

Pre-Signed Download-URL für den PDF-Report.

**Response 200:**
```json
{
  "success": true,
  "data": {
    "downloadUrl": "http://minio:9000/scan-reports/550e8400.pdf?X-Amz-...",
    "fileName": "vectiscan-beispiel.de-2026-03-12.pdf",
    "fileSize": 245760
  }
}
```

**Response 404 (Report noch nicht fertig):**
```json
{
  "success": false,
  "error": "Report not yet available"
}
```

---

## GET /health

**Response 200:**
```json
{ "status": "ok", "timestamp": "2026-03-12T14:30:00Z" }
```