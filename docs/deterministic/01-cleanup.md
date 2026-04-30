# 01 — Cleanup Test-Datenbestand (Big-Bang)

**Ziel:** Alle Scan-Daten, Reports, Caches und MinIO-Objekte aus dem Test-
Betrieb entfernen, damit die neue Determinismus-Logik auf grüner Wiese
startet. **User-Accounts und Subscriptions bleiben erhalten** — nur die
Scan-Artefakte werden gewipt.

**Nicht-Ziel:** User-Accounts, Roles, Subscription-Konfigurationen anfassen.
Wer heute Zugriff hat, hat danach immer noch Zugriff.

---

## Was bleibt, was geht

### Bleibt
- `users` (alle Accounts inkl. Admin)
- `subscriptions` (Abo-Header)
- `subscription_domains` (verifizierte Domains, damit Customer ohne neue
  Verifizierung weiterscannen kann)
- `verified_domains` (90-Tage-Verifizierungs-Cache)
- Schema selbst (alle Tables, Indexes, Constraints) — wir migrieren danach,
  nicht davor

### Geht
| Tabelle | Action | Begründung |
|---|---|---|
| `orders` | TRUNCATE CASCADE | Alle Scan-Orders weg |
| `scan_results` | TRUNCATE | implizit via CASCADE, aber explizit listen |
| `report_findings_data` | TRUNCATE | alte Findings-Strukturen passen nicht mehr |
| `report_findings_exclusions` | TRUNCATE | basieren auf gelöschten Findings |
| `reports` | TRUNCATE | binärer Report-Storage |
| `audit_log` | TRUNCATE | Test-Audit-Spuren weg |
| `report_versions` | TRUNCATE | alte Versionen weg |
| `scan_schedules` | DELETE WHERE last_run_at IS NOT NULL | aktive Schedules behalten, History weg |

| MinIO-Bucket | Action |
|---|---|
| `scan-rawdata` | komplett leeren (`mc rm --recursive`) |
| `scan-debug` | komplett leeren |
| `reports` | komplett leeren |

| Redis-Key-Pattern | Action |
|---|---|
| `nvd:*`, `epss:*`, `kev:*`, `exploitdb:*` | DEL (Threat-Intel-Cache) |
| `ai_cache:*` | DEL (falls vorhanden — sonst No-Op) |
| `ws:*` | DEL (WebSocket-State) |
| `bull:*` | FLUSHDB nur wenn alle Queues leer (sonst nur stale Jobs) |

## Reihenfolge der Operationen (kritisch)

```
1. Pre-Flight Check
   ├─ DB-Connectivity prüfen
   ├─ MinIO-Connectivity prüfen
   ├─ Redis-Connectivity prüfen
   └─ Active-Scan-Check: SELECT count(*) FROM orders WHERE status IN
      ('queued','scanning','passive_intel','dns_recon','scan_phase1',
       'scan_phase2','scan_phase3','report_generating') = 0
      → wenn nicht 0: Abort, manuelle Klärung

2. Backup (optional, default an)
   ├─ pg_dump > backup-pre-cleanup-<TS>.sql.gz
   └─ MinIO buckets als tar.gz (optional, kann skipped werden)

3. API-Service stoppen (verhindert neue Orders während Cleanup)
   └─ docker compose stop api scan-worker-1 scan-worker-2 report-worker

4. DB-Cleanup
   ├─ TRUNCATE orders, scan_results, report_findings_data,
   │            report_findings_exclusions, reports, report_versions,
   │            audit_log RESTART IDENTITY CASCADE
   ├─ DELETE FROM scan_schedules WHERE last_run_at IS NOT NULL
   └─ VACUUM ANALYZE (Reclaim disk space)

5. MinIO-Cleanup
   ├─ mc rm --recursive --force minio/scan-rawdata/
   ├─ mc rm --recursive --force minio/scan-debug/
   └─ mc rm --recursive --force minio/reports/

6. Redis-Cleanup
   ├─ redis-cli --scan --pattern 'nvd:*'      | xargs redis-cli DEL
   ├─ redis-cli --scan --pattern 'epss:*'     | xargs redis-cli DEL
   ├─ redis-cli --scan --pattern 'kev:*'      | xargs redis-cli DEL
   ├─ redis-cli --scan --pattern 'exploitdb:*'| xargs redis-cli DEL
   ├─ redis-cli --scan --pattern 'ai_cache:*' | xargs redis-cli DEL
   └─ redis-cli --scan --pattern 'ws:*'       | xargs redis-cli DEL

7. Migrations 014 + 015 anwenden
   └─ npm run migrate (oder eurer Migrations-Runner)

8. Services starten
   └─ docker compose up -d

9. Smoke-Test
   ├─ GET /health == 200 OK
   ├─ POST /api/orders mit Test-Domain → Scan startet
   └─ Scan läuft erfolgreich durch (~22 min für Perimeter)
```

## Sicherheitsmaßnahmen im cleanup.sh

- **`--dry-run`**: Default-Modus, zeigt nur was passieren würde, ändert nichts
- **`--confirm`**: Explizit erforderlich für echten Wipe; ohne = Dry-Run
- **Confirmation-Prompt** mit Domain-Echo: User muss `vectiscan-prod` eintippen
- **Active-Scan-Check** als Hard-Stop
- **Backup-Step** ist Default an, kann mit `--no-backup` deaktiviert werden
- **Logging** in `cleanup-<TS>.log` mit allen ausgeführten Statements

## Schema-Reihenfolge bei TRUNCATE CASCADE

Bei TRUNCATE CASCADE auf `orders` werden via FK automatisch geleert:
- `scan_results` (FK orders_id)
- `report_findings_data` (FK orders_id)
- `report_findings_exclusions` (FK report_findings_data_id → orders_id)
- `report_versions` (FK orders_id)
- `reports` (FK orders_id)

Trotzdem listen wir alle Tabellen explizit, um Schema-Drift zu erkennen
(falls eine FK fehlt oder eine neue Tabelle hinzugekommen ist).

## Was passiert mit `verified_domains`?

Bleibt erhalten. Wenn Customer A heute `example.com` verifiziert hat und
das in den nächsten 90 Tagen wieder scannen will, soll er nicht erneut
verifizieren müssen. Das ist UX, nicht Daten-Hygiene.

## Was passiert mit `scan_schedules`?

Aktive Schedules (`enabled=true`, `next_run_at IN FUTURE`) bleiben.
Vergangenheit (`last_run_at` gesetzt) wird weggeräumt. Wenn ein Schedule
für morgen einen Re-Scan plant, läuft der einfach durch — nur ohne
History.

## Wenn ein Cleanup-Schritt fehlschlägt

| Fehler in Schritt | Aktion |
|---|---|
| 1 (Pre-Flight) | Abort, kein Daten-Schaden |
| 2 (Backup) | User fragen ob trotzdem fortfahren |
| 3 (Services stoppen) | Abort, Services manuell prüfen |
| 4 (DB) | Backup einspielen, Investigation |
| 5 (MinIO) | DB ist schon leer; MinIO-Reste sind harmlos, später nachräumen |
| 6 (Redis) | DB+MinIO sind leer, Redis-Reste sind harmlos (Cache rebuild bei Erstem Scan) |
| 7 (Migrations) | Backup einspielen, Migration debuggen, neu starten |
| 8 (Services starten) | Services manuell prüfen |
| 9 (Smoke-Test) | Investigation, nicht zurück-rollen ohne Diagnose |

## Verifikation nach Cleanup

```sql
-- Alle MUSS-Werte auf 0
SELECT 'orders'                  AS tbl, count(*) FROM orders
UNION ALL SELECT 'scan_results',           count(*) FROM scan_results
UNION ALL SELECT 'report_findings_data',   count(*) FROM report_findings_data
UNION ALL SELECT 'reports',                count(*) FROM reports
UNION ALL SELECT 'audit_log',              count(*) FROM audit_log;

-- Diese MÜSSEN ihre Test-Werte behalten haben:
SELECT 'users',                   count(*) FROM users;             -- z.B. 5
SELECT 'subscriptions',           count(*) FROM subscriptions;     -- z.B. 2
SELECT 'subscription_domains',    count(*) FROM subscription_domains;
```

```bash
# MinIO sollte leer sein:
mc ls minio/scan-rawdata/
mc ls minio/scan-debug/
mc ls minio/reports/

# Migration-Check:
psql -c "SELECT version FROM migrations ORDER BY version DESC LIMIT 3;"
# erwartet: 015, 014, 013
```

## Crosslinks

- Skript: [`01-cleanup.sh`](./01-cleanup.sh)
- Migrationen: [`05-schema-migrations.md`](./05-schema-migrations.md)
- Cutover-Reihenfolge: [`99-CUTOVER.md`](./99-CUTOVER.md)
