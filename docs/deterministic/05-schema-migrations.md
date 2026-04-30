# 05 — Schema-Migrations 014 + 015

**Ziel:** Datenbank-Schema-Erweiterungen für Severity-Provenance-Tracking
und Threat-Intel-Snapshots (Vorbereitung für P2).

**Lokation:** `api/src/migrations/`

**Migrations-Runner:** Eurer bestehender (Convention 002–013, einzelne SQL-Files).

---

## Migration 014: Severity-Provenance auf Findings

### Motivation
Nach Severity-Policy-Implementierung will jeder Finding eine
nachvollziehbare Begründung mitführen, **wie** seine Severity zustande kam.

### Änderungen
`report_findings_data` ist eine JSONB-Tabelle (`findings_data` ist ein
Array von Finding-Objekten). Wir ergänzen pro Finding-Objekt zwei Felder
in der JSON-Struktur (kein DDL nötig).

**Zusätzliche Spalten** auf `report_findings_data` für schnelle
Aggregation und Index-Suche:

```sql
ALTER TABLE report_findings_data
    ADD COLUMN policy_version TEXT,
    ADD COLUMN policy_id_distinct TEXT[],
    ADD COLUMN severity_counts JSONB
        GENERATED ALWAYS AS (
            jsonb_build_object(
                'critical', (SELECT count(*) FROM jsonb_array_elements(findings_data) f
                             WHERE f->>'severity' = 'critical'),
                'high',     (SELECT count(*) FROM jsonb_array_elements(findings_data) f
                             WHERE f->>'severity' = 'high'),
                'medium',   (SELECT count(*) FROM jsonb_array_elements(findings_data) f
                             WHERE f->>'severity' = 'medium'),
                'low',      (SELECT count(*) FROM jsonb_array_elements(findings_data) f
                             WHERE f->>'severity' = 'low'),
                'info',     (SELECT count(*) FROM jsonb_array_elements(findings_data) f
                             WHERE f->>'severity' = 'info')
            )
        ) STORED;
```

**Index** für Audit-Queries:
```sql
CREATE INDEX idx_findings_policy_version ON report_findings_data(policy_version);
CREATE INDEX idx_findings_policy_ids ON report_findings_data USING gin(policy_id_distinct);
```

### Datenmigration
Da Cleanup vor Migration läuft (siehe `99-CUTOVER.md`), gibt es **keine
Bestandsdaten** zu migrieren. Die Spalten sind initial NULL.
Neue Reports füllen sie über den Reporter-Code.

### Rollback
```sql
ALTER TABLE report_findings_data
    DROP COLUMN IF EXISTS policy_version,
    DROP COLUMN IF EXISTS policy_id_distinct,
    DROP COLUMN IF EXISTS severity_counts;
DROP INDEX IF EXISTS idx_findings_policy_version;
DROP INDEX IF EXISTS idx_findings_policy_ids;
```

---

## Migration 015: Threat-Intel-Snapshots-Tabelle

### Motivation (P2-Vorbereitung)
Ein Re-Scan derselben Domain in 30 Tagen kann andere Severities liefern,
wenn sich NVD/KEV/EPSS-Daten geändert haben. Das ist **erwünscht** (neue
Bedrohungen werden erkannt), aber muss auditierbar sein. Die Tabelle
nimmt einen Snapshot der Threat-Intel-Daten zum Scan-Zeitpunkt auf.

In diesem Q2-Block legen wir nur das **Schema** an. Die aktive Nutzung
(Snapshot bei jedem Scan schreiben) kommt in P2.

### Änderungen

```sql
CREATE TABLE threat_intel_snapshots (
    snapshot_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    nvd_version     TEXT,
    kev_version     TEXT,
    epss_version    TEXT,
    nvd_data        JSONB,
    kev_data        JSONB,
    epss_data       JSONB,
    metadata        JSONB DEFAULT '{}'::JSONB
);

CREATE INDEX idx_ti_snapshots_created_at ON threat_intel_snapshots(created_at DESC);

-- Verknüpfung zur Order
ALTER TABLE orders
    ADD COLUMN threat_intel_snapshot_id UUID
        REFERENCES threat_intel_snapshots(snapshot_id) ON DELETE SET NULL;

CREATE INDEX idx_orders_ti_snapshot ON orders(threat_intel_snapshot_id);
```

### Initial-Daten
Keine. Tabelle ist leer.

### Speicher-Projektion
Bei voller Nutzung (P2):
- 1 Snapshot pro Order ist zu viel (Daten sind redundant zwischen Orders)
- Snapshots werden täglich neu erstellt, nicht pro Order
- Orders referenzieren auf den nächsten älteren Snapshot
- Pro Snapshot: ~5 MB (NVD ist größter Teil) → ~2 GB/Jahr bei täglicher Erstellung

In P2 wird eine TTL/Cleanup-Policy ergänzt (z.B. nur letzte 12 Monate behalten).

### Rollback
```sql
ALTER TABLE orders DROP COLUMN IF EXISTS threat_intel_snapshot_id;
DROP INDEX IF EXISTS idx_orders_ti_snapshot;
DROP INDEX IF EXISTS idx_ti_snapshots_created_at;
DROP TABLE IF EXISTS threat_intel_snapshots;
```

---

## Idempotenz

Beide Migrations sollen idempotent sein (re-run-safe):

- `ADD COLUMN` mit `IF NOT EXISTS`
- `CREATE TABLE` mit `IF NOT EXISTS`
- `CREATE INDEX` mit `IF NOT EXISTS`

Eintrag in `migrations`-Tabelle:
```sql
INSERT INTO migrations (version, applied_at) VALUES (14, NOW())
    ON CONFLICT (version) DO NOTHING;
INSERT INTO migrations (version, applied_at) VALUES (15, NOW())
    ON CONFLICT (version) DO NOTHING;
```

## Reihenfolge

014 vor 015 — keine direkten Abhängigkeiten, aber numerisch korrekt.

## Crosslinks

- Migration-Files: [`05-014-severity-policy.sql`](./05-014-severity-policy.sql),
  [`05-015-threat-intel-snapshots.sql`](./05-015-threat-intel-snapshots.sql)
- Severity-Policy-Spec: [`02-severity-policy.md`](./02-severity-policy.md)
- Cutover-Plan: [`99-CUTOVER.md`](./99-CUTOVER.md)
