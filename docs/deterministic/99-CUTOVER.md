# 99 — Cutover-Plan + Smoke-Tests

**Ziel:** Geordneter Übergang vom alten zum neuen Determinismus-Stand mit
klaren Smoke-Tests und Rollback-Pfad.

**Strategie:** Big-Bang. Kein Feature-Flag, kein Parallel-Logging. Test-
Kunden werden vor dem Cutover informiert; alte Reports sind im
gewipten Datenstand nicht mehr abrufbar.

---

## 0. Vorbereitung (T-3 Tage)

- [ ] Test-Kunden informieren: „Am `<DATUM>` zwischen `<UHR>`–`<UHR>` UTC
      werden alle bestehenden Scan-Daten gelöscht. User-Accounts und
      Subscriptions bleiben erhalten."
- [ ] Backup-Speicher prüfen (mind. 5 GB frei in `${PROJECT_ROOT}/backups`)
- [ ] `.env`-File auf Vollständigkeit prüfen (POSTGRES_PASSWORD, MINIO_*, REDIS_*)
- [ ] Aktive Scans drainen: keine neuen Orders zwischen T-2 und Cutover

---

## 1. Code-Vorbereitung (T-2 Tage)

```bash
git checkout main
git pull
git checkout -b feature/q2-determinism

# Specs ins Repo (für PR-Review)
cp -r ~/Downloads/2026-Q2-determinism docs/specs/

# Specs lesen, Akzeptanzkriterien checken (00-OVERVIEW.md §"Definition of Done")
```

### Implementierungs-Reihenfolge

1. **Migrations** — `api/src/migrations/014_severity_policy.sql`,
                      `015_threat_intel_snapshots.sql`
   - Lokal anwenden, prüfen
   - Tests: `npm run migrate:test` (oder eurer Test-Runner)

2. **`severity_policy.py`** in `report-worker/reporter/`
   - Aus 02-severity-policy-skeleton.py übernehmen
   - Aus 02-severity-policy-tests.py: Tests in `report-worker/tests/`
   - `pytest report-worker/tests/test_severity_policy.py` muss grün sein

3. **`ai_cache.py`** in `scan-worker/scanner/`
   - Aus 03-ai-cache-skeleton.py übernehmen
   - Aus 03-ai-cache-tests.py: Tests
   - `requirements.txt`: `redis>=5.0`, `fakeredis` (dev only)
   - `pytest scan-worker/tests/test_ai_cache.py` muss grün sein

4. **AI-Calls instrumentieren**
   - `scan-worker/scanner/ai_strategy.py`: alle `anthropic_client.messages.create()`
     ersetzen durch `cached_call(...)`
   - KI #4 System-Prompt anpassen (siehe 03-ai-determinism.md §3)
   - `report-worker/reporter/claude_client.py`: ebenso instrumentieren

5. **`selection.py`** in `report-worker/reporter/`
   - Aus 04-selection-skeleton.py
   - Aus 04-selection-tests.py: Tests
   - `pytest report-worker/tests/test_selection.py` grün

6. **Reporter-Integration**
   - `report-worker/reporter/worker.py::process_report()` umbauen:
     ```python
     findings = parse_phase3_output(...)
     findings = severity_policy.apply_policy(findings, scan_context)
     findings = business_impact.recompute(findings)
     findings = validate_cvss_scores(findings)
     findings = validate_cwe_mappings(findings)
     selected = selection.select_findings(findings, package=order.package)
     report_data = claude_client.generate_narrative(selected)
     ```
   - `cap_implausible_scores()`-Aufruf entfernen
   - System-Prompt für Reporter umschreiben auf "Narrative-only"
     (siehe 04-deterministic-selection.md §6)

7. **Lokaler End-to-End-Test**
   ```bash
   docker compose up -d
   curl -X POST http://localhost:3001/api/orders \
        -H "Content-Type: application/json" \
        -d '{"domain": "example.com", "package": "perimeter"}'
   # Order durchlaufen lassen, Report prüfen
   # severity_provenance auf jedem Finding gesetzt?
   # Top-N respektiert?
   ```

8. **Code-Review** — PR review, mind. 1 Reviewer
   - Schwerpunkt: Severity-Policy-Vollständigkeit, Cache-Hash-Stabilität,
     Selection-Determinismus

---

## 2. Staging-Deploy (T-1 Tag)

- [ ] PR mergen
- [ ] Staging-Deploy via eurem Deploy-Pipeline
- [ ] **Migrations laufen automatisch beim Deploy** (Reihenfolge: 014 → 015)
- [ ] Smoke-Test #1 (s.u.)

---

## 3. Cutover (Tag T)

### Reihenfolge
```
T+0:00  Service-Health-Check (alle services up, queues leer)
T+0:05  Cleanup-Script: ./cleanup.sh --confirm
        - Backup wird automatisch erstellt
        - Confirmation-Prompt: "vectiscan-prod" eingeben
        - Wartet auf 0 active scans
        - DB → MinIO → Redis → Migrations → Service-Restart
T+0:15  Smoke-Test #2: Erste neue Scan-Order
T+0:40  Smoke-Test #3: Reproducibility-Re-Scan
T+1:00  Customer-Mail: "Cutover abgeschlossen, neue Scans verfügbar"
```

### Rollback-Trigger

Falls einer der Smoke-Tests fehlschlägt:

| Fehler-Stadium | Rollback-Aktion |
|---|---|
| Migration fehlgeschlagen | Backup einspielen, Code-Revert, Investigation |
| Cleanup teilweise (DB ja, MinIO nein) | MinIO manuell nachräumen, weitermachen |
| Smoke-Test #2 (neue Scan-Order) schlägt fehl | Code-Revert, Backup einspielen |
| Smoke-Test #3 (Reproducibility) schlägt fehl | Code-Revert, **dann** Backup einspielen |

---

## 4. Smoke-Tests

### Smoke-Test #1: Staging-Deploy-Health (vor Cleanup)

```bash
# Service-Status
curl -sf https://staging.vectigal.tech/health | jq

# Migrations-Stand
psql -h staging-db -c "SELECT version FROM migrations ORDER BY version DESC LIMIT 3;"
# Erwartet: 015, 014, 013

# Beispiel-Scan
ORDER_ID=$(curl -sX POST https://staging.vectigal.tech/api/orders \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"domain": "test.example.com", "package": "perimeter"}' | jq -r .order_id)

# Warten bis fertig (max 30 min)
while true; do
    STATUS=$(curl -s https://staging.vectigal.tech/api/orders/$ORDER_ID | jq -r .status)
    echo "Status: $STATUS"
    [[ "$STATUS" == "completed" ]] && break
    [[ "$STATUS" == "failed" ]] && { echo "FAIL"; exit 1; }
    sleep 30
done

# Report holen + prüfen
curl -s https://staging.vectigal.tech/api/orders/$ORDER_ID/report > report.json
jq '.findings | map(.policy_id) | unique' report.json
# Erwartet: Liste mit SP-*-Einträgen, KEINE "SP-FALLBACK"
```

**Pass-Kriterium:**
- API health = 200
- Migration-Stand = 15
- Scan läuft durch
- Findings haben `policy_id` mit `SP-*` Prefix
- `severity_provenance` auf jedem Finding vorhanden
- Top-N respektiert (≤ 15 für Perimeter)

### Smoke-Test #2: Erste Scan-Order nach Cleanup

Identisch zu #1, aber gegen Prod-API.

**Zusätzliche Pass-Kriterien:**
- AI-Cache-Hit-Rate auf erstem Scan = 0% (erwartet, frisch nach Cleanup)
- Report wird in MinIO `reports/` abgelegt
- DB-Eintrag in `report_findings_data` mit `policy_version` = aktuelle Version

### Smoke-Test #3: Reproducibility-Re-Scan

```bash
# Erster Scan (T+0:15)
ORDER_ID_1=$(curl -sX POST ... )
# warten bis completed
# Findings-Hash 1
HASH_1=$(curl -s ../report | jq '.findings | map({policy_id, severity, business_impact_score})' | sha256sum)

# Zweiter Scan derselben Domain (T+0:35)
ORDER_ID_2=$(curl -sX POST ... )
# warten bis completed
HASH_2=$(curl -s ../report | jq '.findings | map({policy_id, severity, business_impact_score})' | sha256sum)
```

**Pass-Kriterium:**
- `HASH_1 == HASH_2` (deterministisch)
- AI-Cache-Hit-Rate auf zweitem Scan ≥ 80% (Logs prüfen)
- Beide Reports haben identische `policy_id_distinct`-Liste

**Akzeptierte Abweichungen:**
- Unterschiedliche `order_id`, `created_at`
- Unterschiedliche `tool_metrics.runtime_ms` (variiert mit Last)
- Bei minimalen Floating-Point-Differenzen: business_impact_score-Differenz < 0.01

### Smoke-Test #4: KI #4 verhält sich wie spezifiziert

Logs des zweiten Re-Scans prüfen:

```bash
docker compose logs scan-worker-1 | grep "ki4_phase3"
```

**Pass-Kriterium:**
- KI #4 schreibt nur `confidence_scores`-Antworten, KEINE FP-Marker
- Findings nach Phase 3 haben unverändertes `false_positive`-Feld
  (gleich vor und nach KI #4)

---

## 5. Post-Deploy-Monitoring (T+0 bis T+7 Tage)

### Metriken zu beobachten

```sql
-- Severity-Verteilung (Vorher-Nachher-Vergleich)
SELECT
    DATE(created_at) AS day,
    severity_counts->>'critical' AS critical,
    severity_counts->>'high'     AS high,
    severity_counts->>'medium'   AS medium,
    severity_counts->>'low'      AS low,
    severity_counts->>'info'     AS info
FROM report_findings_data
WHERE created_at > NOW() - INTERVAL '7 days'
ORDER BY day DESC;

-- Erwartung: Verschiebung von Medium nach Low/Info

-- SP-FALLBACK-Rate (sollte < 5% sein)
SELECT
    COUNT(*) FILTER (WHERE 'SP-FALLBACK' = ANY(policy_id_distinct)) * 100.0 / COUNT(*) AS fallback_pct
FROM report_findings_data
WHERE created_at > NOW() - INTERVAL '7 days';

-- AI-Cache-Hit-Rate
-- (aus audit_log oder scan_results.tool_metrics extrahieren)
```

### Alerting (für nächste 7 Tage)

- SP-FALLBACK-Rate > 10 %: hinweisende Policy fehlt
- Cache-Hit-Rate auf Re-Scans < 50 %: Cache-Key-Logik prüfen
- Average Cost per Scan > $1.50: Cache funktioniert nicht

---

## 6. Customer-Communication

### T-3: Pre-Notice
> Wir planen am `<DATUM>` einen technischen Cutover. Zwischen
> `<UHR_VON>`–`<UHR_BIS>` UTC ist der Scan-Service kurzzeitig nicht
> verfügbar. Bestehende Scan-Daten werden im Zuge dessen neu strukturiert
> — das verbessert die Reproduzierbarkeit von Re-Scans und die
> Vergleichbarkeit unserer Severity-Bewertungen mit kommerziellen Tools.
> Account und Subscription bleiben unverändert.

### T+0:50: Completion-Notice
> Der Cutover ist abgeschlossen. Sie können wie gewohnt neue Scans starten.
> Bei Fragen oder Anomalien bitte support@vectigal.de.

---

## 7. Rollback-Plan (Notfall)

Falls ein kritischer Fehler entdeckt wird, der nicht innerhalb 1 h
behoben werden kann:

```bash
# 1. Code zurückrollen
git revert <merge-commit>
# Deploy

# 2. DB restoren aus Backup
gunzip -c backups/backup-pre-cleanup-<TS>.sql.gz | \
    docker compose exec -T postgres psql -U vectiscan -d vectiscan

# 3. MinIO-Buckets — sind nach Cleanup leer; Rollback ohne MinIO-Restore
#    funktioniert (alte Reports nicht mehr da, aber System läuft).
#    Falls MinIO-Backup vorhanden: mc mirror restore_backup/ minio/

# 4. Migrations zurückrollen (siehe Rollback-Sektionen in den .sql-Files)

# 5. Customer informieren: Maintenance Window verlängert
```

**Kritisches Detail:** Backup wird VOR der Migration erstellt, also nimmt
die Wiederherstellung das alte Schema mit. Migrations müssen explizit
zurückgerollt werden, sonst inkompatibel.

---

## 8. Definition of „Cutover Done"

Alle Häkchen müssen gesetzt sein, bevor der Cutover als abgeschlossen gilt:

- [ ] Migrations 014 + 015 sind in Prod aktiv
- [ ] Smoke-Test #1 (Staging) grün
- [ ] Cleanup erfolgreich, Verifikations-Queries (siehe 01-cleanup.md §"Verifikation") = 0
- [ ] Smoke-Test #2 (erster neuer Scan) grün
- [ ] Smoke-Test #3 (Reproducibility) grün
- [ ] Smoke-Test #4 (KI #4 Verhalten) grün
- [ ] SP-FALLBACK-Rate < 10 % in den ersten 5 Scans
- [ ] AI-Cache-Hit-Rate ≥ 50 % auf zweitem Scan derselben Domain
- [ ] Customer-Completion-Notice versendet
- [ ] Backup-File 7 Tage aufbewahren, dann archivieren

---

## 9. Open Items für P2 (Q3/2026)

- Aktive Threat-Intel-Snapshot-Erstellung (heute nur Schema da)
- Reproducibility-Test als CI-Job
- Tool-Versionen (wpscan-DB, testssl) im Report-Footer pinnen
- Evidence-Appendix mit Request/Response-Samples
- JS-Sink-Erkennung (DOM-XSS) als neues Scanner-Modul
