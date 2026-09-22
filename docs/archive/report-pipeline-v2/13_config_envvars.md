# 13 — Konfiguration: Environment-Variablen

Alles, was der `report-worker` zur Laufzeit aus `os.environ` liest. Verifiziert per grep gegen `report-worker/reporter/**.py` und `docker-compose.yml:389-419`.

## VECTISCAN_*

| ENV | Default | Wirkung | Gelesen in |
|---|---|---|---|
| `VECTISCAN_VALIDATION_LEVEL` | `warn` (Code), `strict` (Prod-Compose) | `off / warn / strict` — steuert das Validation-Gate. STRICT blockt den PDF-Build und setzt Order auf failed. WARN persistiert die Defekte in `reports.validation_warnings`. | `validation/gate.py:87` (`ValidationGate.from_env`) |
| `VECTISCAN_REPORT_LAYOUT` | `v1` (Code), `v2` (Prod-Compose) | Schaltet zwischen Legacy-v1-Renderer und v2 3-Schichten-Renderer. Wirkt auf zwei Stellen: `_augment_for_v2`-Aufruf im Mapper UND PDF-Generator-Auswahl im Worker. | `report_mapper.py:1776`, `worker.py:711` |
| `VECTISCAN_POLICY_VERSION` | `2026-06-01.1` (severity_policy), `2026-05-10.1` (ai_cache **mismatch**) | Wird in `reports.policy_version` persistiert; geht in den AI-Cache-Key (Cache-Invalidate bei Bump). | `severity_policy.py:36`, `ai_cache.py:22`, `v2_data.py:122` |

In `docker-compose.yml:411, 419` haben `VECTISCAN_VALIDATION_LEVEL` und `VECTISCAN_REPORT_LAYOUT` per `${VAR:-default}`-Substitution Prod-Defaults `strict` und `v2`.

`VECTISCAN_POLICY_VERSION` ist NICHT im Compose-Override gesetzt — gilt damit der Code-Default. Aufgrund der Code-Inkonsistenz (zwei Default-Werte in zwei Modulen) entsteht der Bug aus `99_known_issues.md`.

## Infrastruktur-ENV (von docker-compose gefüllt)

| ENV | Default | Verwendung |
|---|---|---|
| `REDIS_URL` | `redis://localhost:6379` | BullMQ-Queue + AI-Cache + Posture-Status-Trigger | `worker.py:36`, `ai_cache.py:37`, `cwe_api_client.py:26`, `posture_aggregator.py:497` |
| `DATABASE_URL` | `postgresql://localhost:5432/vectiscan` | PG-Connections, alle DB-Operationen | `worker.py:37`, `ai_cost_persist.py:37`, `status_report_generator.py:375`, `scripts/replay_gate.py:52` |
| `MINIO_ENDPOINT` | `minio` | Scan-Rawdata-Download + Report-Upload | `worker.py:38`, `status_report_generator.py:353` |
| `MINIO_PORT` | `9000` | Mit Endpoint zu `f"{MINIO_ENDPOINT}:{MINIO_PORT}"` zusammengefügt | `worker.py:38` |
| `MINIO_ACCESS_KEY` | `minioadmin` | MinIO-Auth | `worker.py:39` |
| `MINIO_SECRET_KEY` | `minioadmin` | MinIO-Auth | `worker.py:40` |
| `MINIO_SECURE` | `false` | HTTPS-Toggle für MinIO-Client | `worker.py:41` |
| `MINIO_BUCKET` | `scan-reports` | Bucket für Status-Reports | `status_report_generator.py:356` |
| `ANTHROPIC_API_KEY` | (none) | API-Key für alle Claude-Calls (Sonnet 4.6 + Haiku 4.5) | `claude_client.py:667`, `qa_check.py:526`, `ai_finding_type_fallback.py:145`, `batch_api.py:37/73/101` |

## Zusammenfassung Prod-Werte (docker-compose.yml:389-419)

```yaml
report-worker:
  environment:
    REDIS_URL: redis://redis:6379
    MINIO_ENDPOINT: minio
    MINIO_PORT: "9000"
    MINIO_ACCESS_KEY: ${MINIO_ACCESS_KEY}
    MINIO_SECRET_KEY: ${MINIO_SECRET_KEY}
    DATABASE_URL: postgresql://${DB_USER}:${DB_PASSWORD}@postgres:5432/${DB_NAME}
    ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}
    VECTISCAN_VALIDATION_LEVEL: ${VECTISCAN_VALIDATION_LEVEL:-strict}
    VECTISCAN_REPORT_LAYOUT: ${VECTISCAN_REPORT_LAYOUT:-v2}
```

Restlichliste der ENV-Variablen (`MINIO_SECURE`, `VECTISCAN_POLICY_VERSION`) ist nicht im Compose-File gesetzt — Code-Defaults gelten.

## Override-Pattern für Incident-Response

Aus dem Code-Kommentar `docker-compose.yml:400-410`:

> "M2-Ende (2026-06-01): Validation-Gate STRICT. Defekte blockieren PDF-Build, Order geht auf failed mit Begruendung in error_message. Per ENV-Override auf 'warn' oder 'off' zurueckfallbar bei Prod-Incidents."

Operationelle Praxis: bei einem Mass-Failure wird der Wert über `.env` auf `warn` gesetzt, um vorerst die Builds wieder durchzulassen — die Defekte landen dann in `reports.validation_warnings` und können nachträglich beim Replay (`scripts/replay_gate.py`) ausgewertet werden.

## Worker-Modul-Konstanten (nicht aus ENV)

Werte, die im Code hartcodiert sind und über keinen ENV-Override geändert werden können:

| Konstante | Wert | Wirkt auf |
|---|---|---|
| `screenshot_pipeline.DEFAULT_MAX_SCREENSHOTS` | `2` | Max Screenshots im Render |
| `selection.TOP_N_PER_PACKAGE` | `{webcheck:8, perimeter:15, compliance:20, supplychain:15, insurance:15}` | Top-N pro Paket |
| `selection.MIN_N_PER_PACKAGE` | `{webcheck:3, perimeter:6, compliance:10, supplychain:6, insurance:6}` | Mindest-Floor bei Underrun |
| `selection.DEFAULT_TOP_N` | `10` | Fallback bei unbekanntem Paket-Key |
| `tech_table_builder.KERNEL_DETECTION_BLACKLIST` | 8 String-Pattern | Tech-Detection-Filter |
| `tech_table_builder.MIN_PUBLIC_VERSIONS` | 10 Library-Min-Versionen | Halluzinations-Filter |
| `_MAX_IMAGE_WIDTH_V2` (strategy.py) | `160 mm` | Screenshot-Render-Max-Breite |
| `_TRIGGER_LIST` (appendix.py:555) | 6 Trigger | Wiederholungs-Empfehlungs-Anhang F |
| `_TOOL_CONFIDENCE` (appendix.py:352) | 16 Tools | Anhang C Konfidenz-Map |
| `_SERVICE_RECOMMENDATION_HINT` (appendix.py:186) | 25 Ports | Anhang B Empfehlungs-Map |

Bei Änderungen an diesen Werten muss neu deployed werden.
