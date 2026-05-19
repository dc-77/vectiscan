# 01 — Big Picture der PDF-Report-Pipeline

Ist-Stand aus dem Code, Mai 2026.

## Trigger und Queue

Der `report-worker` ist ein BullMQ-Consumer auf der Redis-Queue `report-pending`. Die API enqueued nach Abschluss der Phase-3-Korrelation einen Job mit:

```
{
  "orderId": "<uuid>",
  "rawDataPath": "<orderId>.tar.gz",
  "hostInventory": {...},
  "techProfiles": [...],
  "package": "perimeter",
  "excludedFindings": [...],
  "approved": <bool>,
  "enrichment": {...}
}
```

Variante: Bei `subscriptionId` statt `orderId` läuft der Posture-Status-Report-Pfad in `reporter/status_report_generator.py` (nicht in diesem Dokument behandelt).

Einstiegspunkt: `report-worker/reporter/worker.py:387` (`process_job`).

## ASCII-Pipeline (End-to-End)

```
┌──────────────────────────────────────────────────────────────────────┐
│ BullMQ Queue "report-pending"   redis://redis:6379                    │
└────────────────────────┬─────────────────────────────────────────────┘
                         │ job_data
                         ▼
   ┌─────────────────────────────────────────────────┐
   │ worker.process_job          worker.py:387        │
   ├─────────────────────────────────────────────────┤
   │ 1. MinIO download           worker.py:432 _download_rawdata
   │ 2. tar.extractall           worker.py:437
   │ 3. parse_scan_data          parser.py:1051
   │ 4. call_claude              worker.py:499  -> claude_client.py
   │ 4b. run_qa_checks           worker.py:533  qa_check.py:712
   │ 4c. apply_deterministic_pipeline   worker.py:553
   │      ├ finding_type_mapper.annotate_finding_types
   │      ├ severity_policy.apply_policy   severity_policy.py:1275
   │      ├ business_impact.recompute
   │      └ selection.select_findings      selection.py:243
   │ 4d. Severity-Cap (SP-FALLBACK)        worker.py:565
   │ 4e. _recalculate_overall_risk         worker.py:594
   │ 5.  map_to_report_data      report_mapper.py:1694
   │      └ _augment_for_v2      report_mapper.py:1784  (v2-only)
   │ 5d. ValidationGate.run      validation/gate.py:95
   │ 6.  generate_report_v2      pdf/v2/generate.py:29
   │      OR legacy generate_report (v1 fallback)
   │ 7.  MinIO upload PDF        worker.py:729 _upload_report
   │ 8.  INSERT reports          worker.py:748 _create_report_record
   │ 8b. UPDATE superseded_by    worker.py:765
   │ 8c. posture_aggregator      worker.py:791
   │ 9.  UPDATE orders.status    worker.py:818 _update_order_status
   │ 10. shutil.rmtree work_dir  worker.py:851
   └─────────────────────────────────────────────────┘
```

## Layout-Switch v1 / v2

`worker.py:711`:

```python
layout = os.environ.get("VECTISCAN_REPORT_LAYOUT", "v1").lower()
if layout == "v2":
    from reporter.pdf.v2 import generate_report_v2
    generate_report_v2(report_data, str(pdf_path))
else:
    generate_report(report_data, str(pdf_path))
```

In `docker-compose.yml:419` ist `VECTISCAN_REPORT_LAYOUT=v2` der Default für den `report-worker`-Service. Legacy-v1-Code unter `reporter/generate_report.py` bleibt nur als Fallback im Tree (Big-Bang-Cutover gemäß `docker-compose.yml:413-417` bereits am 2026-05-13).

`map_to_report_data` ruft `_augment_for_v2` ebenfalls ENV-gesteuert (`report_mapper.py:1776`) — die v2-Augmentierungs-Felder werden also nur erzeugt, wenn der Renderer auch v2 ist.

## Drei zentrale Determinismus-Schichten

```
Claude Output (KI-Vorschläge)
       │
       ▼
┌─────────────────────────────────────┐
│ 1. Severity-Policy                  │
│    severity_policy.apply_policy     │ 74 Regeln + SP-FALLBACK
│    POLICY_VERSION = 2026-06-01.1    │
│    (severity_policy.py:36)          │
└─────────────────┬───────────────────┘
                  │ policy_id, final_severity
                  ▼
┌─────────────────────────────────────┐
│ 2. Selection                        │
│    selection.consolidate +          │ Evidence-Hash über stable Keys
│    selection.select_findings        │ Top-N pro Paket + Floor
│    (selection.py:173, 243)          │
└─────────────────┬───────────────────┘
                  │ selected[] + additional[]
                  ▼
┌─────────────────────────────────────┐
│ 3. Validation-Gate                  │ 7 Checks: titles, ids, cvss,
│    ValidationGate.run               │ consistency, tech_table, eol, plan
│    (validation/gate.py:95)          │ STRICT -> Order failed
│    Level via VECTISCAN_VALIDATION_LEVEL
└─────────────────┬───────────────────┘
                  │ passed/failed
                  ▼
              PDF-Renderer
```

Default in Prod: `VECTISCAN_VALIDATION_LEVEL=strict` (`docker-compose.yml:411`).

## Datenfluss-Artefakte je Stufe

| Stufe | Eingabe | Persistiert in |
|---|---|---|
| MinIO-Download | `<orderId>.tar.gz` aus Bucket `scan-rawdata` | `/tmp/report-<orderId>-*/scan-data/` |
| Parser | `scan_data/{phase0,hosts/<ip>/{phase1,phase2,phase3}}/` | In-Memory `parsed` dict |
| Claude | Prompt-Variante aus `prompts.py` (5 Pakete) | `claude_output` dict + `claude_debug` zu MinIO |
| Severity-Policy | claude_output.findings + scan_context | `findings[*].policy_id, final_severity, severity_provenance` |
| Selection | Findings nach Policy | claude_output.findings = selected; additional_findings = rest |
| Mapper | claude_output + scan_meta | `report_data` dict |
| `_augment_for_v2` | report_data + claude_output | report_data zusätzlich: `layer1, scope_meta, methodology_stats, business_context, compliance_indicators, tech_table_v2, service_cards, posture_indicators, befund_landschaft, compliance_mappings, additional_findings, screenshots_v2, _renderer_layout="v2"` |
| ValidationGate | findings_data + report_data + context | `report_data["_validation_warnings"]` + DB-Spalte `reports.validation_warnings` |
| PDF-Renderer | report_data | `/tmp/report-<orderId>-*/<orderId>.pdf` |
| MinIO-Upload | PDF | Bucket `scan-reports`, Key `<orderId>.pdf` oder `<orderId>_v<N>.pdf` |
| DB-Insert | `_create_report_record` Parameter | `reports`-Zeile (findings_data JSONB, policy_version, policy_id_distinct, tech_profiles JSONB, additional_findings JSONB, validation_warnings JSONB) |
| Posture | findings_data + DB-Connection | `consolidated_findings`, `scan_finding_observations`, `subscription_posture`, `posture_history` |
| Status-Update | order_id + final_status | `orders.status` -> `pending_review` oder `report_complete` |

## Fehlerpfade

- **ValidationGate STRICT failed**: `worker.py:689-705` setzt `orders.status='failed'` mit kuratierter `error_message`, kein PDF, kein Upload, kein report-record. Exception `ValidationFailedError` aus `validation/gate.py:152`.
- **Claude-Cost-Save fehlgeschlagen**: nur Warning (`worker.py:526`), Job läuft weiter.
- **Posture-Aggregation Crash**: Rollback der Connection (`worker.py:805`), Job läuft weiter mit neuer DB-Connection.
- **Generelle Exception**: `worker.py:830` setzt Order auf `failed` mit letzten 500 Zeichen Traceback in `error_message`.

## Cleanup

`finally`-Block in `worker.py:840` lädt `claude_debug` als JSON nach MinIO hoch und löscht `work_dir`. DB-Connection wird geschlossen.

## Was diese Doku abdeckt

| # | Datei | Inhalt |
|---|---|---|
| 02 | `02_data_sources.md` | Tar-Inhalt, parser.parse_scan_data, DB-Tabellen |
| 03 | `03_orchestration.md` | worker.process_job + _augment_for_v2 im Detail |
| 04 | `04_determinism.md` | title_policy, severity_policy, selection, eol_detector, tech_table_builder, id_renumber, cvss_consistency |
| 05 | `05_validation_gate.md` | ValidationGate + alle 7 Checks |
| 06 | `06_v2_renderer.md` | generate_report_v2 Step-by-Step |
| 07 | `07_layer1_aggregators.md` | layer1_aggregator + 5 Risk-Kategorien + 8 Cluster |
| 08 | `08_layer2_data.md` | business_context, v2_data, befund_landschaft, posture_v2 |
| 09 | `09_layer3_findings.md` | layer3-Renderer + verification_templates |
| 10 | `10_appendices.md` | A-F Anhänge |
| 11 | `11_compliance_mappings.md` | NIS2/BSIG, ISO 27001, BSI-Grundschutz, DSGVO |
| 12 | `12_screenshot_pipeline.md` | dedup_and_cap |
| 13 | `13_config_envvars.md` | Alle VECTISCAN_*-ENV-Variablen |
| 99 | `99_known_issues.md` | Code ≠ Rendering Mismatches |
