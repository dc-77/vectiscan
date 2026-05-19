# report-pipeline — Code-Truth-Dokumentation

Ist-Stand der PDF-Report-Pipeline aus dem laufenden Code (Mai 2026, v2-Renderer als Prod-Default).

## Methodik

- **Code-Wahrheit vor Spec-Wahrheit.** Alle Aussagen sind aus dem aktuellen Code (`report-worker/reporter/**.py`, `docker-compose.yml`) verifiziert. Wo der Code von Design-Dokumenten oder dem Master-Plan abweicht, ist der Code dokumentiert.
- **`file:line`-Verweise** auf alle nicht-trivialen Funktionen und Konstanten — der Leser kann in einem Klick zur Code-Stelle springen.
- **Test-Fixtures (`tests/fixtures/`) sind nicht als Schema-Quelle herangezogen** — sie sind synthetisch.

## Lesereihenfolge

| Datei | Inhalt |
|---|---|
| [`01_overview.md`](01_overview.md) | Big-Picture-Pipeline, ASCII-Diagramm, Layout-Switch v1/v2, Determinismus-Schichten |
| [`02_data_sources.md`](02_data_sources.md) | MinIO-Tar-Layout, `parse_scan_data`, DB-Tabellen, Phase-1-Profil-Schema |
| [`03_orchestration.md`](03_orchestration.md) | `worker.process_job` Block-für-Block, `_augment_for_v2` Augment-Felder |
| [`04_determinism.md`](04_determinism.md) | title_policy, severity_policy (74 Regeln), selection (Top-N/Floor), eol_detector, tech_table_builder, cvss_consistency, id_renumber |
| [`05_validation_gate.md`](05_validation_gate.md) | ValidationGate + 7 Checks (titles/ids/cvss/consistency/tech_table/eol/plan) |
| [`06_v2_renderer.md`](06_v2_renderer.md) | `generate_report_v2`, PageTemplates, 6 Flowables, Story-Aufbau |
| [`07_layer1_aggregators.md`](07_layer1_aggregators.md) | `layer1_aggregator`: 5 Risk-Kategorien, POLICY_PREFIX_TO_RISK_CATEGORY, 8 MASSNAHMEN_CLUSTER |
| [`08_layer2_data.md`](08_layer2_data.md) | business_context (8 Branchencluster), v2_data, befund_landschaft, posture_v2 |
| [`09_layer3_findings.md`](09_layer3_findings.md) | 7-Sektionen-Body, verification_templates (21 policy_ids), Severity-Mapping |
| [`10_appendices.md`](10_appendices.md) | Anhänge A–F mit allen Tool-Konfidenz-Maps, Port-Recommendation-Maps |
| [`11_compliance_mappings.md`](11_compliance_mappings.md) | NIS2/BSIG, BSI-Grundschutz, ISO 27001, DSGVO mit allen Keyword-Mappings |
| [`12_screenshot_pipeline.md`](12_screenshot_pipeline.md) | `_build_screenshot_data` + `dedup_and_cap` + Render-Pfad |
| [`13_config_envvars.md`](13_config_envvars.md) | Alle `VECTISCAN_*`-ENV-Variablen + Infra-ENV + hartcodierte Konstanten |
| [`99_known_issues.md`](99_known_issues.md) | Code ≠ Code Inkonsistenzen, Code ≠ CLAUDE.md Drift, offene Bug-Marker |
| [`samples/`](samples/) | Zwei Real-Sample-PDFs + README mit Struktur-Hinweisen |

## Quick-Links zu Schlüssel-Code

- Worker-Orchestrator: [`worker.py:387`](../../report-worker/reporter/worker.py)
- Report-Mapper: [`report_mapper.py:1694`](../../report-worker/reporter/report_mapper.py)
- v2-Renderer: [`pdf/v2/generate.py:29`](../../report-worker/reporter/pdf/v2/generate.py)
- Severity-Policy: [`severity_policy.py:1275`](../../report-worker/reporter/severity_policy.py)
- Selection: [`selection.py:243`](../../report-worker/reporter/selection.py)
- Validation-Gate: [`validation/gate.py:95`](../../report-worker/reporter/validation/gate.py)

## Was diese Doku NICHT abdeckt

- Scan-Worker-Pipeline (Phase 0-3, Tool-Outputs). Quelle: `docs/SCAN-PIPELINE-v2.md`, `docs/PIPELINE-AI-FLOW.md`.
- Frontend / Dashboard. Quelle: `frontend/`-Source.
- DB-Schema. Quelle: `docs/DB-SCHEMA.sql`.
- API-Endpoints. Quelle: `docs/API-SPEC.md`.
- Compliance-Spezial-Sektionen pro Paket (NIS2-Audit-Trail im `map_nis2_report`, ISO-27001-Summary im `map_supplychain_report`, Insurance-Matrix). Diese sind paket-spezifische Pfade im `report_mapper.py`, nicht im 3-Schichten-v2-Layout.

## Verifikation

Quick-Check `file:line`-Referenzen:

```bash
grep -rc "\.py:[0-9]" docs/report-pipeline/ | grep -v ":0$"
```
