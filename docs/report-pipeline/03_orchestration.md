# 03 — Orchestrierung: worker.process_job + _augment_for_v2

Code-Anatomie der zentralen Orchestrator-Funktion und der v2-Augmentierung.

## process_job (worker.py:387–859)

### Block 1 — Job-Pfad-Switch (387–410)

`process_job` unterstützt zwei Job-Typen:

```python
if job_data.get("subscriptionId") and not job_data.get("orderId"):
    # Subscription-Status-Report-Pfad
    from reporter.status_report_generator import process_status_report_job
    process_status_report_job(job_data)
    return
```

Der normale Scan-Report-Pfad läuft ab Zeile 412.

### Block 2 — Job-Daten und Setup (412–429)

```python
order_id  = job_data["orderId"]
raw_data_path = job_data["rawDataPath"]
host_inventory = job_data["hostInventory"]
tech_profiles = job_data["techProfiles"]
package = job_data.get("package", "perimeter")
excluded = job_data.get("excludedFindings", [])
is_approved = job_data.get("approved", False)

work_dir = Path(tempfile.mkdtemp(prefix=f"report-{order_id}-"))
minio_client = _get_minio_client()
conn = _get_db_connection()
```

Persistiert: nichts. State im Local Filesystem unter `/tmp/report-<order_id>-*`.

### Block 3 — MinIO-Download + Tar-Extract (431–453)

```python
tar_path = _download_rawdata(minio_client, raw_data_path, work_dir)
with tarfile.open(tar_path, "r:gz") as tar:
    tar.extractall(path=extract_dir)
```

Resolver in 446–453: ein einzelnes Subdir mit `hosts/` wird als `scan_data_dir` genommen; sonst `extract_dir` direkt.

### Block 4 — Parser (455–468)

```python
parsed = parse_scan_data(str(scan_data_dir))   # parser.py:1051
```

Liefert das in `02_data_sources.md` beschriebene Dict. Der Worker zieht effektive Inventar-/Profile-Werte mit Fallback aufs Job-Payload (Zeile 466–467) und ermittelt `domain` aus dem effektiven Inventar.

### Block 5 — Claude-Call (470–527)

Zwei Pfade:

- `package == "tlscompliance"` (470–495): `check_tr03116_compliance` läuft VOR dem Claude-Call und produziert einen Findings-Text mit FAIL/WARN-Einträgen. Claude bekommt diesen Text statt der konsolidierten Tool-Findings.
- Sonst (498–527): Standard-Pfad. `call_claude` aus `claude_client.py` mit dem konsolidierten Findings-Text, der Paket-Variante und `debug_info` für die spätere MinIO-Ablage. Cost-Tracking als `scan_results.tool_name="report_cost"` (Phase=4).

### Block 5b — QA-Checks ohne Severity-Cap (528–542)

```python
qa_report = run_qa_checks(claude_output, package=package,
                         enrichment=enrichment, apply_severity_cap=False)
```

Der Severity-Cap wird hier explizit ausgeschaltet (`apply_severity_cap=False`). Grund laut Kommentar Zeile 529: severity_policy würde sonst ~95% der Caps wieder überschreiben — der Cap kommt erst in Block 5d nochmal, gezielt auf SP-FALLBACK.

### Block 5c — Deterministische Pipeline (544–558)

```python
scan_context = {
    "dns_records":   effective_inventory.get("dns_findings", {}),
    "tech_profiles": effective_profiles,
    "enrichment":    enrichment or {},
    "host_inventory": effective_inventory,
}
apply_deterministic_pipeline(claude_output,
                            package=package, domain=domain,
                            scan_context=scan_context)
```

Diese Funktion (`reporter/deterministic_pipeline.py`) ist die zentrale Determinismus-Schicht: `finding_type_mapper → severity_policy.apply_policy → business_impact.recompute → selection.select_findings`. Schreibt `claude_output.findings`, `policy_version`, `policy_id_distinct`, `additional_findings` in-place um. Details in `04_determinism.md`.

### Block 5d — Severity-Cap nur für SP-FALLBACK (560–591)

Nur Findings ohne policy_id-Treffer (SP-FALLBACK) gehen durch den evidence-basierten Severity-Cap. Jedes geänderte Finding bekommt `_qa_cap_applied=True` als Audit-Flag.

### Block 5e — Overall-Risk-Recalc (593–594)

`_recalculate_overall_risk(claude_output)` setzt `overall_risk` (low/medium/high/critical) basierend auf der Severity-Verteilung nach allen Korrekturen.

### Block 6 — Report-Mapping (596–617)

```python
scan_meta = {
    "domain":       domain,
    "orderId":      order_id,
    "startedAt":    parsed_meta.get("startedAt"),
    "completedAt":  parsed_meta.get("finishedAt"),
    "package":      package,
    "toolVersions": parsed_meta.get("toolVersions", []),
    "techProfiles": effective_profiles or [],   # Migration 027
}
report_data = map_to_report_data(
    claude_output=claude_output,
    scan_meta=scan_meta,
    host_inventory=effective_inventory,
    package=package,
    host_screenshots=host_screenshots,
    testssl_raw_by_host=parsed.get("testssl_raw_by_host"),
    headers_by_host=parsed.get("headers_by_host"),
)
```

`map_to_report_data` (`report_mapper.py:1694`) dispatched per Paket auf den jeweiligen Sub-Mapper (`map_basic_report`, `map_professional_report`, ..., siehe `report_mapper.py:1718-1730`).

Wenn ENV `VECTISCAN_REPORT_LAYOUT=v2`, ruft es danach `_augment_for_v2` (siehe unten).

### Block 6b — Filter Excluded Findings (619–633)

Wenn `excludedFindings` im Job-Payload gesetzt sind (Admin-Review): die Findings werden aus `report_data["findings"]`, `claude_output["findings"]` entfernt und `severity_counts` neu berechnet. Excludes greifen NACH der Selection — sie sind also nicht Teil der Determinismus-Kette.

### Block 6c — Version-Bestimmung (635–648)

`v1` für Erstgenerierung, `MAX(version)+1` für Regenerationen mit `excluded`. MinIO-Key folgt der Konvention `<orderId>.pdf` (v1) bzw. `<orderId>_v<N>.pdf` (N≥2).

### Block 6d — Validation-Gate (650–705)

```python
from reporter.validation.gate import (
    ValidationFailedError, ValidationGate, ValidationLevel,
)
findings_data_for_validation = _build_findings_data(
    claude_output, package, report_data,
)
gate = ValidationGate.from_env()                 # VECTISCAN_VALIDATION_LEVEL
gate_result = gate.run(
    findings_data_for_validation,
    report_data=report_data,
    context={
        "package":       package,
        "order_id":      order_id,
        "domain":        domain,
        "tech_profiles": effective_profiles or [],
    },
)
validation_warnings_payload = gate_result.to_json()
report_data["_validation_warnings"] = validation_warnings_payload

if not gate_result.passed and gate.level == ValidationLevel.STRICT:
    _update_order_status(conn, order_id, "failed",
                        error_message=f"Validation-Gate STRICT: {N} Defekte")
    raise ValidationFailedError(gate_result)
```

`warning`/`off`-Mode: Defekte werden in `validation_warnings` persistiert, der Build läuft weiter. Details in `05_validation_gate.md`.

### Block 7 — PDF-Generierung (707–726)

```python
layout = os.environ.get("VECTISCAN_REPORT_LAYOUT", "v1").lower()
if layout == "v2":
    from reporter.pdf.v2 import generate_report_v2
    generate_report_v2(report_data, str(pdf_path))
else:
    generate_report(report_data, str(pdf_path))   # legacy v1
```

Default in `docker-compose.yml:419` ist `v2`.

### Block 8 — MinIO-Upload (728–729)

`_upload_report(minio_client, pdf_path, minio_pdf_path)` legt das PDF unter dem berechneten Key in `scan-reports` ab und gibt `file_size` zurück.

### Block 9 — DB-Insert Report-Record (731–762)

```python
findings_data = _build_findings_data(claude_output, package, report_data)
policy_version    = claude_output.get("policy_version")
policy_id_distinct = [pid for pid in claude_output.get("policy_id_distinct") or [] if pid] or None

# Migration 027: tech_profiles + pre-computed tech_rows
enriched_profiles = []
for p in effective_profiles or []:
    tech_rows = build_tech_table_for_host(p)
    enriched_profiles.append({**p, "tech_rows": tech_rows})

additional_findings = claude_output.get("additional_findings_summary") or None

report_id, download_token = _create_report_record(
    conn, order_id, minio_pdf_path, file_size, findings_data,
    version=version,
    excluded_findings=excluded if excluded else None,
    policy_version=policy_version,
    policy_id_distinct=policy_id_distinct,
    tech_profiles=enriched_profiles,
    additional_findings=additional_findings,
    validation_warnings=validation_warnings_payload,
)
```

`tech_rows` werden hier nochmal redundant berechnet und mit dem Profile zusammengeschrieben, weil das Frontend auf diese Single Source of Truth setzt.

### Block 9b — Supersede (764–778)

Wenn `version > 1`, wird die vorherige Version mit `superseded_by = report_id` aktualisiert (Audit-Trail für Regenerationen).

### Block 9c — Posture-Aggregation (780–812)

`aggregate_into_posture(conn, order_id, findings_data)` aktualisiert den Subscription-Posture-Score, Trend, Regression. Best-effort: bei SQL-Exception macht der Worker explizit `conn.rollback()` (notwendig wegen aborted-transaction-State, sonst crasht der nächste UPDATE), zur Not eine neue Connection.

### Block 10 — Order-Status (814–818)

```python
final_status = "report_complete" if (is_approved or bool(excluded)) else "pending_review"
_update_order_status(conn, order_id, final_status)
```

Erstlauf nach Scan → `pending_review` (Admin reviewt vor Customer-Delivery). Regen oder explizit approved → `report_complete`.

### Exception-Handling (821–839)

- `ValidationFailedError`: nur Warning loggen, Order ist schon auf `failed` gesetzt mit kuratierter Message.
- Sonst: `_update_order_status(conn, order_id, "failed", error_message=traceback[-500:])`.

### Finally (840–859)

- Claude-Debug-JSON zu MinIO hochladen (best-effort).
- `shutil.rmtree(work_dir)`.
- `conn.close()`.

## _augment_for_v2 (report_mapper.py:1784–1944)

Wird nur aufgerufen, wenn `VECTISCAN_REPORT_LAYOUT=v2` (`report_mapper.py:1776`). Schreibt 12 Augment-Felder in `report_data` in-place.

```
                              _augment_for_v2
                                     │
        ┌────────────┬───────────────┼────────────────┬──────────────┐
        ▼            ▼               ▼                ▼              ▼
   _renderer_layout  layer1     scope_meta       tech_table_v2   posture_indicators
       (v2)       (Risiken,    methodology_stats  service_cards   (Email/Web/DNS/TLS)
                  Hebel)       business_context   befund_landschaft
                               compliance_indicators
                               compliance_mappings
                               additional_findings
                               screenshots_v2
```

### Augment-Felder im Detail

| Feld | Quelle | Zeile | Renderer-Konsument |
|---|---|---|---|
| `_renderer_layout` | const `"v2"` | 1811 | — (Flag) |
| `domain` | scan_meta/host_inventory | 1812 | cover, frontpage |
| `layer1` | `layer1_aggregator.build_layer1(findings, recommendations, host_inventory, package)` | 1822–1838 | `pdf/v2/layers/frontpage.py` |
| `scope_meta` | `v2_data.build_scope_meta(scan_meta, host_inventory, claude_output)` | 1841–1849 | `strategy.py:_build_scope_methodology` |
| `methodology_stats` | `v2_data.build_methodology_stats(scan_meta, claude_output)` | 1849 | dito |
| `business_context` | `business_context.build_business_context(scan_meta, host_inventory, claude_output)` | 1858–1865 | `strategy.py:_build_business_context` |
| `compliance_indicators` | `v2_data.build_compliance_indicators(claude_output, business_context)` | 1868–1875 | `frontpage.py` |
| `tech_table_v2` | `v2_data.build_tech_table_v2(host_inventory, tech_profiles)` | 1878–1885 | `strategy.py:_build_tech_stack` |
| `service_cards` | `befund_landschaft.build_service_cards(host_inventory, tech_profiles)` | 1887–1893 | `strategy.py:_build_service_cards` |
| `befund_landschaft` | `befund_landschaft.build_befund_landschaft(findings, positive_findings)` | 1887–1897 | `strategy.py:_build_befund_landschaft` |
| `posture_indicators` | `posture_v2.build_posture_indicators(claude_output, tr03116_compliance)` | 1903–1910 | `strategy.py:_build_posture_indicators` |
| `compliance_mappings` | `compliance_mappings.build_compliance_mappings(claude_output.findings)` | 1913–1923 | `findings.py:_render_compliance_inline`, `appendix.py:_build_appendix_d` |
| `additional_findings` | `claude_output.additional_findings` (1:1) | 1925–1932 | `appendix.py:_build_appendix_e` |
| `screenshots_v2` | `screenshot_pipeline.dedup_and_cap(report_data.screenshots)` | 1934–1944 | `strategy.py:_build_screenshots_v2` |

Alle Imports passieren lazy in try/except-Blöcken: bei ImportError oder Exception bleibt das Feld auf `None` bzw. `{}`, der Renderer hat dafür Defensiv-Pfade. Bei Crash wird `v2_augment_<feldname>_failed` geloggt.

Wichtig: `compliance_mappings` läuft über die rohen Claude-Findings (`claude_output.findings`) und nicht über die ge-`_safe`-escapeden `report_data["findings"]` (Zeile 1915-1919) — die Keyword-Klassifikation in `compliance/*.py` braucht den natürlichen Wortlaut.
