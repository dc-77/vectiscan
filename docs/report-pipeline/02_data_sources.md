# 02 — Datenquellen

Was der report-worker liest, in welcher Form, und wo es im PDF landet.

## MinIO-Tar-Layout

Der Scan-Worker schreibt am Ende von Phase 3 ein Tarball nach `s3://scan-rawdata/<orderId>.tar.gz`. Download in `worker.py:432` (`_download_rawdata`), Extraktion `worker.py:437`.

Resolver `worker.py:445-453` löst die innere Struktur auf: meistens enthält das Tar einen einzelnen Top-Level-Ordner `<orderId>/`, manchmal die Daten flach.

Erwarteter Inhalt (relativ zum aufgelösten `scan_data_dir`):

```
scan_data_dir/
├── meta.json                          # startedAt, finishedAt, toolVersions
├── phase0/
│   ├── host_inventory.json            # {domain, hosts: [{ip, fqdns, ports, ...}]}
│   └── dns_records.json               # MX, SPF, DMARC, DKIM, NS, ...
└── hosts/
    └── <ip>/
        ├── phase1/
        │   ├── tech_profile.json      # build_tech_profile-Output
        │   └── nmap.xml               # nmap -sV
        └── phase2/
            ├── nuclei.json            # nuclei -jsonl
            ├── testssl.json           # testssl.sh --jsonfile
            ├── nikto.json             # nikto -Format json
            ├── headers.json           # custom header probe
            ├── gobuster_dir.txt       # gobuster dir
            ├── httpx.json             # httpx -json
            ├── katana.txt             # katana plain URLs
            ├── wpscan.json            # wpscan --format json
            ├── zap_alerts.json        # OWASP ZAP alerts export
            ├── zap_spider_urls.json   # ZAP-Spider-Resultate
            └── screenshot_<vhost>.png # gowitness/Playwright
```

Phase 3-Ergebnisse (NVD/EPSS/KEV-Anreicherung) sind nicht im Tar — sie hängen bereits an den `consolidated_findings`, die der Scan-Worker in Phase 3 schreibt. Dieser Pfad ist im report-worker nicht explizit dokumentiert; Findings werden direkt aus den per-host Tool-Outputs konsolidiert via `parser.consolidate_findings` (`parser.py:772`).

## parser.parse_scan_data

Datei: `report-worker/reporter/parser.py:1051`. Returns:

```python
{
    "host_inventory":           dict,   # 1:1 phase0/host_inventory.json
    "tech_profiles":            list,   # phase1/tech_profile.json je Host
    "consolidated_findings":    str,    # Text-Block fuer Claude-Prompt
    "host_screenshots":         dict,   # {ip: [path, ...]}    Legacy
    "host_screenshots_per_vhost": dict, # {ip: [{vhost, path}, ...]}  F-PH1-003
    "testssl_raw_by_host":      dict,   # {ip: [raw_finding, ...]}
    "headers_by_host":          dict,   # {ip: header_dict}
    "meta":                     dict,   # meta.json
}
```

Per-Host-Loop steht in `parser.py:1099-1188`, Fallback-Verzeichnis-Scan in `parser.py:1192-1260` (wenn host_inventory leer aber `hosts/` doch Subdirs hat).

### Tool-Parser-Tabelle

| Tool | Funktion | Parser-Datei:Zeile | Output-Schema |
|---|---|---|---|
| nmap | `parse_nmap_xml` | `parser.py` (Anfang) | `{open_ports, os_detection, summary}` |
| nuclei | `parse_nuclei_json` | `parser.py` | `[{template_id, severity, matched_at, info}]` |
| testssl (gefiltert) | `parse_testssl_json` | `parser.py` | `[{id, severity, finding}]` |
| testssl (raw) | `parse_testssl_raw` | `parser.py` | Vollständige Findings für TR-03116 |
| nikto | `parse_nikto_json` | `parser.py` | `[{id, msg, url, method}]` |
| headers | `parse_headers_json` | `parser.py` | `{url, score, missing, present}` |
| gobuster | `parse_gobuster_dir` | `parser.py` | `[path, ...]` |
| httpx | `parse_httpx` | `parser.py` | `{status_code, title, server, technologies}` |
| katana | `parse_katana` | `parser.py` | `{total_urls, interesting_paths, api_endpoints}` |
| wpscan | `parse_wpscan` | `parser.py` | `{wp_version, vulnerable_plugins, users}` |
| ZAP alerts | `parse_zap_alerts_json` | `parser.py` | `[{name, severity, description, cweid}]` |
| Screenshots | `find_playwright_screenshots` | `parser.py` | `[png_path, ...]` |

### Screenshot-VHost-Resolution

`parser.py:1283-1290`: Konvention ist `screenshot_<vhost-fqdn>.png`. Der Parser strippt das `screenshot_`-Präfix vom Stem; ist es nicht vorhanden, wird der gesamte Stem als VHost-Label genommen. Beide Schemata (`host_screenshots` = Liste von Strings, `host_screenshots_per_vhost` = Liste von Dicts) werden parallel populiert — der report-mapper konsumiert beides.

### TR-03116 Raw-Pickup

`parser.py:1300-1308` sammelt `testssl_raw` und `headers` pro IP separat — diese werden im report_mapper an `check_tr03116_compliance` weitergegeben (`report_mapper.py:1736-1752`), nicht über die normale Claude-Pipeline.

## Phase-1-Tech-Profil-Format

Das echte Prod-Schema wird vom Scan-Worker geschrieben:

```
scan-worker/scanner/phase1.py:build_tech_profile
```

Felder, die der report-worker tatsächlich liest (siehe `tech_table_builder.py:441` + `befund_landschaft.py:256`):

```python
{
  "host_ip":   str,
  "fqdns":    [str, ...],
  "ports":    [{port: int, proto: "tcp"|"udp", service: str, banner: str?}],
  "cms":      {name, version, source}?,
  "server_banner": str?,
  "tech":     [{name, version, source, vendor?, product?}, ...],
  "waf":      {name, vendor}?,
  "shodan_exposed_services": [{port, service, ...}]?,
}
```

Hinweis Testfixturen: `report-worker/tests/fixtures/` und `validation/tests/fixtures/replay_*.json` sind synthetisch und nicht für die Spec-Ableitung gedacht — die echte Struktur entsteht in Phase 1 des Scan-Workers.

## DB-Tabellen, die der report-worker liest oder schreibt

| Tabelle | Verwendung | Code-Stelle |
|---|---|---|
| `reports` | INSERT (Report-Record), UPDATE `superseded_by`, SELECT für Versionierung | `worker.py:641, 748, 770` (`_create_report_record`) |
| `orders` | UPDATE `status`, `error_message` | `worker.py:693, 818, 837` (`_update_order_status`) |
| `scan_results` | INSERT `report_cost` als phase=4 | `worker.py:516-524` |
| `consolidated_findings` | UPSERT von posture_aggregator | `posture_aggregator.py:_do_aggregate` |
| `scan_finding_observations` | INSERT je Scan | `posture_aggregator.py` |
| `subscription_posture` | UPSERT Score + Trend | `posture_aggregator.py` |
| `posture_history` | INSERT Historie | `posture_aggregator.py` |
| `subscriptions` | nicht direkt — Limits kommen aus `host_inventory` | — |

## Felder, die im PDF landen

Hier ist die Spur vom Daten-Ursprung bis zur PDF-Sektion:

| Quelle | report_data-Key | PDF-Sektion | Renderer |
|---|---|---|---|
| `meta.json` startedAt/finishedAt | `scope_meta.scan_date, started_at, finished_at` | Seite 4 Methodik | `pdf/v2/layers/strategy.py:_build_scope_methodology` |
| `host_inventory.domain` | `domain`, `scope_meta.domain` | Cover, Seite 4 | `pdf/v2/cover.py:build_cover_v2`, `strategy.py` |
| Anzahl `host_inventory.hosts` | `scope_meta.hosts_count` | Seite 4 | `strategy.py:_build_scope_methodology` |
| `tech_profiles[].cms,server_banner,tech` | `tech_table_v2[]` | Seite 6 Tech-Stack | `strategy.py:_build_tech_stack` |
| `tech_profiles[].ports` | `service_cards[]` | Seite 7 Service-Karte | `strategy.py:_build_service_cards` |
| Claude-Findings nach Policy/Selection | `findings[]` | Layer 3 Befund-Details | `pdf/v2/layers/findings.py:build_layer3_findings` |
| Aggregierte Findings nach Risk-Kategorie | `layer1.risk_categories` | Seite 2 Ampel | `pdf/v2/layers/frontpage.py:build_layer1_frontpage` |
| `dns_records` + Findings | `posture_indicators.email/web/dns/tls` | Seite 7 Posture | `posture_v2.build_posture_indicators` |
| `tr03116_compliance` | inline in `posture_indicators.tls` | Seite 7 Posture | `posture_v2._tls_indicator` |
| Screenshots (Body-Hash-dedupliziert) | `screenshots_v2` | Seite 7-8 | `strategy.py:_build_screenshots_v2` |
| `additional_findings` (Selection-Rest) | `additional_findings` | Anhang E Filterungen | `appendix.py:_build_appendix_e` |
| Compliance-Mappings | `compliance_mappings[finding_id]` | Layer 3 inline + Anhang D | `findings.py:_render_compliance_inline`, `appendix.py:_build_appendix_d` |

Was NICHT von außen kommt: `layer1`, `befund_landschaft`, `compliance_indicators`, `methodology_stats`, `business_context`, `compliance_mappings` — diese werden von `_augment_for_v2` (`report_mapper.py:1784`) aus den vorhandenen Quellen abgeleitet.
