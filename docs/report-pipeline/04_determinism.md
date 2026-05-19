# 04 — Determinismus-Schichten

Alle Pfade, die zwischen Claude-Output und PDF-Render Severity, Reihenfolge, Titel und Tech-Werte deterministisch festschreiben.

## Pipeline-Reihenfolge

`reporter/deterministic_pipeline.py:apply_deterministic_pipeline` (vom Worker in `worker.py:553` aufgerufen) orchestriert in dieser Reihenfolge:

1. `finding_type_mapper.annotate_finding_types` — setzt `finding_type` auf jedem Finding (Pattern-Mapping aus Tool-Output + Title-Heuristik).
2. `ai_finding_type_fallback` (Haiku) — füllt `finding_type` für Findings, die der Pattern-Mapper nicht treffen konnte.
3. `severity_policy.apply_policy` — Severity, policy_id, severity_provenance.
4. `cvss_consistency.apply_consistency` — wird IN `apply_policy` am Ende für jedes Finding aufgerufen (`severity_policy.py:1369-1386`).
5. `business_impact.recompute` — `business_impact_score`.
6. `selection.select_findings` — Konsolidierung, Top-N, Floor.
7. `id_renumber.renumber_findings` — finale `VS-YYYY-NNN`-IDs ab 001 lückenlos.
8. `title_policy.apply_titles` — Title-Templates + Smart-Var-Fallback.

Schritte 1–7 stehen vor dem `report_mapper`; Titles werden teilweise vom Mapper nochmal angewendet (siehe `title_policy.apply_titles` in `report_mapper.py`).

## 1. title_policy (title_policy.py)

POLICY_VERSION-Bump-Quelle, aber separat vom severity_policy versioniert.

### TITLE_TEMPLATES (`title_policy.py:155+`)

Mehr als 50 Templates, alphabetisch nach Policy-ID:

| Prefix | Range | Beispiel |
|---|---|---|
| SP-HDR-001..009 | Header-Defekte | `"HSTS-Header fehlt auf {host}"` (Z. 157) |
| SP-CSP-001..005 | Content-Security-Policy | `"Content-Security-Policy fehlt auf {host}"` (Z. 171) |
| SP-COOK-001..005 | Cookies | `"Cookie {cookie_name} ohne Secure-Flag auf {host}"` (Z. 177) |
| SP-CSRF-001..003 | CSRF | (Z. 184–186) |
| SP-DISC-001..010 | Info-Disclosure | (Z. 191–200) |
| SP-TLS-001..007 | TLS | (Z. 202–208) |
| SP-DNS-001..014 | Mail/DNS | (Z. 213–227) |
| SP-CVE-001..004 | CVE-Findings | (Z. 229–232) |
| SP-EOL-001..004 | End-of-Life | (Z. 234–237) |
| SP-WP-001..002 | WordPress | (Z. 239–240) |
| SP-ENUM-001, SP-DB-001, SP-CORS-001, SP-JS-001, SP-SRI-001, SP-SSH-001, SP-URLHAUS-001 | Sonstige | (Z. 242–249) |

### SERVICE_BANNER_TEMPLATES + MAIL_SECURITY_TEMPLATES

Zwei weitere Template-Maps für Sonderfälle ohne policy_id-Treffer (Service-Banner mit Versionsinfo, Mail-Security-Defekte als kanonische Titel).

### Smart-Var-Fallback (`title_policy.py:63, 310, 448`)

`_derive_var_from_finding` (Z. 63) füllt fehlende Title-Variablen aus dem Finding-Body via Regex:

- `_RFC1918_RE`, `_COOKIE_NAME_RE`, `_PORT_RE`, `_VERSION_RE`, `_CSP_DIRECTIVE_RE`, `_PLUGIN_NAME_RE`, `_LIBRARY_NAME_RE`.

`_resolve_host_with_fallback` (Z. 310) — Host-Fallback-Kette:

```
title_vars.host → finding.affected → affected_hosts → vhost/fqdn
→ host/host_ip/ip → scan_context.hosts[].fqdns[0] → tech_profiles[].fqdns[0] → domain
```

`apply_title_template` (Z. 448) verwendet `_SafeDict` mit "?"-Default — fehlende Variablen werden im finalen Title als `?` sichtbar (Sicherheitsnetz aus M2.x).

`_validate_title_tokens` (Z. 408) — Token-Linter (P0-04): erkennt nackte Zahlen ohne Port/Version/Einheit. Setzt `_title_degraded=True` auf dem Finding, was später vom ValidationGate `titles`-Check geprüft wird.

### ai_finding_type_fallback (Haiku-Mapper)

Datei `reporter/ai_finding_type_fallback.py`. Wird in der Determinismus-Pipeline vor `severity_policy.apply_policy` aufgerufen — füllt `finding_type` aus dem Title+Body via Haiku-Klassifikation, wenn der regelbasierte Mapper `finding_type_mapper.py` kein Pattern matched. Cache läuft über `ai_cache.py`.

## 2. severity_policy (severity_policy.py)

### POLICY_VERSION

```python
# severity_policy.py:36
POLICY_VERSION = os.environ.get("VECTISCAN_POLICY_VERSION", "2026-06-01.1")
```

Bump-Historie als Code-Kommentar (Z. 31–35): `2026-05-10.1 → 2026-06-01.1` wegen neuer `SP-RDP-001/002/003`, `SP-DB-001` auf C:H/I:H/A:H, `SP-DB-002/003`, `SP-EOL-005` und vier neuer Context-Flags.

### Schema `SeverityPolicy` (Z. 82)

Pydantic-Modell mit `policy_id`, `finding_type`, `matches_when` (Context-Flags), `final_severity`, optional `cvss_vector`/`cvss_score`, `rationale`, `references`, `overrides_tool_severity=True`.

### SEVERITY_POLICIES Registry (`severity_policy.py:120+`)

74 hardcoded Regeln + SP-FALLBACK + 1 dynamisches Regel-Set für CVEs (`apply_policy_for_cve` Z. 1228).

| Section | Anzahl | Bereich (Zeile) |
|---|---|---|
| HEADER (SP-HDR-001..009) | 9 | 124–202 |
| CSP (SP-CSP-001..005) | 5 | 207–253 |
| Cookies (SP-COOK-001..005) | 5 | 257–302 |
| CSRF (SP-CSRF-001..003) | 3 | 309–337 |
| Info-Disclosure (SP-DISC-001..010) | 10 (mit DISC-009/010 in Z. 869, 880) | 342–412, 869–894 |
| TLS (SP-TLS-001..007) | 7 | 416–475 |
| DNS / Mail (SP-DNS-001..014) | 14 | 481–610 |
| CVE (SP-CVE-001..003 statisch, SP-CVE-004 dynamisch) | 4 | 616–642, 1244 |
| EOL (SP-EOL-001..005) | 5 | 644–699 |
| WordPress (SP-WP-001..002) | 2 | 705–725 |
| Misc (SP-ENUM-001, SP-CORS-001, SP-JS-001, SP-SRI-001, SP-SSH-001, SP-URLHAUS-001) | 6 | 731–943 |
| RDP (SP-RDP-001..003) | 3 | 754–786 |
| DB (SP-DB-001..003) | 3 | 798–831 |
| Fallback (SP-FALLBACK) | 1 | 1318 |

Beispiel-Regel mit Context-Flag (`severity_policy.py:124`):

```python
SeverityPolicy(
    policy_id="SP-HDR-001",
    finding_type="hsts_missing",
    matches_when={"is_session_path": False},
    final_severity=Severity.INFO,
    cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
    cvss_score=0.0,
    rationale="Statische Seite ohne Session - HSTS-Fehlen ist Hardening-Issue, kein praktisches Risiko",
    references=["CWE-523", "OWASP2025-A02"],
)
```

Bei mehreren passenden Regeln für denselben `finding_type` gewinnt die mit der spezifischsten Context-Flag-Bedingung (siehe `lookup_policy` Z. 1208).

### Context-Flag-Logik (`extract_context_flags` Z. 958)

Setzt Flags aus Finding + scan_context:

| Flag | Quelle | Verwendet in |
|---|---|---|
| `is_session_path` | URL gegen `SESSION_PATH_PATTERNS` | SP-HDR-002/004/007, SP-COOK-004/005 |
| `https_in_use` | URL-Schema oder scan_context | implizit |
| `form_present` | evidence.forms_on_page / form_present | SP-CSP-001/002/003/004, SP-CSRF-002 |
| `inline_scripts` | evidence.has_inline_scripts | SP-CSP-001 |
| `cookie_session` | evidence.cookie.session_cookie + Name-Heuristik | SP-COOK-004/005 |
| `state_change` | evidence.http_method ∈ POST/PUT/DELETE/PATCH | SP-CSRF-003 |
| `auth_present` | evidence.login_form_detected | — |
| `mx_present` | scan_context.dns_records.mx | SP-DNS-* (Mail-Defekte nur wenn MX-Record vorhanden) |
| `dmarc_pct_partial` | dns_security.dmarc.pct < 100 | SP-DNS-013 |
| `nsec3_iterations_nonzero` | dns_security.dnssec.nsec3_rfc9276_violation | SP-DNS-014 |
| `is_eol` | enrichment.eol_status | SP-EOL-005 |
| `is_internet_facing` | host-inventory shodan-exposed | SP-EOL-005, SP-DB-* |
| `tech_critical` | tech_profile critical-flag | SP-EOL-005 |
| `count_hosts_gt_one` | global host count | SP-DB-003 |
| `has_exploits` | enrichment.cisa_kev / epss high | SP-CVE-001, SP-RDP-* |

### apply_policy (Z. 1275)

Sequenziell pro Finding:

1. `extract_context_flags(finding, scan_context)`.
2. Wenn `finding_type == "cve_finding"`: `apply_policy_for_cve` (dynamische CVSS-basierte Regel SP-CVE-001/002/003 nach KEV/EPSS).
3. Sonst: `lookup_policy(finding_type, flags)` — wählt die Regel mit den meisten passenden Flags.
4. Kein Match → SP-FALLBACK mit Tool-Severity übernommen, `_original_severity` archiviert.
5. Match → `severity`, `policy_id`, `cvss_score` (Policy-Wert oder gecapped per `_cap_cvss_to_severity`), `cvss_vector`, `severity_provenance`.

Provenance-Schema (`SeverityProvenance` Z. 106):

```python
{
  "policy_id": "SP-HDR-002",
  "policy_decision": "low",
  "policy_version": "2026-06-01.1",
  "tool_severities": {"zap": "medium"},
  "context_flags": {"is_session_path": true, ...},
  "rationale": "Session-bearing path ohne HSTS — SSL-Stripping-Risiko bei MitM",
  "rule_references": ["CWE-523", "OWASP2025-A02", "OWASP2021-A05"],
}
```

### cvss_consistency (Z. 1369–1386 / Modul `reporter/cvss_consistency.py`)

`apply_consistency(finding)` normalisiert den CVSS-Vektor (z.B. `CVSS:3.1/...`-Prefix erzwingen) und berechnet den Score neu aus dem Vektor, falls beide vorhanden sind. Wird am Ende von `apply_policy` über alle Findings gezogen.

## 3. selection (selection.py)

### TOP_N_PER_PACKAGE (Z. 29)

| Paket | Top-N | Floor |
|---|---|---|
| webcheck | 8 | 3 |
| perimeter | 15 | 6 |
| compliance | 20 | 10 |
| supplychain | 15 | 6 |
| insurance | 15 | 6 |

`tlscompliance` läuft eigenen Pfad ohne Top-N (Kommentar Z. 35).

Legacy-Aliase (Z. 51): `basic → webcheck`, `professional → perimeter`, `nis2 → compliance`.

### Evidence-Hash (Z. 113)

`_normalized_evidence_hash` über ein JSON mit:

- `finding_type`, `policy_id`, `cvss_vector`
- `STABLE_EVIDENCE_KEYS` (Z. 96): `header_name, cookie_name, cipher_suite, tls_version, cve_id, cwe_id, missing_directive, exposed_path`
- `STABLE_TITLE_VARS` (Z. 107, F-RPT-002): `port, tech, version, plugin, library, directive, selector`

Nicht im Hash: `host, ip, port (im affected), timestamp, finding_id` — diese variieren pro Host und sollen nicht diskriminieren.

Leere/`"?"`-Werte werden aus dem Hash entfernt (Z. 136-147), damit Findings ohne title_vars nicht künstlich in eigene Gruppen fallen.

### _affected_host (Z. 160)

Identitäts-Funktion für Konsolidierung. Reihenfolge: `vhost → fqdn → host → host_ip → ip → affected`. VHost hat seit Mai 2026 Vorrang vor host_ip (Multi-VHost-Probe — zwei VHosts auf derselben IP bleiben getrennt).

### consolidate (Z. 173)

Gruppiert Findings nach Evidence-Hash. Bei mehreren Findings im Bucket:
- `affected_hosts = sorted(unique _affected_host)`
- `confidence = max`
- `business_impact_score = max`
- Title bekommt `" (N Hosts betroffen)"` angehängt (Z. 209).

### _sort_key (Z. 221)

```python
(
  -business_impact_score,
  -cvss_score,
  -epss_score,
  -confidence,
  finding_id ASC,    # Tiebreaker — 100 % deterministisch
)
```

### select_findings (Z. 243)

1. Optional FP-Filter (`drop_false_positives=True`).
2. `consolidate(pool)` → konsolidierte Liste.
3. Sort.
4. `selected = [:top_n]`, `additional = [top_n:]`.
5. Floor: wenn `len(selected) < min_n`, ziehe aus `additional` nach (`floor_applied`). Wenn auch das nicht reicht: `retry_hint`-Warnung.

Output: `SelectionResult` mit `selected`, `additional`, `consolidation_groups`, `original_count`, `package`, `top_n`, `floor_applied`, `retry_hint`.

## 4. eol_detector (eol_detector.py)

Deterministische EOL-Erkennung VOR der KI, damit `is_eol`-Context-Flag und SP-EOL-Regeln greifen können.

### Datenquellen

- `eol_data_generated.py` — 388 Einträge, Sync aus endoflife.date via `scripts/sync-eol-data.py`. Jeder Eintrag: `{technology, version_pattern, eol_date, lts}`.
- `known_vuln_builds_generated.py` — KNOWN_VULN_BUILDS für ProxyShell, Heartbleed etc. (spezifische Build-Versionen mit unmittelbarem CVE-Bezug, unabhängig vom EOL-Datum).

Siehe Memory `project_eol_detector.md`.

### Funktion

`detect_eol_findings(tech_profiles, today=date.today())` → Liste neuer Findings mit `finding_type ∈ {software_eol, software_near_eol}`. Diese werden mit dem Claude-Output gemerged und durchlaufen die normale Severity-Pipeline (SP-EOL-001..005).

## 5. tech_table_builder (tech_table_builder.py)

`build_tech_table_for_host(tech_profile)` (Z. 441) erzeugt die Per-Host-Tech-Tabelle für das PDF (Seite 6) und das Frontend.

### KERNEL_DETECTION_BLACKLIST (Z. ~30)

8 String-Patterns, die fälschlich als Tech erkannt werden (Header-Namen, http.sys-Modul):

```python
{"http.sys", "httpapi", "hsts", "csp", "x-frame-options",
 "x-content-type-options", "referrer-policy", "permissions-policy", "feature-policy"}
```

### MIN_PUBLIC_VERSIONS (Z. ~80)

Minimale Major-Version, ab der eine Version als "öffentlich existierend" akzeptiert wird (gegen Halluzination):

```python
{"bootstrap": 2, "angular": 1, "react": 0, "vue": 1, "jquery": 1,
 "tailwind": 1, "next.js": 1, "nuxt": 1, "ember": 1, "backbone": 0}
```

### _CATEGORY_MAP

44 Tupel `(vendor, product) → Kategorie`: `(apache, httpd) → "Web-Server"`, `(nginx, "") → "Web-Server"`, `(php, "") → "Sprache"`, `(mysql, "") → "Datenbank"`, etc.

### _classify_status (Z. 376)

Mappt jeden Tech-Eintrag auf `(status, is_mega_cve, info)` mit `status ∈ {eol, minor_eol, outdated, current}`. `is_mega_cve` ist orthogonal (z.B. Apache mit Log4Shell-CVE auch wenn Version aktuell).

### Output

15-Spalten-Liste je Host:

```python
{
  "name", "version", "category", "patch_status", "is_mega_cve",
  "eol_date", "cves", "top_cve", "confidence", "source",
  "vendor", "product", "fingerprint_detail", "raw_source", "rank",
}
```

`top_cve` wird nach EPSS-Score sortiert ausgewählt. Diese Liste landet in `report_data["tech_table_v2"]` und im DB-Feld `reports.tech_profiles[*].tech_rows` (`worker.py:744`).

## 6. id_renumber (id_renumber.py)

Nach `select_findings` werden die Findings finalisiert in `VS-YYYY-NNN`-IDs lückenlos ab 001 nummeriert. Reihenfolge bleibt die Sort-Reihenfolge von `select_findings`.

`renumber_findings(findings, year=current_year)` wird vom `deterministic_pipeline` aufgerufen.

Wichtig für Cross-Referenzen: Compliance-Mappings im `_augment_for_v2` referenzieren `finding.id`, nicht `policy_id`. Da `id_renumber` vor `_augment_for_v2` läuft (Worker-Reihenfolge), stimmt die Referenz.

## Bug-Marker

> Code-Notiz: `ai_cache.py:22` definiert `POLICY_VERSION = os.environ.get("VECTISCAN_POLICY_VERSION", "2026-05-10.1")` mit altem Default. `severity_policy.py:36` hat den korrekten `"2026-06-01.1"`. In Prod ist die ENV-Variable nicht gesetzt (`docker-compose.yml:404-405` empfiehlt nur den Override), also wirkt der AI-Cache mit dem alten Versions-Hash und der severity_policy mit dem neuen. Cache-Invalidate funktioniert dadurch zwischen den beiden Versionen nicht synchron — siehe `99_known_issues.md`.
