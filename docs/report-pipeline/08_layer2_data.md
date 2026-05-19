# 08 — Layer-2-Daten

Welche Builder die Seiten 3-9 mit Inhalt füllen.

## Aufruf-Kette

`pdf/v2/layers/strategy.py:build_layer2_strategy` (Z. 465) ruft sieben Sub-Builder. Die Daten dafür kommen aus dem `_augment_for_v2`-Block in `report_mapper.py:1784-1944`.

```
build_layer2_strategy
  ├─ _build_business_context       (strategy.py:55,  liest report_data["business_context"])
  ├─ _build_scope_methodology       (strategy.py:109, liest scope_meta + methodology_stats)
  ├─ _build_tech_stack              (strategy.py:225, liest tech_table_v2)
  ├─ _build_service_cards           (strategy.py:308, liest service_cards)
  ├─ _build_posture_indicators      (strategy.py:330, liest posture_indicators)
  ├─ _build_screenshots_v2          (strategy.py:348, liest screenshots_v2)
  └─ _build_befund_landschaft       (strategy.py:424, liest befund_landschaft)
```

## Business-Context (business_context.py)

`build_business_context(scan_meta, host_inventory, claude_output)` (Z. 325) liefert:

```python
{
  "cluster_key":       "real_estate" | "cybersecurity" | ... | "generic",
  "cluster_label":     "Immobilienwirtschaft / Makler",
  "data_kinds":        [..., ...],   # Cluster-Default + observed
  "narrative":         str,          # Plain-Text, kein HTML
  "compliance_focus":  ("DSGVO Art. 32/33", "BSI-Grundschutz Basis"),
  "observed_apps":     [str],        # aus _APP_DATA_HINTS gematcht
  "source":            "override" | "tech_heuristic" | "domain_heuristic" | "generic",
}
```

### INDUSTRY_CLUSTERS (Z. 44)

Acht Cluster, jeder mit `label`, `data_kinds`, `narrative`, `compliance_focus`:

| Key | Label | Compliance-Focus |
|---|---|---|
| `real_estate` | Immobilienwirtschaft / Makler | DSGVO Art. 32/33, BSI-Grundschutz Basis |
| `cybersecurity` | Cybersecurity- / IT-Sicherheits-Anbieter | ISO 27001, NIS2 §30 BSIG, Branchen-Reputation |
| `healthcare` | Gesundheitswesen / MedTech | DSGVO Art. 9/32/33, B3S Krankenhaus, KRITIS |
| `legal_services` | Rechtsanwaltskanzlei / Notariat | DSGVO Art. 32, §203 StGB, §43a BRAO |
| `ecommerce` | Online-Handel / E-Commerce | DSGVO Art. 32, PCI-DSS, TKG/TMG |
| `industrial` | Industrie / Maschinenbau | TISAX, NIS2 §30 BSIG, Geschäftsgeheimnis-Gesetz |
| `financial_services` | Finanzdienstleister | DORA, BaFin/MaRisk, DSGVO Art. 32 |
| `public_sector` | Oeffentliche Verwaltung | BSI-Grundschutz, ... |

`GENERIC_CLUSTER` (Z. ~180): neutraler datenarten-gebundener Text ohne branchenspezifische Floskeln.

### Heuristik-Reihenfolge

`build_business_context` (Z. 353-378) — Reihenfolge entspricht Dokument-Header Z. 7-11:

1. `scan_meta["industry_vertical"]` (Override aus dem Order-Wizard) — `source="override"`.
2. `_detect_industry_from_techs(tech_profiles)` (Z. 229) — sucht in CMS + server + technologies.name nach den 21 `_TECH_HINTS`-Pattern → `source="tech_heuristic"`.
3. `_detect_industry_from_domain(domain)` (Z. 253) — Tokens "anwalt/kanzlei/notar", "immobilien/makler/haus-", "klinik/praxis/arzt/med-", "bank/versicher/finanz", TLD-Suffix ".gov.de/.bund.de" → `source="domain_heuristic"`.
4. Fallback `GENERIC_CLUSTER` → `source="generic"`.

### _TECH_HINTS (Z. ~200)

21 Einträge, Auszug:

```
shopware → ecommerce
magento → ecommerce
medatixx → healthcare
ranet → legal_services
advoware → legal_services
rena2 → legal_services
sap → industrial
siemens → industrial
rockwell → industrial
...
```

### _APP_DATA_HINTS (Z. 282)

11 Einträge — übersetzt erkannte Apps in vermutete Datenarten:

```
contact form 7    → "Kontaktanfragen ueber Web-Formulare"
woocommerce       → "Bestell- und Zahlungsdaten (WooCommerce-Shop)"
phpmyadmin        → "direkter Datenbankzugriff"
roundcube         → "E-Mail-Postfaecher"
nextcloud/owncloud → "Dateifreigaben und Kalenderdaten"
mautic            → "Marketing-Kontaktdatenbank"
matomo/piwik      → "Web-Analyse-/Besucherdaten"
```

`_observed_data_kinds` (Z. 297) dedupliziert die Treffer in der Reihenfolge der Detection — die werden den Cluster-Default-Datenarten angehängt.

## v2_data.py

Drei Aggregatoren für die Strategie-Seiten.

### build_scope_meta (Z. 28)

Returns:

```python
{
  "domain":            str,
  "hosts_count":       int,                      # len(host_inventory.hosts)
  "subdomains_count":  int,                      # set(host_inventory.subdomains + alle host.fqdns)
  "scan_date":         str,                      # YYYY-MM-DD
  "started_at":        str,                      # ISO timestamp
  "finished_at":       str | None,
  "package":           str,
  "out_of_scope": (
    "interne Netzsegmente",
    "mitarbeiterseitige Authentifizierungssysteme",
    "mobile Endgeraete",
    "Social-Engineering-Versuche",
    "physische Sicherheit",
  ),
}
```

`out_of_scope` ist hardcoded — fünf fixe Boilerplate-Items für die Seite-4-Aufzählung.

### build_methodology_stats (Z. 93)

Returns:

```python
{
  "filtered_count":   int,    # len(claude_output.additional_findings)
  "selected_count":   int,    # len(claude_output.findings)
  "filter_rate_pct":  float,  # filtered / (selected+filtered) * 100, runden auf 1 Stelle
  "policy_version":   str,    # ENV VECTISCAN_POLICY_VERSION oder "2026-06-01.1"
  "ai_models":        [dict, dict, dict],
  "tool_versions":    [(tool, version), ...],
  "phases":           [dict, dict, dict, dict],
  "out_of_scope_note": str,   # langer Paragraph über manuellen Pentest
}
```

`ai_models` (Z. 128) ist hardcoded 3 Einträge:

1. **Sonnet 4.6** (`claude-sonnet-4-6`): "Cross-Tool-Confidence-Boost (Phase 3) und Klassifizierung neu beobachteter Finding-Pattern."
2. **Haiku 4.5** (`claude-haiku-4-5-20251001`): "Host-Strategie (Phase 0b), Phase-2-Tool-Konfiguration und Title-Type-Fallback. Deterministisch durch temperature=0 + Redis-Cache."
3. **VECTISCAN-Severity-Policy `<POLICY_VERSION>`** (`deterministic`): "Deterministische Severity-Vergabe ueberschreibt die Tool-Severities. KEINE KI im Severity-Pfad."

`phases` (Z. 163) sind 4 Einträge entsprechend Scan-Pipeline (Phase 0 Reconnaissance, Phase 1 Tech-Erkennung, Phase 2 Tiefer Scan, Phase 3 Korrelation + Threat-Intel).

> Bug-Marker: Die Doku in CLAUDE.md spricht von "5 KI-Punkten" im Scan-Worker. Die `ai_models`-Liste in der PDF nennt aber nur 3 Einträge (Sonnet, Haiku, Policy). Render-Text auf Seite 4 ist daher knapper als die CLAUDE.md-Beschreibung suggeriert. Code-Wahrheit: 3 Einträge.

### build_compliance_indicators (Z. 249)

Drei feste Indikatoren — alle mit demselben Status (`_global_status` Z. 236, mapped Max-Severity → Status):

| max_severity | Status |
|---|---|
| CRITICAL, HIGH | `"Handlungsbedarf"` |
| MEDIUM, LOW | `"Teilerfuellt"` |
| INFO | `"Konform"` |

Die drei Labels:

1. `"DSGVO Art. 32 (Datensicherheit)"`
2. `"BSI IT-Grundschutz (Basisabsicherung)"`
3. `"Branchen-Empfehlungen: <cluster_label>"` (z.B. "Branchen-Empfehlungen: Immobilienwirtschaft / Makler")

Mapping zum Render-Farb-Code: `pdf/v2/layers/frontpage.py:_STATUS_COLOR_HEX` (`Konform → #16A34A`, `Teilerfuellt → #CA8A04`, `Handlungsbedarf → #DC2626`).

### build_tech_table_v2 (Z. 283)

Per-Host-Tech-Tabelle für die Seite 6. Quelle ist `tech_table_builder.build_tech_table_for_host(profile)` (siehe `04_determinism.md`). Output:

```python
[
  {
    "host_label": "<fqdn> - <ip>",  # ohne FQDN: nur "<ip>"
    "ip":         str,
    "rows":       [tech_row, tech_row, ...],
  },
  ...
]
```

Hosts ohne tech_profile werden ausgelassen (Z. 316). Hosts mit leerer `rows`-Liste auch (Z. 326).

## Service-Cards (befund_landschaft.py:build_service_cards, Z. 256)

Liest `host_inventory.hosts[]` + `tech_profiles[]`. Output pro Host:

```python
{
  "host":  "<fqdn> - <ip>",
  "ip":    str,
  "ports": [{port: int, label: str, color: "RED"|"ORANGE"|"GRAY"}, ...],
}
```

Port-Klassifikation (`befund_landschaft.py:113` `_classify_finding` und Z. 256 `build_service_cards`):

- RED_PORTS (14 Stück, `befund_landschaft.py:RED_PORTS`): `3306, 5432, 27017, 6379, 3389, 23, 111, 445, 139, 1433, 1521, 9200, 11211, 5900, 5984`.
- ORANGE_PORTS (7 Stück): `21, 80, 25, 110, 143, 389`.
- Alles andere: `GRAY`.

SERVICE_LABELS (22 Mappings): `80→HTTP`, `443→HTTPS`, `22→SSH`, `3306→MySQL`, `5432→PostgreSQL`, etc.

`ServiceCard`-Flowable (`pdf/v2/flowables.py:198`) rendert die Karte mit farbigen Port-Chips, max 6 pro Reihe.

## Posture-Indicators (posture_v2.py:build_posture_indicators, Z. 207)

Vier Mini-Dashboards. Input: `claude_output.findings`, `tr03116_compliance` (aus `report_data["tr03116_compliance"]`).

Output:

```python
[
  {"label": "E-Mail-Authentizitaet",   "sub": [{"name": "SPF", "status": ok|warn|fail, "detail": "..."}, ...]},
  {"label": "Web-Hygiene",             "sub": [...]},  # HSTS, CSP, X-Frame, Cookies
  {"label": "DNS",                     "sub": [...]},  # AXFR, Dangling, DNSSEC
  {"label": "TLS-Konfiguration",       "sub": [...]},  # TLS-Cipher, TLS-Version, TR-03116
]
```

Sub-Indikator-Definitionen (`posture_v2.py:21-30`):

```python
EMAIL_SUBS = ("SPF", "DKIM", "DMARC")
WEB_SUBS   = ("HSTS", "CSP", "X-Frame", "Cookies")
DNS_SUBS   = ("AXFR", "Dangling", "DNSSEC")
TLS_SUBS   = ("TLS-Cipher", "TLS-Version", "TR-03116")
```

Status-Logik (`_email_indicator` Z. 63, `_web_indicator` Z. 113, `_dns_indicator` Z. 142, `_tls_indicator` Z. 166): durchsucht Findings nach `policy_id`-Prefix, `finding_type` und Title-Tokens (Helper `_matches_policy`, `_matches_finding_type`, `_matches_text` Z. 41-56). Treffer im Severity-Band HIGH/CRITICAL → `fail`; LOW/MEDIUM → `warn`; sonst → `ok`.

Für TLS wird zusätzlich `tr03116_compliance.overall_status` (`PASS/PARTIAL/FAIL`) ausgewertet.

`PostureIndicator`-Flowable (`pdf/v2/flowables.py:143`) rendert die Pille pro Sub-Indikator.

## Befund-Landschaft (befund_landschaft.py:build_befund_landschaft, Z. 127)

Output:

```python
{
  "categories": [
    {"key": "A", "label": "Exponierte Dienste", "count": 3, "findings": [...]},
    {"key": "B", "label": "Veraltete Software", "count": 5, "findings": [...]},
    ...
  ],
  "positive_findings": [...],
}
```

### CATEGORIES (`befund_landschaft.py:CATEGORIES`)

Sieben Kategorien:

| Key | Label | Trigger (Policy-IDs) |
|---|---|---|
| A | exposed_services | SP-DB, SP-RDP, SP-FTP, SP-SSH |
| B | outdated_software | SP-EOL, SP-CVE, SP-WP, SP-CMS, SP-JS |
| C | mail_authenticity | SP-DNS |
| D | info_disclosure | SP-DISC, SP-INFO |
| E | web_hygiene | SP-HDR, SP-CSP, SP-COOK, SP-CSRF, SP-WEB |
| F | tls_crypto | SP-TLS |
| G | other | (Fallback) |

`_classify_finding` (Z. 113) macht Prefix-Match auf `finding.policy_id`. Findings ohne match landen in `G`.

`_schwerpunkt_label` (Z. 96) macht ein DE-Label aus Schwerpunkt-String (Domain/IP/Tech).

`KategorieBlock`-Flowable (`pdf/v2/flowables.py:108`) rendert die Kategorie mit ihrem Header + bis zu 8 Findings (mehr wird abgeschnitten).

## Methodik-Render (strategy.py:_build_scope_methodology, Z. 109)

Sektion-Reihenfolge:

1. H2 "Prüfungsumfang".
2. Vier Stats-Felder (Domain, Hosts, Subdomains, Datum).
3. H2 "Methodik".
4. Vier Phasen-Absätze (Phase 0/1/2/3).
5. KI-Modelle-Liste (3 Einträge).
6. Tool-Versions-Tabelle.
7. Filter-Statistik (filter_rate_pct, selected_count, filtered_count).
8. `out_of_scope_note` als Paragraph.

Helper `_section` (Z. 37), `_subsection` (Z. 42), `_body` (Z. 47) sind dünne Wraps um `Paragraph` mit den entsprechenden Style-Lookups.

## Tech-Stack-Render (strategy.py:_build_tech_stack, Z. 225)

Pro Host eine Tabelle mit Spalten: Komponente, Version, Erkennung, Patch-Status, Top-CVE. Patch-Status-Label und -Farbe kommen aus `_patch_status_label` (Z. 203, mapped `eol/minor_eol/outdated/current` zu deutschen Labels) und `_patch_status_color_hex` (Z. 214).
