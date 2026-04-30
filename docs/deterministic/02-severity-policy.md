# 02 — Severity-Policy als Code

**Ziel:** Severity-Vergabe wird auditierbar, deterministisch und gegen
kommerzielle DAST-Baselines (Rapid7, Acunetix, Burp, Qualys) kalibriert.

**Lokation:** `report-worker/reporter/severity_policy.py`

**Aufruf-Punkt:** Im Report-Worker **nach** `correlation/correlator.py` und
**vor** `correlation/business_impact.py`. Die Policy überschreibt die von
ZAP, header_check und anderen Tools vorgeschlagenen Severities, und legt
zusätzlich `policy_id` und `severity_provenance` auf jedes Finding.

---

## 1. Problemraum

Heute kommt Severity aus drei Quellen, die sich widersprechen:

1. **ZAP-Risk-Mapping** (`tools/zap_mapper.py`): `High→7.5, Medium→5.3, Low→3.1`
   — pauschal, kontext-frei
2. **Tool-spezifische Severity** (testssl, header_check, wpscan)
3. **`cap_implausible_scores()`** im Reporter — versucht überhöhte
   CVSS-Scores nachträglich zu deckeln, aber per Heuristik

Resultat: ~370 Mediums in Securess-Scan, die Rapid7 als Informational meldet.
Das macht Reports gegenüber Vergleichs-Tools unglaubwürdig.

## 2. Architektur

```
   ┌─────────────────────┐
   │  Phase 3 Output     │  CorrelatedFindings mit raw severity aus Tools
   │  (correlator.py)    │
   └──────────┬──────────┘
              │
              ▼
   ┌─────────────────────┐
   │  severity_policy    │  ← NEU
   │  apply_policy(...)  │
   └──────────┬──────────┘
              │
              ▼  Findings haben jetzt: policy_id, final severity, provenance
   ┌─────────────────────┐
   │  business_impact    │  rechnet Score auf NEUER Severity
   └──────────┬──────────┘
              │
              ▼
   ┌─────────────────────┐
   │  selection.py       │  Top-N nach business_impact
   └──────────┬──────────┘
              ▼
        Reporter (Sonnet) — Narrative-only
```

## 3. Schema

### `SeverityPolicy` (Pydantic-Modell)

```python
class SeverityPolicy(BaseModel):
    policy_id: str                    # "SP-CSP-002"
    finding_type: str                 # interner Match-Key, z.B. "csp_missing"
    matches_when: dict[str, Any]      # Context-Flag-Bedingungen
    final_severity: Severity          # Enum: critical|high|medium|low|info
    cvss_vector: str | None           # CVSS 3.1 Vektor wenn anwendbar
    cvss_score: float | None          # Score aus Vektor (Validierung)
    rationale: str                    # WARUM diese Einstufung
    references: list[str]             # CWE, OWASP, CVE-Beispiele
    overrides_tool_severity: bool     # default True
```

### Context-Flags

Werden **deterministisch** aus Tool-Outputs abgeleitet (nie KI):

| Flag | Quelle | Bedeutung |
|---|---|---|
| `form_present` | ZAP-Spider HTML-Parse | Mindestens ein `<form>`-Tag in der Page |
| `cookie_session` | ZAP cookie analysis | Cookie ohne Lifetime / Session-Cookie erkannt |
| `inline_scripts` | ZAP-Spider HTML-Parse | `<script>` ohne `src=` oder `style=`-inline |
| `state_change` | ZAP request analysis | Form-Method `POST/PUT/DELETE/PATCH` |
| `auth_present` | ZAP login-form heuristic | Form mit `type=password` |
| `is_session_path` | Path-Pattern-Check | Path enthält `/login`, `/account`, `/admin`, `/cart`, `/checkout` |
| `cve_in_kev` | Phase 3 Threat-Intel | CVE in CISA KEV |
| `cve_epss_high` | Phase 3 Threat-Intel | EPSS > 0.5 |
| `cve_ransomware` | Phase 3 Threat-Intel | KEV-Entry mit Ransomware-Tag |
| `tech_eol` | Phase 1 + Tech-DB | Erkannte Technologie ist End-of-Life |
| `port_management` | nmap | Port ∈ {22, 3389, 5900, 8080, 8443, 10000} |

Implementierung in `severity_policy.py::extract_context_flags(finding, scan_context) -> dict`.

## 4. Policy-Regeln (vollständig — 40 Regeln)

### Header — `SP-HDR-*`

| Policy ID | Match | Context | Severity | Rationale |
|---|---|---|---|---|
| SP-HDR-001 | `hsts_missing` | `is_session_path=False` | **info** | Static page, no session — info only (Rapid7 baseline) |
| SP-HDR-002 | `hsts_missing` | `is_session_path=True` | **low** | Session-bearing page sollte HSTS haben |
| SP-HDR-003 | `hsts_no_includesubdomains` | — | **info** | Hardening, aber Risiko gering |
| SP-HDR-004 | `hsts_short_maxage` | maxage < 15768000 | **info** | <6 Monate ist „best practice"-Verstoß, kein Risiko |
| SP-HDR-005 | `xcto_missing` | — | **info** | MIME-sniffing Risiko ist theoretisch (alt-Browser) |
| SP-HDR-006 | `xfo_missing` | `is_session_path=False` | **info** | Nicht clickjacking-relevant ohne Session |
| SP-HDR-007 | `xfo_missing` | `is_session_path=True` | **low** | Clickjacking-Risiko mit Session |
| SP-HDR-008 | `referrer_policy_missing` | — | **info** | Privacy-Hardening |
| SP-HDR-009 | `permissions_policy_missing` | — | **info** | Hardening |

### Content Security Policy — `SP-CSP-*`

| Policy ID | Match | Context | Severity | Rationale |
|---|---|---|---|---|
| SP-CSP-001 | `csp_missing` | `inline_scripts=False, form_present=False` | **info** | Statische Seite, kein User-Input — kein praktisches XSS-Risiko |
| SP-CSP-002 | `csp_missing` | `inline_scripts=True OR form_present=True` | **low** | Risk-vector existiert (form/script), aber Header-fehlen ist nicht XSS-Beweis |
| SP-CSP-003 | `csp_unsafe_inline` | `form_present=True` | **medium** | Erlaubt inline JS auf Form-Page |
| SP-CSP-004 | `csp_unsafe_eval` | — | **medium** | `eval()` erlaubt → echte XSS-Lücke wahrscheinlicher |
| SP-CSP-005 | `csp_wildcard_source` | — | **low** | `*` in `script-src` schwächt CSP, aber nicht offen |

### Cookie-Attribute — `SP-COOK-*`

| Policy ID | Match | Context | Severity | Rationale |
|---|---|---|---|---|
| SP-COOK-001 | `cookie_no_secure_https` | `cookie_session=True` | **medium** | Session-Cookie über HTTP übertragbar = Hijacking |
| SP-COOK-002 | `cookie_no_httponly` | `cookie_session=True` | **medium** | Session-Cookie via JS lesbar = XSS-Token-Diebstahl |
| SP-COOK-003 | `cookie_no_samesite` | `cookie_session=True` | **low** | CSRF-Mitigation fehlt; kein direktes Lecken |
| SP-COOK-004 | `cookie_no_secure_https` | `cookie_session=False` | **info** | Tracking-Cookie, kein Auth-Risiko |
| SP-COOK-005 | `cookie_no_samesite` | `cookie_session=False` | **info** | Tracking-Cookie ohne SameSite |

### CSRF — `SP-CSRF-*`

| Policy ID | Match | Context | Severity | Rationale |
|---|---|---|---|---|
| SP-CSRF-001 | `csrf_token_missing` | `state_change=False` | **info** | GET-only Form, kein State-Change |
| SP-CSRF-002 | `csrf_token_missing` | `state_change=True, auth_present=False` | **low** | State-Change ohne Auth — geringeres Risiko |
| SP-CSRF-003 | `csrf_token_missing` | `state_change=True, auth_present=True` | **medium** | Authenticated state-change ohne Token = CSRF |

### Information Disclosure — `SP-DISC-*`

| Policy ID | Match | Context | Severity | Rationale |
|---|---|---|---|---|
| SP-DISC-001 | `server_banner_with_version` | — | **low** | Reduktion Recon-Information |
| SP-DISC-002 | `server_banner_no_version` | — | **info** | Banner-Existenz allein ist kein Issue |
| SP-DISC-003 | `nginx_status_endpoint_open` | — | **medium** | Internal-stats endpoint exposed |
| SP-DISC-004 | `phpinfo_exposed` | — | **high** | Komplette Server-Config + Pfade |
| SP-DISC-005 | `directory_listing_enabled` | — | **low** | Verzeichnis-Listing aktiv |
| SP-DISC-006 | `error_message_with_stack` | — | **medium** | Stack-Traces leaken Pfade, Versionen, Credentials |
| SP-DISC-007 | `git_directory_exposed` | — | **high** | `.git/` öffentlich → Source-Code-Leak |
| SP-DISC-008 | `env_file_exposed` | — | **critical** | `.env` öffentlich → API-Keys, DB-Creds |

### TLS — `SP-TLS-*`

| Policy ID | Match | Context | Severity | Rationale |
|---|---|---|---|---|
| SP-TLS-001 | `tls_below_tr03116_minimum` | — | **high** | BSI TR-03116-4 Verstoß |
| SP-TLS-002 | `tls_weak_cipher_suites` | — | **medium** | Schwache Cipher-Suiten verfügbar |
| SP-TLS-003 | `tls_no_pfs` | — | **medium** | Perfect Forward Secrecy fehlt |
| SP-TLS-004 | `tls_certificate_expired` | — | **high** | Cert abgelaufen — Browser-Warnung |
| SP-TLS-005 | `tls_certificate_expiring_30d` | — | **low** | Erinnerungs-Schwelle, nicht akut |
| SP-TLS-006 | `tls_self_signed` | — | **medium** | Self-signed außerhalb von intern. PKI |
| SP-TLS-007 | `hsts_preload_missing` | — | **info** | Best-Practice, Hardening |

### DNS / Mail — `SP-DNS-*`

| Policy ID | Match | Context | Severity | Rationale |
|---|---|---|---|---|
| SP-DNS-001 | `dnssec_missing` | — | **low** | DNSSEC nicht aktiviert |
| SP-DNS-002 | `dnssec_chain_broken` | — | **medium** | DNSSEC aktiviert aber Chain kaputt = false security |
| SP-DNS-003 | `caa_missing` | — | **info** | CA-Authorization fehlt — Hardening |
| SP-DNS-004 | `spf_missing` | `mx_present=True` | **medium** | Spoofing möglich für Mail-Domain |
| SP-DNS-005 | `spf_softfail` | — | **low** | `~all` statt `-all` = soft fail |
| SP-DNS-006 | `dmarc_missing` | `mx_present=True` | **medium** | Phishing-Schutz fehlt |
| SP-DNS-007 | `dmarc_p_none` | — | **low** | DMARC monitoring-only |
| SP-DNS-008 | `dkim_missing` | `mx_present=True` | **low** | Mail-Auth-Layer fehlt |
| SP-DNS-009 | `mta_sts_missing` | — | **info** | MTA-STS optional, hardening |

### CVE-driven — `SP-CVE-*`

CVE-Findings nutzen NVD-CVSS als Basis und werden nur nach **oben**
korrigiert (nie nach unten — eine bekannte CVE ist nie weniger schlimm
als ihr CVSS).

| Policy ID | Match | Context | Severity | Rationale |
|---|---|---|---|---|
| SP-CVE-001 | `cve_finding` | `cve_in_kev=True` | **critical** | CISA KEV → known exploited |
| SP-CVE-002 | `cve_finding` | `cve_ransomware=True` | **critical** | Ransomware-related CVE |
| SP-CVE-003 | `cve_finding` | `cve_epss_high=True, cvss>=7.0` | **high** | EPSS>0.5 + CVSS≥7 = sehr wahrscheinlich exploitiert |
| SP-CVE-004 | `cve_finding` | else | **derived from CVSS** | Standard-Mapping (≥9 critical, ≥7 high, ≥4 medium, ≥0.1 low) |

### EOL-Software — `SP-EOL-*`

| Policy ID | Match | Context | Severity | Rationale |
|---|---|---|---|---|
| SP-EOL-001 | `software_eol` | `tech="exchange"` | **high** | Exchange EOL → ProxyLogon/Shell-Risiko |
| SP-EOL-002 | `software_eol` | `tech in ("php","nodejs","python")` | **medium** | Unmaintainted runtime |
| SP-EOL-003 | `software_eol` | `tech in ("nginx","apache")` | **medium** | Unmaintainted webserver |
| SP-EOL-004 | `software_eol` | `tech="wordpress" AND major_version_behind` | **high** | WP-Major hinter EOL |

## 5. Match-Logik

```python
def lookup_policy(finding_type: str, context_flags: dict) -> SeverityPolicy | None:
    """
    Findet die spezifischste Policy für einen Finding.
    Spezifität = Anzahl der zutreffenden context_flags-Bedingungen.
    Ties werden alphabetisch nach policy_id aufgelöst (deterministisch).
    """
    candidates = [p for p in SEVERITY_POLICIES if p.finding_type == finding_type]
    matching = [p for p in candidates if _matches_context(p, context_flags)]

    if not matching:
        return None  # Caller fällt auf default-Logik zurück

    # Sort by specificity DESC, then policy_id ASC for stable tiebreak
    matching.sort(key=lambda p: (-len(p.matches_when), p.policy_id))
    return matching[0]
```

## 6. Fallback-Strategie

Wenn `lookup_policy` `None` liefert (= unbekannter Finding-Typ):

1. **Log Warning** mit `finding_type` und Tool-Quelle
2. **Tool-Severity übernehmen**, aber mit `policy_id="SP-FALLBACK"`
3. **In `severity_audit`-Tabelle** zählen (`COUNT(*) GROUP BY finding_type`)
4. **Wöchentliches Review**: Top-Misses → neue Policy-Regel ergänzen

Ziel: Innerhalb 4 Wochen sollten >95 % aller Findings durch eine konkrete
Policy-Regel laufen, nur <5 % über `SP-FALLBACK`.

## 7. Provenance im Finding

Nach `apply_policy()` hat jedes Finding diese zusätzlichen Felder:

```json
{
  "policy_id": "SP-CSP-002",
  "severity": "low",
  "severity_provenance": {
    "policy_decision": "low",
    "tool_severities": {
      "zap_passive": "medium",
      "header_check": "low"
    },
    "context_flags": {
      "form_present": true,
      "inline_scripts": false,
      "is_session_path": false
    },
    "rationale": "CSP fehlt, aber keine inline-scripts erkannt",
    "rule_references": ["CWE-693", "OWASP2025-A05"]
  }
}
```

Wird in DB-Tabelle `report_findings_data.findings_data->[]->severity_provenance`
serialisiert (Migration 014).

## 8. Test-Strategie

Pro Policy-Regel:
- **1× positiver Test**: Context-Flags treffen zu → Policy greift
- **1× negativer Test** (wenn anwendbar): Context-Flags treffen nicht → andere Policy oder `None`

Plus übergreifende Tests:
- **Determinismus**: Gleiche Inputs → identisches Output
- **Spezifitäts-Sortierung**: Spezifischere Regel gewinnt gegen generischere
- **CVSS-Validierung**: Vektor → Score (innerhalb 0.1 Toleranz)
- **Fallback**: Unbekannter Finding-Typ → `SP-FALLBACK`-Policy

## 9. Integrations-Reihenfolge im Reporter

`report-worker/reporter/worker.py::process_report()` aktuell:

```python
findings = parse_phase3_output(...)
findings = apply_cap_implausible_scores(findings)   # ← fällt weg
findings = validate_cvss_scores(findings)
findings = validate_cwe_mappings(findings)
report_data = claude_client.generate(findings)      # ← Sonnet wählt aus
```

Neu:

```python
findings = parse_phase3_output(...)
findings = severity_policy.apply_policy(findings, scan_context)   # ← NEU
findings = business_impact.recompute(findings)                    # NACH Policy
findings = validate_cvss_scores(findings)
findings = validate_cwe_mappings(findings)
selected = selection.select_findings(findings, package)            # ← NEU
report_data = claude_client.generate_narrative(selected)           # nur Narrative
```

## 10. Was sich für `business_impact.py` ändert

`business_impact.py::compute_score()` ist heute:
```
base = CVSS × EPSS × KEV × Asset × Package_Weight × Confidence
```

Bleibt unverändert, aber **liest jetzt die finale Severity aus
`finding.severity` (gesetzt von Policy)**, nicht mehr aus dem rohen
Tool-Output. Der CVSS-Score wird ggf. an die Policy-Severity angeglichen
(z.B. wenn Policy „medium" sagt aber CVSS 7.5 ist, dann CVSS auf
Medium-Range capping).

## 11. Crosslinks

- Skeleton: [`02-severity-policy-skeleton.py`](./02-severity-policy-skeleton.py)
- Tests: [`02-severity-policy-tests.py`](./02-severity-policy-tests.py)
- Migration für Provenance-Felder: [`05-014-severity-policy.sql`](./05-014-severity-policy.sql)
