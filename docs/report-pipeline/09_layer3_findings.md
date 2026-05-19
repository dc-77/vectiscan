# 09 — Layer-3: Befund-Details

`pdf/v2/layers/findings.py` — alle Finding-Bodies ab Seite 11 mit 7-Sektionen-Struktur.

## Eintrittspunkt

`build_layer3_findings(story, styles, data)` (Z. 420):

```python
findings = (data or {}).get("findings") or []
if not findings:
    return

# H1 + Beschreibungs-Paragraph
story.append(Paragraph("<b>BEFUND-DETAILS</b>", section_style))
story.append(Paragraph(
    "Pro Befund: Was wurde gefunden, wie wurde es nachgewiesen, ..."
))

policy_version = data["methodology_stats"]["policy_version"] or "unbekannt"
scan_context = {"domain": scope.get("domain") or data.get("domain") or ""}
compliance_mappings = data.get("compliance_mappings")

for finding in findings:
    if finding.get("is_positive_finding"):
        continue
    _build_single_finding(story, styles, finding,
                          policy_version=str(policy_version),
                          scan_context=scan_context,
                          compliance_mappings=compliance_mappings)

story.append(PageBreak())
```

`is_positive_finding`-Findings werden hier ausgelassen — sie tauchen in der Befund-Landschaft (Seite 8/9) als positive Section auf.

## _build_single_finding (Z. 300)

Reihenfolge der 8 Render-Schritte pro Finding:

1. **Header-Group** (KeepTogether, Z. 316-356):
   - `FindingHeaderV2(finding_id, title, priority, risk, policy_id)`.
   - Inline-Meta (`Betroffene Systeme`, `CVSS x.y (CVSS:3.1/...)`, `CWE`).
   - "WAS WURDE GEFUNDEN"-Label + Description.

2. **NACHWEIS** (Z. 359-363): Label + Evidence-Body (Newlines → `<br/>`).

3. **THREAT INTELLIGENCE** (Z. 366): nur wenn `_normalize_cve_entries(finding)` Treffer hat (siehe unten).

4. **GESCHAEFTSAUSWIRKUNG** (Z. 369-371): Label + `finding["impact"]`.

5. **EMPFEHLUNG** (Z. 374-385) mit Priority-Prefix:
   - "Sofort: " für `Unverzueglich`
   - "In Kuerze: " für `In Kuerze`
   - "Mittelfristig: " für `Mittelfristig`
   - "Strategisch: " für `Strategisch`

6. **COMPLIANCE** (inline, Z. 388): `_render_compliance_inline` — siehe unten.

7. **VERIFIKATION** (Z. 391-399): `get_verification_block(finding, scan_context)` aus `verification_templates.py`.
   - `is_fallback=True` → kursive Note + Generic-Fallback-Text.
   - `is_fallback=False` → Evidence-Style (monospace) für den Shell-Befehl.

8. **INTERNE REFERENZ** (Z. 402-413): `Severity-Policy: <policy_id> · Version <policy_version>` oder bei fehlender policy_id "kein policy_id zugeordnet".

## Severity → Priority/Risiko Mapping

```python
# findings.py top
_SEV_TO_PRIORITY = {
    "CRITICAL": "Unverzueglich",
    "HIGH":     "Unverzueglich",
    "MEDIUM":   "In Kuerze",
    "LOW":      "Mittelfristig",
    "INFO":     "Strategisch",
}

_SEV_TO_RISIKO = {
    "CRITICAL": "KRITISCH",
    "HIGH":     "HOCH",
    "MEDIUM":   "MITTEL",
    "LOW":      "NIEDRIG",
    "INFO":     "INFO",
}
```

Beide werden im `FindingHeaderV2`-Flowable (`flowables.py:239`) angezeigt — als deutsche Pille rechts oben am Header.

## _normalize_cve_entries (Z. 51)

Sammelt CVE-Einträge aus 5 möglichen Quellen am Finding:

| Quelle | Form | Verwendet |
|---|---|---|
| `finding.cves` | `list[str]` oder `list[dict]` | cve_id, epss_score, kev (Z. 67-81) |
| `finding.cve_id` / `finding.cve` | string | als Single-Entry, Threat-Intel-Fields aus `_extract_threat_intel` |
| `finding.threat_intel` (no cve_id) | `{epss_score, in_kev}` | Pseudo-CVE `"(unspezifiziert)"` (Z. 96-103) |
| `finding.enrichment` | `{epss: {epss}, cisa_kev}` | via `_extract_threat_intel` |
| `finding.correlation_data` | nested | merged in den ersten Eintrag (Z. 107-112) |

### Sort + Cap (Z. 115-120)

```python
out.sort(key=lambda e: (
    0 if e.get("kev") else 1,    # KEV zuerst
    -float(e.get("epss_score") or 0.0),
    str(e.get("cve_id") or ""),
))
return out[:3]
```

Top-3 nach EPSS DESC, mit KEV-Vorrang bei Tie.

### Render (Z. 201-241)

THREAT INTELLIGENCE-Sektion erscheint NUR wenn `_normalize_cve_entries` Treffer hat. Sonst wird die Sektion komplett ausgelassen (Doc-Kommentar Z. 205: Vermeidung leerer Boxen pro Header-Finding).

Format:

```
CVE-Treffer (Top 3 nach EPSS-Score):
  • CVE-2024-1234 · EPSS 0.85 · (Top-Risikobereich) · KEV
  • CVE-2024-5678 · EPSS 0.42
  • CVE-2024-9012 · EPSS 0.15

CISA KEV — aktiv ausgenutzt    [oder]    CISA KEV: nein
```

"(Top-Risikobereich)"-Label erscheint ab EPSS ≥ 0.5 (Z. 232).

## verification_templates.py

`get_verification_block(finding, scan_context)` (Z. 321) returnt `(rendered_text, is_generic_fallback)`.

### VERIFICATION_TEMPLATES (Z. 42-220, 21 policy_ids)

| Policy-ID | Zweck | Zeile |
|---|---|---|
| SP-DB-001 | DB-Port-Exposure | 42 |
| SP-RDP-001 | RDP-Exposure | 50 |
| SP-FTP-001 | FTP-Cleartext | 58 |
| SP-EOL-002 | EOL-near | 67 |
| SP-EOL-001 | EOL | 76 |
| SP-WEB-002 | Web-Defekt-Variante | 84 |
| SP-WEB-001 | Web-Defekt | 93 |
| SP-WP-001 | WordPress-Plugin | 101 |
| SP-CMS-001 | CMS-Generic | 110 |
| SP-DNS-002 | DNSSEC-Bruch | 119 |
| SP-DNS-004 | SPF-fehlt | 127 |
| SP-DNS-007 | DMARC-policy=none | 135 |
| SP-HDR-001 | HSTS-fehlt | 144 |
| SP-COOK-003 | Cookie-SameSite | 153 |
| SP-DISC-001 | Server-Banner-Version | 161 |
| SP-CSP-001 | CSP-fehlt | 171 |
| SP-CSRF-001 | CSRF-Token-fehlt | 180 |
| SP-DNS-005 | SPF-softfail | 189 |
| SP-DNS-010 | DMARC-quarantine | 196 |
| SP-JS-001 | Vulnerable JS-Library | 204 |
| SP-URLHAUS-001 | URLhaus-Listed | 213 |

Jedes Template enthält den Re-Scan-Shell-Befehl, ein erwartetes Soll-Ergebnis und Smart-Var-Platzhalter `{host}`, `{port}`, `{domain}`, `{cookie_name}`, `{tech}`, `{version}`, `{plugin}`, `{library}`, `{cve_id}`.

### GENERIC_FALLBACK (Z. 230)

```
Nach Umsetzung der Empfehlung: gezielter Re-Scan derselben Pruefkomponente mit
identischer Tool-Konfiguration. Das Finding darf in der erneuten Pruefung nicht
mehr reproduzierbar sein. Bei Befunden mit CVE-Bezug zusaetzlich Patchstand der
betroffenen Software gegen Hersteller-Advisory verifizieren.
```

Wird verwendet, wenn `policy_id` nicht in `VERIFICATION_TEMPLATES` ist. Der Renderer (`findings.py:392-396`) markiert diesen Fall mit kursivem Vorspann "Generischer Hinweis (kein spezifischer Befehl hinterlegt):".

### Smart-Var-Substitution (Z. 252)

`_collect_vars(finding, scan_context)` sammelt Variablen mit folgender Priorität pro Var:

1. `title_vars` aus dem Finding (KI-Output).
2. Direkte Felder am Finding (`host_ip`, `port`, `version`, ...).
3. `affected` (gesplittet bei `:` und `,`).
4. `scan_context.domain`.

Verarbeitet werden mindestens: `host` (mit Fallback-Kette über vhost/fqdn/host/host_ip/ip/affected, Z. 274-287), `domain`, `port` (Z. 297, Regex `:(\d{1,5})\b` gegen `affected`), `cookie_name` (aus evidence), und `tech, version, plugin, library, cve_id`.

`_SafeDict` (Z. 245) → `"?"`-Default bei fehlenden Keys. Falls also der Smart-Fallback eine Var nicht ermitteln kann, erscheint sie als `?` im finalen Verifikations-Text (Sicherheitsnetz).

## _render_compliance_inline (Z. 244)

Liest `mappings[finding_id]` aus `report_data["compliance_mappings"]`. Erwartetes Schema:

```python
{
  "VS-2026-001": {
    "nis2":        "§30 Abs. 2 Nr. 5 BSIG",
    "nis2_title":  "Schwachstellenmanagement",
    "bsi":         "NET.3.2",
    "bsi_title":   "Firewall",
    "iso27001":    "A.8.20",
    "iso27001_title": "Netzwerksicherheit",
    "dsgvo":       "Art. 32 Abs. 1 lit. b",
    "dsgvo_title": "Vertraulichkeit, Integritaet, Verfuegbarkeit",
  },
  ...
}
```

Wenn das Mapping vorhanden und mindestens ein Framework gesetzt ist, rendert die Funktion eine kompakte Inline-Tabelle (NIS2/BSI/ISO27001/DSGVO-Spalten) als Vorbereitung auf Anhang D.

Wenn `mappings` `None` oder kein Eintrag für die `finding_id` da ist: Sektion wird ausgelassen.

## Render-Style-Lookups

| Helper | Style-Lookup |
|---|---|
| `_body_style` (Z. 165) | `styles["BodyText2"]` mit Fallback `styles["BodyText"]` |
| `_label_style` (Z. 169) | `styles["FindingLabel"]` mit Fallbacks `SubsectionTitle` → `BodyText` |
| `_evidence_style` (Z. 174) | `styles["Evidence"]` (monospace) mit Fallback `BodyText` |

Diese werden aus `create_styles()` (in `reporter/generate_report.py`) befüllt — derselbe Style-Pool wie der v1-Renderer.

## KeepTogether-Strategie

Nur die ersten 4 Block-Komponenten (Header + Meta + WAS-Label + Description) sind in `KeepTogether` gewrapped (Z. 356), damit der Header nicht ohne Body auf der Seite hängt. Die übrigen Sektionen sind frei und dürfen über Page-Breaks gehen — bei langen Empfehlungen oder vielen CVEs wird das Finding sonst nicht renderbar.

## Page-Break am Ende

`PageBreak` nach allen Findings (Z. 469) trennt Layer 3 sauber vom Anhang.
