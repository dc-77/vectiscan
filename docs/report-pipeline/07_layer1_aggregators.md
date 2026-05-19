# 07 — Layer-1-Aggregator

`reporter/layer1_aggregator.py` — die Engine hinter Seite 2 "Auf einen Blick".

## Output

`build_layer1(findings, recommendations, host_inventory, package)` (`layer1_aggregator.py:252`) returnt:

```python
{
  "risk_ampel":    [{"label": str, "key": str, "level": str, "count": int, "max_severity": str}, ... x5],
  "top_hebel":     [{"rank": 1..3, "title": str, "effect": str, "finding_ids": [str], "cluster_score": float}, ...],
  "overall_level": "hoch" | "mittel-hoch" | "mittel" | "niedrig-mittel" | "niedrig" | "info",
  "hygiene_split": {"cvss": [findings], "hygiene": [findings]},
}
```

Konsument: `pdf/v2/layers/frontpage.py:build_layer1_frontpage` (Z. 34).

Aufrufer: `report_mapper.py:1822-1838` (innerhalb `_augment_for_v2`).

## Die 5 Risk-Kategorien

```python
# layer1_aggregator.py:33
RISK_CATEGORIES = (
    "perimeter_exposition",
    "patch_eol",
    "mail_authenticity",
    "web_hygiene",
    "config_hygiene",
)
```

Deutsche Labels (`layer1_aggregator.py:41`):

| Key | Label DE |
|---|---|
| `perimeter_exposition` | Perimeter-Exposition |
| `patch_eol` | Patch- & EOL-Status |
| `mail_authenticity` | E-Mail-Authentizitaet |
| `web_hygiene` | Web-Hygiene |
| `config_hygiene` | Konfigurations-Hygiene |

## POLICY_PREFIX_TO_RISK_CATEGORY (Z. 50)

Vollständiges Mapping (Policy-Prefix → Kategorie):

| Prefix | Kategorie |
|---|---|
| SP-RDP | perimeter_exposition |
| SP-DB | perimeter_exposition |
| SP-FTP | perimeter_exposition |
| SP-SSH | perimeter_exposition |
| SP-EOL | patch_eol |
| SP-CVE | patch_eol |
| SP-WP | patch_eol |
| SP-JS | patch_eol |
| SP-DNS | mail_authenticity |
| SP-HDR | web_hygiene |
| SP-CSP | web_hygiene |
| SP-COOK | web_hygiene |
| SP-CSRF | web_hygiene |
| SP-DISC | config_hygiene |
| SP-TLS | config_hygiene |
| SP-CORS | config_hygiene |
| SP-SRI | config_hygiene |
| SP-ENUM | config_hygiene |
| SP-URLHAUS | config_hygiene |

`_category_for_finding` (Z. 99) macht Longest-Prefix-Match auf `finding.policy_id`. Findings ohne policy_id (SP-FALLBACK oder leer) bekommen `None` zurück — sie tauchen nicht in der Ampel auf, aber in der Befund-Landschaft (Z. 272-273).

## Level-Logik (`_level_from_max_severity`, Z. 83)

| max_severity | count | Level |
|---|---|---|
| (any) | 0 | `info` |
| CRITICAL | ≥1 | `hoch` |
| HIGH | 1 | `mittel-hoch` |
| HIGH | ≥2 | `hoch` |
| MEDIUM | 1 | `niedrig-mittel` |
| MEDIUM | ≥2 | `mittel` |
| LOW | ≥1 | `niedrig` |
| INFO | ≥1 | `info` |

`AmpelBar._bar_width` (`pdf/v2/flowables.py:51`) und `_bar_color` (Z. 62) mappen diese Levels auf Balkenbreite + Hex-Farbe.

## MASSNAHMEN_CLUSTER (Z. 124)

Acht Cluster, jeder mit `title`, `matches_policy_prefixes`, `matches_finding_types`, `effect`, `priority_boost`:

| # | Title | Prefixes | Finding-Types | priority_boost |
|---|---|---|---|---|
| 1 | "Datenbank-, RDP- und Dev-Ports per Firewall sperren" | SP-DB, SP-RDP | database_port_exposed, rdp_exposed | 30 |
| 2 | "E-Mail-Authentifizierung vervollstaendigen (SPF + DKIM + DMARC reject)" | SP-DNS | mail_security_missing*, mail_security_dmarc_none | 15 |
| 3 | "EOL-Software auf supportete Version migrieren" | SP-EOL | software_eol | 25 |
| 4 | "CMS / Plugin / Theme aktualisieren" | SP-WP | wordpress_plugin_vulnerability, wordpress_user_enumeration, outdated_software | 12 |
| 5 | "Klartext-Protokolle abschalten (FTP, HTTP-Login, SMTP ohne STARTTLS)" | SP-TLS | ftp_cleartext, cleartext_login, tls_weak_cipher, tls_obsolete_version | 10 |
| 6 | "Sicherheitsheader haerten (HSTS, CSP, Cookies)" | SP-HDR, SP-CSP, SP-COOK, SP-CSRF | — | 5 |
| 7 | "Server-Banner, Generator-Tags und Konfig-Lecks unterdruecken" | SP-DISC | info_disclosure_banner, info_disclosure_meta_generator | 3 |
| 8 | "CVEs aus CISA-KEV / hohem EPSS unverzueglich patchen" | SP-CVE | cve_finding | 28 |

### Cluster-Scoring (`_score_cluster`, Z. 215)

```python
score = severity_sum × count + priority_boost
```

mit `_SEVERITY_RANK = {CRITICAL:5, HIGH:4, MEDIUM:3, LOW:2, INFO:1}`.

Bewusste Konsequenz (Doc-Kommentar Z. 121-122): Ein Cluster mit 3× HIGH gewinnt gegen ein Cluster mit 1× CRITICAL, weil der Score multipliziert. Das ist im Sinne des Geschäftsführer-Mehrwerts — die Empfehlung "maximale Reduktion durch eine Aktion".

### Top-3-Auswahl (`build_layer1`, Z. 292-325)

```
1. Score jedes Clusters auf den aktuellen Findings.
2. Sortiere DESC.
3. Iteriere; pro Cluster:
   a. Berechne new_matched = matched ohne bereits verwendete finding_ids.
   b. Wenn new_matched leer (Cluster überlappt komplett mit höher-rankendem) -> skip.
   c. Sonst: Top-Hebel mit rank=len(top_hebel)+1, sortierte finding_ids.
   d. used_findings += finding_ids.
4. Stoppe bei 3 Cluster oder wenn keine Cluster mehr scoren.
```

Wichtig: die `finding_ids`-Liste enthält ALLE matched Findings (nicht nur new_matched) — die Überlappungs-Logik wirkt nur auf die Auswahl, nicht auf die Anzeige.

## hygiene_split (`split_findings_by_scale`, Z. 231)

Trennt Findings nach `scale ∈ {"cvss", "hygiene"}` (gesetzt von `cvss_consistency.apply_consistency` während der Determinismus-Pipeline). Fallback ohne Feld: `cvss`.

Konsument:
- `pdf/v2/layers/appendix.py:_build_appendix_a` rendert die zwei Listen in A.1 (CVSS-Tabelle) und A.2 (Hygiene-Skala).

## overall_level

Identische Logik wie pro Kategorie, nur über ALLE Findings: max_severity gewinnt.

## Frontpage-Render (pdf/v2/layers/frontpage.py)

Ungefähre Render-Reihenfolge (Z. 34-163):

1. H1 "Auf einen Blick".
2. `risk_ampel`-Loop: pro Kategorie 1× `AmpelBar(level, count, label)`.
3. Gesamt-Bewertung-Paragraph (`overall_level`).
4. `top_hebel`-Loop: 1-3× `HebelBox(rank, title, effect, finding_ids)`.
5. Kontext-Block: Branche, Datenarten, Compliance-Fokus (aus `business_context`).
6. Compliance-Indikatoren: bis zu 3 Pillen aus `compliance_indicators` mit Farb-Mapping `_STATUS_COLOR_HEX` (`#16A34A` Konform, `#CA8A04` Teilerfuellt, `#DC2626` Handlungsbedarf).

## Render-Korrespondenz

| Layer1-Feld | Flowable | flowables.py:Zeile |
|---|---|---|
| `risk_ampel[*]` | `AmpelBar` | 16 |
| `top_hebel[*]` | `HebelBox` | 74 |
| `overall_level` | `Paragraph` (Style aus styles.py) | — |
| `compliance_indicators[*]` (aus v2_data) | `Paragraph` mit Farb-Span | — |
