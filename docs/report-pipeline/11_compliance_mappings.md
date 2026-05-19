# 11 — Compliance-Mappings

Per-Finding-Zuordnung auf vier Frameworks für Layer-3-Inline-Tabelle und Anhang D.

## Aggregator: compliance_mappings.py

`build_compliance_mappings(findings)` (Z. 35) ruft pro Finding die vier Mapper auf und baut:

```python
{
  "VS-2026-001": {
    "nis2":        "§30 Abs. 2 Nr. 5 BSIG",
    "nis2_key":    "nr5",
    "nis2_title":  (nicht im Output -- nur intern via get_bsig_ref)
    "bsi":         "NET.3.2",
    "bsi_title":   "Firewall",
    "iso27001":    "A.8.20",
    "iso27001_title": "Netzwerksicherheit",
    "dsgvo":       "Art. 32 Abs. 1 lit. b",
    "dsgvo_title": "Vertraulichkeit, Integritaet, ..."
  },
  ...
}
```

Aufruf in `report_mapper._augment_for_v2:1918` über die rohen Claude-Findings (vor `_safe`-Escape).

Positive Findings (`is_positive_finding=True`) werden ausgelassen (Z. 56).

Findings ohne `external_id`/`id` werden ausgelassen (Z. 58).

Jeder der vier Mapper läuft in seinem eigenen `try/except` — bei Crash bleibt das Feld auf `""`, der Eintrag wird trotzdem geschrieben.

## NIS2 / §30 BSIG (compliance/nis2_bsig.py)

### BSIG_REQUIREMENTS-Tabelle (Z. 12)

10 Anforderungen (nr1–nr10):

| Key | Ref | Title |
|---|---|---|
| nr1 | §30 Abs. 2 Nr. 1 BSIG | Risikoanalyse und Sicherheitskonzepte |
| nr2 | §30 Abs. 2 Nr. 2 BSIG | Bewältigung von Sicherheitsvorfällen |
| nr3 | §30 Abs. 2 Nr. 3 BSIG | Aufrechterhaltung und Wiederherstellung |
| nr4 | §30 Abs. 2 Nr. 4 BSIG | Sicherheit der Lieferkette |
| nr5 | §30 Abs. 2 Nr. 5 BSIG | Schwachstellenmanagement |
| nr6 | §30 Abs. 2 Nr. 6 BSIG | Bewertung der Wirksamkeit |
| nr7 | §30 Abs. 2 Nr. 7 BSIG | Cyberhygiene und Schulungen |
| nr8 | §30 Abs. 2 Nr. 8 BSIG | Kryptografie und Verschlüsselung |
| nr9 | §30 Abs. 2 Nr. 9 BSIG | Personalsicherheit und Zugriffskontrolle |
| nr10 | §30 Abs. 2 Nr. 10 BSIG | Multi-Faktor-Authentifizierung |

### Keyword-Mapping (Z. 66)

Erste-Treffer-gewinnt-Liste mit 6 Buckets:

| Trigger-Keywords | Mapping |
|---|---|
| ssl, tls, cipher, encryption, hsts, certificate, zertifikat, kryptogra, verschlüsselung, dnssec | nr8 (Kryptografie) |
| port, firewall, header, security-header, information disclosure, robots.txt, banner, cve-, schwachstell, vulnerability, patch, exponiert, exposed | nr5 (Schwachstellenmanagement) |
| mfa, multi-faktor, authentifizierung, authentication, 2fa | nr10 (MFA) |
| access, zugriff, permission, privilege, authorization | nr9 (Zugriffskontrolle) |
| supply chain, lieferkette, third-party, drittanbieter | nr4 (Lieferkette) |
| risiko, risk, general, allgemein | nr1 (Risikoanalyse) |

Default (kein Treffer, Z. 100): `nr5` (Schwachstellenmanagement).

`get_bsig_ref(key)` (Z. 103) gibt das `ref`-Feld aus `BSIG_REQUIREMENTS` zurück.

### Compliance-Summary (build_compliance_summary, Z. 109)

Eigenständige Funktion (nicht im normalen Mapping-Flow), die einen pre-fertigen `{nr1_risikoanalyse: COVERED|PARTIAL|NOT_IN_SCOPE, ...}`-Block liefert für die Compliance-Spezial-Sektion im NIS2-Mapper (`report_mapper.map_nis2_report`).

## BSI IT-Grundschutz (compliance/bsi_grundschutz.py)

### BSI_BAUSTEINE-Tabelle (Z. 12)

10 Bausteine:

| Ref | Title | Layer |
|---|---|---|
| APP.3.1 | Webanwendungen und Webservices | APP |
| APP.3.2 | Webserver | APP |
| NET.1.1 | Netzarchitektur und -design | NET |
| NET.3.2 | Firewall | NET |
| OPS.1.1.4 | Schutz vor Schadprogrammen | OPS |
| OPS.1.1.5 | Protokollierung | OPS |
| CON.1 | Kryptokonzept | CON |
| CON.3 | Datensicherungskonzept | CON |
| SYS.1.1 | Allgemeiner Server | SYS |
| SYS.1.6 | Containerisierung | SYS |

### Keyword-Mapping (Z. 25)

8 Buckets:

| Keywords | Baustein |
|---|---|
| ssl, tls, cipher, encryption, certificate, kryptogra | CON.1 |
| web, http, html, webapp, cms, wordpress | APP.3.1 |
| server, nginx, apache, iis | APP.3.2 |
| firewall, port, netzwerk, network | NET.3.2 |
| backup, sicherung, restore | CON.3 |
| container, docker, kubernetes | SYS.1.6 |
| malware, virus, ransomware | OPS.1.1.4 |
| log, protokoll, audit | OPS.1.1.5 |

Default (kein Treffer, Z. 45): `SYS.1.1` (Allgemeiner Server).

`get_baustein_title(ref)` (Z. 48) gibt den Title aus `BSI_BAUSTEINE` zurück, ansonsten `ref` selbst.

## ISO 27001:2022 Annex A (compliance/iso27001.py)

### ISO27001_CONTROLS-Tabelle (Z. 12)

12 Controls:

| Ref | Title | Category |
|---|---|---|
| A.5.1 | Informationssicherheitspolitik | Organisatorisch |
| A.5.7 | Bedrohungsintelligenz | Organisatorisch |
| A.5.23 | Informationssicherheit bei Cloud-Diensten | Organisatorisch |
| A.8.1 | Verwaltung von Vermögenswerten | Technologisch |
| A.8.5 | Sichere Authentifizierung | Technologisch |
| A.8.8 | Management technischer Schwachstellen | Technologisch |
| A.8.9 | Konfigurationsmanagement | Technologisch |
| A.8.20 | Netzwerksicherheit | Technologisch |
| A.8.21 | Sicherheit von Netzwerkdiensten | Technologisch |
| A.8.24 | Einsatz von Kryptografie | Technologisch |
| A.8.25 | Sichere Entwicklung | Technologisch |
| A.8.28 | Sichere Programmierung | Technologisch |

### Keyword-Mapping (Z. 28)

9 Buckets:

| Keywords | Control |
|---|---|
| ssl, tls, cipher, encryption, hsts, certificate, kryptogra | A.8.24 |
| port, firewall, netzwerk, network, exponiert, exposed | A.8.20 |
| cve-, schwachstell, vulnerability, patch, update | A.8.8 |
| header, security-header, konfiguration, default, misconfigur | A.8.9 |
| authentication, login, passwort, password, mfa, credential | A.8.5 |
| xss, injection, sqli, rce, code execution | A.8.28 |
| cloud, aws, azure, s3, bucket | A.5.23 |
| cisa, exploit, threat, bedrohung | A.5.7 |
| asset, inventar, inventory | A.8.1 |

Default (kein Treffer, Z. 53): `A.8.8` (Schwachstellenmanagement).

`get_control_title(ref)` (Z. 56) gibt den Title aus `ISO27001_CONTROLS` zurück.

### build_iso27001_summary (Z. 62)

Zusätzliche Aggregator-Funktion, die ein Summary-Dict mit `controls_covered`, `controls_partial` (top 5 nicht abgedeckt), `total_controls_assessed`, `scope_note` liefert — wird vom `map_supplychain_report`-Renderer in `report_mapper.py` für eine eigene Spezial-Sektion genutzt.

## DSGVO (compliance/dsgvo.py)

### DSGVO_ARTICLES-Tabelle (Z. 18)

7 Artikel:

| Ref | Title |
|---|---|
| Art. 32 Abs. 1 lit. a | Pseudonymisierung und Verschluesselung personenbezogener Daten |
| Art. 32 Abs. 1 lit. b | Vertraulichkeit, Integritaet, Verfuegbarkeit und Belastbarkeit der Verarbeitungssysteme |
| Art. 32 Abs. 1 lit. c | Wiederherstellung der Verfuegbarkeit personenbezogener Daten nach Zwischenfall |
| Art. 32 Abs. 1 lit. d | Verfahren zur regelmaessigen Ueberpruefung, Bewertung und Evaluierung der Wirksamkeit |
| Art. 5 Abs. 1 lit. f | Integritaet und Vertraulichkeit (Grundsatz) |
| Art. 25 | Datenschutz durch Technikgestaltung und durch Voreinstellungen |
| Art. 33 | Meldung von Verletzungen des Schutzes personenbezogener Daten |

### Keyword-Mapping (Z. 56) — Reihenfolge wichtig

Sieben Buckets, spezifischere Pattern oben:

| # | Keywords | Mapping |
|---|---|---|
| 1 | hsts, strict-transport-security, csp, content-security-policy, x-content-type-options, x-frame-options, referrer-policy, permissions-policy, cookie, samesite, httponly, secure flag, secure-flag, subresource-integrity, sri | Art. 25 |
| 2 | tls, ssl, cipher, encryption, verschluess, kryptogra, certificate, zertifikat, tr-03116, rc4, starttls | Art. 32 Abs. 1 lit. a |
| 3 | urlhaus, kompromittiert, compromised, abuse, leak | Art. 33 |
| 4 | backup, sicherung, restore, wiederherstell | Art. 32 Abs. 1 lit. c |
| 5 | patch, update, eol, end-of-life, outdated, veraltet, cve-, schwachstell, vulnerability | Art. 32 Abs. 1 lit. d |
| 6 | spf, dkim, dmarc, spoofing, mta-sts, bimi, dnssec | Art. 5 Abs. 1 lit. f |
| 7 | klartext, cleartext, ftp, telnet, klar, http statt https, http-login | Art. 32 Abs. 1 lit. b |

Default (kein Treffer, `_DEFAULT` Z. 105): `Art. 32 Abs. 1 lit. b` (allgemeine TOM-Klausel).

Bucket 1 (HSTS/CSP/Cookies → Art. 25) ist bewusst vor Bucket 2 (TLS → Art. 32 lit. a) sortiert (Kommentar Z. 58-60): HSTS ist transport-bezogen, gehört aber laut Code-Doku zur "Datenschutz-by-Default"-Domain (Art. 25).

`map_finding_to_dsgvo` (Z. 108) baut den Match-Text aus 5 Feldern: `title + description + recommendation + policy_id + finding_type`. Damit greift das Keyword-Mapping auch direkt auf die Policy-ID, z.B. `SP-DNS-008` enthält "dns" → Bucket 6.

## Verwendung im Renderer

| Konsument | Aufruf | Zeile |
|---|---|---|
| Layer 3 inline | `findings.py:_render_compliance_inline` | 244 |
| Anhang D Tabelle | `appendix.py:_build_appendix_d` | 414 |

Beide lesen `report_data["compliance_mappings"][finding_id]`.

## Weitere Compliance-Module (nicht in den 4 Standard-Frameworks)

| Datei | Verwendung |
|---|---|
| `compliance/nist_csf.py` (48 Zeilen) | NIST Cybersecurity Framework (5 Functions: ID/PR/DE/RS/RC) — nur in einzelnen Spezial-Pfaden des Mappers |
| `compliance/insurance.py` (215 Zeilen) | Versicherungs-Underwriting-Matrix für `map_insurance_report` |

Beide werden vom `compliance_mappings.build_compliance_mappings` NICHT eingebunden — sie hängen direkt am paket-spezifischen Mapper im `report_mapper.py`.
