# VectiScan — Architektur-Referenz (Auszug)

> Dieses Dokument enthält die für den Prototyp relevanten Abschnitte aus der
> vollständigen Architekturplanung (VectiScan_IT-Architekturplanung.md).
> NIS2-Mapping, Zahlungsflow und E-Mail-Versand sind im Prototyp nicht relevant
> und wurden hier weggelassen.

## Anpassungen für den Prototyp

- Queue `mail:pending` entfällt (kein E-Mail-Versand)
- Nur zwei Queues: `scan:pending` und `report:pending`
- Im Claude-API-Prompt: NIS2-Abschnitte entfernt (`nis2_ref`, `nis2_compliance_summary`)
- Subdomain: `scan-api.vectigal.tech` statt `api.vectigal.tech` (Kollision mit Gutachten-KI)
- Payload-Felder `orderId` → `scanId`, `package` und `verifiedAt` entfallen
- Schritt 7 der Report-Pipeline (Mail-Job) entfällt
- **PDF-Generierung über den pentest-report-generator Skill** (statt eigenes ReportLab-Layout)

---

## Queue-System (Redis + BullMQ)

> Basiert auf Architekturplanung Abschnitt 7.4 — angepasst für den Prototyp.

**Zwei Queues:**

| Queue | Produzent | Konsument | Payload |
|---|---|---|---|
| `scan:pending` | Backend-API | Scan-Worker | `{ scanId, targetDomain }` |
| `report:pending` | Scan-Worker | Report-Worker | `{ scanId, rawDataPath, hostInventory, techProfiles[] }` |

**BullMQ-Konfiguration:**
- Retry: 3 Versuche mit exponential Backoff (1 Min., 5 Min., 15 Min.)
- Timeout: `scan:pending` = 120 Minuten (Phase 0 + bis zu 10 Hosts), `report:pending` = 10 Minuten
- Concurrency: Scan-Worker = 1 (pro Container), Report-Worker = 3
- Dead-Letter-Queue für fehlgeschlagene Jobs

---

## Object Storage (MinIO)

> Basiert auf Architekturplanung Abschnitt 7.7.

**Buckets:**

| Bucket | Inhalt | Retention |
|---|---|---|
| `scan-rawdata` | Rohdaten der Scans (tar.gz) | 90 Tage |
| `scan-reports` | Fertige PDF-Berichte | 365 Tage |
| `scan-logs` | Scan-Execution-Logs | 30 Tage |

**Zugriff:**
- Backend-API: Erzeugt Pre-Signed URLs für Downloads (30 Tage gültig)
- Scan-Worker: Schreibt Rohdaten nach Scan-Abschluss
- Report-Worker: Liest Rohdaten, schreibt PDF

---

## Scan-Orchestrierung (Drei-Phasen-Modell)

> Basiert auf Architekturplanung Abschnitt 10.2.

```
┌─────────────────────────────────────────────────────────┐
│  PHASE 0: DNS-Reconnaissance (2–10 Min.)                 │
│                                                         │
│  ┌──────────────┐                                       │
│  │ CT-Logs      │  → Alle jemals ausgestellten Zerts    │
│  │ (crt.sh API) │    für *.domain.de abfragen           │
│  └──────┬───────┘                                       │
│  ┌──────▼───────┐                                       │
│  │ Passiv-Enum  │  → Subdomain-Suche aus öffentlichen   │
│  │ (subfinder)  │    Quellen (Shodan, VirusTotal, etc.) │
│  └──────┬───────┘                                       │
│  ┌──────▼───────┐                                       │
│  │ DNS-Brute    │  → Top-5000-Subdomains testen         │
│  │ (amass/      │    (mail, dev, staging, vpn, ...)     │
│  │  gobuster)   │                                       │
│  └──────┬───────┘                                       │
│  ┌──────▼───────┐                                       │
│  │ Zone-Transfer│  → AXFR-Versuch (oft fehlkonfiguriert)│
│  │ (dig AXFR)   │                                       │
│  └──────┬───────┘                                       │
│  ┌──────▼───────┐                                       │
│  │ Validierung  │  → Alle FQDNs auflösen (dnsx)         │
│  │ + Gruppierung│    Gruppierung nach IP-Adresse         │
│  │ (dnsx)       │    Duplikate entfernen                 │
│  └──────┬───────┘                                       │
│         │                                               │
│         ▼                                               │
│  ┌─────────────────────────────────────────┐            │
│  │ HOST-INVENTAR (JSON)                    │            │
│  │                                         │            │
│  │ { "domain": "beispiel.de",              │            │
│  │   "hosts": [                            │            │
│  │     { "ip": "88.99.35.112",             │            │
│  │       "fqdns": ["beispiel.de",          │            │
│  │                  "www.beispiel.de"],     │            │
│  │       "rdns": "srv1.hoster.de" },       │            │
│  │     { "ip": "88.99.35.113",             │            │
│  │       "fqdns": ["mail.beispiel.de"],    │            │
│  │       "rdns": "mx1.hoster.de" },        │            │
│  │     { "ip": "88.99.35.114",             │            │
│  │       "fqdns": ["dev.beispiel.de"],     │            │
│  │       "rdns": "srv2.hoster.de" }        │            │
│  │   ],                                    │            │
│  │   "dns_findings": {                     │            │
│  │     "zone_transfer": false,             │            │
│  │     "spf": "v=spf1 ... -all",           │            │
│  │     "dmarc": "v=DMARC1; p=reject",     │            │
│  │     "dkim": true,                       │            │
│  │     "mx": ["mx1.hoster.de"],            │            │
│  │     "dangling_cnames": []               │            │
│  │   }                                     │            │
│  │ }                                       │            │
│  └──────────────────────┬──────────────────┘            │
│                         │                               │
└─────────────────────────┼───────────────────────────────┘
                          │
              ┌───────────┼───────────┐
              ▼           ▼           ▼
       Host 1 (IP A) Host 2 (IP B) Host 3 (IP C)
       ┌──────────┐  ┌──────────┐  ┌──────────┐
       │ Phase 1  │  │ Phase 1  │  │ Phase 1  │
       │ Phase 2  │  │ Phase 2  │  │ Phase 2  │
       └──────────┘  └──────────┘  └──────────┘
              │           │           │
              └───────────┼───────────┘
                          ▼
                  Konsolidierter Report

 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─

┌─────────────────────────────────────────────────────────┐
│  PHASE 1: Technologie-Erkennung (2–5 Min. pro Host)     │
│                                                         │
│  ┌─────────────┐                                        │
│  │ Port-Scan   │  → Offene Ports, Services, Versionen   │
│  │ (nmap -sV)  │                                        │
│  └──────┬──────┘                                        │
│  ┌──────▼──────┐                                        │
│  │ Tech-ID     │  → CMS, Framework, Server, WAF         │
│  │ (webtech +  │                                        │
│  │  wafw00f)   │                                        │
│  └──────┬──────┘                                        │
│         │                                               │
│         ▼                                               │
│  ┌─────────────────────────────────────────┐            │
│  │ TECHNOLOGIE-PROFIL (JSON) pro Host      │            │
│  │                                         │            │
│  │ { "ip": "88.99.35.112",                 │            │
│  │   "fqdns": ["beispiel.de", "www..."],   │            │
│  │   "cms": "wordpress",                   │            │
│  │   "cms_version": "6.9.1",              │            │
│  │   "server": "apache/2.4.66",           │            │
│  │   "waf": null,                          │            │
│  │   "open_ports": [21,22,80,443,3306],   │            │
│  │   "mail_services": true,                │            │
│  │   "ftp_service": true,                  │            │
│  │   "has_ssl": true }                     │            │
│  └──────────────────────┬──────────────────┘            │
│                         │                               │
└─────────────────────────┼───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│  PHASE 2: Tiefer Scan (15–60 Min. pro Host)              │
│  Tool-Auswahl basierend auf Technologie-Profil           │
│                                                         │
│  IMMER:                                                  │
│  ├── testssl.sh      → SSL/TLS-Analyse                   │
│  ├── nikto           → Web-Vulnerability-Scan             │
│  ├── nuclei (basic)  → CVE-Templates, Fehlkonfig.        │
│  ├── HTTP-Header     → Security-Header-Analyse            │
│  └── gowitness       → Screenshot                         │
│                                                         │
│  WENN cms=wordpress: (Post-MVP, nicht im Prototyp)       │
│  └── wpscan          → Plugins, Themes, User-Enum.       │
│                                                         │
│  WENN cms=joomla: (Post-MVP, nicht im Prototyp)          │
│  └── joomscan        → Joomla-Schwachstellen             │
│                                                         │
│  WENN cms=drupal: (Post-MVP, nicht im Prototyp)          │
│  └── droopescan      → Drupal-Schwachstellen             │
│                                                         │
│  WENN mail_services=true:                                │
│  └── Mail-Check      → SPF/DKIM/DMARC, Open-Relay       │
│                                                         │
│  WENN ftp_service=true:                                  │
│  └── FTP-Check       → Anon-Login, TLS-Pflicht           │
│                                                         │
│  WENN open_ports enthält DB-Ports:                        │
│  └── DB-Check        → Auth-Test (keine Brute-Force!)    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Prototyp-Einschränkung:** Die entdeckten Hosts werden **sequenziell** gescannt (ein Host nach dem anderen). Das erhöht die Gesamtlaufzeit, vermeidet aber die Komplexität paralleler Container-Orchestrierung. Bei 3 gefundenen Hosts und ~20 Min. pro Host ergeben sich ~70 Min. Gesamtlaufzeit (10 Min. Phase 0 + 3 × 20 Min.), was innerhalb des 120-Minuten-Timeouts liegt.

---

## DNS-Reconnaissance: Typische Findings

> Basiert auf Architekturplanung Abschnitt 10.3.

Phase 0 generiert eigenständige Findings, die im Report als **DNS-Security-Abschnitt** erscheinen:

| Finding | Schweregrad | Beschreibung |
|---|---|---|
| Zone-Transfer möglich (AXFR) | HOCH (7.5) | DNS-Server gibt die gesamte Zone an Dritte preis |
| Dangling CNAME | HOCH (8.2) | Subdomain zeigt auf nicht mehr existierenden Dienst → Subdomain-Takeover möglich |
| Vergessene Subdomains (dev, staging) | MITTEL (5.0–6.5) | Öffentlich erreichbare Entwicklungsumgebungen, oft schlechter gesichert |
| Fehlender SPF-Record | NIEDRIG (3.5) | E-Mail-Spoofing unter der Domain möglich |
| Fehlender DMARC-Record | NIEDRIG (3.5) | Kein Schutz gegen E-Mail-Impersonation |
| Fehlender DKIM | NIEDRIG (3.0) | Keine kryptografische E-Mail-Signatur |
| Wildcard-DNS-Record | INFO | *.domain zeigt auf IP → potenziell unbeabsichtigte Subdomains erreichbar |
| Viele Subdomains entdeckt (>20) | INFO | Große Angriffsoberfläche — Inventar empfohlen |

---

## Tool-Konfiguration und Timeouts

> Basiert auf Architekturplanung Abschnitt 10.4.

### Phase 0 — DNS-Reconnaissance

| Tool | Timeout | Argumente |
|---|---|---|
| `crt.sh` | 30 Sek. | API-Abfrage: `https://crt.sh/?q=%.domain.de&output=json` |
| `subfinder` | 2 Min. | `-d domain.de -silent -json` |
| `amass` | 5 Min. | `enum -passive -d domain.de -json` (nur passiv) |
| `gobuster` | 3 Min. | `dns -d domain.de -w subdomains-top5000.txt -q` |
| `dig` (AXFR) | 30 Sek. | `dig @ns1.domain.de domain.de AXFR` |
| `dnsx` | 1 Min. | `-a -aaaa -cname -resp -json` (Validierung aller FQDNs) |

**Phase 0 Gesamt-Timeout:** 10 Minuten. **Max. Hosts für Phase 1+2:** 10 (Schutz vor Domains mit hunderten Subdomains).

### Phase 1+2 — pro Host

| Tool | Timeout | Argumente |
|---|---|---|
| `nmap` | 5 Min. | `-sV -sC -T4 --top-ports 1000 -oX` |
| `webtech` | 60 Sek. | `-u https://{fqdn} --json` |
| `wafw00f` | 30 Sek. | `-o json` |
| `testssl.sh` | 5 Min. | `--json --quiet` |
| `nikto` | 10 Min. | `-Format json -Tuning 1234567890` |
| `nuclei` | 15 Min. | `-severity low,medium,high,critical -json` |
| `gobuster` | 10 Min. | `dir -w /usr/share/wordlists/common.txt -q` |
| `gowitness` | 30 Sek. | `single --screenshot-path` |

**Gesamt-Timeout pro Scan-Auftrag:** 120 Minuten (Phase 0 + bis zu 10 Hosts × Phase 1+2). Danach wird abgebrochen und ein Partial-Report aus den bis dahin gesammelten Daten erstellt. Bei Partial-Reports wird im PDF klar gekennzeichnet, welche Hosts vollständig und welche nur teilweise gescannt wurden.

---

## Output-Format

> Basiert auf Architekturplanung Abschnitt 10.5.

Jedes Tool schreibt seine Ausgabe in ein Verzeichnis, gruppiert nach Phase und Host:

```
/tmp/scan-<scanId>/
├── meta.json                        ← Domain, Timestamps, Host-Inventar
├── phase0/
│   ├── crtsh.json                   ← Certificate Transparency Ergebnisse
│   ├── subfinder.json               ← Passive Subdomain-Enumeration
│   ├── amass.json                   ← OWASP Amass Ergebnisse
│   ├── gobuster_dns.txt             ← DNS-Bruteforce Ergebnisse
│   ├── zone_transfer.txt            ← AXFR-Versuch (Ergebnis oder Fehlermeldung)
│   ├── dnsx_validation.json         ← Validierte FQDNs mit aufgelösten IPs
│   ├── dns_records.json             ← MX, SPF, DMARC, DKIM, NS-Records
│   └── host_inventory.json          ← Finale Host-Liste (gruppiert nach IP)
│
├── hosts/
│   ├── 88.99.35.112/                ← Host 1 (beispiel.de, www.beispiel.de)
│   │   ├── phase1/
│   │   │   ├── nmap.xml
│   │   │   ├── nmap.txt
│   │   │   ├── webtech.json
│   │   │   ├── wafw00f.json
│   │   │   └── tech_profile.json    ← Technologie-Profil dieses Hosts
│   │   └── phase2/
│   │       ├── testssl.json
│   │       ├── nikto.json
│   │       ├── nuclei.json
│   │       ├── gobuster_dir.txt
│   │       ├── headers.json
│   │       └── screenshot.png
│   │
│   ├── 88.99.35.113/                ← Host 2 (mail.beispiel.de)
│   │   ├── phase1/
│   │   │   └── ...
│   │   └── phase2/
│   │       └── ...
│   │
│   └── 88.99.35.114/                ← Host 3 (dev.beispiel.de)
│       ├── phase1/
│       │   └── ...
│       └── phase2/
│           └── ...
│
└── scan.log                         ← Execution-Log (alle Phasen)
```

Dieses Verzeichnis wird als `.tar.gz` gepackt und nach MinIO hochgeladen (`scan-rawdata/<scanId>.tar.gz`), dann wird ein Job in die `report:pending`-Queue geschrieben. Der Report-Worker konsolidiert alle Host-Ergebnisse in einen einzigen PDF-Bericht, gruppiert nach Host mit einer übergreifenden Zusammenfassung.

---

## Sicherheit des Scan-Workers

> Basiert auf Architekturplanung Abschnitt 10.6.

- Container läuft als Non-Root-User (`scanner`)
- Persistent-Worker, der nach jedem Job das /tmp-Verzeichnis aufräumt
- Minimales Base-Image (Debian-Slim) reduziert Angriffsoberfläche gegenüber Kali um ~90%
- Kein Volume-Mount auf Host-Dateisystem
- Resource-Limits (CPU, RAM) verhindern Ressourcenerschöpfung
- Tools werden nur mit den minimal notwendigen Parametern aufgerufen
- **Keine aktive Exploitation** — nur Scanning und Enumeration
- Alle Tool-Aufrufe werden geloggt (für Audit und Abuse-Nachverfolgung)

---

## Report-Pipeline

### Ablauf

> Basiert auf Architekturplanung Abschnitt 11.1 — angepasst für den Prototyp
> (ohne Mail-Versand, PDF-Generierung über pentest-report-generator Skill).

```
report:pending Queue
        │
        ▼
┌───────────────────────────────────────┐
│  1. Rohdaten aus MinIO laden          │
│     scan-rawdata/<scanId>.tar.gz      │
│     → Entpacken in /tmp/             │
│                                       │
│  2. Rohdaten vorverarbeiten           │
│     → Jede Tool-Ausgabe parsen        │
│     → Strukturierte Findings          │
│       extrahieren (JSON)              │
│     → Duplikate konsolidieren         │
│                                       │
│  3. Claude API aufrufen               │
│     Input: Strukturierte Findings     │
│            + Technologie-Profil       │
│            + CVSS-Scoring-Regeln      │
│     Output: Report-Datenstruktur      │
│             (Findings mit Bewertung,  │
│              Impact, Empfehlungen)    │
│                                       │
│  4. Claude-Output → report_data       │
│     Mapping auf die Datenstruktur     │
│     des pentest-report-generator      │
│     Skills (siehe unten)              │
│                                       │
│  5. PDF generieren                    │
│     generate_report(report_data, path)│
│     → Professionelles PTES-Layout     │
│                                       │
│  6. PDF nach MinIO hochladen          │
│     scan-reports/<scanId>.pdf         │
│                                       │
│  7. Datenbank aktualisieren           │
│     Scan-Status → report_complete     │
│     Report-Record anlegen             │
└───────────────────────────────────────┘
```

### PDF-Generierung: pentest-report-generator Skill

> Statt ein eigenes ReportLab-Layout zu bauen, nutzen wir den bestehenden
> pentest-report-generator Skill. Dieser liefert ein professionelles,
> PTES-konformes PDF-Layout mit Cover, TOC, Severity-Bars, Finding-Templates
> und Appendices. Später kann das Branding angepasst werden (Farben, Logo, Firmendaten).

**Dateien im Report-Worker:**

```
report-worker/
├── reporter/
│   ├── worker.py                    ← BullMQ Consumer, Orchestrierung
│   ├── parser.py                    ← Tool-Output-Parser (JSON/XML → Findings)
│   ├── claude_client.py             ← Claude API Aufruf + JSON-Parsing
│   ├── report_mapper.py             ← Claude-Output → report_data Dict
│   └── generate_report.py           ← Kopie aus dem Skill (PDF-Engine)
├── references/
│   └── report_structure.md          ← Kopie aus dem Skill (Layout-Referenz)
├── Dockerfile
└── requirements.txt                 ← reportlab, anthropic, minio, redis, etc.
```

**Integration: Claude-Output → report_data Mapping**

Der Claude-API-Aufruf liefert JSON mit `findings[]`, `positive_findings[]` und `recommendations[]`. Der `report_mapper.py` transformiert das in die `report_data`-Datenstruktur, die `generate_report()` erwartet:

```python
def map_claude_to_report_data(claude_output, scan_meta, host_inventory):
    """
    Mappt den Claude-API-Output auf die report_data-Struktur
    des pentest-report-generator Skills.
    """
    domain = scan_meta["domain"]
    scan_date = scan_meta["date"]
    hosts_count = len(host_inventory.get("hosts", []))

    # Findings zählen nach Severity
    severity_counts = count_by_severity(claude_output["findings"])

    # Finding-Summary für Cover
    finding_summary = ", ".join(
        f"{count} {sev}" for sev, count in severity_counts.items() if count > 0
    )

    return {
        "meta": {
            "title": f"Security Assessment — {domain}",
            "author": "VectiScan Automated Security Assessment",
            "header_left": "VECTISCAN — SECURITY ASSESSMENT",
            "header_right": f"{domain}",
            "footer_left": f"Vertraulich  |  {scan_date}",
            "classification_label":
                "KLASSIFIZIERUNG: VERTRAULICH — NUR FÜR AUTORISIERTE EMPFÄNGER",
        },
        "cover": {
            "cover_subtitle": "AUTOMATED SECURITY ASSESSMENT",
            "cover_title": f"Sicherheitsbewertung<br/>{domain}",
            "cover_meta": [
                ["Ziel:", f"{domain} ({hosts_count} Hosts)"],
                ["Datum:", scan_date],
                ["Methodik:", "PTES (automatisiert)"],
                ["Scoring:", "CVSS v3.1"],
                ["Klassifizierung:", "Vertraulich"],
                ["Befunde:", finding_summary],
            ],
        },
        "toc": build_toc_entries(claude_output),
        "executive_summary": build_executive_summary(claude_output, domain),
        "scope": build_scope_section(domain, host_inventory, scan_meta),
        "findings_section_label": "3&nbsp;&nbsp;&nbsp;Befunde",
        "findings": [
            map_finding(f) for f in claude_output["findings"]
        ] + [
            map_positive_finding(f) for f in claude_output.get("positive_findings", [])
        ],
        "recommendations": build_recommendations(claude_output),
        "appendices": build_appendices(host_inventory, scan_meta),
        "disclaimer": (
            "<b>Haftungsausschluss:</b> Dieser Bericht gibt den Sicherheitsstatus "
            "zum Zeitpunkt der Prüfung wieder. Sicherheitsbewertungen sind "
            "Momentaufnahmen. Regelmäßige Wiederholungsprüfungen werden empfohlen."
        ),
    }


def map_finding(f):
    """Mappt ein Claude-Finding auf das Skill-Finding-Format."""
    return {
        "id": f["id"],
        "title": f["title"],
        "severity": f["severity"],
        "cvss_score": f["cvss_score"],
        "cvss_vector": f["cvss_vector"],
        "cwe": f["cwe"],
        "affected": f["affected"],
        "description": f["description"],
        "evidence": f["evidence"],
        "impact": f["impact"],
        "recommendation": f["recommendation"],
        # Deutsche Labels
        "label_description": "Beschreibung",
        "label_evidence": "Nachweis",
        "label_impact": "Geschäftsauswirkung",
        "label_recommendation": "Empfehlung",
    }


def map_positive_finding(f):
    """Mappt ein positives Finding (INFO-Severity)."""
    return {
        "id": f.get("id", "VS-2026-POS"),
        "title": f["title"],
        "severity": "INFO",
        "cvss_score": "N/A",
        "cvss_vector": "N/A",
        "cwe": "N/A",
        "affected": f.get("affected", "Gesamte Infrastruktur"),
        "description": f["description"],
        "evidence": f.get("evidence", "—"),
        "impact": "Positiver Befund — korrekte Konfiguration.",
        "recommendation": "Aktuelle Konfiguration beibehalten.",
        "label_description": "Beschreibung",
        "label_evidence": "Nachweis",
        "label_impact": "Bewertung",
        "label_recommendation": "Empfehlung",
    }
```

**Was das Skill-Script liefert (ohne eigenen Aufwand):**
- Professionelles Cover mit dunklem Navy-Design und Klassifizierungsbalken
- Inhaltsverzeichnis mit Finding-Referenzen
- Executive Summary mit Risk-Box (farbcodiert nach Gesamtrisiko)
- Severity-farbige Finding-Header (18mm Bars) mit CVSS-Badge
- Metadata-Zeile pro Finding (CVSS-Vektor, CWE, betroffene Systeme)
- Evidence-Blöcke in Monospace auf grauem Hintergrund
- Recommendations-Tabelle mit Timeframes
- Appendices für CVSS-Tabelle, Tool-Liste, Raw-Output-Auszüge
- Disclaimer-Box am Ende
- Deutsche Lokalisierung ist eingebaut

**Branding-Anpassungen (später):**
Die Farbkonstanten im Script können für VectiScan-Branding angepasst werden.
Aktuell nutzt der Skill ein neutrales Navy-Farbschema, das für den Prototyp passt.
Für das Produkt können Farben, Logo und Firmendaten ergänzt werden — das betrifft
nur die `COLORS`-Dict und die `draw_cover()`-Funktion im Script.

---

### Claude API Prompt-Struktur

> Basiert auf Architekturplanung Abschnitt 11.2 — **NIS2-Abschnitte entfernt** für den Prototyp.
> Die CVSS-Scoring-Regeln sind bewusst identisch mit dem pentest-report-generator Skill,
> damit Claude keine überhöhten Scores liefert.

```python
SYSTEM_PROMPT = """
Du bist ein erfahrener Penetration Tester, der Scan-Rohdaten in professionelle
Befunde umwandelt. Du arbeitest nach dem PTES-Standard.

REGELN FÜR CVSS-SCORING:
- Score was du beweisen kannst, nicht was du dir vorstellst
- Exponierter Port MIT Auth = NICHT dasselbe wie OHNE Auth
- Scope Change (S:C) erfordert Nachweis
- Information Disclosure ist fast nie über LOW (3.0-3.9)
- Immer den vollständigen CVSS-Vektorstring angeben

CVSS-REFERENZWERTE (häufige Findings):
- DB-Port exponiert, Auth funktioniert: HIGH (7.0-8.5)
- DB-Port exponiert, keine Auth: CRITICAL (9.8-10.0)
- Mail-Services auf Prod-Server: MEDIUM (5.0-6.5)
- FTP exponiert mit SSL: MEDIUM (4.0-5.5)
- SSH ohne fail2ban: LOW (3.0-4.0)
- Info Disclosure (robots.txt, Banner): LOW (2.0-3.5)
- Gute Security-Header: INFORMATIONAL (positiver Befund)

REGELN FÜR TONALITÄT:
- Professionell und sachlich, nicht alarmistisch
- Keine Superlative ("katastrophal", "existenziell")
- Positive Befunde immer einschließen
- Empfehlungen müssen konkret und umsetzbar sein
- Dringlichkeit an tatsächlichen Schweregrad koppeln:
  CRITICAL: "Sofortige Behebung (24-48 Stunden)"
  HIGH: "Behebung innerhalb weniger Tage"
  MEDIUM: "Empfohlen innerhalb 2-4 Wochen"
  LOW: "Empfohlen innerhalb 1-3 Monaten"
  INFO: "Für kontinuierliche Verbesserung berücksichtigen"

OUTPUT-FORMAT:
Antworte ausschließlich in JSON nach folgendem Schema:
{
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "overall_description": "2-3 Sätze Gesamtbewertung",
  "findings": [
    {
      "id": "VS-2026-001",
      "title": "Kurzer, präziser Titel",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "cvss_score": "8.6",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
      "cwe": "CWE-284",
      "affected": "88.99.35.112:3306 (beispiel.de)",
      "description": "Was wurde gefunden. Sachlich und präzise.",
      "evidence": "$ nmap -sV 88.99.35.112\\n3306/tcp open mysql MariaDB 10.11.6",
      "impact": "Mögliche Auswirkung bei Ausnutzung. Business-Kontext.",
      "recommendation": "<b>Kurzfristig (Tage):</b> Konkrete Maßnahme.\\n<b>Mittelfristig:</b> Strategische Verbesserung."
    }
  ],
  "positive_findings": [
    {
      "title": "Korrekte TLS-Konfiguration",
      "description": "Alle Hosts nutzen TLS 1.2+, keine veralteten Cipher-Suites."
    }
  ],
  "recommendations": [
    {
      "timeframe": "Sofort|Tag 1-3|Woche 1|Monat 1",
      "action": "Konkrete Maßnahme",
      "finding_refs": ["001"],
      "effort": "2-4 h"
    }
  ]
}
"""

USER_PROMPT = f"""
Analysiere die folgenden Scan-Rohdaten für {domain}.

HOST-INVENTAR:
{json.dumps(host_inventory, indent=2)}

TECHNOLOGIE-PROFILE (pro Host):
{json.dumps(tech_profiles, indent=2)}

SCAN-ERGEBNISSE:
{consolidated_findings}

Erstelle die Befunde auf Deutsch. Finding-ID-Prefix: VS
"""
```

**Hinweise zum Prompt:**
- `domain` = die gescannte Domain (z.B. "beispiel.de")
- `host_inventory` = das JSON aus Phase 0 (host_inventory.json)
- `tech_profiles` = Array der tech_profile.json aller Hosts
- `consolidated_findings` = zusammengefasste Tool-Outputs aller Hosts
- Finding-ID-Prefix `VS` steht für VectiScan
- Das Claude-Output-Format ist so gestaltet, dass es direkt auf die `report_data`-Struktur des Skill-Scripts gemappt werden kann (1:1 Finding-Felder)
- Die CVSS-Referenzwerte im Prompt spiegeln die Tabelle aus dem Skill wider, damit Claude konsistent scored

### Claude-API-Kosten (Schätzung)

| Szenario | Input-Tokens | Output-Tokens |
|---|---|---|
| Einfacher Scan (1–2 Hosts) | ~3.000 | ~2.000 |
| Komplexer Scan (5–10 Hosts) | ~8.000 | ~4.000 |

Die API-Kosten pro Scan sind bei den aktuellen Claude-Sonnet-Tarifen vernachlässigbar gering. Die genauen Kosten hängen vom gewählten Modell und den aktuellen Anthropic-Tarifen ab.