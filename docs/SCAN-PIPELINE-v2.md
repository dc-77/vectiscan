# VectiScan — Evolved Scan Pipeline Architecture v2

> Stand: 17. März 2026
> Ziel: Enterprise-grade Security Assessment Pipeline mit 5 Paketen,
> Passive Intelligence, AI-Orchestrierung und Threat-Intelligence-Korrelation.

---

## 1. Executive Summary

Die VectiScan v2 Pipeline transformiert den bisherigen Drei-Phasen-Scan in eine
sechs-stufige Assessment-Pipeline, die einem professionellen Penetrationstest
in Methodik und Tiefe nahekommt — vollautomatisiert:

```
Phase 0a: Passive Intelligence        ← NEU (kein Kontakt zum Ziel)
Phase 0b: Active Discovery            ← bisherige Phase 0 (erweitert)
Phase 1:  Technology Fingerprinting   ← bisherige Phase 1 (erweitert)
Phase 2:  Deep Scan                   ← bisherige Phase 2 (erweitert)
Phase 3:  Correlation & Enrichment    ← NEU (Cross-Tool-Korrelation, EPSS, ExploitDB)
Report:   AI-Analysis + PDF           ← erweitert um 5 Report-Varianten
```

**Differenzierung gegenüber Status Quo:**

| Aspekt | v1 (aktuell) | v2 (Ziel) |
|--------|--------------|-----------|
| Phasen | 3 (0 → 1 → 2) | 6 (0a → 0b → 1 → 2 → 3 → Report) |
| Passive Intel | Keine | Shodan, AbuseIPDB, SecurityTrails |
| DNS-Security | SPF/DMARC/DKIM | + DNSSEC, CAA, MTA-STS, DANE/TLSA |
| Mail-Security | Minimal (MX-Records) | Vollständige Mail-Posture-Analyse |
| Tool-Count | 21 | 34+ |
| AI-Entscheidungspunkte | 2 | 4 |
| Threat-Intelligence | Keine | NVD, EPSS, ExploitDB, CISA KEV |
| False-Positive-Reduktion | Keine (nur CVSS-Capping) | Cross-Tool-Korrelation + Confidence-Scoring |
| Pakete | 3 (Basic/Pro/NIS2) | 5 (WebCheck/Perimeter/Compliance/SupplyChain/Insurance) |
| Compliance-Mappings | §30 BSIG (nur NIS2) | §30 BSIG, ISO 27001, BSI-Grundschutz, NIST CSF |

**AI-Modellzuweisung:**

| Entscheidungspunkt | Modell | Begründung |
|---|---|---|
| Host Strategy (nach Phase 0) | Haiku 4.5 | Pattern-Matching, begrenzter Entscheidungsraum |
| Phase-2 Config (nach Phase 1) | Haiku 4.5 | Endliche Optionen (Tags, Wordlists, Tool-Auswahl) |
| Phase-3 Korrelation (nach Phase 2) | **Sonnet 4** | Cross-Tool-Reasoning, FP-Erkennung, Confidence-Scoring |
| Report-Generierung | Sonnet 4 | Komplexe Analyse, Prosa-Qualität, Compliance-Mapping |
| Report-QA | **Programmatisch + Haiku 4.5** | Mechanische Checks im Code, Urteilsfragen via Haiku |

---

## 2. Paketstruktur

### 2.1 Übersicht

| Paket | Interner Name | Zielgruppe | Scan-Tiefe | Geschätzte Dauer | Max Hosts |
|-------|---------------|------------|------------|------------------|-----------|
| **WebCheck** | `webcheck` | Kleines Unternehmen, "Check mal unsere Website" | Website + Mail-Security | ~15–20 Min | 3 |
| **PerimeterScan** | `perimeter` | IT-Verantwortliche, MSPs, Systemhäuser | Voller Perimeter, alle Hosts | ~60–90 Min | 15 |
| **ComplianceScan** | `compliance` | NIS2-pflichtige Unternehmen | = Perimeter + Compliance-Mapping | ~65–95 Min | 15 |
| **SupplyChain** | `supplychain` | Lieferanten von NIS2-Unternehmen | = Perimeter + Lieferketten-Nachweis | ~65–95 Min | 15 |
| **InsuranceReport** | `insurance` | Cyberversicherungs-Kunden | = Perimeter + Versicherungsformat | ~65–95 Min | 15 |

### 2.2 Detaillierte Paketdefinitionen

#### WebCheck — "Ist meine Website sicher?"

**Zielgruppe:** Bäckerei, Handwerksbetrieb, Arztpraxis, kleiner Online-Shop.
Menschen die keine IT-Abteilung haben und wissen wollen, ob ihre Webpräsenz
grundlegend abgesichert ist.

**Scan-Schwerpunkte:**
- Website-Sicherheit (SSL, Headers, bekannte Vulnerabilities)
- E-Mail-Sicherheit (SPF, DMARC, DKIM)
- DNS-Basishygiene
- Offene Ports auf dem Webserver
- CMS-Sicherheit (WordPress, Shopware, etc.)
- Screenshot der Website

**Report-Stil:** Einfache Sprache, kein Fachjargon. Ampelsystem (Rot/Gelb/Grün).
Max 5–8 Findings. Handlungsempfehlungen in "Aufgaben für Ihren Webmaster"-Format.
Positiv-Findings werden hervorgehoben ("Das machen Sie bereits richtig").

#### PerimeterScan — "Wie sieht unsere Angriffsfläche aus?"

**Zielgruppe:** KMU mit 50–500 Mitarbeitern, IT-Abteilung vorhanden.
MSPs und Systemhäuser die einen externen Sicherheitscheck für ihre Kunden
beauftragen.

**Scan-Schwerpunkte:**
- Vollständige Attack-Surface-Enumeration
- Passive Intelligence (Shodan, AbuseIPDB)
- Alle Hosts und Subdomains
- Deep Vulnerability Scan (nuclei, nikto, ffuf)
- SSL/TLS-Vollanalyse
- Web-Crawler + Directory-Bruteforce
- Mail-Server-Sicherheit
- DNS-Security-Posture

**Report-Stil:** PTES-konform, vollständige CVSS-Vektoren, Evidence-Blöcke,
technische Details. Geeignet als Nachweis für Audits und Management-Reviews.
Executive Summary + technischer Detailteil.

#### ComplianceScan — "Erfüllen wir NIS2?"

**Zielgruppe:** Unternehmen die unter NIS2/§30 BSIG fallen (Energie, Transport,
Gesundheit, Digitale Infrastruktur, etc.).

**Scan-Schwerpunkte:**
- = PerimeterScan (alle Tools)
- §30 BSIG-Mapping aller Findings (Abs. 2 Nr. 1–10)
- DNSSEC-Validierung (NIS2-relevant)
- CAA-Record-Prüfung
- MTA-STS und DANE/TLSA
- Lieferketten-Analyse (Third-Party-Erkennung)
- BSI-Grundschutz-Referenzen

**Report-Stil:** = PerimeterScan + NIS2-Compliance-Summary, §30 BSIG-Mapping-Tabelle,
Lieferketten-1-Seiter, Maßnahmen mit Priorisierung nach BSIG-Relevanz.
Geeignet als Nachweis für BSI-Prüfungen.

#### SupplyChain — "Nachweis für unseren NIS2-pflichtigen Auftraggeber"

**Zielgruppe:** KMU die Zulieferer oder Dienstleister für NIS2-pflichtige
Unternehmen sind und einen Sicherheitsnachweis liefern müssen.

**Scan-Schwerpunkte:**
- = PerimeterScan (alle Tools)
- ISO 27001 Annex A Mapping
- BSI-Grundschutz-Mapping
- Fokus auf Datenaustausch-Sicherheit (verschlüsselte Kanäle, API-Sicherheit)
- Zertifikatsketten-Validierung

**Report-Stil:** = PerimeterScan + Lieferketten-Compliance-Summary,
ISO 27001-Mapping, "Sicherheitsnachweis für Auftraggeber"-Sektion mit
Bestätigung der geprüften Bereiche. Format das direkt an den Auftraggeber
weitergegeben werden kann.

#### InsuranceReport — "Nachweis für unsere Cyberversicherung"

**Zielgruppe:** Unternehmen mit Cyberversicherung die jährlich oder bei
Vertragsabschluss einen Sicherheitsnachweis vorlegen müssen.

**Scan-Schwerpunkte:**
- = PerimeterScan (alle Tools)
- Fokus auf versicherungsrelevante Risiken (Ransomware-Indikatoren, offene RDP/SMB,
  fehlende MFA-Indikatoren, veraltete Software)
- Patch-Level-Einschätzung
- Backup-Indikator-Prüfung (soweit extern feststellbar)
- Historischer Vergleich (wenn Vorscan vorhanden)

**Report-Stil:** = PerimeterScan + Versicherungs-Summary im Fragebogen-Format
(typische Fragen von Cyberversicherern mit Ja/Nein/Teilweise-Bewertung),
Risk-Score-Trend (wenn historische Daten vorhanden), Empfehlungen priorisiert
nach Versicherungsrisiko.

### 2.3 Tool-Matrix pro Paket

Legende: ● = aktiv | ○ = reduziert/Basic-Config | – = nicht enthalten

| Tool | Phase | WebCheck | Perimeter | Compliance | SupplyChain | Insurance |
|------|-------|----------|-----------|------------|-------------|-----------|
| **Phase 0a: Passive Intelligence** | | | | | | |
| Shodan API | 0a | – | ● | ● | ● | ● |
| AbuseIPDB API | 0a | – | ● | ● | ● | ● |
| SecurityTrails API | 0a | – | ● | ● | ● | ● |
| WHOIS Lookup | 0a | ● | ● | ● | ● | ● |
| **Phase 0b: Active Discovery** | | | | | | |
| crt.sh | 0b | ● | ● | ● | ● | ● |
| subfinder | 0b | ● | ● | ● | ● | ● |
| amass | 0b | – | ● | ● | ● | ● |
| gobuster dns | 0b | – | ● | ● | ● | ● |
| dig (DNS Records) | 0b | ● | ● | ● | ● | ● |
| dig (AXFR) | 0b | – | ● | ● | ● | ● |
| dnsx | 0b | ● | ● | ● | ● | ● |
| httpx (Web-Probe) | 0b | ● | ● | ● | ● | ● |
| DNSSEC-Validierung | 0b | ○ (nur Check) | ● | ● (Detail) | ● | ● |
| CAA-Record-Check | 0b | ○ | ● | ● (Detail) | ● | ● |
| MTA-STS Check | 0b | ○ | ● | ● (Detail) | ● | ● |
| DANE/TLSA Check | 0b | – | ● | ● (Detail) | ● | ● |
| **Phase 1: Tech Fingerprinting** | | | | | | |
| nmap | 1 | ○ (Top 100) | ● (Top 1000) | ● (Top 1000) | ● (Top 1000) | ● (Top 1000) |
| webtech | 1 | ● | ● | ● | ● | ● |
| wafw00f | 1 | ● | ● | ● | ● | ● |
| CMS-Fingerprinting-Engine | 1 | ● | ● | ● | ● | ● |
| **Phase 2: Deep Scan** | | | | | | |
| testssl.sh | 2 | ● | ● | ● | ● | ● |
| nikto | 2 | – | ● | ● | ● | ● |
| nuclei | 2 | ○ (high,crit) | ● (all sev) | ● (all sev) | ● (all sev) | ● (all sev) |
| gobuster dir | 2 | – | ● | ● | ● | ● |
| ffuf | 2 | – | ● | ● | ● | ● |
| feroxbuster | 2 | – | ● | ● | ● | ● |
| dalfox | 2 | – | ● | ● | ● | ● |
| gowitness | 2 | ● | ● | ● | ● | ● |
| header_check | 2 | ● | ● | ● | ● | ● |
| httpx (Phase 2) | 2 | ● | ● | ● | ● | ● |
| katana | 2 | – | ● | ● | ● | ● |
| wpscan | 2 | ● | ● | ● | ● | ● |
| **Phase 3: Correlation & Enrichment** | | | | | | |
| NVD API (CVE-Details) | 3 | ○ | ● | ● | ● | ● |
| EPSS (Exploit Prediction) | 3 | – | ● | ● | ● | ● |
| CISA KEV (Known Exploited) | 3 | ○ | ● | ● | ● | ● |
| ExploitDB Check | 3 | – | ● | ● | ● | ● |
| Cross-Tool-Korrelation | 3 | ○ | ● | ● | ● | ● |
| **Report-Spezifisch** | | | | | | |
| §30 BSIG-Mapping | Rep | – | – | ● | – | – |
| ISO 27001 Annex A Mapping | Rep | – | – | ○ | ● | – |
| BSI-Grundschutz-Refs | Rep | – | – | ● | ● | – |
| NIST CSF Mapping | Rep | – | – | ○ | ○ | ○ |
| Versicherungs-Fragebogen | Rep | – | – | – | – | ● |
| Trend-Vergleich | Rep | – | – | – | – | ● |
| Lieferketten-Summary | Rep | – | – | ● | ● | – |

---

## 3. Phase 0a — Passive Intelligence

### 3.1 Konzept

Phase 0a sammelt Informationen über das Ziel **ohne einen einzigen Paket an die
Zielinfrastruktur zu senden**. Alle Daten kommen aus öffentlichen Datenbanken,
APIs und OSINT-Quellen. Das hat drei Vorteile:

1. **Rechtlich sauber** — kein aktiver Kontakt vor Domain-Verifizierung nötig
   (Phase 0a kann theoretisch sogar vor der Verifizierung laufen)
2. **Kontext für AI** — die Host-Strategy-AI erhält deutlich besseren Input
3. **Findings ohne Scan** — exponierte Services und historische
   Schwachstellen werden erkannt bevor ein aktiver Scan sie bestätigt

### 3.2 Tools

#### Shodan API (Passive Port/Service Intelligence)

**Lizenz:** Proprietary
**Preismodell:** Freelancer $69/Monat (10.000 Credits). Small Business $359/Monat
(inkl. `vuln`-Filter für CVE-Suche). Membership $49 einmalig (nur 100 Credits/Monat,
zu wenig für Produktivbetrieb).
**Empfehlung für VectiScan:** Freelancer ($69/Monat). 10.000 Query Credits reichen
für ~600 Assessments/Monat. Für CVE-Enrichment via `vuln`-Filter wird
Small Business ($359/Monat) benötigt (erst bei Scale-Phase).
**Pakete:** Perimeter, Compliance, SupplyChain, Insurance

```python
# Zwei API-Calls pro Assessment:

# 1. Host-Suche nach Domain
GET https://api.shodan.io/dns/domain/{domain}?key={API_KEY}
# → Subdomains, DNS-Records, IPs

# 2. Host-Details pro IP (aus Phase 0b oder Shodan DNS)
GET https://api.shodan.io/shodan/host/{ip}?key={API_KEY}
# → Offene Ports, Banner, Service-Versionen, OS, Hostnames
```

**Output-Verarbeitung:**
```python
# Für jede IP aus Shodan-Response:
{
    "ip": "88.99.35.112",
    "ports": [80, 443, 22, 25, 21],
    "os": "Linux",
    "tags": ["cloud", "self-signed"],
    "last_update": "2026-03-10T12:00:00Z",
    "hostnames": ["example.com", "www.example.com"],
    "services": [
        {"port": 443, "product": "nginx", "version": "1.24.0", "banner": "..."},
        {"port": 22, "product": "OpenSSH", "version": "8.9p1", "banner": "..."},
        {"port": 21, "product": "ProFTPD", "version": "1.3.5", "banner": "..."}
    ]
}
```

**Persistierung:** `scan_results` mit `tool_name=shodan`, `phase=0`, `host_ip=<ip>`
**Timeout:** 10s pro API-Call, max 30s gesamt
**Kosten:** Freelancer-Plan ($69/Mo) liefert 10.000 Query Credits/Monat.
DNS-Domain-Lookup kostet 1 Credit, Host-Lookups kosten 0–1 Credit je nach Filternutzung.
~16 Calls pro Assessment → reicht für ~600 Assessments/Monat.
**Hinweis:** CVE-Daten via `vuln`-Suchfilter erfordern Small Business ($359/Mo).
Beim Freelancer-Plan nutzen wir stattdessen die Service-Versionen aus den Bannern —
die AI kann daraus nuclei-Tags ableiten (z.B. "nginx 1.18" → bekannte nginx-CVEs testen).

#### AbuseIPDB API (IP-Reputation & Abuse-History)

**Lizenz:** Proprietary
**Preismodell:** Free-Plan verbietet kommerzielle Nutzung. Basic: $25/Monat (10.000 IP-Checks/Tag).
Premium: $99/Monat (50.000/Tag). Enterprise: custom.
**Empfehlung für VectiScan:** Basic-Plan ($25/Monat). 10.000 Checks/Tag reicht für ~600
Assessments/Tag (je ~16 IPs). Ersetzt VirusTotal für den IP-Reputation-Use-Case.
**Pakete:** Perimeter, Compliance, SupplyChain, Insurance

```python
# IP-Reputation-Check pro entdeckte IP
GET https://api.abuseipdb.com/api/v2/check
Headers: Key: {ABUSEIPDB_API_KEY}, Accept: application/json
Params: ipAddress={ip}&maxAgeInDays=90&verbose=true
# → Abuse-Score (0–100), Anzahl Reports, Kategorien, ISP, Usage-Type
```

**Output-Verarbeitung:**
```python
{
    "ip": "88.99.35.112",
    "abuseConfidenceScore": 15,     # 0–100, höher = verdächtiger
    "totalReports": 3,
    "numDistinctUsers": 2,
    "lastReportedAt": "2026-02-28T14:23:01+00:00",
    "isWhitelisted": false,
    "countryCode": "DE",
    "usageType": "Data Center/Web Hosting/Transit",
    "isp": "Hetzner Online GmbH",
    "domain": "hetzner.com",
    "isTor": false
}
```

**Report-Integration:**
- Abuse-Score > 50 → Warnung im Report ("IP wurde als verdächtig gemeldet")
- Abuse-Score > 80 → HIGH-Finding ("IP hat hohe Abuse-Rate, mögliche Kompromittierung")
- Insurance: Abuse-Score ist relevanter Risiko-Indikator
- isTor=true → Informational Finding (Tor-Exit-Node als Webserver ist ungewöhnlich)

**Persistierung:** `scan_results` mit `tool_name=abuseipdb`, `phase=0`
**Timeout:** 10s pro Call
**Rate-Limit:** Basic-Plan: 10.000/Tag, Reset um 00:00 UTC

**Warum AbuseIPDB statt VirusTotal:**
VirusTotal Public API verbietet kommerzielle Nutzung, Premium startet bei $5.000/Jahr.
AbuseIPDB Basic für $25/Monat liefert IP-Reputation, Abuse-Reports und Confidence-Scores —
das deckt den IP-Reputation-Use-Case für Security-Assessments vollständig ab. VirusTotal
bietet zusätzlich Domain-Malware-History und File-Scanning — für VectiScan als reinen
Perimeter-Scanner nicht essentiell. VirusTotal kann als Premium-Feature nachgerüstet werden
wenn der Umsatz die $5.000/Jahr rechtfertigt.

#### SecurityTrails API (Historische DNS-Intelligence)

**Lizenz:** Proprietary (Recorded Future)
**⚠️ Lizenz-Hinweis:** Der Free-Tier (2.500 Queries/Monat) ist laut ToS auf
"internal, non-commercial security purposes" beschränkt. Für den internen
Prototypen akzeptabel. **Vor Produktionsstart muss auf den Prototyper-Plan
($50/Monat, 1.500 Requests/Monat, kommerzielle Nutzung erlaubt) gewechselt werden.**
**Preismodell:** Free: 2.500 Queries/Monat (non-commercial). Prototyper: $50/Monat
(1.500 Req/Mo, kommerziell). Professional: $500/Monat (20.000 Req/Mo).
**Pakete:** Perimeter, Compliance, SupplyChain, Insurance

```python
# Domain-Details + Subdomains
GET https://api.securitytrails.com/v1/domain/{domain}
GET https://api.securitytrails.com/v1/domain/{domain}/subdomains
Headers: apikey: {ST_API_KEY}
# → Aktuelle + historische DNS-Records, Subdomains, IP-History

# DNS-History (IP-Wechsel erkennen → Hinweis auf Migrationen/Übernahmen)
GET https://api.securitytrails.com/v1/history/{domain}/dns/a
```

**Wert für Assessment:**
- Historische IP-Wechsel zeigen Infrastruktur-Migrationen
- Alte DNS-Records können noch auf vergessene Server zeigen
- Subdomain-Entdeckung ergänzt crt.sh und subfinder

**Persistierung:** `scan_results` mit `tool_name=securitytrails`, `phase=0`
**Timeout:** 10s pro Call
**Fallback:** Wenn kein API-Key → Phase wird übersprungen, kein Fehler

#### WHOIS Lookup (Domain-Registrar-Daten)

**Lizenz:** Keine Lizenzprobleme (öffentliches Protokoll)
**Pakete:** Alle

```bash
whois {domain} > {output}
# Alternativ für strukturierte Daten:
# python3 -c "import whois; w = whois.whois('{domain}'); print(json.dumps(w, default=str))"
```

**Output-Verarbeitung:**
```python
{
    "domain": "example.com",
    "registrar": "United Domains AG",
    "creation_date": "2010-05-15",
    "expiration_date": "2027-05-15",
    "name_servers": ["ns1.example.com", "ns2.example.com"],
    "dnssec": "signedDelegation",  # oder "unsigned"
    "registrant_country": "DE"
}
```

**Sicherheits-Findings aus WHOIS:**
- Domain läuft bald ab (< 30 Tage) → Warning
- Keine DNSSEC-Signierung → Finding (Compliance: hohes Gewicht)
- Registrar ohne Domain-Lock → Hinweis
- Nameserver bei anderem Provider als Webserver → Informational

**Persistierung:** `scan_results` mit `tool_name=whois`, `phase=0`
**Timeout:** 30s (WHOIS-Server können langsam sein)

### 3.3 AI-Input-Anreicherung

Die Ergebnisse aus Phase 0a werden der AI Host Strategy als zusätzlicher
Kontext mitgegeben. Das verbessert die Scan-Entscheidungen erheblich:

```
Bisheriger AI-Input:     Host-Inventar + Web-Probe-Daten
Neuer AI-Input:          Host-Inventar + Web-Probe + Shodan-Ports + Shodan-Service-Versionen
                         + AbuseIPDB-Score + DNS-History
```

**Konkreter Nutzen:**
- Shodan kennt bereits offene Ports → AI kann nmap-Scan optimieren (nur unbekannte Ports tiefer scannen)
- Shodan-Service-Versionen (z.B. "nginx 1.18", "OpenSSH 8.9p1") → AI kann nuclei-Tags
  präziser wählen, da bekannte Vuln-Ranges für diese Versionen gezielt getestet werden können
- AbuseIPDB-Score > 50 → Host bekommt höhere Scan-Priorität (aktiv als verdächtig gemeldet)

### 3.4 Paket-spezifische Phase-0a-Konfiguration

| API | WebCheck | Perimeter+ |
|-----|----------|------------|
| Shodan | – | Vollständig (DNS + Host-Details pro IP) |
| AbuseIPDB | – | IP-Reputation pro entdeckte IP |
| SecurityTrails | – | Domain + Subdomains + DNS-History |
| WHOIS | Basis (Ablauf, DNSSEC) | Vollständig |

**WebCheck-Philosophie:** Minimaler API-Verbrauch, da WebCheck günstig sein soll.
WHOIS ist kostenlos und liefert Domain-Ablauf + DNSSEC-Status. Passive Intel
über Shodan, AbuseIPDB und SecurityTrails ist den höheren Paketen vorbehalten
und rechtfertigt den Preisunterschied.

---

## 4. Phase 0b — Active Discovery (erweitert)

### 4.1 Bestehende Tools (unverändert)

Diese Tools bleiben wie in v1 implementiert:

| Tool | Pakete | Timeout | Beschreibung |
|------|--------|---------|-------------|
| crt.sh | Alle | 60s | Certificate Transparency Logs |
| subfinder | Alle | 120s | Passive Subdomain-Enumeration |
| amass | Perimeter+ | 300s | OSINT + aktive Enumeration |
| gobuster dns | Perimeter+ | 180s | DNS-Bruteforce |
| dig (DNS Records) | Alle | 10s/Query | SPF, DMARC, DKIM, MX, NS |
| dig (AXFR) | Perimeter+ | 30s/NS | Zone-Transfer-Versuch |
| dnsx | Alle | 60s | DNS-Validierung + IP-Gruppierung |
| httpx (Web-Probe) | Alle | 10s/FQDN | HTTP-Alive-Check |

### 4.2 Neue Tools

#### DNSSEC-Validierung

**Lizenz:** Eigenentwicklung (dig + Python-Validierung)
**Pakete:** Alle (Detail-Level variiert)

```bash
# DNSSEC-Signatur prüfen
dig {domain} DNSKEY +dnssec +short
dig {domain} DS +short
dig {domain} RRSIG +short

# Validierung via unbound-host oder drill
drill -S {domain}
# Exit 0 = DNSSEC valide, Exit 1 = nicht signiert oder fehlerhaft
```

**Output-Verarbeitung:**
```python
{
    "dnssec_signed": true,          # Domain hat DNSKEY/DS Records
    "dnssec_valid": true,           # Chain of Trust valide
    "ds_algorithm": "ECDSAP256SHA256",  # oder RSA, SHA-1 (schwach!)
    "dnskey_count": 2,
    "issues": []                    # z.B. ["DS Algorithm SHA-1 (deprecated)"]
}
```

**Findings:**
- Keine DNSSEC-Signierung → MEDIUM (Compliance: HIGH für NIS2)
- DS mit SHA-1 → LOW (veralteter Algorithmus)
- DNSSEC-Validierung fehlgeschlagen → HIGH (DNS-Spoofing möglich)

#### CAA-Record-Check (Certificate Authority Authorization)

**Lizenz:** Eigenentwicklung (dig)
**Pakete:** Alle

```bash
dig {domain} CAA +short
# Erwartete Antwort z.B.: 0 issue "letsencrypt.org"
# Keine Antwort = kein CAA-Record
```

**Findings:**
- Kein CAA-Record → LOW (jede CA kann Zertifikate ausstellen)
- CAA vorhanden + restriktiv → Positiv-Finding

#### MTA-STS Check (Mail Transfer Agent Strict Transport Security)

**Lizenz:** Eigenentwicklung (dig + curl)
**Pakete:** Alle

```bash
# 1. DNS TXT Record prüfen
dig _mta-sts.{domain} TXT +short
# Erwartet: "v=STSv1; id=20260315"

# 2. Policy-Datei abrufen
curl -sL https://mta-sts.{domain}/.well-known/mta-sts.txt
# Erwartet:
# version: STSv1
# mode: enforce
# mx: mail.example.com
# max_age: 604800
```

**Findings:**
- Kein MTA-STS → MEDIUM (E-Mail-Transport nicht erzwungen verschlüsselt)
  - Compliance/NIS2: Höheres Gewicht (§30 Abs. 2 Nr. 4: Sicherheit der Lieferkette)
- MTA-STS mode: testing → LOW (noch nicht enforced)
- MTA-STS mode: enforce → Positiv-Finding

#### DANE/TLSA Check (DNS-based Authentication of Named Entities)

**Lizenz:** Eigenentwicklung (dig)
**Pakete:** Perimeter+ (nicht WebCheck — zu technisch)

```bash
# TLSA-Record für SMTP (Port 25)
dig _25._tcp.mail.{domain} TLSA +short
# Erwartet z.B.: 3 1 1 <hash>

# TLSA-Record für HTTPS (Port 443)
dig _443._tcp.{domain} TLSA +short
```

**Findings:**
- DANE/TLSA vorhanden → Positiv-Finding (zusätzliche Zertifikatsvalidierung)
- DANE/TLSA fehlerhaft (Hash stimmt nicht) → HIGH

#### Erweiterte E-Mail-Security-Analyse

Zusätzlich zu den bestehenden SPF/DMARC/DKIM-Checks werden diese
tiefgehend analysiert:

```bash
# SPF-Analyse (Tiefe)
dig {domain} TXT +short | grep "v=spf1"
# Prüfungen:
#   - Mehr als 10 DNS-Lookups? → SPF-Limit-Warnung
#   - +all am Ende? → CRITICAL (jeder darf E-Mails senden)
#   - ~all (Softfail)? → MEDIUM (sollte -all sein)
#   - include-Ketten auflösen und Tiefe messen

# DMARC-Analyse (Tiefe)
dig _dmarc.{domain} TXT +short
# Prüfungen:
#   - p=none? → MEDIUM (keine Durchsetzung)
#   - p=quarantine? → LOW (gut, aber reject ist besser)
#   - p=reject? → Positiv-Finding
#   - rua/ruf-Tags vorhanden? → Reporting aktiv
#   - sp=... für Subdomains?
#   - pct < 100? → Hinweis (nicht 100% der Mails)

# DKIM-Analyse
dig default._domainkey.{domain} TXT +short
dig selector1._domainkey.{domain} TXT +short
dig google._domainkey.{domain} TXT +short
# Prüfungen:
#   - Key vorhanden und gültig?
#   - Key-Länge (RSA 1024 = schwach, 2048+ = gut)
#   - Mehrere Selektoren (gut — zeigt aktive Nutzung)
```

### 4.3 Phase-0b-Konfiguration pro Paket

| Parameter | WebCheck | Perimeter+ |
|-----------|----------|------------|
| Phase-0b-Timeout | 5 Min | 15 Min |
| Subdomain-Tools | crt.sh, subfinder | + amass, gobuster dns |
| DNS-Records | SPF, DMARC, DKIM, MX, NS | + CAA, TLSA, DNSSEC |
| AXFR-Versuch | Nein | Ja |
| SPF-Tiefenanalyse | Basis (nur ±all) | Voll (Lookup-Count, Include-Ketten) |
| DMARC-Tiefenanalyse | Basis (nur Policy) | Voll (Subdomains, Reporting, pct) |
| MTA-STS | Basis-Check | Voll (Policy-Analyse) |
| DANE/TLSA | Nein | Ja |

---

## 5. AI-Entscheidungspunkt 1: Host Strategy (erweitert)

### 5.1 Erweiterter Input

Der AI Host Strategy erhält jetzt deutlich mehr Kontext:

```
v1 Input:                              v2 Input (NEU):
─────────                              ────────────────
Host-Inventar (IP, FQDNs)             Host-Inventar (IP, FQDNs)
Web-Probe (has_web, status, title)     Web-Probe (has_web, status, title)
                                       + Shodan: offene Ports, Banner, Service-Versionen
                                       + AbuseIPDB: Abuse-Confidence-Score
                                       + SecurityTrails: DNS-History
                                       + WHOIS: Registrar, Ablaufdatum
                                       + DNSSEC-Status
                                       + Mail-Security-Posture (SPF/DMARC/DKIM Score)
```

### 5.2 Erweiterter System-Prompt

**Modell:** Claude Haiku 4.5 (`claude-haiku-4-5-20251001`)
**Begründung:** Strukturiertes Pattern-Matching mit klaren Regeln. Begrenzter
Entscheidungsraum (scan/skip pro Host). Haiku reicht zuverlässig aus.

```
Du bist ein Security-Scanner-Orchestrator. Du entscheidest, welche Hosts
gescannt werden und mit welcher Priorität.

DU HAST ZUGANG ZU PASSIVER INTELLIGENCE:
- Shodan-Daten: Bereits bekannte offene Ports und Services pro IP.
  Nutze diese um die Scan-Priorität zu erhöhen wenn kritische Services
  exponiert sind (RDP, SMB, Telnet, FTP, alte SSH-Versionen).
- AbuseIPDB-Score: Hoher Score (>50) bedeutet die IP wurde als verdächtig
  gemeldet → höhere Scan-Priorität, mögliche Kompromittierung prüfen.
- DNSSEC-Status: Nicht signiert = DNS-Manipulation möglich → DNS-Findings relevanter.

ERWEITERTE REGELN:
- Hosts mit veralteten Service-Versionen aus Shodan (alte OpenSSH, alte nginx, etc.) → Priorität 1
- Hosts mit exponierten Management-Ports (22, 3389, 5900, 8080, 8443) → Priorität 1
- Hosts mit hohem AbuseIPDB-Score (>50) → Priorität 1
- Hosts mit nur Port 80/443 und niedrigem AbuseIPDB-Score → Priorität 2
- Mailserver mit fehlender SPF/DMARC → scannen (nicht skippen!)
- CDN-Edge-Nodes (Cloudflare, Akamai, Fastly) → skip (außer bei has_web=true mit eigenem Content)
- Parking-Pages → skip
- Autodiscover-Only → skip

[... bestehende Regeln bleiben erhalten ...]
```

### 5.3 Neues Antwort-Format

```json
{
    "hosts": [
        {
            "ip": "88.99.35.112",
            "action": "scan",
            "priority": 1,
            "reasoning": "Basisdomain mit exponiertem FTP (Port 21) und veralteter OpenSSH 7.9.",
            "scan_hints": {
                "shodan_ports": [21, 22, 80, 443],
                "shodan_services": {"22": "OpenSSH 7.9", "443": "nginx 1.18"},
                "abuseipdb_score": 15,
                "focus_areas": ["ftp_security", "web_vulns", "ssl"]
            }
        }
    ],
    "strategy_notes": "4 Hosts scannen, 1 CDN-Node übersprungen. Host .112 hat höchste Priorität wegen exponiertem FTP und veralteter SSH-Version.",
    "passive_intel_summary": "Shodan: 12 offene Ports gefunden. AbuseIPDB: Alle Hosts sauber (Score <20)."
}
```

Die `scan_hints` werden an die AI Phase-2-Config weitergegeben, sodass
nuclei-Tags und Scan-Fokus an die bekannten Schwachstellen angepasst werden.

---

## 6. Phase 1 — Technology Fingerprinting (erweitert)

Phase 1 behält nmap, webtech und wafw00f bei. Die bisherige CMS-Fallback-Probe
wird zu einer vollständigen **CMS-Fingerprinting-Engine** ausgebaut.

### 6.1 nmap-Erweiterung: Shodan-Port-Hints (Perimeter+)

Bei Perimeter+-Paketen kann nmap die Shodan-Daten als Hinweis nutzen.
Wenn Shodan bereits offene Ports kennt, werden diese zusätzlich zu den
Standard-Ports gezielt gescannt. WebCheck hat keinen Shodan-Zugang und
verwendet nur die Standard-Port-Liste:

```bash
# Perimeter+: Top 1000 + Shodan-bekannte Ports
nmap -sV -sC -T4 --top-ports 1000 -p 21,3389,8080 -oX ... {ip}
#                                      ↑ zusätzlich aus Shodan

# WebCheck: Top 100 (kein Shodan — nicht im Paket enthalten)
nmap -sV -sC -T4 --top-ports 100 -oX ... {ip}
```

### 6.2 CMS-Fingerprinting-Engine (Eigenentwicklung, ersetzt CMS-Fallback-Probe)

**Lizenz:** Eigenentwicklung — kein Lizenzproblem
**Pakete:** Alle
**Begründung:** Statt externe CMS-Scanner (CMSmap/droopescan/CMSeeK — alle GPL,
kaum maintained, teilweise zu invasiv) zu integrieren, erkennt die Engine das CMS
selbst. Die AI Phase-2-Config wählt dann CMS-spezifische nuclei-Tags.

**Erkennungs-Pipeline (5 Methoden, sequenziell):**

```python
class CMSFingerprinter:
    """
    Erkennt CMS-Typ und geschätzte Version über 5 komplementäre Methoden.
    Jede Methode liefert einen CMS-Kandidaten mit Confidence.
    Bei Übereinstimmung mehrerer Methoden steigt die Gesamt-Confidence.
    """

    def fingerprint(self, fqdn: str) -> CMSResult:
        results = []

        # 1. webtech (wie bisher, erster Versuch)
        results.append(self.run_webtech(fqdn))

        # 2. Meta-Tag-Analyse (generator, powered-by im HTML)
        #    <meta name="generator" content="WordPress 6.4.2">
        #    <meta name="generator" content="TYPO3 CMS">
        #    <meta name="generator" content="Joomla! 4.3">
        results.append(self.check_meta_tags(fqdn))

        # 3. Probe-Matrix (CMS-spezifische Pfade + Response-Pattern)
        results.append(self.run_probe_matrix(fqdn))

        # 4. Cookie-Analyse (Session-Cookie-Namen sind CMS-spezifisch)
        results.append(self.check_cookies(fqdn))

        # 5. Response-Header-Analyse
        #    X-Powered-By: Express (→ Node.js), PHP/8.1 (→ PHP-basiert)
        #    X-Generator: Drupal 10
        results.append(self.check_headers(fqdn))

        return self.merge_results(results)
```

**Probe-Matrix (DACH-Markt-optimiert):**

| CMS | Probes | Response-Pattern | Confidence |
|-----|--------|-----------------|------------|
| **WordPress** | `/wp-login.php`, `/wp-admin/`, `/wp-content/` | Status 200/301/302, "wp-" im Body | 0.95 |
| **Shopware 5** | `/backend/admin`, `/web/css/` | "Shopware" im Title, `sw-` Cookies | 0.90 |
| **Shopware 6** | `/admin`, `/api/_info/config` | JSON-Response mit "shopware", `sw-` Headers | 0.90 |
| **TYPO3** | `/typo3/`, `/typo3conf/` | "TYPO3" in Meta-Generator, `fe_typo_user` Cookie | 0.90 |
| **Joomla** | `/administrator/` | "Joomla" in Meta-Generator, `mosvisitor` Cookie | 0.90 |
| **Contao** | `/contao/` | "Contao" in Meta-Generator, `contao_` Cookies | 0.85 |
| **Drupal** | `/user/login`, `/core/misc/drupal.js` | "Drupal" in X-Generator, `SSESS` Cookie | 0.90 |
| **Magento** | `/admin/`, `/checkout/cart/` | `Mage`/`PHPSESSID` Cookies, "Magento" in HTML-Kommentar | 0.85 |
| **NEOS** | `/neos/` | "neos-" in HTML-Klassen | 0.80 |
| **Craft CMS** | `/admin/login` | `CraftSessionId` Cookie | 0.85 |
| **Strapi** | `/admin/`, `/_health` | JSON-Response mit "strapi" | 0.80 |
| **Ghost** | `/ghost/` | "ghost-" in HTML, `ghost-admin` Cookie | 0.85 |
| **PrestaShop** | `/admin/login`, `/modules/` | `PrestaShop` Cookie, "prestashop" in HTML | 0.80 |

**Methodik:** Alle Probes werden als HEAD-Requests mit User-Agent "VectiScan/1.0"
und Timeout 5s ausgeführt. Pro Host max 20 Requests (nur relevante CMS werden
geprobt — wenn Meta-Tag "WordPress" sagt, werden keine Joomla-Probes gesendet).

**Output:**
```python
{
    "cms": "shopware",
    "version": "6.x",                     # geschätzt, nicht immer verfügbar
    "confidence": 0.95,                    # 0.0–1.0
    "detection_methods": ["probe_matrix", "cookie_analysis", "meta_tag"],
    "details": {
        "probe_hits": ["/admin → 302", "/api/_info/config → 200 JSON"],
        "cookies": ["sw-states", "sw-context-token"],
        "meta_generator": null             # Shopware setzt oft keinen Generator-Tag
    }
}
```

**Integration mit AI Phase-2-Config:**

Das CMS-Ergebnis fließt direkt in die AI-Entscheidung. Der System-Prompt enthält
ein CMS→nuclei-Tag-Mapping:

```
CMS-SPEZIFISCHE NUCLEI-TAG-EMPFEHLUNGEN:
- WordPress     → nuclei_tags: ["wordpress", "wp-plugin", "wp-theme"]
- Shopware 5/6  → nuclei_tags: ["shopware", "php", "exposure", "misconfig"]
- TYPO3         → nuclei_tags: ["typo3", "php", "exposure", "misconfig"]
- Joomla        → nuclei_tags: ["joomla", "php", "exposure"]
- Drupal        → nuclei_tags: ["drupal", "php", "exposure", "cve"]
- Contao        → nuclei_tags: ["php", "exposure", "misconfig"]
- Magento       → nuclei_tags: ["magento", "php", "exposure", "token"]
- Strapi        → nuclei_tags: ["nodejs", "exposure", "misconfig", "api"]
- Ghost         → nuclei_tags: ["nodejs", "exposure", "misconfig"]

Wenn kein CMS erkannt:  → Standard-Tags basierend auf Tech-Stack (Apache/nginx/PHP/Node)
Wenn WordPress erkannt: → wpscan wird automatisch aktiviert (wie bisher)
```

**Vorteile gegenüber externen CMS-Scannern (CMSmap, droopescan, CMSeeK):**
- Keine GPL-Abhängigkeiten
- Keine unmaintained Dritttools
- Nicht invasiv (nur HEAD-Requests, kein Exploit-Versuch)
- DACH-Markt-optimiert (Shopware, TYPO3, Contao sind in generischen Tools schlecht abgedeckt)
- AI-gesteuerte nuclei-Tags liefern tiefere Ergebnisse als dedizierte Scanner
  die oft nur "Version X ist veraltet" melden

---

## 7. AI-Entscheidungspunkt 2: Phase-2-Config (erweitert)

### 7.1 Erweiterter Input

```
v1 Input:                              v2 Input (NEU):
─────────                              ────────────────
nmap-Ergebnisse                        nmap-Ergebnisse
webtech-Output                         webtech-Output
wafw00f-Output                         wafw00f-Output
CMS-Erkennung                         CMS-Fingerprinting (Typ + Version + Confidence)
                                       + Shodan-Service-Versionen für diesen Host
                                       + scan_hints aus Host-Strategy
                                       + AbuseIPDB-Score
```

### 7.2 Erweiterte Tools für Phase-2-Konfiguration

**Modell:** Claude Haiku 4.5 (`claude-haiku-4-5-20251001`)
**Begründung:** Endlicher Entscheidungsraum (nuclei-Tags, Wordlists, Tool-Auswahl).
Gut definierte Optionen. Haiku reicht zuverlässig aus.

Die AI konfiguriert jetzt drei zusätzliche Tools:

```json
{
    "nuclei_tags": ["apache", "exposure", "misconfig", "ssl", "default-login"],
    "nuclei_exclude_tags": ["dos", "fuzz"],
    "nikto_tuning": "1,2,3,4",
    "gobuster_wordlist": "common",
    "ffuf_mode": "dir",
    "ffuf_extensions": ".php,.html,.js,.bak,.old,.conf",
    "feroxbuster_depth": 3,
    "feroxbuster_enabled": true,
    "dalfox_enabled": true,
    "skip_tools": [],
    "reasoning": "Apache+PHP-Server. ffuf mit PHP-Extensions, feroxbuster rekursiv, dalfox für XSS."
}
```

---

## 8. Phase 2 — Deep Scan (erweitert)

### 8.1 Bestehende Tools (unverändert)

Alle v1-Tools bleiben erhalten mit identischen Kommandos und Timeouts:
testssl.sh, nikto, nuclei, gobuster dir, gowitness, header_check, httpx,
katana, wpscan.

### 8.2 Neue Tools

#### ffuf (Web-Fuzzer)

**Lizenz:** MIT ✅
**Pakete:** Perimeter+
**Warum zusätzlich zu gobuster:** ffuf kann Parameter-Fuzzing, vHost-Discovery
und Extension-Fuzzing — nicht nur Verzeichnisse. Die AI wählt den Modus.

```bash
# Modus 1: Directory/File Discovery (Ergänzung zu gobuster)
ffuf -u https://{fqdn}/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  -e {ai_extensions} -mc 200,301,302,403 -fc 404 \
  -t 40 -rate 100 -timeout 5 -json -o {output}

# Modus 2: vHost Discovery
ffuf -u https://{ip}/ -H "Host: FUZZ.{domain}" \
  -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc 200,301,302 -fs {baseline_size} -json -o {output}

# Modus 3: Parameter Discovery (wenn katana Endpoints gefunden hat)
ffuf -u "https://{fqdn}/{endpoint}?FUZZ=test" \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 -fs {baseline_size} -json -o {output}
```

**AI-Steuerung:** Modus, Extensions und Wordlist werden von der Phase-2-Config AI gewählt.
**Timeout:** 180s (3 Min)
**Rate-Limit:** 100 req/s (respektvoll, kein DoS)

#### feroxbuster (Rekursives Directory-Bruteforce)

**Lizenz:** MIT ✅
**Pakete:** Perimeter+
**Warum zusätzlich zu gobuster/ffuf:** feroxbuster arbeitet rekursiv —
wenn es `/admin/` findet, crawlt es automatisch `/admin/*`. Das findet
versteckte Bereiche die flache Tools übersehen.

```bash
feroxbuster -u https://{fqdn} \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  -d {ai_depth} -t 30 --rate-limit 100 \
  -s 200,301,302,403 --json -o {output} \
  --dont-scan "logout|signout|delete" \
  --timeout 5 --no-recursion-on 403
```

**AI-Steuerung:** `feroxbuster_depth` (1–4) und `feroxbuster_enabled` (skip bei reinen API-Hosts)
**Timeout:** 300s (5 Min)
**Dedup:** Ergebnisse werden gegen gobuster/ffuf dedupliziert

#### dalfox (XSS-Scanner)

**Lizenz:** MIT ✅
**Pakete:** Perimeter+
**Warum:** nuclei findet Reflected XSS über Templates, aber dalfox ist ein
dedizierter XSS-Scanner der Parameter-Injection, DOM-basierte XSS und
Blind XSS erkennt. Ergänzt nuclei mit tieferer Analyse.

```bash
# Input: URLs aus katana-Crawl (mit Parametern)
cat {katana_output} | grep "?" | dalfox pipe \
  --silence --no-color --format json -o {output} \
  --timeout 5 --delay 100 --skip-bav
```

**Voraussetzung:** Nur wenn katana URLs mit Parametern gefunden hat.
**AI-Steuerung:** `dalfox_enabled` (skip bei statischen Sites ohne Parameter)
**Timeout:** 300s (5 Min)
**Wichtig:** `--skip-bav` deaktiviert Blind XSS (wäre zu invasiv für automatisierten Scanner)

### 8.3 Erweiterte Tool-Orchestrierung in Phase 2

Die Reihenfolge der Tools in Phase 2 ist jetzt optimiert, sodass spätere
Tools von früheren Ergebnissen profitieren:

```
testssl.sh          → SSL/TLS-Baseline
nikto               → Bekannte Web-Vulns
nuclei              → Template-basierte CVEs + Misconfigs
gobuster dir        → Flache Directory-Discovery
ffuf                → Extension-Fuzzing + vHost-Discovery
feroxbuster         → Rekursive Discovery (basierend auf gobuster/ffuf)
katana              → JS-Crawling, Endpoint-Discovery
dalfox              → XSS auf katana-Endpoints
gowitness           → Screenshot
header_check        → Security-Headers
httpx               → Final Tech-Detection
wpscan              → WordPress-spezifisch (wenn CMS=WP)
```

**Dependency-Chain:**
- feroxbuster profitiert von gobuster/ffuf (kennt bereits gefundene Pfade → Dedup)
- dalfox braucht katana-Output (URLs mit Parametern)
- Die AI Phase-2-Config entscheidet welche Tools übersprungen werden

---

## 9. AI-Entscheidungspunkt 3: Phase-3-Priorisierung (NEU)

### 9.1 Konzept

Nach Phase 2 gibt es potentiell hunderte Findings aus verschiedenen Tools.
Vor Phase 3 trifft die AI eine Priorisierungsentscheidung:

**Modell:** Claude Sonnet 4 (`claude-sonnet-4-20250514`)
**Begründung:** Cross-Tool-Korrelation erfordert echtes Reasoning über widersprüchliche
Signale — ob ein nuclei-Finding und ein nikto-Finding dieselbe Schwachstelle beschreiben,
ob eine Versionsabweichung ein False Positive signalisiert. Haiku ist dafür nicht
zuverlässig genug; die Korrelationsqualität bestimmt direkt die Report-Qualität.
**Input:** Aggregierte Finding-Summary aus allen Phase-2-Tools
**Output:** Priorisierte Finding-Liste mit Confidence-Scores

```json
{
    "high_confidence_findings": [
        {
            "source_tool": "nuclei",
            "finding_id": "CVE-2023-1234",
            "confidence": 0.95,
            "corroboration": ["shodan_version_match", "nmap_version_match"],
            "enrich_priority": "high"
        }
    ],
    "low_confidence_findings": [
        {
            "source_tool": "nikto",
            "finding_id": "OSVDB-12345",
            "confidence": 0.3,
            "reason": "nikto-only, keine Bestätigung durch andere Tools",
            "enrich_priority": "low"
        }
    ],
    "potential_false_positives": [...]
}
```

---

## 10. Phase 3 — Correlation & Enrichment (NEU)

### 10.1 Konzept

Phase 3 ist der zentrale Differentiator. Kein automatisierter Scanner am
Markt (in der DACH-Preisklasse) bietet Cross-Tool-Korrelation und
Threat-Intelligence-Enrichment. Das ist die Phase die aus einem
Tool-Dump einen professionellen Assessment-Bericht macht.

### 10.2 Cross-Tool-Korrelation

**Ziel:** Gleiche Schwachstelle die von mehreren Tools gefunden wurde →
höheres Confidence. Finding das nur ein Tool meldet → niedrigeres Confidence.

```python
class CrossToolCorrelator:
    """
    Korreliert Findings über Tool-Grenzen hinweg.

    Korrelationsregeln:
    1. CVE-Match: Gleiche CVE-ID aus verschiedenen Tools → merge, confidence++
    2. Port-Service-Match: nmap findet Service X, nuclei findet CVE für X → korreliert
    3. Tech-Version-Match: webtech erkennt nginx 1.18, nuclei findet nginx-CVE → korreliert
    4. Header-Korrelation: header_check findet fehlenden HSTS, testssl findet
       schwache TLS-Config → gruppieren als "Transport-Sicherheit"-Cluster
    5. CMS-Korrelation: wpscan findet vulnerable Plugin, nuclei findet gleiches
       Plugin-CVE → merge, confidence = 0.99
    """

    def correlate(self, all_findings: list[Finding]) -> list[CorrelatedFinding]:
        # Schritt 1: CVE-Dedup (gleiche CVE aus verschiedenen Tools → ein Finding)
        # Schritt 2: Port-Service-Korrelation (nmap + Shodan-Banner → bestätigt)
        # Schritt 3: Technologie-Korrelation
        # Schritt 4: Cluster-Bildung (verwandte Findings gruppieren)
        # Schritt 5: Confidence-Score berechnen
        pass
```

**Confidence-Score-Berechnung:**
```
Base Confidence:
  nuclei (template-match):     0.85
  nmap (version detection):    0.80
  testssl.sh:                  0.90
  nikto:                       0.40  (viele False Positives)
  wpscan:                      0.85
  ffuf/feroxbuster/gobuster:   0.60  (Discovery, nicht Vuln)
  header_check:                0.95  (deterministisch)
  dalfox:                      0.75

Korrelations-Boost:
  +0.10 pro zusätzliches Tool das bestätigt
  +0.10 wenn Shodan-Service-Version zum Finding passt (z.B. nuclei meldet nginx-CVE, Shodan bestätigt nginx 1.18)
  +0.05 wenn Tech-Version aus webtech/httpx übereinstimmt

Degrade:
  -0.20 wenn nur ein einziges Tool meldet und Tool-Confidence < 0.7
  -0.10 wenn hinter WAF (wafw00f positiv) und kein Bypass bestätigt
```

### 10.3 NVD API Enrichment

**Lizenz:** Öffentliche API (kostenlos, Rate-Limit 5 req/30s ohne Key, 50 req/30s mit Key)
**Pakete:** WebCheck (nur für CISA KEV), Perimeter+

```python
# CVE-Details abrufen
GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}
Headers: apiKey: {NVD_API_KEY}  # Optional, erhöht Rate-Limit

# Response enthält:
# - CVSS v3.1 Score + Vektor (autoritativ!)
# - CWE-ID (autoritativ!)
# - Beschreibung
# - Referenzen (Advisories, Patches)
# - Affected Products (CPE)
```

**Integration:**
1. Für jedes Finding mit CVE-ID → NVD-Lookup
2. CVSS-Score aus NVD hat Vorrang vor Tool-Score
3. CWE-ID aus NVD hat Vorrang über Claude-Zuordnung
4. Patch-Referenzen werden dem Report hinzugefügt

**Rate-Limit-Strategie:**
- Batch-Requests: Bis zu 100 CVEs in einem Call
- Cache: CVE-Daten lokal cachen (Redis, TTL 24h)
- Fallback: Ohne NVD-Key max 10 CVE-Lookups pro Assessment

### 10.4 EPSS (Exploit Prediction Scoring System)

**Lizenz:** Öffentlich (FIRST.org, kostenlos, täglich aktualisiert)
**Pakete:** Perimeter+

```python
# EPSS-Scores für CVEs abrufen
GET https://api.first.org/data/v1/epss?cve={cve_id_1},{cve_id_2},...

# Response:
{
    "data": [
        {
            "cve": "CVE-2023-1234",
            "epss": 0.87,          # 87% Wahrscheinlichkeit dass in 30 Tagen exploited
            "percentile": 0.98     # Höher als 98% aller CVEs
        }
    ]
}
```

**Integration:**
- EPSS > 0.5 → Finding-Priorität auf CRITICAL hochstufen (unabhängig von CVSS)
- EPSS wird im Report als "Exploit-Wahrscheinlichkeit" angezeigt
- Insurance-Report: EPSS ist zentral für Risikobewertung
- NIS2-Report: EPSS unterstützt Priorisierung nach §30 BSIG

**Report-Darstellung:**
```
CVE-2023-1234 — Apache Struts RCE
  CVSS: 9.8 (CRITICAL)
  EPSS: 87% (Exploit-Wahrscheinlichkeit in 30 Tagen)
  CISA KEV: ✅ Bekannter aktiver Exploit
  → SOFORTIGE MAẞNAHME ERFORDERLICH
```

### 10.5 CISA KEV (Known Exploited Vulnerabilities Catalog)

**Lizenz:** Öffentlich (US Government, kostenlos)
**Pakete:** Alle (WebCheck: reduziert)

```python
# Vollständiger Katalog (JSON, ~1.5 MB, täglich aktualisiert)
GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

# Lokal cachen (Redis, TTL 6h) und gegen gefundene CVEs matchen
```

**Integration:**
- CVE in CISA KEV → **automatisch CRITICAL**, unabhängig von CVSS
- Report-Text: "Diese Schwachstelle wird aktiv ausgenutzt (CISA KEV)"
- Insurance-Report: KEV-Match ist das stärkste Signal für akute Gefahr

### 10.6 ExploitDB Check

**Lizenz:** GPL v2 (Datenbank), wir nutzen `searchsploit` lokal (Teil des exploit-database Pakets)
**Pakete:** Perimeter+
**Hinweis:** ExploitDB hat keine öffentliche REST-API. Die Implementierung nutzt
`searchsploit --cve {cve_id} -j` (lokale Offline-DB, wird periodisch aktualisiert via
`searchsploit -u`). Alternativ: GitLab-Mirror-API (gitlab.com/exploit-database/exploitdb).

```bash
# Lokale Suche nach CVE
searchsploit --cve {cve_id} -j
# → JSON mit Exploit-Titeln, Pfaden, Typen

# DB-Update (wöchentlich via Cronjob im Container)
searchsploit -u
```

**Output-Verarbeitung:**
```python
{
    "cve": "CVE-2023-1234",
    "exploits_available": true,
    "exploit_count": 3,
    "exploit_types": ["remote", "webapps"],
    "metasploit_module": true
}
```

**Integration:**
- Exploit verfügbar → Finding-Priorität erhöhen
- Metasploit-Modul vorhanden → "Script-Kiddie-tauglich", besonders hohes Risiko
- Report: "Öffentlicher Exploit verfügbar" als Warnung

### 10.7 False-Positive-Reduktion

Phase 3 eliminiert systematisch False Positives:

```python
class FalsePositiveFilter:
    """
    Regeln zur FP-Reduktion:

    1. WAF-Filter: Wenn wafw00f eine WAF erkannt hat und ein Finding
       nur von nikto gemeldet wird (confidence < 0.5) → als FP markieren.
       Nuclei-Findings hinter WAF bekommen confidence -0.1.

    2. Version-Mismatch: Wenn nuclei CVE-2023-1234 für nginx 1.18 meldet,
       aber nmap/httpx nginx 1.24 erkennt → FP (Version nicht betroffen).

    3. CMS-Mismatch: Wenn nuclei WordPress-Templates matchen, aber
       webtech+CMS-Fingerprinting-Engine kein WordPress erkennt → FP.

    4. SSL-Dedup: testssl und nuclei melden SSL-bezogene Schwachstellen
       oft doppelt → merge zu einem Finding.

    5. Header-Dedup: nikto, header_check und nuclei melden fehlende
       Security-Headers dreifach → merge zu einem Finding.

    6. Info-Noise: Reine Informational-Findings die keinen Sicherheitswert
       haben werden gefiltert (z.B. "Server: nginx" ohne Version).
    """
```

### 10.8 Business-Impact-Scoring

Zusätzlich zum technischen CVSS-Score berechnet Phase 3 einen
Business-Impact-Score:

```python
def calculate_business_impact(finding, context):
    """
    Business-Impact basiert auf:
    1. CVSS Base Score (technische Schwere)
    2. EPSS Score (Exploit-Wahrscheinlichkeit)
    3. CISA KEV (aktiv ausgenutzt?)
    4. Asset-Wert (Basisdomain > Subdomain > Mail > Intern)
    5. Daten-Exposure (Login-Seite > Info-Seite)
    6. Paket-spezifische Gewichtung:
       - Insurance: RDP/SMB offene Ports × 2 (Ransomware-Vektor)
       - Compliance: fehlende Verschlüsselung × 1.5 (§30 BSIG Nr. 4)
       - SupplyChain: API-Sicherheit × 1.5 (Lieferketten-Schnittstelle)
    """
    base = finding.cvss_score

    # EPSS-Multiplikator
    if finding.epss and finding.epss > 0.5:
        base *= 1.3
    if finding.in_cisa_kev:
        base *= 1.5

    # Asset-Wert
    if finding.is_base_domain:
        base *= 1.2
    elif finding.is_mail_server:
        base *= 1.1

    return min(base, 10.0)
```

### 10.9 Phase-3-Konfiguration pro Paket

| Parameter | WebCheck | Perimeter+ |
|-----------|----------|------------|
| Phase-3-Timeout | 2 Min | 5 Min |
| NVD-Lookups | Max 5 (nur CRITICAL) | Alle CVEs |
| EPSS | Nein | Ja |
| CISA KEV | Ja (nur Match) | Ja (vollständig) |
| ExploitDB | Nein | Ja |
| Cross-Tool-Korrelation | Basis (Dedup) | Vollständig |
| Business-Impact-Score | Nein | Ja |
| FP-Reduktion | Basis | Vollständig |

---

## 11. AI-Entscheidungspunkt 4: Report-Qualitätssicherung (NEU)

### 11.1 Konzept

Die Report-QA verwendet einen **hybriden Ansatz**: mechanische Checks werden
programmatisch gelöst (deterministisch, kostenlos), nur Urteilsfragen gehen an Haiku.

#### Programmatische Checks (in `qa_check.py`, kein AI-Call):

1. **CVSS-Vektor-Berechnung:** Score aus Vektor berechnen, Divergenz > 0.1 korrigieren
2. **CWE-Format-Validierung:** CWE-ID gegen `cwe_reference.py` prüfen
3. **Severity-Konsistenz:** CVSS-Score muss zur Severity-Einstufung passen
4. **Duplikat-Erkennung:** Titel-Similarity-Check (Levenshtein/Fuzzy)
5. **Pflichtfeld-Prüfung:** Jedes HIGH/CRITICAL-Finding hat eine Empfehlung?
6. **EPSS-Referenz-Check:** Wenn EPSS-Daten vorhanden, sind sie im Finding referenziert?
7. **NIS2-Mapping-Prüfung:** (nur Compliance) Alle §30-Absätze abgedeckt?

#### Haiku-basierte Checks (nur für Urteilsfragen):

**Modell:** Claude Haiku 4.5
**Input:** Nur die Findings bei denen die programmatischen Checks Anomalien gefunden haben
**Aufgabe:** Plausibilität prüfen — ist die CWE-Zuordnung inhaltlich korrekt?
Passt die Empfehlung zum Finding? Sind positive Findings tatsächlich positiv?

**Output:**
```json
{
    "quality_score": 0.92,
    "issues": [
        {
            "finding_id": "VS-2026-003",
            "issue": "CVSS-Score 7.5 passt nicht zu Vektor mit AC:H (sollte ~6.0 sein)",
            "auto_fix": true,
            "corrected_score": 6.1
        }
    ],
    "auto_fixes_applied": 2,
    "manual_review_needed": false
}
```

---

## 12. Report-Generierung (5 Varianten)

### 12.1 Prompt-Varianten

| Paket | Prompt-Name | Report-Sprache | Besonderheiten |
|-------|-------------|----------------|----------------|
| WebCheck | `SYSTEM_PROMPT_WEBCHECK` | Einfach, kein Jargon | Ampelsystem, max 8 Findings, "Aufgaben für Ihren Webmaster" |
| PerimeterScan | `SYSTEM_PROMPT_PERIMETER` | PTES-konform, technisch | CVSS-Vektoren, Evidence, EPSS-Kontext |
| ComplianceScan | `SYSTEM_PROMPT_COMPLIANCE` | = Perimeter + NIS2 | §30 BSIG-Mapping, BSI-Grundschutz-Refs, Compliance-Summary |
| SupplyChain | `SYSTEM_PROMPT_SUPPLYCHAIN` | = Perimeter + Lieferkette | ISO 27001 Mapping, Auftraggeber-Nachweis-Sektion |
| InsuranceReport | `SYSTEM_PROMPT_INSURANCE` | = Perimeter + Versicherung | Fragebogen-Format, Risk-Score, Trend-Vergleich |

### 12.2 Report-Sektionen pro Paket

#### Alle Pakete:
- Deckblatt mit Scan-Datum, Domain, Paket-Typ
- Executive Summary (Ampel/Score)
- Finding-Liste (sortiert nach Severity/Business-Impact)
- Empfehlungen (priorisiert)
- Positiv-Findings ("Das machen Sie richtig")
- Scan-Methodologie (verwendete Tools, Scan-Zeitraum)
- Disclaimer

#### WebCheck zusätzlich:
- "So lesen Sie diesen Bericht" (Erklärseite für Nicht-Techniker)
- Mail-Security-Zusammenfassung (SPF/DMARC/DKIM als Ampel)
- "Die 3 wichtigsten Maßnahmen" (Top-Priority-Seite)

#### PerimeterScan zusätzlich:
- Attack-Surface-Übersicht (alle entdeckten Hosts und Services)
- EPSS-Top-10 (Findings mit höchster Exploit-Wahrscheinlichkeit)
- Technische Evidence-Blöcke pro Finding

#### ComplianceScan zusätzlich:
- NIS2-Compliance-Summary (§30 BSIG Abs. 2 Nr. 1–10 mit Status)
- BSI-Grundschutz-Referenzen (wo anwendbar)
- DNSSEC/MTA-STS/DANE-Status als eigene Sektion
- Lieferketten-1-Seiter
- Maßnahmen-Priorisierung nach BSIG-Relevanz

#### SupplyChain zusätzlich:
- "Sicherheitsnachweis für Auftraggeber" (eigenständiges Kapitel)
- ISO 27001 Annex A Mapping-Tabelle
- Bestätigung der geprüften Bereiche
- QR-Code zum Online-Validierungslink (optional)

#### InsuranceReport zusätzlich:
- Versicherungs-Fragebogen-Sektion (20–30 typische Fragen mit Bewertung)
- Ransomware-Risiko-Indikator (basierend auf offenen Ports, Patch-Level)
- Risk-Score (0–100) mit Trendvergleich (wenn historische Daten vorhanden)
- "Maßnahmen die Ihre Prämie senken können"

---

## 13. Neue Tools — Lizenz-Compliance

Alle neuen Tools sind lizenzrechtlich unbedenklich für SaaS-Backend-Nutzung:

| Tool | Lizenz | SaaS-Nutzung | Anmerkung |
|------|--------|-------------|-----------|
| ffuf | MIT | ✅ Unproblematisch | Nur Copyright-Notice |
| feroxbuster | MIT | ✅ Unproblematisch | Nur Copyright-Notice |
| dalfox | MIT | ✅ Unproblematisch | Nur Copyright-Notice |
| Shodan API | Proprietary | ✅ API-Nutzung | Freelancer $69/Mo, Small Biz $359/Mo |
| AbuseIPDB API | Proprietary | ✅ API-Nutzung (Basic+) | Free verbietet kommerz. Nutzung! Basic $25/Mo, Premium $99/Mo |
| SecurityTrails API | Proprietary | ⚠️ Free = non-commercial | Free für Prototyp OK. Produktion: Prototyper $50/Mo nötig |
| NVD API | Public Domain | ✅ Kostenlos | US Government, Rate-Limited |
| EPSS API | Public | ✅ Kostenlos | FIRST.org, täglich aktualisiert |
| CISA KEV | Public Domain | ✅ Kostenlos | US Government |
| ExploitDB | GPL v2 (DB) | ✅ Lokale Nutzung | `searchsploit` lokal, DB als Offline-Kopie im Container |
| whois | ISC (BSD) | ✅ Unproblematisch | Standardtool |
| drill/unbound | BSD | ✅ Unproblematisch | Für DNSSEC-Validierung |

**Keine AGPL-Tools.** Keine Tools mit problematischer Lizenz.

---

## 14. API-Kosten-Kalkulation

### 14.1 Pro Assessment (Perimeter-Paket, worst case ~15 Hosts)

| API | Calls | Kosten (geschätzt) |
|-----|-------|-------------------|
| Shodan (Host-Lookup) | ~16 (1 DNS + 15 Host) | anteilig (~$0.11 bei Freelancer $69/Monat, ~600 Assessments) |
| AbuseIPDB (IP-Check) | ~15 (1 pro IP) | anteilig (~$0.04 bei Basic $25/Monat, ~600 Assessments) |
| SecurityTrails | ~3 (Domain + Subs + History) | $0 (Free im Prototyp; Produktion: ~$0.10 bei Prototyper $50/Mo) |
| NVD | ~20 (CVE-Lookups) | $0 (kostenlos) |
| EPSS | ~1 (Batch-Request) | $0 (kostenlos) |
| CISA KEV | ~0 (lokal gecacht) | $0 (kostenlos) |
| Claude Haiku (2× AI-Calls) | ~2 | ~$0.02 |
| Claude Sonnet (Korrelation + Report) | ~2 | ~$0.20–0.40 |
| **Gesamt pro Assessment** | | **~$0.37–0.57** (variable Kosten) |

### 14.2 Monatliche Fixkosten (API-Subscriptions)

#### Phase 1: MVP-Start

| API | Plan | Monatlich | Kapazität |
|-----|------|-----------|-----------|
| Shodan | Freelancer | $69 | 10.000 Query Credits/Monat |
| AbuseIPDB | Basic | $25 | 10.000 IP-Checks/Tag |
| SecurityTrails | Free (⚠️ non-commercial) | $0 | 2.500 Queries/Monat — OK für internen Prototyp |
| WPScan | Free | $0 | 25 API-Calls/Tag |
| **Gesamt Phase 1** | | **$94/Monat** | |

#### Phase 2: Wachstum (~50+ Assessments/Monat)

| API | Plan | Monatlich | Kapazität |
|-----|------|-----------|-----------|
| Shodan | Freelancer | $69 | 10.000 Credits reichen weiterhin |
| AbuseIPDB | Premium | $99 | 50.000 IP-Checks/Tag |
| SecurityTrails | Prototyper | $50 | 1.500 Queries/Monat, kommerziell lizenziert |
| WPScan | Free | $0 | 25 API-Calls/Tag |
| **Gesamt Phase 2** | | **$218/Monat** | |

#### Phase 3: Scale (~200+ Assessments/Monat)

| API | Plan | Monatlich | Kapazität |
|-----|------|-----------|-----------|
| Shodan | Small Business | $359 | 100.000 Credits + `vuln`-Filter für CVE-Enrichment |
| AbuseIPDB | Premium | $99 | 50.000/Tag reicht weiterhin |
| SecurityTrails | Prototyper oder Professional | $50–$500 | 1.500–20.000 Queries/Monat |
| VirusTotal (optional) | Lite | ~$417 ($5.000/Jahr) | Premium-Feature, nicht essentiell |
| **Gesamt Phase 3** | | **$508–$1.375/Monat** | |

**Fazit:** Der MVP/Prototyp startet mit **$94/Monat** (Shodan Freelancer + AbuseIPDB Basic).
SecurityTrails Free wird im Prototyp genutzt (non-commercial OK für internen Betrieb).
**Vor Produktionsstart** muss SecurityTrails auf den Prototyper-Plan ($50/Mo) gewechselt
werden → Produktions-Fixkosten: **$144/Monat**. NVD, EPSS und CISA KEV sind kostenlos.
VirusTotal kommt erst in Phase 3 als optionales Premium-Feature dazu.

---

## 15. Ressourcen-Schätzung (Scan-Worker)

### 15.1 Zeitbudget pro Paket

| Phase | WebCheck | Perimeter+ |
|-------|----------|------------|
| Phase 0a (Passive Intel) | ~30s (nur WHOIS) | ~60–120s (API-Calls + Rate-Limits) |
| Phase 0b (Active Discovery) | ~3 Min | ~10–15 Min |
| AI Host Strategy | ~5s | ~5s |
| Phase 1 (Tech Detection) | ~2 Min (3 Hosts) | ~8 Min (15 Hosts) |
| AI Phase-2 Config | ~5s | ~15s (pro Host) |
| Phase 2 (Deep Scan) | ~8–12 Min (3 Hosts, weniger Tools) | ~30–50 Min (15 Hosts, alle Tools, AI-Skipping) |
| AI Phase-3 Priorisierung | ~3s | ~5s |
| Phase 3 (Correlation) | ~30s | ~2–3 Min |
| AI Report QA | ~3s | ~5s |
| Report Generation | ~30s | ~60–90s |
| **Gesamt** | **~15–20 Min** | **~60–90 Min** |

### 15.2 Compute-Ressourcen (Scan-Worker-Container)

Unverändert gegenüber v1. Die neuen Tools (ffuf, dalfox: Go; feroxbuster: Rust) sind
kompakte Binaries mit niedrigem Footprint. Phase 3 ist reine API-Calls + Python-Logik.

| Ressource | Limit |
|-----------|-------|
| CPU | 2.0 Cores |
| RAM | 2 GB (Peak bei nuclei/amass) |
| Disk | 500 MB temp pro Assessment |
| Network | Moderate (Rate-Limited) |

---

## 16. DB-Schema-Erweiterungen

### 16.1 Neue Spalten in `orders`

```sql
-- Paket-Erweiterung (5 statt 3 Werte) — betrifft BEIDE Tabellen
ALTER TABLE orders DROP CONSTRAINT chk_orders_package;
ALTER TABLE orders ADD CONSTRAINT chk_orders_package
    CHECK (package IN ('webcheck', 'perimeter', 'compliance', 'supplychain', 'insurance'));

ALTER TABLE scan_schedules DROP CONSTRAINT chk_schedule_package;
ALTER TABLE scan_schedules ADD CONSTRAINT chk_schedule_package
    CHECK (package IN ('webcheck', 'perimeter', 'compliance', 'supplychain', 'insurance'));

-- Phase-3-Daten
ALTER TABLE orders ADD COLUMN correlation_data JSONB;  -- Cross-Tool-Korrelation
ALTER TABLE orders ADD COLUMN business_impact_score DECIMAL(3,1);  -- 0.0-10.0
ALTER TABLE orders ADD COLUMN passive_intel_summary JSONB;  -- Phase-0a-Zusammenfassung
```

### 16.2 Backward-Compatibility

Bestehende Orders und Schedules mit `basic`, `professional`, `nis2` werden migriert:
```sql
UPDATE orders SET package = 'webcheck' WHERE package = 'basic';
UPDATE orders SET package = 'perimeter' WHERE package = 'professional';
UPDATE orders SET package = 'compliance' WHERE package = 'nis2';

UPDATE scan_schedules SET package = 'webcheck' WHERE package = 'basic';
UPDATE scan_schedules SET package = 'perimeter' WHERE package = 'professional';
UPDATE scan_schedules SET package = 'compliance' WHERE package = 'nis2';
```

### 16.3 Neue Tabelle: `threat_intel_cache`

```sql
CREATE TABLE threat_intel_cache (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cache_key   VARCHAR(255) NOT NULL UNIQUE,  -- z.B. "nvd:CVE-2023-1234" oder "epss:CVE-2023-1234"
    cache_value JSONB NOT NULL,
    source      VARCHAR(50) NOT NULL,          -- nvd, epss, cisa_kev, exploitdb, shodan
    fetched_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_threat_intel_cache_key ON threat_intel_cache(cache_key);
CREATE INDEX idx_threat_intel_cache_expires ON threat_intel_cache(expires_at);
```

**TTL pro Quelle:**
| Quelle | TTL | Begründung |
|--------|-----|------------|
| NVD | 24h | CVE-Details ändern sich selten |
| EPSS | 6h | Täglich aktualisiert, aber nicht stündlich relevant |
| CISA KEV | 6h | Wird sporadisch aktualisiert |
| ExploitDB | 24h | Neue Exploits sind selten stündlich relevant |
| Shodan | 12h | Host-Daten ändern sich nicht schnell |
| AbuseIPDB | 12h | Abuse-Reports ändern sich nicht schnell |

---

## 17. Implementierungs-Roadmap

### Phase I: Foundation (Wochen 1–2)
- [ ] DB-Migration: Neue Paket-Werte, threat_intel_cache Tabelle
- [ ] API-Key-Management: Vault/Env für Shodan, AbuseIPDB, SecurityTrails, NVD, WPScan
- [ ] Basis-Infrastruktur für Phase 0a (API-Client-Klasse mit Rate-Limiting, Caching)
- [ ] Backward-Compatibility: basic→webcheck, professional→perimeter, nis2→compliance Migration

### Phase II: Passive Intelligence (Wochen 3–4)
- [ ] Shodan-Integration (DNS + Host-Lookup)
- [ ] AbuseIPDB-Integration (IP-Reputation pro Host)
- [ ] SecurityTrails-Integration (Domain + Subdomains)
- [ ] WHOIS-Integration
- [ ] Erweiterte DNS-Security (DNSSEC, CAA, MTA-STS, DANE)
- [ ] AI Host Strategy Update (erweiterter Input)

### Phase III: Extended Deep Scan (Wochen 5–6)
- [ ] CMS-Fingerprinting-Engine (Eigenentwicklung, ersetzt CMS-Fallback-Probe)
- [ ] CMS→nuclei-Tag-Mapping im AI Phase-2 System-Prompt
- [ ] ffuf-Integration (3 Modi: dir, vhost, param)
- [ ] feroxbuster-Integration (rekursiv)
- [ ] dalfox-Integration (XSS auf katana-Endpoints)
- [ ] AI Phase-2-Config Update (neue Tool-Parameter + CMS-Input)
- [ ] Tool-Orchestrierung: Dependency-Chain (dalfox nach katana, etc.)
- [ ] Dockerfiles: ffuf, feroxbuster, dalfox in Scan-Worker-Image

### Phase IV: Correlation & Enrichment (Wochen 7–8)
- [ ] NVD-API-Client (Batch, Cache)
- [ ] EPSS-Client (Batch)
- [ ] CISA-KEV-Loader (Cache, 6h Refresh)
- [ ] ExploitDB-Client
- [ ] CrossToolCorrelator (Dedup, Confidence)
- [ ] FalsePositiveFilter
- [ ] BusinessImpactScorer
- [ ] AI Phase-3-Korrelation (Sonnet)

### Phase V: Report-Varianten (Wochen 9–10)
- [ ] Prompt: SYSTEM_PROMPT_WEBCHECK
- [ ] Prompt: SYSTEM_PROMPT_PERIMETER (= überarbeitetes PROFESSIONAL)
- [ ] Prompt: SYSTEM_PROMPT_COMPLIANCE (= überarbeitetes NIS2)
- [ ] Prompt: SYSTEM_PROMPT_SUPPLYCHAIN (neu: ISO 27001 Mapping)
- [ ] Prompt: SYSTEM_PROMPT_INSURANCE (neu: Fragebogen-Format)
- [ ] Report-Mapper für alle 5 Varianten
- [ ] PDF-Templates für neue Sektionen
- [ ] AI Report-QA (programmatisch + Haiku für Urteilsfragen)

### Phase VI: Integration & Testing (Wochen 11–12)
- [ ] End-to-End-Tests pro Paket
- [ ] Frontend: Paket-Selector Update (5 Pakete)
- [ ] Frontend: Phase-0a-Anzeige in Scan-Detail
- [ ] Frontend: Phase-3-Korrelationsdaten in Findings-Viewer
- [ ] Performance-Tests (Timeouts, Rate-Limits)
- [ ] Lizenz-Dokumentation (NOTICES-Datei)

---

## 18. Scan-Worker Dockerfile-Erweiterungen

```dockerfile
# Neue Tools im Scan-Worker-Image

# ffuf (MIT)
RUN wget -q https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_linux_amd64.tar.gz \
    && tar -xzf ffuf_*.tar.gz -C /usr/local/bin/ ffuf \
    && rm ffuf_*.tar.gz

# feroxbuster (MIT)
RUN wget -q https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb.zip \
    && unzip feroxbuster_*.zip && dpkg -i feroxbuster_*_amd64.deb \
    && rm feroxbuster_*.zip feroxbuster_*.deb

# dalfox (MIT)
RUN wget -q https://github.com/hahwul/dalfox/releases/latest/download/dalfox_2.9.3_linux_amd64.tar.gz \
    && tar -xzf dalfox_*.tar.gz -C /usr/local/bin/ dalfox \
    && rm dalfox_*.tar.gz

# drill (BSD) für DNSSEC-Validierung
RUN apt-get install -y ldnsutils

# whois
RUN apt-get install -y whois

# exploitdb / searchsploit (GPL v2 — lokale Nutzung, keine Distribution)
RUN apt-get install -y exploitdb \
    && searchsploit -u  # Initiales DB-Update

# SecLists Wordlists (erweitert)
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists
```

---

## 19. Verzeichnisstruktur-Erweiterungen

```
scan-worker/scanner/
├── ...bestehende Dateien...
├── cms_fingerprinter.py    ← NEU: CMS-Fingerprinting-Engine (ersetzt CMS-Fallback-Probe)
├── phase0a.py              ← NEU: Passive Intelligence Orchestrierung
├── passive/                ← NEU: Passive Intel Clients
│   ├── __init__.py
│   ├── shodan_client.py
│   ├── abuseipdb_client.py
│   ├── securitytrails_client.py
│   ├── whois_client.py
│   └── dns_security.py     ← DNSSEC, CAA, MTA-STS, DANE
├── phase3.py               ← NEU: Correlation & Enrichment Orchestrierung
├── correlation/            ← NEU: Korrelations-Engine
│   ├── __init__.py
│   ├── correlator.py       ← Cross-Tool-Korrelation
│   ├── fp_filter.py        ← False-Positive-Reduktion
│   ├── business_impact.py  ← Business-Impact-Scoring
│   └── threat_intel.py     ← NVD, EPSS, CISA KEV, ExploitDB Clients
└── cache.py                ← NEU: Redis/DB Cache für Threat-Intel

report-worker/reporter/
├── ...bestehende Dateien...
├── prompts.py              ← Erweitert: 5 statt 3 Prompt-Varianten
├── report_mapper.py        ← Erweitert: 5 Mapper-Funktionen
├── qa_check.py             ← NEU: Programmatische QA + Haiku für Urteilsfragen
└── compliance/             ← NEU: Compliance-Mapping-Module
    ├── __init__.py
    ├── nis2_bsig.py        ← §30 BSIG Mapping (aus v1, refactored)
    ├── iso27001.py          ← ISO 27001 Annex A Mapping
    ├── bsi_grundschutz.py   ← BSI-Grundschutz-Referenzen
    ├── nist_csf.py          ← NIST CSF Mapping
    └── insurance.py         ← Versicherungs-Fragebogen-Generator
```

---

## 20. Zusammenfassung

Die VectiScan v2 Pipeline hebt sich durch folgende Merkmale ab:

1. **Passive-First Intelligence** — Informationssammlung ohne Zielkontakt,
   rechtlich sauber, kontextreich für AI-Entscheidungen.

2. **4 AI-Entscheidungspunkte** — Nicht nur "welche Hosts scannen" und
   "welche Tools konfigurieren", sondern auch "wie priorisieren" und
   "ist der Report konsistent".

3. **Cross-Tool-Korrelation** — Kein Tool-Dump, sondern korrelierte,
   deduplizierte Findings mit Confidence-Scores.

4. **Threat-Intelligence-Enrichment** — EPSS, CISA KEV, NVD und ExploitDB
   geben jedem Finding realen Bedrohungskontext. Das unterscheidet VectiScan
   von jedem Wettbewerber in der DACH-Preisklasse.

5. **5 marktgerechte Pakete** — Jede Zielgruppe bekommt exakt das was sie
   braucht: vom Website-Check für die Bäckerei bis zum Versicherungsnachweis
   für das KMU.

6. **Keine Lizenzprobleme** — Alle neuen Tools sind MIT/Apache/BSD oder
   API-basiert. Kein AGPL, kein Copyleft-Trigger.

7. **Kosteneffizient** — Prototyp startet mit $94/Monat (Shodan Freelancer $69 + AbuseIPDB Basic $25).
   Produktions-Fixkosten: $144/Monat (+ SecurityTrails Prototyper $50). Variable Kosten pro
   Assessment: ~$0.37–0.57. NVD, EPSS und CISA KEV sind kostenlos. Alle kommerziellen APIs
   haben verifizierte Lizenzen — SecurityTrails-Upgrade vor Produktionsstart eingeplant.
