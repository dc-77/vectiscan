# VectiScan — Scan-Pipeline im Detail

Vollständige technische Referenz der Scan-Abläufe, Tool-Konfigurationen,
KI-Entscheidungspunkte und Paket-Unterschiede. Basiert ausschließlich auf
dem implementierten Code (Stand: 2026-04-21).

Übersicht und Schnellnachschlag: `SCAN-TOOLS.md`. Architektur und Status-
flow: `architecture.md`. API-Endpoints: `API-SPEC.md`.

---

## Inhaltsverzeichnis

1. [Architektur-Überblick](#1-architektur-überblick)
2. [Paket-Konfigurationen](#2-paket-konfigurationen)
3. [Phase 0a: Passive Intelligence](#3-phase-0a-passive-intelligence)
4. [Phase 0b: DNS-Reconnaissance](#4-phase-0b-dns-reconnaissance)
5. [KI-Entscheidung 1: Host Strategy](#5-ki-entscheidung-1-host-strategy)
6. [Phase 1: Technology Detection](#6-phase-1-technology-detection)
7. [KI-Entscheidung 2: Tech Analysis](#7-ki-entscheidung-2-tech-analysis)
8. [KI-Entscheidung 3: Phase-2-Config](#8-ki-entscheidung-3-phase-2-config)
9. [Phase 2: Deep Scan](#9-phase-2-deep-scan)
10. [KI-Entscheidung 4: Phase-3-Priorisierung](#10-ki-entscheidung-4-phase-3-priorisierung)
11. [Phase 3: Correlation & Enrichment](#11-phase-3-correlation--enrichment)
12. [Timeout-Architektur](#12-timeout-architektur)
13. [Datenfluss zwischen Phasen](#13-datenfluss-zwischen-phasen)
14. [KI-Modelle und Kosten](#14-ki-modelle-und-kosten)

---

## 1. Architektur-Überblick

### Ausführungsreihenfolge

```
Redis Job Queue (scan-pending)
    │
    ▼
worker.py::_process_job(order_id, domain, package)
    │
    ├── Phase 0a: Passive Intelligence (parallel, API-Calls)
    │
    ├── Phase 0b: DNS-Reconnaissance (parallel, 6 Tools)
    │       └── Web-Probe (httpx pro FQDN)
    │
    ├── KI-Entscheidung 1: Host Strategy (Haiku)
    │       → scan/skip pro Host, Priorität, scan_hints
    │
    ├── Phase 1: Technology Detection (parallel, max 3 Hosts)
    │       ├── nmap, webtech, wafw00f, CMS-Fingerprinting
    │       └── Playwright Redirect-Probe
    │
    ├── KI-Entscheidung 2: Tech Analysis (Haiku)
    │       → CMS-Korrektur basierend auf Redirect-Daten
    │
    ├── KI-Entscheidung 3: Phase-2-Config (Haiku, pro Host)
    │       → ZAP-Policy, Spider-Tiefe, ffuf-Modus, skip_tools
    │
    ├── Phase 2: Deep Scan (parallel, max 3 Hosts / 1 bei ZAP)
    │       ├── Stage 1: Discovery (ZAP Spider, testssl, headers, httpx)
    │       ├── Stage 2: Deep (ZAP Active, ffuf, feroxbuster, wpscan)
    │       └── Stage 3: Alert Collection
    │
    ├── KI-Entscheidung 4: Phase-3-Priorisierung (Sonnet)
    │       → Konfidenz-Scoring, FP-Erkennung
    │
    ├── Phase 3: Correlation & Enrichment
    │       ├── Cross-Tool-Korrelation
    │       ├── False-Positive-Filter (6 Regeln)
    │       ├── Threat-Intel-Enrichment (NVD, EPSS, CISA KEV, ExploitDB)
    │       └── Business-Impact-Scoring
    │
    └── Finalize
            ├── tar.gz packen → MinIO (scan-rawdata/<orderId>.tar.gz)
            └── Report-Job in Queue (report-pending)
```

### Quelldateien

| Datei | Zweck | Zeilen |
|-------|-------|--------|
| `scanner/worker.py` | Haupt-Orchestrator | ~738 |
| `scanner/packages.py` | Paket-Konfigurationen | 139 |
| `scanner/phase0.py` | DNS-Reconnaissance | ~860 |
| `scanner/phase0a.py` | Passive Intelligence | ~218 |
| `scanner/phase1.py` | Technology Detection | ~445 |
| `scanner/phase2.py` | Deep Scan | ~1000 |
| `scanner/phase3.py` | Correlation & Enrichment | ~361 |
| `scanner/ai_strategy.py` | 4 KI-Entscheidungspunkte | 681 |
| `scanner/cms_fingerprinter.py` | CMS-Erkennung | ~400 |
| `scanner/tools/__init__.py` | Tool-Runner (subprocess) | ~209 |
| `scanner/tools/zap_client.py` | ZAP REST-API-Client | ~200 |
| `scanner/tools/zap_mapper.py` | ZAP-Alert → Finding-Mapping | ~200 |
| `scanner/tools/redirect_probe.py` | Playwright Redirect-Probe | ~200 |
| `scanner/passive/shodan_client.py` | Shodan API | ~150 |
| `scanner/passive/abuseipdb_client.py` | AbuseIPDB API | ~100 |
| `scanner/passive/securitytrails_client.py` | SecurityTrails API | ~150 |
| `scanner/passive/whois_client.py` | WHOIS Lookup | ~100 |
| `scanner/passive/dns_security.py` | DNSSEC, CAA, MTA-STS, DANE | ~250 |
| `scanner/correlation/correlator.py` | Cross-Tool-Korrelation | 386 |
| `scanner/correlation/fp_filter.py` | False-Positive-Filter | 254 |
| `scanner/correlation/business_impact.py` | Business-Impact-Scoring | 218 |
| `scanner/correlation/threat_intel.py` | NVD, EPSS, KEV, ExploitDB | 452 |

---

## 2. Paket-Konfigurationen

Quelle: `scanner/packages.py`

### Konfigurations-Matrix

| Parameter | WebCheck | Perimeter | Compliance | SupplyChain | Insurance | TLSCompliance |
|-----------|----------|-----------|------------|-------------|-----------|---------------|
| **total_timeout** | 1.200s (20 Min) | 7.200s (120 Min) | 7.200s | 7.200s | 7.200s | 600s (10 Min) |
| **max_hosts** | 3 | 15 | 15 | 15 | 15 | 15 |
| **phase0a_timeout** | 30s | 120s | 120s | 120s | 120s | 30s |
| **phase0b_timeout** | 300s | 900s | 900s | 900s | 900s | 300s |
| **phase3_timeout** | 120s | 300s | 300s | 300s | 300s | 0s |
| **nmap_ports** | `--top-ports 100` | `--top-ports 1000` | `--top-ports 1000` | `--top-ports 1000` | `--top-ports 1000` | `443,8443,993,...` |
| **zap_min_risk** | Low | Low | Low | Low | Low | Low |
| **skip_ai_decisions** | nein | nein | nein | nein | nein | **ja** |
| **testssl_severity** | (default) | (default) | (default) | (default) | (default) | `""` (alle) |

### Tools pro Phase und Paket

#### Phase 0a (Passive Intelligence)

| Tool | WebCheck | Perimeter+ | TLSCompliance |
|------|----------|------------|---------------|
| whois | x | x | x |
| shodan | - | x | - |
| abuseipdb | - | x | - |
| securitytrails | - | x | - |

#### Phase 0b (DNS-Recon)

| Tool | WebCheck | Perimeter+ | TLSCompliance |
|------|----------|------------|---------------|
| crtsh | x | x | x |
| subfinder | x | x | x |
| amass | - | x | - |
| gobuster_dns | - | x | - |
| axfr | - | x | - |
| dnsx | x | x | x |
| dnssec | x | x | x |
| caa | x | x | x |
| mta_sts | x | x | x |
| dane_tlsa | - | x | - |

#### Phase 1 (Tech Detection)

| Tool | WebCheck | Perimeter+ | TLSCompliance |
|------|----------|------------|---------------|
| nmap | x | x | x |
| webtech | x | x | - |
| wafw00f | x | x | - |
| cms_fingerprint | x | x | - |

#### Phase 2 (Deep Scan)

| Tool | WebCheck | Perimeter+ | TLSCompliance |
|------|----------|------------|---------------|
| zap_spider | x | x | - |
| zap_passive | x | - | - |
| zap_active | - | x | - |
| ffuf | - | x | - |
| feroxbuster | - | x | - |
| headers | x | x | x |
| httpx | x | x | - |
| wpscan | x | x | - |
| testssl | - | - | x |

#### Phase 3 (Enrichment)

| Tool | WebCheck | Perimeter+ | TLSCompliance |
|------|----------|------------|---------------|
| nvd | x | x | - |
| epss | - | x | - |
| cisa_kev | x | x | - |
| exploitdb | - | x | - |
| correlator | x | x | - |
| fp_filter | x | x | - |
| business_impact | - | x | - |

### Legacy-Aliase

```python
"basic"        → "webcheck"
"professional" → "perimeter"
"nis2"         → "compliance"
```

**Compliance, SupplyChain und Insurance** teilen sich die identische Perimeter-Scan-Konfiguration. Die Unterschiede liegen ausschließlich in der Report-Generierung (Prompts, Mapper, PDF-Sektionen, Compliance-Module).

---

## 3. Phase 0a: Passive Intelligence

Quelle: `scanner/phase0a.py`

Passive Datensammlung **ohne aktiven Kontakt** zum Ziel. Alle Tools laufen parallel.

### 3.1 WHOIS Lookup

| Parameter | Wert |
|-----------|------|
| **Befehl** | `whois <domain>` |
| **Timeout** | 30s |
| **Pakete** | alle |

**Extrahierte Felder:**
- `registrar` — Registrar-Name
- `creation_date` — Registrierungsdatum
- `expiration_date` — Ablaufdatum
- `name_servers` — Liste der Nameserver
- `dnssec` — DNSSEC-Status
- `registrant_country` — Land des Registranten

**Fallback:** Gibt `None` bei jedem Fehler zurück.

### 3.2 Shodan API

| Parameter | Wert |
|-----------|------|
| **Base-URL** | `https://api.shodan.io` |
| **API-Key** | `SHODAN_API_KEY` (Env) |
| **Timeout** | 10s pro Request |
| **Pakete** | Perimeter+ |
| **IP-Limit** | max. 15 IPs |

**Endpoints:**
1. `GET /dns/domain/{domain}` → Subdomains + IPs
2. `GET /shodan/host/{ip}` → Offene Ports, Services, Versionen, Banner

**Rate-Limiting:** HTTP 429 → exponentieller Backoff (2^attempt × 2s, max 30s).

**Output pro IP:**
```json
{
  "ip": "192.0.2.1",
  "ports": [22, 80, 443],
  "os": "Linux",
  "tags": [],
  "services": [
    {"port": 443, "product": "nginx", "version": "1.18"}
  ]
}
```

### 3.3 AbuseIPDB API

| Parameter | Wert |
|-----------|------|
| **Base-URL** | `https://api.abuseipdb.com/api/v2` |
| **Endpoint** | `GET /check` |
| **API-Key** | `ABUSEIPDB_API_KEY` (Header: `Key`) |
| **Parameter** | `ipAddress`, `maxAgeInDays=90`, `verbose=true` |
| **Timeout** | 10s |
| **Pakete** | Perimeter+ |
| **IP-Limit** | max. 15 IPs |

**Output pro IP:**
```json
{
  "abuseConfidenceScore": 42,
  "totalReports": 15,
  "isTor": false,
  "countryCode": "DE",
  "isp": "Hetzner",
  "domain": "example.com"
}
```

### 3.4 SecurityTrails API

| Parameter | Wert |
|-----------|------|
| **Base-URL** | `https://api.securitytrails.com/v1` |
| **API-Key** | `SECURITYTRAILS_API_KEY` (Header: `apikey`) |
| **Timeout** | 10s |
| **Pakete** | Perimeter+ |

**Drei Endpoints:**
1. `GET /domain/{domain}` → Aktuelle DNS-Records (A, MX, NS, TXT)
2. `GET /domain/{domain}/subdomains` → Bekannte Subdomains
3. `GET /history/{domain}/dns/a` → DNS-Änderungshistorie (max. 20 Einträge)

### 3.5 DNS-Security-Checks

Quelle: `scanner/passive/dns_security.py`

#### DNSSEC-Validierung

| Befehl | Zweck |
|--------|-------|
| `dig <domain> DNSKEY +short +time=5 +tries=2` | DNSKEY-Records |
| `dig <domain> DS +short +time=5 +tries=2` | DS-Records (Delegation Signer) |
| `dig <domain> RRSIG +short +time=5 +tries=2` | RRSIG-Records (Signaturen) |
| `drill -S <domain>` (Timeout: 15s) | Chain-of-Trust-Validierung |

**Algorithmus-Erkennung:**

| ID | Algorithmus |
|----|-------------|
| 5 | RSASHA1 |
| 7 | RSASHA1-NSEC3 |
| 8 | RSASHA256 |
| 10 | RSASHA512 |
| 13 | ECDSAP256SHA256 |
| 14 | ECDSAP384SHA384 |
| 15 | ED25519 |
| 16 | ED448 |

**Issue-Detection:** Warnt bei veralteten SHA-1-Algorithmen.

#### CAA-Records

```bash
dig <domain> CAA +short +time=5 +tries=2
```

Output: `has_caa`, `records` (Liste), `issuers` (autorisierte CAs).

#### MTA-STS

```bash
dig _mta-sts.<domain> TXT +short +time=5 +tries=2
curl https://mta-sts.<domain>/.well-known/mta-sts.txt  # Timeout 5s
```

Output: `has_dns_record`, `has_policy`, `mode` (enforce/testing/none).

#### DANE/TLSA (nur Perimeter+)

```bash
dig <domain> MX +short                   # Mailserver ermitteln
dig _25._tcp.<mx> TLSA                   # SMTP-TLSA pro MX (max 3)
dig _443._tcp.<domain> TLSA              # HTTPS-TLSA
```

Output: `has_smtp_dane`, `has_https_dane`, `smtp_tlsa` (pro MX), `https_tlsa`.

---

## 4. Phase 0b: DNS-Reconnaissance

Quelle: `scanner/phase0.py`

Aktive Subdomain-Enumeration und DNS-Validierung. Alle Discovery-Tools laufen **parallel** mit `ThreadPoolExecutor(max_workers=6)`.

### 4.1 Certificate Transparency (crt.sh)

```bash
curl -s -o <output_file> "https://crt.sh/?q=%.<domain>&output=json"
```

| Parameter | Wert |
|-----------|------|
| **Timeout** | 60s |
| **Pakete** | alle |
| **Parsing** | `name_value`-Feld, Wildcard-Einträge (`*.`) entfernen, deduplizieren |

### 4.2 Subfinder

```bash
subfinder -d <domain> -silent -json -disable-update-check -o <output_path>
```

| Parameter | Wert |
|-----------|------|
| **Timeout** | 120s |
| **Pakete** | alle |
| **Output** | JSON Lines (ein Eintrag pro Zeile) |

### 4.3 Amass

```bash
amass enum -passive -d <domain> -json <output_path>
```

| Parameter | Wert |
|-----------|------|
| **Timeout** | 300s (5 Min) |
| **Pakete** | Perimeter+ |
| **Output** | JSON Lines |

### 4.4 Gobuster DNS

```bash
gobuster dns --domain <domain> --wordlist /usr/share/wordlists/subdomains-top5000.txt -q -o <output_path>
```

| Parameter | Wert |
|-----------|------|
| **Timeout** | 180s (3 Min) |
| **Pakete** | Perimeter+ |
| **Wordlist** | 5.000 häufigste Subdomains |
| **Output** | Text (plain hostnames) |

### 4.5 AXFR (Zone Transfer)

```bash
dig NS <domain> +short +time=5 +tries=2    # Nameserver ermitteln
dig @<nameserver> <domain> AXFR             # Zone Transfer pro NS
```

| Parameter | Wert |
|-----------|------|
| **NS-Lookup-Timeout** | 15s |
| **AXFR-Timeout** | 30s pro Nameserver |
| **Pakete** | Perimeter+ |
| **Erfolgskriterium** | > 2 Records (nicht nur SOA) |

### 4.6 dnsx (DNS-Validierung)

```bash
dnsx -l <wordlist_file> -a -aaaa -cname -resp -json -o <output_path>
```

| Parameter | Wert |
|-----------|------|
| **Timeout** | 60s |
| **Pakete** | alle |
| **Input** | Alle Subdomains aus vorherigen Tools (Temp-Datei) |
| **Output** | JSON Lines (A, AAAA, CNAME mit Responses) |

### 4.7 DNS-Record-Sammlung (dig)

| Record | Befehl | Timeout |
|--------|--------|---------|
| SPF | `dig <domain> TXT +short` → Pattern `v=spf1` | 10s |
| DMARC | `dig _dmarc.<domain> TXT +short` → Pattern `v=dmarc1` | 10s |
| DKIM | `dig default._domainkey.<domain> TXT +short` → Pattern `v=dkim1` | 10s |
| MX | `dig <domain> MX +short` | 10s |
| NS | `dig <domain> NS +short` | 10s |

### 4.8 Post-Processing: Merge & Group

Funktion: `merge_and_group()`

1. **Deduplizierung** aller gefundenen Subdomains
2. **Gruppierung** nach IP-Adresse → Host-Inventar
3. **Socket-Fallback** für Dangling CNAMEs und nicht aufgelöste Subdomains (5s pro FQDN)
4. **Host-Priorisierung:**
   - Priorität 0: Basisdomain selbst
   - Priorität 1: `www.<domain>`
   - Priorität 2: Andere Subdomains (Web, Portale, Apps)
   - Priorität 3: Mail/Autodiscover/MX (deprioritisiert)
5. **Host-Limit-Enforcement:** Überschüssige Hosts → `skipped_hosts`

### 4.9 Web-Probe

Pro FQDN (max. 3 pro Host):

```bash
httpx -u <fqdn> -json -silent -follow-redirects -status-code -title -timeout 5
```

**Parking-Page-Erkennung** (Patterns):
- `"domain not configured"`, `"nicht konfiguriert"`
- `"froxlor"`, `"plesk"`, `"cpanel"`
- `"this domain is parked"`, `"coming soon"`
- `"default web page"`, `"welcome to nginx"`

**Output pro Host:**
```json
{
  "has_web": true,
  "status": 200,
  "final_url": "https://www.example.com/",
  "title": "Example Corp",
  "web_fqdn": "www.example.com"
}
```

---

## 5. KI-Entscheidung 1: Host Strategy

Quelle: `scanner/ai_strategy.py`, Funktion `plan_host_strategy()`

| Parameter | Wert |
|-----------|------|
| **Modell** | Claude Haiku 4.5 (`claude-haiku-4-5-20251001`) |
| **Max Tokens** | 8.192 |
| **Aufgerufen** | Nach Phase 0, vor Phase 1 |
| **Übersprungen bei** | `skip_ai_decisions=True` (nur TLSCompliance) |

### System-Prompt (vollständig)

```
Du bist ein Security-Scanner-Orchestrator. Du entscheidest, welche Hosts
gescannt werden und mit welcher Priorität.

WICHTIG ZU FQDNs:
- Jeder Host hat eine Liste von FQDNs die auf dieselbe IP zeigen
- Die ERSTE FQDN in der Liste ist die relevanteste (Basisdomain vor www
  vor Subdomains)
- Wenn ein Host sowohl die Basisdomain als auch Mail-FQDNs enthält, ist
  er IMMER ein Web-Host
- Beurteile den Host nach seiner wichtigsten FQDN, nicht nach
  Mail-Subdomains

WEB-PROBE DATEN:
- Jeder Host kann ein "web_probe" Feld haben mit has_web, status,
  final_url, title
- has_web=true: HTTP-Content vorhanden → Web-Scan (alle Tools)
- has_web=false: Kein HTTP-Content → Port-Scan (nmap + testssl reichen)
- final_url zeigt wohin Redirects führen → die relevante Scan-URL

PASSIVE INTELLIGENCE (wenn verfügbar):
- Jeder Host kann ein "passive_intel" Feld haben mit Daten aus Shodan,
  AbuseIPDB, WHOIS:
  - shodan_ports: Bereits bekannte offene Ports pro IP
  - shodan_services: Service-Versionen (z.B. {"443": "nginx 1.18",
    "22": "OpenSSH 7.9"})
  - abuseipdb_score: IP-Reputation (0-100, höher = verdächtiger)
  - is_tor: Ob die IP ein Tor-Exit-Node ist
  - dnssec_signed: Ob die Domain DNSSEC-signiert ist
  - whois_expiration: Domain-Ablaufdatum

ERWEITERTE REGELN (Passive Intel):
- Hosts mit veralteten Service-Versionen aus Shodan (alte OpenSSH, alte
  nginx) → Priorität 1
- Hosts mit exponierten Management-Ports (22, 3389, 5900, 8080, 8443)
  aus Shodan → Priorität 1
- Hosts mit hohem AbuseIPDB-Score (>50) → Priorität 1 (mögliche
  Kompromittierung)
- Hosts mit nur Port 80/443 und niedrigem AbuseIPDB-Score → Priorität 2
- Mailserver mit fehlender SPF/DMARC → scannen (nicht skippen!)

STANDARD-REGELN:
- Basisdomain und www-Subdomain: IMMER scannen (action: "scan"),
  höchste Priorität
- Webserver mit interaktivem Content (Apps, APIs, CMS, Shops): scan
  (hohe Priorität)
- Mailserver (MX, SMTP, IMAP): scan mit NIEDRIGERER Priorität —
  NICHT skippen!
- Autodiscover-Hosts (nur Exchange/Outlook-Konfiguration): skip
- Parking-Pages, Redirect auf externe Domain: skip
- CDN-Edge-Nodes (nur CDN-IP, kein eigener Content): skip (außer bei
  has_web=true mit eigenem Content)
- Wenn unklar: lieber scannen als überspringen

Jeder Host braucht eine kurze Begründung (1 Satz).
Priority: 1 = höchste Priorität, aufsteigend.

Antworte NUR mit validem JSON, kein anderer Text.
```

### User-Prompt-Template

```
Domain: {domain}
Paket: {package}

Gefundene Hosts ({count}):
{hosts_json}

DNS-Findings:
{dns_findings_json}

Entscheide für jeden Host: scan oder skip?
Antwort im Format:
{SCHEMA}
```

### Erwartetes Output-Schema

```json
{
  "hosts": [
    {
      "ip": "192.168.1.1",
      "action": "scan|skip",
      "priority": 1,
      "reasoning": "Kurze Begründung",
      "scan_hints": {
        "shodan_ports": [21, 22, 80, 443],
        "focus_areas": ["web_vulns", "ssl", "ftp_security"]
      }
    }
  ],
  "strategy_notes": "Kurze Zusammenfassung der Strategie",
  "passive_intel_summary": "Was die Passive Intelligence ergeben hat"
}
```

### Fallback bei Fehler

Wenn JSON-Parsing fehlschlägt oder API nicht erreichbar: **Alle Hosts scannen** in Original-Reihenfolge mit Fallback-Reasoning.

```python
{"ip": h["ip"], "action": "scan", "priority": i + 1,
 "reasoning": f"Fallback — {reason}"}
```

---

## 6. Phase 1: Technology Detection

Quelle: `scanner/phase1.py`

Pro Host parallel mit `ThreadPoolExecutor(max_workers=3)`. Vor jedem Host: TCP-Reachability-Check auf Port 80/443 (5s Timeout) — unerreichbare Hosts werden übersprungen.

### 6.1 nmap (Service/Version Detection)

```bash
nmap -sV -sC -T4 <nmap_port_args> -oX <xml_output> -oN <text_output> <ip>
```

| Parameter | Wert |
|-----------|------|
| **Timeout** | 300s |
| **Pakete** | alle |
| **Flags** | `-sV` (Service-Versionen), `-sC` (Default-NSE-Scripts), `-T4` (Aggressives Timing) |
| **Port-Args** | WebCheck: `--top-ports 100`, Perimeter+: `--top-ports 1000`, TLSCompliance: `443,8443,993,995,465,587,636,989,990,5061` |
| **Output** | XML + Text |
| **Parsing** | ElementTree XML-Parsing → `open_ports`, `services` (port, name, product, version) |

### 6.2 webtech (Technology Detection)

**Primär:** Playwright-basiert (Headless Chromium)

| Parameter | Wert |
|-----------|------|
| **Timeout** | 60s pro Scheme |
| **Pakete** | WebCheck, Perimeter+ |
| **Scheme-Reihenfolge** | HTTPS zuerst, Fallback HTTP |
| **Max FQDNs** | bis zu 8 pro Host |

**Gesammelte Technologie-Indikatoren:**
- `<meta name="generator">` Tag
- `X-Powered-By` Header
- `Server` Header (als Name/Version geparst)
- JS-Evaluation: Scripts, Stylesheets, Meta-Tags, Cookies

**Fallback:** `webtech -u <url> --json` (CLI-Tool) wenn Playwright nicht verfügbar.

### 6.3 wafw00f (WAF Detection)

```bash
wafw00f <fqdn> -o <output_path> -f json
```

| Parameter | Wert |
|-----------|------|
| **Timeout** | 60s |
| **Pakete** | WebCheck, Perimeter+ |
| **Output** | JSON-Array |
| **Parsing** | `firewall`-Feld aus erstem Ergebnis (exkludiert "none") |

### 6.4 CMS-Fingerprinting-Engine

Quelle: `scanner/cms_fingerprinter.py`

Klasse: `CMSFingerprinter` — max. 20 HTTP-Requests pro Host, Early-Exit bei Konfidenz ≥ 0.70.

#### 5 Erkennungsmethoden (werden gemergt mit Konfidenz-Boost):

**Methode 1: Webtech-Analyse** — CMS aus Phase-1-webtech-Output extrahieren.
- CMS-Liste: WordPress, Joomla, Drupal, TYPO3, Magento, Shopify, Shopware, Wix, PrestaShop, Contao, NEOS, Craft, Strapi, Ghost
- Konfidenz: 0.70–0.80

**Methode 2: Meta-Tag-Analyse** — `GET https://<fqdn>/` (Fallback HTTP)
- `<meta name="generator">` → Regex-Extraktion
- `X-Generator`, `X-Powered-By` Header (case-insensitive)
- Cookie-Analyse (piggybacked)
- Konfidenz: 0.75–0.90, Timeout: 5s pro Request

**Methode 3: Probe-Matrix** — CMS-spezifische Pfade proben

| CMS | Probe-Pfade | Body-Pattern | Konfidenz |
|-----|-------------|--------------|-----------|
| WordPress | `/wp-login.php`, `/wp-admin/`, `/wp-content/` | `wp-`, `wordpress` | 0.95 |
| Shopware 5 | `/backend/admin`, `/web/css/` | `shopware` | 0.90 |
| Shopware 6 | `/api/_info/config`, `/store-api/context` | `shopware` | 0.90 |
| TYPO3 | `/typo3/`, `/typo3conf/` | `typo3` | 0.90 |
| Joomla | `/administrator/` | `joomla` | 0.90 |
| Contao | `/contao/` | `contao` | 0.85 |
| Drupal | `/user/login`, `/core/misc/drupal.js` | `drupal` | 0.90 |
| Magento | `/admin/`, `/checkout/cart/` | `magento`, `mage` | 0.85 |
| NEOS | `/neos/` | `neos-` | 0.80 |
| Craft CMS | `/admin/login` | `craft` | 0.85 |
| Strapi | `/admin/`, `/_health` | `strapi` | 0.80 |
| Ghost | `/ghost/` | `ghost-` | 0.85 |
| PrestaShop | `/admin/login`, `/modules/` | `prestashop` | 0.80 |

- HTTP-Methode: GET, Timeout: 5s
- Status 200 + 301–308 akzeptiert; 404 abgelehnt; Cross-Domain-Redirects abgelehnt
- **Konfidenz-Penalty:** Pfad gefunden aber kein Body-Match → 0.3 (schwaches Signal)

**Methode 4: Cookie-Analyse**

| Cookie-Pattern | CMS |
|----------------|-----|
| `wordpress_logged_in`, `wp-settings` | WordPress |
| `sw-states`, `sw-context-token` | Shopware 6 |
| `session-` | Shopware 5 |
| `fe_typo_user` | TYPO3 |
| `mosvisitor`, `joomla_` | Joomla |
| `contao_` | Contao |
| `SSESS`, `Drupal.visitor` | Drupal |
| `CraftSessionId` | Craft CMS |
| `ghost-admin` | Ghost |
| `PrestaShop` | PrestaShop |

Konfidenz: 0.80

**Methode 5: Response-Headers** — `x-generator`, `x-powered-by`, `x-content-powered-by` (Regex, case-insensitive). Konfidenz: 0.75.

#### Merging-Logik

1. Kandidaten nach CMS gruppieren (case-insensitive)
2. Base-Konfidenz = höchste im Cluster
3. Boost: +0.05 pro zusätzliche bestätigende Methode (max +0.15)
4. Finale Konfidenz: `min(base + boost, 0.99)`
5. Version: spezifischste vom höchstkonfidenten Kandidat

### Phase-1-Output: tech_profile.json

```json
{
  "ip": "192.0.2.1",
  "fqdns": ["example.com", "www.example.com"],
  "cms": "WordPress",
  "cms_version": "6.0",
  "cms_confidence": 0.95,
  "cms_details": {},
  "server": "Apache/2.4.41",
  "waf": "Cloudflare",
  "open_ports": [80, 443, 22],
  "has_ssl": true,
  "has_web": true,
  "web_fqdn": "www.example.com",
  "redirect_data": {}
}
```

---

## 7. KI-Entscheidung 2: Tech Analysis

Quelle: `scanner/ai_strategy.py`, Funktion `plan_tech_analysis()`

| Parameter | Wert |
|-----------|------|
| **Modell** | Claude Haiku 4.5 (`claude-haiku-4-5-20251001`) |
| **Max Tokens** | 8.192 |
| **Aufgerufen** | Nach Phase 1, vor Phase 2 |

### System-Prompt (vollständig)

```
Du bist ein Web-Technologie-Analyst. Du bestimmst die korrekte
Technologie für jeden Host basierend auf Redirect-Verhalten,
HTTP-Headern und Scan-Ergebnissen.

REGELN:
- Wenn eine FQDN auf eine ANDERE Domain redirected → die FQDN nutzt
  NICHT das CMS dieser anderen Domain
- Wenn /wp-login.php existiert aber Body "nicht gefunden", "not found"
  oder "404" enthält → KEIN WordPress
- Wenn /wp-login.php auf eine andere Domain redirected → KEIN WordPress
  auf DIESER Domain
- Page Title "Outlook Web App" oder "OWA" → Microsoft Exchange,
  KEIN WordPress/CMS
- Page Title mit "TYPO3" oder "Neos" → TYPO3
- meta generator Tag hat Vorrang vor Pfad-Probes
- IIS Server + .aspx/.asmx Pfade → Microsoft-Stack, KEIN PHP-CMS
- Wenn CMS-Fingerprinter WordPress mit hoher Konfidenz (>0.8) meldet
  UND /wp-login.php tatsächlich WordPress-Login zeigt → WordPress
  bestätigt
- Wenn CMS-Fingerprinter WordPress meldet ABER /wp-login.php zeigt
  Fehlerseite → WordPress NICHT bestätigt, CMS auf null setzen

WICHTIG:
- Nur CMS melden wenn du sicher bist. Im Zweifel: cms=null
- technology_stack ist eine Liste aller erkannten Technologien
  (Server, Sprache, Framework)
- is_spa=true nur wenn React, Vue, Angular, Next.js, Nuxt oder
  Shopware 6 erkannt

Antworte NUR mit validem JSON, kein anderer Text.
```

### Erwartetes Output-Schema

```json
{
  "hosts": {
    "<ip>": {
      "cms": "WordPress|TYPO3|Shopware|Joomla|Drupal|Exchange|null",
      "cms_version": "6.8|null",
      "cms_confidence": 0.95,
      "technology_stack": ["nginx", "PHP 8.2", "WordPress"],
      "is_spa": false,
      "reasoning": "Kurze Begründung"
    }
  }
}
```

### Fallback

Bei JSON-Fehler: leeres Dict zurückgeben, CMS-Korrekturen überspringen.

---

## 8. KI-Entscheidung 3: Phase-2-Config

Quelle: `scanner/ai_strategy.py`, Funktion `plan_phase2_config()`

| Parameter | Wert |
|-----------|------|
| **Modell** | Claude Haiku 4.5 (`claude-haiku-4-5-20251001`) |
| **Max Tokens** | 8.192 |
| **Aufgerufen** | Pro Host, nach Phase 1, vor Phase 2 |

### System-Prompt (vollständig)

```
Du bist ein Security-Scanner-Orchestrator. Du konfigurierst
Phase-2-Scan-Tools optimal basierend auf dem erkannten Tech-Stack
eines Hosts.

ZAP-KONFIGURATION (OWASP ZAP Daemon):
- zap_scan_policy: "passive-only"|"waf-safe"|"standard"|"aggressive"
  (Default: "standard")
  - "passive-only": Kein Active Scan (WebCheck-Default, wird
    automatisch gesetzt)
  - "waf-safe": Reduzierte Intensität, langsamer — für Hosts hinter WAF
  - "standard": Gute Balance zwischen Coverage und Laufzeit (Default)
  - "aggressive": Alle Scan-Rules, hohe Intensität — nur bei
    verdächtigen Hosts
- zap_spider_max_depth: 3–7 (Default: 5). SPAs/JS-Heavy Apps: 6-7.
  Statische Seiten: 3.
- zap_ajax_spider_enabled: true für SPA-Frameworks (React, Vue,
  Angular, Next.js, Nuxt, Shopware 6), false sonst
- zap_active_categories: Aktivierte Active-Scan-Kategorien:
  - "sqli" — SQL Injection
  - "xss" — Cross-Site Scripting (reflected + stored)
  - "lfi" — Local File Inclusion / Path Traversal
  - "rfi" — Remote File Inclusion
  - "ssrf" — Server-Side Request Forgery
  - "cmdi" — Command Injection
  - "xxe" — XML External Entity
  - "crlf" — CRLF Injection
  Bei PHP-Servern: sqli, xss, lfi, rfi, cmdi
  Bei Java/Spring/Tomcat: sqli, xss, lfi, xxe, cmdi
  Bei Node.js/Express: xss, ssrf, cmdi, crlf
  Bei statischen Seiten: nur xss
- zap_rate_req_per_sec: 15–80 (Default: 80). Bei WAF: 15. Ohne WAF: 80.
- zap_threads: 2–5 (Default: 5). Bei WAF: 2. Ohne WAF: 5.
- zap_spider_delay_ms: 0–800 (Default: 0). Bei WAF: 800. Ohne WAF: 0.
- zap_extra_urls: [] — Zusätzliche URLs für offene Non-Standard-Ports
  (z.B. 8080, 8443, 9090)

WAF-SIGNAL → ZAP-DEFAULTS:
WAF erkannt (Cloudflare, Akamai, Sucuri, Imperva, F5 etc.):
→ zap_scan_policy: "waf-safe", zap_rate_req_per_sec: 15, zap_threads: 2,
  zap_spider_delay_ms: 800
Keine WAF:
→ zap_scan_policy: "standard" oder "aggressive",
  zap_rate_req_per_sec: 80, zap_threads: 5, zap_spider_delay_ms: 0

TOOLS DIE ÜBERSPRUNGEN WERDEN KÖNNEN:
feroxbuster, zap_ajax_spider

WANN feroxbuster ÜBERSPRINGEN:
- Große Webshops/CMS mit vielen Produktseiten (Shopware, Magento,
  WooCommerce mit >1000 Seiten) — ZAP Spider findet bereits umfangreiche
  URLs
- Hosts hinter aggressiver WAF (Cloudflare etc.) — feroxbuster erzeugt
  viele 403er ohne Mehrwert
- Reine API-Hosts ohne Web-Frontend

WICHTIG FÜR skip_tools:
- Für die Basisdomain und www-Subdomain: skip_tools MUSS IMMER leer
  sein []
- Für Hosts mit Web-Content (has_web=true) und kleinen/mittleren
  Seiten: skip_tools leer lassen
- skip_tools nur für reine API-Hosts, reine Mailserver, minimale
  Services, oder große Webshops (nur feroxbuster)
- Im Zweifel: skip_tools leer lassen — lieber ein Tool zu viel als
  wichtige Findings verpassen

REGELN:
- Bei WAF vorhanden: ZAP auf waf-safe setzen
- zap_ajax_spider_enabled=true nur wenn SPA/JS-Framework erkannt
- Bei WordPress: wpscan wird automatisch aktiviert

Antworte NUR mit validem JSON, kein anderer Text.
```

### Erwartetes Output-Schema

```json
{
  "zap_scan_policy": "standard",
  "zap_spider_max_depth": 5,
  "zap_ajax_spider_enabled": true,
  "zap_active_categories": ["sqli", "xss", "lfi", "ssrf"],
  "zap_rate_req_per_sec": 80,
  "zap_threads": 5,
  "zap_spider_delay_ms": 0,
  "zap_extra_urls": [],
  "skip_tools": [],
  "reasoning": "Kurze Begründung der Konfiguration"
}
```

### Fallback-Konfiguration

```python
{
    "zap_scan_policy": "standard",
    "zap_spider_max_depth": 5,
    "zap_ajax_spider_enabled": False,
    "zap_active_categories": ["sqli", "xss", "lfi", "ssrf", "cmdi"],
    "zap_rate_req_per_sec": 80,
    "zap_threads": 5,
    "zap_spider_delay_ms": 0,
    "zap_extra_urls": [],
    "skip_tools": [],
    "reasoning": f"Fallback — {reason}",
}
```

### Basisdomain-Override

Wenn der Host die Basisdomain oder `www.<domain>` enthält, wird die `skip_tools`-Liste der KI ignoriert — die Basisdomain wird **immer vollständig gescannt**.

---

## 9. Phase 2: Deep Scan

Quelle: `scanner/phase2.py`

### Parallelitäts-Steuerung

- Wenn ZAP-Tools (`zap_spider`, `zap_active`, `zap_passive`) konfiguriert: `max_workers=1` (ZAP-Daemon ist ein Singleton)
- Sonst: `max_workers=5`

### 3-Stufen-Pipeline pro Host

#### Stage 1: Discovery (parallel, 3 Worker)

##### ZAP Spider (Traditional + AJAX)

Quelle: `scanner/tools/zap_client.py`

**Architektur:** REST-API-Client zum ZAP-Daemon auf Port 8090 (Container-basiert).

**Kontext-Isolation:** Jeder Scan bekommt einen eigenen Kontext: `ctx-{order_id[:8]}-{ip}`

**Traditional Spider:**

| Endpoint | `POST /JSON/spider/action/scan/` |
|----------|------|
| **Parameter** | `url`, `maxChildren=0`, `recurse=true`, `contextName` |
| **Max Depth** | Konfigurierbar (Default: 5) |
| **Polling** | `GET /JSON/spider/view/status/` alle 5s bis 100% |
| **Timeout** | WebCheck: 120s, Perimeter: 180s |

**AJAX Spider** (nur wenn `zap_ajax_spider_enabled=true`):

| Endpoint | `POST /JSON/ajaxSpider/action/scan/` |
|----------|------|
| **Polling** | `GET /JSON/ajaxSpider/view/status/` alle 10s bis "stopped" |
| **Timeout** | 240s |
| **Stop** | `POST /JSON/ajaxSpider/action/stop/` bei Timeout |

**Rate-Limiting:**

| Parameter | Default | Bei WAF |
|-----------|---------|---------|
| req/sec | 80 | 15 |
| Threads | 5 | 2 |
| Delay (ms) | 0 | 800 |

##### testssl.sh

```bash
bash /opt/testssl.sh/testssl.sh \
  --jsonfile <output_path> --quiet --ip one --warnings off \
  --sneaky --hints [--severity <level>] --nodns min \
  https://<fqdn>
```

| Parameter | Wert |
|-----------|------|
| **Timeout** | 300s |
| **Bedingung** | Nur wenn `has_ssl=true` |
| **Severity-Filter** | Default: `MEDIUM` (MEDIUM+), TLSCompliance: `""` (alle inkl. OK/INFO) |
| **Exit-Codes** | 0 und 1 = Erfolg, Rest = Fehler |

Flags:
- `--quiet` — Banner unterdrücken
- `--ip one` — Single-IP-Probe
- `--warnings off` — Keine unkritischen Warnungen
- `--sneaky` — WAF-Trigger vermeiden
- `--hints` — Hinweise zu Findings
- `--nodns min` — Minimale DNS-Abfragen

##### HTTP-Security-Headers

```bash
curl -sI https://<fqdn>
```

| Parameter | Wert |
|-----------|------|
| **Timeout** | 10s |
| **Pakete** | alle |

**Geprüfte Header (7 Stück):**
1. X-Frame-Options
2. X-Content-Type-Options
3. Strict-Transport-Security (HSTS)
4. Content-Security-Policy (CSP)
5. X-XSS-Protection
6. Referrer-Policy
7. Permissions-Policy

**Output:** Score (present_count / 7)

##### httpx

```bash
httpx -u <fqdn> -json -o <output_path> -status-code -title \
  -tech-detect -server -content-length -follow-redirects -silent
```

| Parameter | Wert |
|-----------|------|
| **Timeout** | 60s |
| **Pakete** | WebCheck, Perimeter+ |

#### Stage 2: Deep Scan (parallel, Spider-URLs als Input)

##### ZAP Active Scan (nur Perimeter+)

| Endpoint | `POST /JSON/ascan/action/scan/` |
|----------|------|
| **Parameter** | `url`, `contextId`, `scanPolicyName`, `recurse=true` |
| **Timeout** | 600s (10 Min) |
| **Polling** | `GET /JSON/ascan/view/status/` alle 10s bis 100% |

**Custom Scan Policies:** Pro Scan erstellt mit Name `policy-{order_id[:8]}-{ip}`:
- Alle Scanner zunächst deaktiviert
- Nur angeforderte Kategorien aktiviert
- Attack Strength + Alert Threshold pro Policy-Typ gesetzt

**Scanner-Kategorien (ZAP Plugin IDs):**

| Kategorie | Plugin-IDs |
|-----------|------------|
| sqli | 40018, 40019, 40020, 40021, 40022, 40024 |
| xss | 40012, 40014, 40016, 40017 |
| lfi | 6, 40009 |
| rfi | 7 |
| ssrf | 40046 |
| cmdi | 90020 |
| xxe | 90023 |
| crlf | 40003 |

**Verbotene Scanner (werden nie aktiviert):**
- 40032 (DoS)
- 30001, 30002 (Buffer Overflow)
- 40033, 40034 (Fuzzer)

##### ffuf (Web Fuzzer)

| Parameter | Wert |
|-----------|------|
| **Timeout** | 180s |
| **Threads** | 40 |
| **Rate** | 100 req/s |
| **Pro-Request-Timeout** | 5s |
| **Pakete** | Perimeter+ |

**3 Modi (KI-adaptiv):**

**Modus 1: Directory Discovery**
```bash
ffuf -u https://<fqdn>/FUZZ -w <wordlist> -e .php,.html,.js,.bak \
  -mc 200,301,302,403 -fc 404 -t 40 -rate 100 -timeout 5 \
  -json -o <output_path> -s
```
Wordlist: SecLists `Discovery/Web-Content/common.txt`

**Modus 2: Virtual Host Discovery**
```bash
ffuf -u https://<ip>/ -H "Host: FUZZ.<domain>" -w <wordlist> \
  -mc 200,301,302 -json -o <output_path> -t 40 -rate 100 -timeout 5 -s
```
Wordlist: SecLists `Discovery/DNS/subdomains-top1million-5000.txt`

**Modus 3: Parameter Discovery**
```bash
ffuf -u <url>?FUZZ=test -w <wordlist> \
  -mc 200 -json -o <output_path> -t 40 -rate 100 -timeout 5 -s
```
Wordlist: SecLists `Discovery/Web-Content/burp-parameter-names.txt`

##### feroxbuster (Rekursives Directory Brute-Force)

```bash
feroxbuster -u https://<fqdn> -w <wordlist> -d <depth> -t 30 \
  --rate-limit 100 -s 200,301,302,403 --json -o <output_path> \
  --dont-scan logout|signout|delete --timeout 5 --no-recursion --silent
```

| Parameter | Wert |
|-----------|------|
| **Timeout** | 150s |
| **Tiefe** | max 2 (KI-konfigurierbar) |
| **Threads** | 30 |
| **Rate-Limit** | 100 req/s |
| **Ausschluss-Pfade** | `logout`, `signout`, `delete` |
| **Pakete** | Perimeter+ |
| **Deduplizierung** | Gegen gobuster/ffuf-Ergebnisse (nach URL-Pfad) |

##### WPScan (WordPress-Scanner)

```bash
wpscan --url https://<fqdn> --format json --output <output_path> \
  --enumerate vp,vt,u1-5 --random-user-agent --no-banner \
  --disable-tls-checks [--api-token <token>]
```

| Parameter | Wert |
|-----------|------|
| **Timeout** | 600s (10 Min) |
| **Bedingung** | Nur wenn CMS = WordPress |
| **API-Token** | Optional (`WPSCAN_API_TOKEN` Env) |
| **Enumeration** | `vp` (vulnerable Plugins), `vt` (vulnerable Themes), `u1-5` (User 1–5) |
| **Exit-Codes** | 0 (keine Vulns) oder 5 (Vulns gefunden) = Erfolg |

#### Stage 3: Alert Collection

1. Warten auf ZAP Passive Scanner Queue (`GET /JSON/pscan/view/recordsToScan/` bis 0, Timeout 30s, Poll alle 3s)
2. Alle ZAP-Alerts sammeln (`GET /JSON/alert/view/alerts/`)
3. Domain-Filter anwenden (FQDNs müssen in Alert-URL vorkommen)
4. Mapping via `ZapAlertMapper` → Finding-Objekte

### ZAP-Alert-Mapping

Quelle: `scanner/tools/zap_mapper.py`

**Prozess:**
1. "False Positive" Confidence + "Informational" Risk filtern
2. Deduplizierung: gleiche `alertRef` + gleicher URL-Pfad → höchste Confidence behalten
3. Mapping zu Finding-Dicts

**Severity-Mapping:**

| ZAP Risk | VectiScan Severity | CVSS |
|----------|-------------------|------|
| High | high | 7.5 |
| Medium | medium | 5.3 |
| Low | low | 3.1 |
| Informational | info | 0.0 |

**Confidence-Multiplikator:**

| ZAP Confidence | Multiplikator |
|----------------|---------------|
| Confirmed | 1.0 |
| High | 0.9 |
| Medium | 0.7 |
| Low | 0.4 |
| False Positive | 0.0 |

---

## 10. KI-Entscheidung 4: Phase-3-Priorisierung

Quelle: `scanner/ai_strategy.py`, Funktion `plan_phase3_prioritization()`

| Parameter | Wert |
|-----------|------|
| **Modell** | Claude Sonnet 4.6 (`claude-sonnet-4-6`) |
| **Max Tokens** | 16.384 |
| **Aufgerufen** | Nach Phase 2, vor Phase 3, nur wenn >5 Findings |

### System-Prompt (vollständig)

```
Du bist ein Senior-Pentester der Findings aus verschiedenen
Security-Scanning-Tools analysiert.

AUFGABE:
Analysiere die aggregierten Findings und entscheide:
1. Welche Findings haben hohe Konfidenz? (von mehreren Tools bestätigt,
   Version passt)
2. Welche Findings haben niedrige Konfidenz? (nur ein Tool, kein Kontext)
3. Welche Findings sind wahrscheinlich False Positives?
   (Version-Mismatch, WAF-Artefakt, CMS-Mismatch)

KONFIDENZ-REGELN:
- Gleiche CVE aus mehreren Tools → hohe Konfidenz
- ZAP-Finding + passende Service-Version aus nmap → hohe Konfidenz
- ZAP-Finding für falsche Technologie (z.B. WordPress-spezifisch auf
  Shopware-Site) → False Positive
- testssl-Finding + ZAP-SSL-Finding → merge zu einem Finding
- wpscan-Finding + ZAP-Finding für gleiche Schwachstelle → hohe Konfidenz

PRIORISIERUNG:
- Findings mit CVSS ≥ 9.0 → immer "high" Priorität
- Findings mit aktiven Exploits → immer "high" Priorität
- Informational-Findings ohne Sicherheitswert → "low" Priorität

Antworte NUR mit validem JSON, kein anderer Text.
```

### User-Prompt-Template

```
Phase-2 Scan-Ergebnisse ({count} Findings, zeige die ersten
{truncated_count}):

{finding_summary_json}

Tech-Profiles der gescannten Hosts:
{tech_profiles_json}

WAF erkannt: {"Ja" | "Nein"}

Analysiere die Findings: Welche sind echt, welche sind False Positives?
Antwort im Format:
{SCHEMA}
```

**Input-Truncation:** Max. 100 Findings an die KI übergeben.

### Erwartetes Output-Schema

```json
{
  "high_confidence_findings": [
    {
      "finding_ref": "tool:title or CVE-ID",
      "confidence": 0.95,
      "corroboration": ["tool1_match", "version_confirmed"],
      "enrich_priority": "high"
    }
  ],
  "low_confidence_findings": [
    {
      "finding_ref": "tool:title or CVE-ID",
      "confidence": 0.3,
      "reason": "Nur ein Tool, keine Bestätigung",
      "enrich_priority": "low"
    }
  ],
  "potential_false_positives": [
    {
      "finding_ref": "tool:title or CVE-ID",
      "reason": "Version-Mismatch: Finding für nginx 1.18,
                 aber nmap erkennt 1.24"
    }
  ],
  "strategy_notes": "Zusammenfassung der Korrelationsanalyse"
}
```

### Anwendung der KI-Ergebnisse

FP-Vorschläge der KI werden auf die korrelierten Findings angewandt:

```python
for cf in correlated:
    ref = f"{cf.primary.tool}:{cf.primary.title}"
    cve_ref = cf.primary.cve_id or ""
    if ref in ai_fps or cve_ref in ai_fps:
        cf.is_false_positive = True
        cf.fp_reason = f"AI: {reason}"
```

### Fallback

```python
{
    "high_confidence_findings": [],
    "low_confidence_findings": [],
    "potential_false_positives": [],
    "strategy_notes": f"Fallback: programmatische Korrelation ({reason})",
}
```

---

## 11. Phase 3: Correlation & Enrichment

Quelle: `scanner/phase3.py`, `scanner/correlation/`

### 11.1 Finding-Extraktion

Quelle: `scanner/correlation/correlator.py`, Funktion `extract_findings()`

Normalisiert Findings aus allen Phase-2-Tools in kanonische `Finding`-Objekte:

| Quelle | Tool-Name | Severity-Mapping |
|--------|-----------|------------------|
| testssl-Entries | `testssl` | OK/INFO→info, LOW→low, MEDIUM→medium, HIGH/CRITICAL→high |
| Missing Headers | `header_check` | immer `low` |
| wpscan interesting_findings | `wpscan` | immer `medium` |
| ZAP-Alerts (pre-mapped) | `zap_active` / `zap_passive` | aus ZapAlertMapper |

### 11.2 Cross-Tool-Korrelation

Quelle: `scanner/correlation/correlator.py`, Klasse `CrossToolCorrelator`

#### Base-Confidence pro Tool

```python
TOOL_BASE_CONFIDENCE = {
    "nmap":         0.80,
    "testssl":      0.90,
    "wpscan":       0.85,
    "ffuf":         0.60,
    "feroxbuster":  0.60,
    "gobuster_dir": 0.60,
    "header_check": 0.95,
    "httpx":        0.70,
    "zap_passive":  0.85,
    "zap_active":   0.75,
}
```

Nicht gelistete Tools: Default `0.50`.

#### Korrelationsschritte (in Reihenfolge)

**Schritt 1: CVE-Match**
- Gleiche CVE-ID aus verschiedenen Tools → Merge
- Primary = Tool mit höchster Base-Confidence
- Boost: `+0.10` pro zusätzliches bestätigendes Tool
- Beispiel: testssl (0.90) + ZAP (0.75) auf gleiche CVE → 0.90 + 0.10 = 1.00 → Clamp 0.99

**Schritt 2: Non-CVE-Findings**
- Jedes Finding ohne CVE-Match → eigenes `CorrelatedFinding` mit Base-Confidence

**Schritt 3: Tech-Version-Boost**
- Wenn die Technologie des Findings auf dem Host erkannt wurde (webtech/httpx) → `+0.05`

**Schritt 4: Shodan-Boost**
- Wenn der Port des Findings in Shodan-Services für diese IP vorkommt → `+0.10`

**Schritt 5: Cluster-Bildung**

| Cluster-ID | Auslöser |
|------------|----------|
| `transport_security_{ip}` | SSL/TLS Findings, testssl |
| `security_headers_{ip}` | Header-Findings, header_check |
| `xss_{ip}` | XSS-Findings (Titel enthält "xss") |
| `cms_{ip}` | wpscan, WordPress/Shopware/TYPO3/Joomla/Drupal-Findings |
| `discovery_{ip}` | gobuster_dir, ffuf, feroxbuster |
| `sqli_{ip}` | SQL-Injection-Findings |
| `web_vulns_{ip}` | Sonstige ZAP-Findings |

**Schritt 6: WAF-Degradierung**
- Wenn WAF erkannt und Finding nur von einem Tool: `-0.10`

**Schritt 7: Confidence-Clamping**
- `max(0.0, min(confidence, 0.99))` — immer ≤ 0.99

### 11.3 False-Positive-Filter

Quelle: `scanner/correlation/fp_filter.py`, Klasse `FalsePositiveFilter`

Markiert Findings als FP (entfernt sie aber nicht). 6 Regeln in Reihenfolge:

#### Regel 1: WAF-Filter
```
Wenn WAF erkannt UND Tool="zap_active" UND keine Bestätigung UND
Confidence < 0.5:
  → FP. Reason: "WAF detected, ZAP active-only finding with low
    confidence"
```

#### Regel 2: Version-Mismatch
```
Für jedes Finding mit CVE:
  Wenn Produkt im Titel/Beschreibung erwähnt UND
  Major-Version ≠ erkannte Major-Version:
    → FP. Reason: "Version mismatch: finding targets {product}
      {finding_version}, detected {detected_version}"
```

#### Regel 3: CMS-Mismatch
```
CMS-Tag-Map:
  wordpress → {"wordpress", "wp-plugin", "wp-theme"}
  shopware  → {"shopware"}
  typo3     → {"typo3"}
  joomla    → {"joomla"}
  drupal    → {"drupal"}

Wenn Finding-Tags ein fremdes CMS referenzieren:
  → FP. Reason: "CMS mismatch: {cms_name} templates, but detected
    CMS is {detected_cms}"
```

#### Regel 4: SSL-Dedup
```
Innerhalb transport_security_{ip}-Cluster:
  Sortiere nach Confidence (höchste zuerst).
  Für alle weiteren: wenn ≥2 Wort-Overlap im Titel ODER gleiche CVE:
    → FP. Reason: "SSL dedup: same issue as {keep.title}"
```

#### Regel 5: Header-Dedup
```
Für jeden Security-Header (x-frame-options, strict-transport-security,
content-security-policy, etc.):
  Gruppiere alle Findings die diesen Header erwähnen.
  Behalte header_check-Finding (deterministisch, höchste Konfidenz).
  Markiere alle anderen als:
    → FP. Reason: "Header dedup: same header as {tool} finding"
```

#### Regel 6: Info-Noise
```
Noise-Patterns:
  r"^server:\s*\w+$"       — Server-Identifikation ohne Version
  r"robots\.txt"            — robots.txt gefunden
  r"sitemap\.xml"           — Sitemap gefunden
  r"^options method"        — OPTIONS aktiviert

Wenn Severity="info" UND Titel matcht Pattern:
  → FP. Reason: "Info noise: matches noise pattern '{pattern}'"
```

### 11.4 Threat-Intelligence-Enrichment

Quelle: `scanner/correlation/threat_intel.py`

Läuft **parallel** mit `ThreadPoolExecutor(max_workers=4)`. Individuelle Timeouts pro Client.

#### NVD API (National Vulnerability Database)

| Parameter | Wert |
|-----------|------|
| **Endpoint** | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| **API-Key** | `NVD_API_KEY` (optional) |
| **Rate-Limiting** | Ohne Key: 5 req/30s (6.0s Interval), mit Key: 50 req/30s (0.6s Interval) |
| **Timeout** | 15s pro Request, 120s Gesamt-Future |
| **Cache** | Redis, Key: `nvd:{cve_id}`, TTL: 24h |
| **Max Lookups** | WebCheck: 5, Perimeter+: 50 |

**Parsed Output pro CVE:**
```json
{
  "cve_id": "CVE-2024-1234",
  "cvss_v31": {"score": 9.8, "vector": "CVSS:3.1/...", "severity": "CRITICAL"},
  "cvss_score": 9.8,
  "cvss_vector": "CVSS:3.1/...",
  "cwes": ["CWE-79"],
  "description": "...",
  "references": [{"url": "...", "source": "...", "tags": []}],
  "source": "nvd"
}
```

#### EPSS API (Exploit Prediction Scoring System)

| Parameter | Wert |
|-----------|------|
| **Endpoint** | `https://api.first.org/data/v1/epss` |
| **API-Key** | nicht nötig (öffentlich) |
| **Batch-Größe** | 100 CVEs pro Request (komma-separiert) |
| **Timeout** | 15s pro Request, 30s Gesamt-Future |
| **Cache** | Redis, Key: `epss:{cve_id}`, TTL: 12h |

**Output pro CVE:**
```json
{"epss": 0.42, "percentile": 87.5}
```

#### CISA KEV (Known Exploited Vulnerabilities)

| Parameter | Wert |
|-----------|------|
| **Katalog-URL** | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| **Download** | Vollständiger Katalog (~1.5 MB) |
| **Cache** | Redis, Key: `cisa_kev:catalog`, TTL: 6h |
| **Timeout** | 30s Download, 30s Gesamt-Future |

**Output pro CVE-Match:**
```json
{
  "vendor": "Apache",
  "product": "HTTP Server",
  "name": "Apache HTTP Server Path Traversal",
  "date_added": "2021-12-01",
  "due_date": "...",
  "known_ransomware": "Known|Unknown"
}
```

#### ExploitDB (lokales searchsploit)

```bash
searchsploit --cve <cve_id> -j
```

| Parameter | Wert |
|-----------|------|
| **Verfügbarkeits-Check** | `searchsploit --help` |
| **Timeout** | 10s pro CVE, 60s Gesamt-Future |
| **Cache** | Redis, Key: `exploitdb:{cve_id}`, TTL: 24h |

**Output:**
```json
{
  "cve": "CVE-2024-1234",
  "exploits_available": true,
  "exploit_count": 3,
  "exploit_types": ["remote", "webapps"],
  "metasploit_module": true,
  "exploits": [{"title": "...", "path": "...", "type": "..."}]
}
```

### 11.5 Enrichment-Auswirkungen auf Findings

Nach dem Enrichment werden automatische Anpassungen vorgenommen:

| Bedingung | Aktion |
|-----------|--------|
| CVE in CISA KEV | Severity → `critical`, Confidence ≥ 0.95 |
| EPSS > 0.5 | Severity `medium`/`low` → `high` |
| NVD CVSS vorhanden | Wird als `authoritative_cvss` gespeichert |

### 11.6 Business-Impact-Scoring

Quelle: `scanner/correlation/business_impact.py`

#### Severity → CVSS-Approximation (wenn kein exakter Score verfügbar)

| Severity | CVSS |
|----------|------|
| critical | 9.5 |
| high | 7.5 |
| medium | 5.0 |
| low | 2.5 |
| info | 0.5 |

#### Scoring-Formel

```
base = CVSS_Score (NVD > Tool > Severity-Approximation)

// EPSS-Multiplikator
if epss > 0.5:   base *= 1.3
elif epss > 0.2: base *= 1.1

// CISA KEV-Multiplikator
if in_cisa_kev:  base *= 1.5
  if known_ransomware == "Known": base *= 1.2

// Asset-Value-Multiplikator
if fqdn == base_domain || fqdn == www.base_domain:  base *= 1.2
elif fqdn starts with mail/mx/smtp:                  base *= 1.1
else:                                                 base *= 1.0

// Paket-spezifische Gewichtung
max_weight = max(PACKAGE_WEIGHTS[package][category] for category)
base *= max_weight

// Confidence-Adjustment
if confidence < 0.5:  base *= 0.7

result = min(round(base, 1), 10.0)
```

#### Paket-spezifische Gewichtungen

**Insurance:**

| Kategorie | Multiplikator | Grund |
|-----------|--------------|-------|
| rdp_smb | 2.0 | Ransomware-Vektor |
| default_login | 1.8 | Default-Credentials |
| encryption | 1.3 | Schwache Verschlüsselung |

**Compliance:**

| Kategorie | Multiplikator | Grund |
|-----------|--------------|-------|
| encryption | 1.5 | §30 BSIG Nr. 4 |
| access_control | 1.3 | §30 BSIG Nr. 1 |
| logging | 1.3 | §30 BSIG Nr. 5 |

**SupplyChain:**

| Kategorie | Multiplikator | Grund |
|-----------|--------------|-------|
| api_security | 1.5 | Supply-Chain-API-Schnittstellen |
| authentication | 1.5 | Authentifizierungs-Schwächen |
| data_exposure | 1.3 | Daten-Leakage |

#### Kategorie-Erkennung (Keywords)

| Kategorie | Keywords / Ports |
|-----------|-----------------|
| rdp_smb | `rdp`, `smb`, `remote desktop`, `samba`, Ports 3389/445/139/5900/5985/5986 |
| encryption | `ssl`, `tls`, `cipher`, `encryption`, `hsts`, `certificate` |
| default_login | `default`, `login`, `credential`, `password`, `admin` |
| access_control | `access`, `authorization`, `permission`, `privilege`, `bypass` |
| api_security | `api`, `graphql`, `swagger`, `endpoint`, `rest`, `oauth` |
| authentication | `authentication`, `auth`, `session`, `token`, `jwt` |
| data_exposure | `exposure`, `disclosure`, `leak`, `sensitive`, `backup`, `database` |
| logging | `logging`, `audit`, `trace` |

#### Order-Level Impact Score

Gewichteter Durchschnitt der Top-5 Findings:

```python
weights = [1.0, 0.8, 0.6, 0.4, 0.2]
top_5 = sorted(all_non_fp_scores, reverse=True)[:5]
order_score = sum(score * weight) / sum(weights[:len(top_5)])
```

### 11.7 Phase-3-Output

Dateien im Verzeichnis `{scan_dir}/phase3/`:

| Datei | Inhalt |
|-------|--------|
| `correlated_findings.json` | Array von CorrelatedFinding.to_dict() |
| `enrichment.json` | `{cve_id: {nvd, epss, cisa_kev, exploitdb}}` |
| `ai_prioritization.json` | Claude-Sonnet-Antwort |

**Phase-3-Summary:**
```json
{
  "total_findings": 42,
  "false_positives": 8,
  "valid_findings": 34,
  "severity_counts": {"critical": 2, "high": 5, "medium": 12, "low": 15},
  "cves_enriched": 7,
  "cisa_kev_matches": 1,
  "fp_details": [{"tool": "...", "title": "...", "reason": "...", "host": "...", "cve": "..."}],
  "fp_by_reason": {
    "AI-Priorisierung": 2,
    "WAF-Filter": 1,
    "Version-Mismatch": 0,
    "CMS-Mismatch": 1,
    "SSL-Dedup": 2,
    "Header-Dedup": 1,
    "Info-Noise": 1
  }
}
```

---

## 12. Timeout-Architektur

### Globale Timeouts (pro Paket)

```
Total Timeout
├── Phase 0a:  30–120s   (Passive Intel)
├── Phase 0b:  300–900s  (DNS Recon)
├── Phase 1:   per Tool  (Tech Detection, parallel pro Host)
├── Phase 2:   per Tool  (Deep Scan, parallel pro Host)
└── Phase 3:   120–300s  (Correlation & Enrichment)
```

### Timeouts pro Tool (komplett)

| Tool | Timeout | Phase |
|------|---------|-------|
| **Phase 0a** | | |
| WHOIS | 30s | 0a |
| Shodan API | 10s/Request | 0a |
| AbuseIPDB API | 10s/Request | 0a |
| SecurityTrails API | 10s/Request | 0a |
| DNSSEC (dig+drill) | 10–15s | 0a |
| CAA (dig) | 10s | 0a |
| MTA-STS (dig+curl) | 5s | 0a |
| DANE/TLSA (dig) | 10s | 0a |
| **Phase 0b** | | |
| crt.sh | 60s | 0b |
| subfinder | 120s | 0b |
| amass | 300s | 0b |
| gobuster DNS | 180s | 0b |
| AXFR | 30s/NS | 0b |
| dnsx | 60s | 0b |
| DNS-Records (dig) | 10s/Query | 0b |
| **Phase 1** | | |
| nmap | 300s | 1 |
| webtech (Playwright) | 60s/Scheme | 1 |
| wafw00f | 60s | 1 |
| CMS Fingerprinter | max 20 Req × 5s | 1 |
| **Phase 2** | | |
| ZAP Spider | 120–180s | 2 |
| ZAP AJAX Spider | 240s | 2 |
| ZAP Active Scan | 600s | 2 |
| testssl.sh | 300s | 2 |
| HTTP Headers (curl) | 10s | 2 |
| httpx | 60s | 2 |
| wpscan | 600s | 2 |
| ffuf | 180s | 2 |
| feroxbuster | 150s | 2 |
| **Phase 3** | | |
| NVD-Future | 120s | 3 |
| EPSS-Future | 30s | 3 |
| CISA KEV-Future | 30s | 3 |
| ExploitDB-Future | 60s | 3 |

### Timeout-Enforcement

- `_check_timeout()` wird vor jeder größeren Operation geprüft
- Löst `TimeoutError` aus wenn `elapsed >= total_timeout`
- Löst `ScanCancelled` aus wenn Order-Status = "cancelled"

### Prozess-Cleanup

Quelle: `scanner/tools/__init__.py`

- Subprocess mit `start_new_session=True` (Prozessgruppen-Isolation)
- Bei Timeout: `_kill_process_group()` → SIGKILL der gesamten Gruppe
- Fallback: direktes `proc.kill()` wenn SIGKILL fehlschlägt
- Pipes drainieren um Zombies zu verhindern

---

## 13. Datenfluss zwischen Phasen

### Persistenz-Punkte

| Zeitpunkt | Wohin | Was |
|-----------|-------|-----|
| Phase 0a | DB `orders.passive_intel_summary` | Zusammenfassung Passive Intel |
| Phase 0b | Disk `host_inventory.json` | Hosts, IPs, FQDNs, Web-Probe |
| Phase 0b | DB `orders.discovered_hosts` | Anzahl entdeckter Hosts |
| Phase 1 | Disk `hosts/<ip>/phase1/` | tech_profile.json, nmap.xml, webtech.json, wafw00f.json |
| Phase 2 | Disk `hosts/<ip>/phase2/` | testssl.json, headers.json, httpx.json, zap_alerts.json, etc. |
| Phase 2 | DB `scan_results` | Pro Tool: raw_output, exit_code, duration_ms |
| Phase 3 | Disk `phase3/` | correlated_findings.json, enrichment.json, ai_prioritization.json |
| Phase 3 | DB `orders.correlation_data` | Korrelations-Zusammenfassung |
| Phase 3 | DB `orders.business_impact_score` | Order-Impact-Score |
| Finalize | MinIO `scan-rawdata/` | `<orderId>.tar.gz` (komplett) |
| Finalize | Redis `report-pending` | Report-Job enqueued |

### Daten-Weitergabe zwischen Phasen

```
Phase 0a → host_inventory (Passive Intel als passive_intel-Felder)
         ↘ Phase 3 (Shodan-Services für Korrelation)

Phase 0b → host_inventory.json
         → Web-Probe-Ergebnisse
         ↘ KI Host Strategy (Input)

KI Host Strategy → gefilterte Host-Liste für Phase 1
                 → scan_hints pro Host

Phase 1 → tech_profiles (pro Host)
        → Playwright redirect_data
        ↘ KI Tech Analysis (Input)
        ↘ KI Phase-2-Config (Input pro Host)

KI Tech Analysis → korrigierte CMS-Erkennung → tech_profiles aktualisiert

KI Phase-2-Config → adaptive_config pro Host (ZAP-Policy, ffuf-Modus, etc.)

Phase 2 → phase2_results (Findings pro Host)
        → ZAP Spider URLs (für Stage 2)
        ↘ KI Phase-3-Priorisierung (Input)

KI Phase-3-Priorisierung → FP-Markierungen auf correlated_findings

Phase 3 → correlated_findings.json
        → enrichment_data
        → business_impact_score
        ↘ Finalize (tar.gz für Report-Worker)
```

---

## 14. KI-Modelle und Kosten

### Verwendete Modelle

| Modell | Model-ID | Einsatz | Max Tokens |
|--------|----------|---------|------------|
| Haiku 4.5 | `claude-haiku-4-5-20251001` | Host Strategy, Tech Analysis, Phase-2-Config | 8.192 |
| Sonnet 4.6 | `claude-sonnet-4-6` | Phase-3-Priorisierung | 16.384 |

### Preise (pro 1M Tokens)

| Modell | Input | Output |
|--------|-------|--------|
| Haiku 4.5 | $1.00 | $5.00 |
| Sonnet 4.6 | $3.00 | $15.00 |
| Opus 4.6 (definiert, nicht genutzt) | $15.00 | $75.00 |

### Typische KI-Calls pro Scan

| Paket | Host Strategy | Tech Analysis | Phase-2-Config | Phase-3-Prio | Summe |
|-------|---------------|---------------|----------------|-------------|-------|
| WebCheck | - | - | - | - | 0 (skip_ai=nein, aber WebCheck hat wenig Hosts) |
| Perimeter | 1× | 1× | 1× pro Host | 1× (wenn >5 Findings) | 3 + n Hosts |
| TLSCompliance | - | - | - | - | 0 |

### Debug und Audit Trail

Jeder KI-Call speichert Debug-Daten via `_save_ai_debug()`:
- **DB-Tabelle:** `scan_results`
- **Tool-Name:** `{function}_debug`
- **Inhalte:** System-Prompt (vollständig), User-Prompt (max 10.000 Zeichen), Raw-Response, Cost-Dict
- **Größen-Cap:** 50 KB JSON im `raw_output`-Feld

### API-Call-Infrastruktur

1. SDK: `anthropic>=0.52.0`
2. API-Key: `ANTHROPIC_API_KEY` (Environment-Variable)
3. Response-Parsing: Text extrahieren → Markdown-Code-Fences strippen → JSON parsen
4. Error-Handling: `{"_error": "reason"}` bei Fehler, Caller nutzt Fallback-Logik
5. Alle Prompts in Deutsch
6. Cost-Tracking pro Call (Input/Output-Tokens × Preis)

---

## Anhang: Tool-Runner

Quelle: `scanner/tools/__init__.py`

Funktion: `run_tool(cmd, timeout, output_path, order_id, host_ip, phase, tool_name)`

| Aspekt | Verhalten |
|--------|-----------|
| **Prozess-Start** | `subprocess.Popen()` mit `start_new_session=True` |
| **Timeout** | Kills gesamte Prozessgruppe (SIGKILL) |
| **Return** | `(exit_code, duration_ms)` |
| **DB-Persist** | Speichert in `scan_results`: tool_name, raw_output (max 50 KB), exit_code, phase, host_ip |
| **Exit-Codes** | 0=Erfolg, 1=Warnungen, -1=Timeout, -2=Exception |
| **Partial Output** | Bei Timeout wird vorhandener Output aus Datei gelesen |
