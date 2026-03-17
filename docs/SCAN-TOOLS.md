# VectiScan — Scan-Tools Referenz

## Pakete

Drei Pakete steuern, welche Tools in welcher Phase laufen:

| | Basic | Professional | NIS2 |
|---|---|---|---|
| **Phase 0 Tools** | crtsh, subfinder, dnsx | crtsh, subfinder, amass, gobuster_dns, axfr, dnsx | = Professional |
| **Phase 0 Timeout** | 5 Min | 10 Min | 10 Min |
| **Max Hosts** | 5 | 10 | 10 |
| **Nmap Ports** | `--top-ports 100` | `--top-ports 1000` | `--top-ports 1000` |
| **Phase 1 Tools** | nmap, webtech, wafw00f | nmap, webtech, wafw00f | = Professional |
| **Phase 2 Tools** | testssl, headers, gowitness, httpx, wpscan | testssl, nikto, nuclei, gobuster_dir, gowitness, headers, httpx, katana, wpscan | = Professional |
| **Nuclei Severity** | high, critical | low, medium, high, critical | = Professional |
| **Nuclei Timeout** | 10 Min | 25 Min | 25 Min |
| **Gesamt-Timeout** | 15 Min | 120 Min | 120 Min |
| **Geschätzte Dauer** | ~10 Min | ~45 Min | ~45 Min |

Quelle: `scan-worker/scanner/packages.py`

---

## Phase 0: DNS-Reconnaissance

| Tool | Kommando | Timeout | Output-Format | Pakete |
|------|----------|---------|---------------|--------|
| crt.sh | `curl -s -o crtsh_raw.json "https://crt.sh/?q=%.{domain}&output=json"` | 60s | JSON | Alle |
| subfinder | `subfinder -d {domain} -silent -json -disable-update-check -o subfinder.json` | 120s | JSON-Lines | Alle |
| amass | `amass enum -passive -d {domain} -json amass.json` | 300s | JSON-Lines | Pro, NIS2 |
| gobuster dns | `gobuster dns --domain {domain} --wordlist subdomains-top5000.txt -q -o gobuster_dns.txt` | 180s | Text | Pro, NIS2 |
| dig AXFR | `dig @{ns} {domain} AXFR` (pro Nameserver) | 30s/NS | Text | Pro, NIS2 |
| DNS Records | `dig {domain} TXT/MX/NS +short` (SPF, DMARC, DKIM, MX, NS) | 10s/Query | JSON | Alle |
| dnsx | `cat subs.txt \| dnsx -a -aaaa -cname -resp -json -o dnsx_validation.json` | 60s | JSON-Lines | Alle |
| Web Probe (httpx) | `httpx -u {fqdn} -json -silent -follow-redirects -status-code -title -timeout 5` | 10s/FQDN | JSON | Alle |

### Phase 0 Nachverarbeitung

1. **Subdomain-Deduplizierung**: Alle gefundenen Subdomains werden vereinigt und normalisiert.
2. **dnsx-Validierung**: Nur Subdomains mit auflösbaren A/AAAA-Records werden behalten.
3. **IP-Gruppierung**: Subdomains werden nach IP-Adresse gruppiert.
4. **FQDN-Priorisierung**: Innerhalb jedes Hosts werden FQDNs sortiert:
   - Basisdomain (z.B. `example.com`) zuerst
   - `www.example.com` an zweiter Stelle
   - Mail-FQDNs (`mail.`, `mx.`, `smtp.`, `imap.`, usw.) zuletzt
5. **Host-Priorisierung**: Hosts werden nach Relevanz sortiert:
   - Basisdomain-Host (Priorität 0)
   - www-Subdomain-Host (Priorität 1)
   - Sonstige Web-Hosts (Priorität 2)
   - Mail/Autodiscover-Hosts (Priorität 3)
6. **Web Probe**: Schneller HTTP-Check (`httpx`) pro Host, um festzustellen, ob Web-Content vorhanden ist.
   - `has_web=true` -> Voller Web-Scan in Phase 2
   - `has_web=false` -> Nur Port-Scan + SSL
7. **Max-Hosts-Limit**: Überzählige Hosts werden abgeschnitten (Basic: 5, Pro/NIS2: 10).
8. **Base-Domain-Fallback**: Wenn die Basisdomain nicht in den dnsx-Ergebnissen ist, wird sie per `socket.getaddrinfo()` aufgelöst.

**Ergebnis:** `host_inventory.json` mit IP-Gruppierung, FQDN-Listen und Web-Probe-Daten.

---

## AI Host Strategy (nach Phase 0)

Haiku wird aufgerufen, um zu entscheiden, welche Hosts gescannt werden und in welcher Reihenfolge.

**Modell:** `claude-haiku-4-5-20251001`

**Input:** Host-Inventar mit Web-Probe-Daten, DNS-Findings, Paket-Typ.

**Output:**
```json
{
  "hosts": [
    { "ip": "...", "action": "scan|skip", "priority": 1, "reasoning": "..." }
  ],
  "strategy_notes": "..."
}
```

**Regeln:**
- Basisdomain und www: IMMER scannen, höchste Priorität
- Webserver mit Content: scan (hohe Priorität)
- Mailserver: scan mit niedrigerer Priorität (testssl + nmap reichen)
- Autodiscover, Parking-Pages, CDN-Edge-Nodes: skip
- Im Zweifel: scannen

**Fallback:** Bei API-Fehler oder ungültiger Antwort werden alle Hosts in Originalreihenfolge gescannt.

**Persistenz:** Die Strategie wird als `ai_host_strategy` in `scan_results` gespeichert und via WebSocket an das Frontend gepusht.

---

## Phase 1: Technologie-Erkennung (pro Host)

| Tool | Kommando | Timeout | Output-Format |
|------|----------|---------|---------------|
| nmap | `nmap -sV -sC -T4 {nmap_ports} -oX nmap.xml -oN nmap.txt {ip}` | 300s | XML + Text |
| webtech | `webtech -u https://{fqdn} --json` (HTTPS zuerst, Fallback HTTP) | 60s | JSON (stdout) |
| wafw00f | `wafw00f {fqdn} -o wafw00f.json -f json` | 60s | JSON |

### CMS-Fallback-Erkennung

Wenn `webtech` kein CMS findet, werden bekannte Pfade geprobt:
- `/wp-login.php`, `/wp-admin/` -> WordPress
- `/backend/admin`, `/admin/login` -> Shopware

**Ergebnis:** `tech_profile.json` pro Host mit: `ip`, `fqdns`, `cms`, `cms_version`, `server`, `waf`, `open_ports`, `mail_services`, `ftp_service`, `has_ssl`.

---

## AI Phase 2 Config (nach Phase 1, pro Host)

Haiku wird pro Host aufgerufen, um die Phase-2-Tools optimal zu konfigurieren.

**Input:** Tech-Profile des Hosts, Host-Inventar, Paket-Typ.

**Output:**
```json
{
  "nuclei_tags": ["wordpress", "exposure", "misconfig"],
  "nuclei_exclude_tags": ["dos", "fuzz"],
  "nikto_tuning": "1,2,3,4",
  "gobuster_wordlist": "wordpress",
  "skip_tools": [],
  "reasoning": "..."
}
```

**Nuclei-Tag-Regeln:**
- NIEMALS `cve` allein verwenden (3000+ Templates, Timeout)
- Max 5-7 Tags für optimale Laufzeit
- Immer `exposure` und `misconfig` einschließen
- Technologie-spezifische Tags: `wordpress`, `apache`, `nginx`, `shopware`, etc.

**Gobuster-Wordlists:**
- `common` (Standard), `wordpress`, `api`, `cms`

**skip_tools:**
- Für Basisdomain/www: IMMER leer (Override im Code)
- Nur für reine API-Hosts oder Mailserver: `katana`, `gowitness`

**Persistenz:** Die Konfiguration wird als `ai_phase2_config` in `scan_results` gespeichert.

---

## Phase 2: Tiefer Scan (pro Host)

| Tool | Kommando | Timeout | Output-Format | Bedingung |
|------|----------|---------|---------------|-----------|
| testssl.sh | `bash /opt/testssl.sh/testssl.sh --jsonfile testssl.json --quiet --ip one --warnings off https://{fqdn}` | 300s | JSON | has_ssl=true |
| nikto | `perl /opt/nikto/program/nikto.pl -h {fqdn} -Format json -output nikto.json -Tuning {ai_tuning}` | 600s | JSON | Pro, NIS2 |
| nuclei | `nuclei -u {fqdn} -severity {sev} -jsonl -o nuclei.json -timeout 5 -retries 1 -no-interactsh -c 25 -rl 150 [-tags {ai_tags}] [-exclude-tags {ai_exclude}]` | 600s (Basic) / 1500s (Pro) | JSON-Lines | Pro, NIS2 |
| gobuster dir | `gobuster dir -u https://{fqdn} -w {ai_wordlist} -o gobuster_dir.txt -q` | 120s | Text | Pro, NIS2 |
| gowitness | `gowitness scan single -u https://{fqdn} --screenshot-path {dir}/ --chrome-path /usr/bin/chromium --disable-logging` | 30s | PNG | Alle |
| HTTP Headers | `curl -sI https://{fqdn}` -> Security-Header-Analyse | 10s | JSON | Alle |
| httpx | `httpx -u {fqdn} -json -o httpx.json -status-code -title -tech-detect -server -content-length -follow-redirects -silent` | 60s | JSON-Lines | Alle |
| katana | `katana -u https://{fqdn} -o katana.txt -depth 3 -jsluice -known-files all -silent` | 300s | Text | Pro, NIS2 |
| wpscan | `wpscan --url https://{fqdn} --format json --output wpscan.json --enumerate vp,vt,u1-5 --random-user-agent --no-banner --ignore-main-redirect --disable-tls-checks [--api-token]` | 600s | JSON | Alle (nur wenn CMS=WordPress) |

### Nuclei Performance-Flags

- `-no-interactsh`: Kein Out-of-Band-Interaktionscheck (spart Zeit)
- `-timeout 5`: Per-Request-Timeout 5s (statt 10s default)
- `-c 25`: 25 Templates parallel
- `-rl 150`: Rate-Limit 150 req/s
- Severity nach Paket: Basic = `high,critical`, Pro/NIS2 = `low,medium,high,critical`
- AI-adaptive Tags filtern Templates auf relevante Technologien

### nikto Perl Path Fix

nikto wird direkt via `perl /opt/nikto/program/nikto.pl` aufgerufen (nicht via `nikto` binary), da das Perl-Script im Docker-Image unter `/opt/nikto/` liegt.

---

## Scan-Ablauf (Phase-First Architecture)

```
Phase 0 (alle Tools)
    ↓
AI Host Strategy (Haiku)
    ↓
Phase 1 — alle Hosts sequenziell
    ↓
AI Phase 2 Config (Haiku, pro Host)
    ↓
Phase 2 — alle Hosts sequenziell
    ↓
Pack + Upload + Report-Job
```

Hosts werden sequenziell gescannt (ein Host nach dem anderen). Bei 3 Hosts und ~20 Min. pro Host: ~70 Min. Gesamtlaufzeit.

**Gesamt-Timeout:** Basic 15 Min, Professional/NIS2 120 Min.

---

## Output-Verzeichnisstruktur

```
/tmp/scan-{orderId}/
├── meta.json                        ← Domain, Timestamps, Paket, Tool-Versionen
├── phase0/
│   ├── crtsh_raw.json               ← Rohdaten von crt.sh
│   ├── crtsh.json                   ← Geparste Subdomains
│   ├── subfinder.json
│   ├── amass.json
│   ├── gobuster_dns.txt
│   ├── zone_transfer.txt
│   ├── dnsx_validation.json
│   ├── dns_records.json             ← SPF, DMARC, DKIM, MX, NS
│   ├── host_inventory.json          ← Finale Host-Liste mit Web-Probe-Daten
│   └── host_strategy.json           ← AI-Strategie (scan/skip pro Host)
├── hosts/
│   └── {ip}/
│       ├── phase1/
│       │   ├── nmap.xml
│       │   ├── nmap.txt
│       │   ├── webtech.json
│       │   ├── wafw00f.json
│       │   └── tech_profile.json
│       └── phase2/
│           ├── testssl.json
│           ├── nikto.json
│           ├── nuclei.json
│           ├── gobuster_dir.txt
│           ├── headers.json
│           ├── httpx.json
│           ├── katana.txt
│           ├── wpscan.json          ← Nur bei WordPress
│           └── screenshot.png
└── scan.log
```
