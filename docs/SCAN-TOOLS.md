# VectiScan — Scan-Tools Referenz

## Phase 0: DNS-Reconnaissance

| Tool | Kommando | Timeout | Output-Format |
|------|----------|---------|---------------|
| crt.sh | `curl -s "https://crt.sh/?q=%.{domain}&output=json"` | 30s | JSON |
| subfinder | `subfinder -d {domain} -silent -json -o phase0/subfinder.json` | 2 Min | JSON |
| amass | `amass enum -passive -d {domain} -json phase0/amass.json` | 5 Min | JSON |
| gobuster | `gobuster dns -d {domain} -w /usr/share/wordlists/subdomains-top5000.txt -q -o phase0/gobuster_dns.txt` | 3 Min | Text |
| dig AXFR | `dig @{ns} {domain} AXFR` | 30s | Text |
| dnsx | `cat all_subdomains.txt \| dnsx -a -aaaa -cname -resp -json -o phase0/dnsx_validation.json` | 1 Min | JSON |

**Phase 0 Gesamt-Timeout:** 10 Minuten
**Ergebnis:** host_inventory.json mit IP-Gruppierung
**Max Hosts für Phase 1+2:** 10

## Phase 1: Technologie-Erkennung (pro Host)

| Tool | Kommando | Timeout | Output-Format |
|------|----------|---------|---------------|
| nmap | `nmap -sV -sC -T4 --top-ports 1000 -oX hosts/{ip}/phase1/nmap.xml -oN hosts/{ip}/phase1/nmap.txt {ip}` | 5 Min | XML + Text |
| webtech | `webtech -u https://{fqdn} --json` | 60s | JSON |
| wafw00f | `wafw00f {fqdn} -o hosts/{ip}/phase1/wafw00f.json -f json` | 30s | JSON |

**Ergebnis:** tech_profile.json pro Host

## Phase 2: Tiefer Scan (pro Host)

| Tool | Kommando | Timeout | Output-Format | Bedingung |
|------|----------|---------|---------------|-----------|
| testssl.sh | `testssl.sh --jsonfile hosts/{ip}/phase2/testssl.json --quiet {fqdn}` | 5 Min | JSON | has_ssl=true |
| nikto | `nikto -h {fqdn} -Format json -output hosts/{ip}/phase2/nikto.json -Tuning 1234567890` | 10 Min | JSON | immer |
| nuclei | `nuclei -u {fqdn} -severity low,medium,high,critical -json -o hosts/{ip}/phase2/nuclei.json` | 15 Min | JSON | immer |
| gobuster dir | `gobuster dir -u https://{fqdn} -w /usr/share/wordlists/common.txt -o hosts/{ip}/phase2/gobuster_dir.txt -q` | 10 Min | Text | immer |
| gowitness | `gowitness single https://{fqdn} --screenshot-path hosts/{ip}/phase2/` | 30s | PNG | immer |
| HTTP Headers | `curl -sI https://{fqdn}` → parse + bewerte Security-Headers | 10s | JSON | immer |

**Gesamt-Timeout pro Scan-Auftrag:** 120 Minuten

## Output-Verzeichnisstruktur

/tmp/scan-{scanId}/
├── meta.json
├── phase0/
│   ├── crtsh.json
│   ├── subfinder.json
│   ├── amass.json
│   ├── gobuster_dns.txt
│   ├── zone_transfer.txt
│   ├── dnsx_validation.json
│   ├── dns_records.json
│   └── host_inventory.json
├── hosts/
│   ├── {ip}/
│   │   ├── phase1/
│   │   │   ├── nmap.xml
│   │   │   ├── nmap.txt
│   │   │   ├── webtech.json
│   │   │   ├── wafw00f.json
│   │   │   └── tech_profile.json
│   │   └── phase2/
│   │       ├── testssl.json
│   │       ├── nikto.json
│   │       ├── nuclei.json
│   │       ├── gobuster_dir.txt
│   │       ├── headers.json
│   │       └── screenshot.png
│   └── .../
└── scan.log