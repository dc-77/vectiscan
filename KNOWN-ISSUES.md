# VectiScan — Bekannte Probleme & Deployment-Hinweise

Stand: 2026-03-12

---

## Kritische Punkte

### 1. Scan-Worker Internet-Outbound
- **Problem**: Scan-Worker braucht ausgehenden Internet-Zugang für DNS-Enumeration
  und Scan-Tools (subfinder, amass, nmap, nuclei etc.).
- **Ursache**: Docker iptables=false auf vectigal-docker02 → NAT über ens192
  muss manuell konfiguriert sein.
- **Workaround**: Auf dem Host sicherstellen:
  ```bash
  iptables -t nat -A POSTROUTING -s 172.0.0.0/8 -o ens192 -j MASQUERADE
  sysctl net.ipv4.ip_forward=1
  ```
- **Status**: Muss bei Erstdeployment geprüft werden.

### 2. ES-Module Main-Entry (API)
- **Problem**: `api/src/server.ts` nutzt `require.main === module` (CommonJS),
  aber tsconfig kompiliert zu ES-Modulen (Node16).
- **Auswirkung**: Könnte Runtime-Error verursachen wenn direkt aufgerufen.
- **Workaround**: In der Praxis wird `node dist/server.js` aufgerufen, was den
  Top-Level-Code ausführt. Der Guard wird nie true, aber der Server startet
  trotzdem da `startServer()` auch top-level aufgerufen wird.
- **Fix**: `require.main === module` durch `import.meta.url` Pattern ersetzen.

---

## Mittlere Priorität

### 3. Keine Health-Checks für Worker
- **Problem**: scan-worker und report-worker haben keine Docker-Healthchecks.
- **Auswirkung**: Abgestürzte Worker werden nur per `restart: unless-stopped`
  neu gestartet, nicht über compose-Healthcheck erkannt.
- **Empfehlung**: BullMQ-Worker-Status per Redis-Ping als Healthcheck exponieren.

### 4. Datenbank-Migrationen ohne Versionierung
- **Problem**: `initDb()` läuft bei jedem API-Start und führt CREATE TABLE IF
  NOT EXISTS aus. Kein Migration-Framework (z.B. Flyway, node-pg-migrate).
- **Auswirkung**: Für den Prototyp ausreichend, aber Schema-Änderungen erfordern
  manuelle Migration.
- **Empfehlung**: Für Produktion node-pg-migrate einführen.

### 5. MinIO Default-Credentials
- **Problem**: Mehrere Stellen haben `minioadmin/minioadmin` als Fallback.
- **Auswirkung**: In Produktion kein Problem solange .env korrekt gesetzt ist.
- **Empfehlung**: Fallback-Defaults in Code entfernen für Produktion.

---

## Niedrige Priorität

### 6. Wordlist-Naming
- **Problem**: Dockerfile lädt `subdomains-top1million-5000.txt` herunter,
  Code erwartet `/usr/share/wordlists/subdomains-top5000.txt`.
- **Auswirkung**: Datei wird korrekt platziert, Name-Inkonsistenz ist nur kosmetisch.

### 7. Docker-Image-Tags ohne Digest-Pinning
- **Empfehlung**: In CI/CD werden SHA-Tags gebaut. Für Rollback-Sicherheit
  immer SHA-Tags statt `:latest` im Produktionsbetrieb nutzen.

---

## Scan-Tools — Funktionsstatus

| Tool | Phase | Status | Anmerkung |
|------|-------|--------|-----------|
| subfinder | 0 | ✓ OK | Passive DNS-Enumeration |
| amass (enum) | 0 | ✓ OK | Passive Mode, 5min Timeout |
| gobuster dns | 0 | ✓ OK | Brute-Force mit Top-5000 |
| crt.sh | 0 | ✓ OK | CT-Log-Abfrage via API |
| dnsx | 0 | ✓ OK | DNS-Resolution/Verifizierung |
| nmap | 1 | ✓ OK | Top-1000 Ports, Service Detection |
| webtech | 1 | ✓ OK | Technology Fingerprinting |
| wafw00f | 1 | ✓ OK | WAF Detection |
| testssl.sh | 2 | ✓ OK | TLS/SSL-Analyse |
| nikto | 2 | ✓ OK | Web-Vulnerability-Scanner |
| nuclei | 2 | ✓ OK | Template-Based Scanner |
| gobuster dir | 2 | ✓ OK | Directory Brute-Force |
| gowitness | 2 | ✓ OK | Screenshot-Capture |

---

## PDF-Qualitätsprüfung (Checkliste)

Manuell nach erstem echtem Scan durchführen:

- [ ] Cover vorhanden mit Domain und Datum?
- [ ] Inhaltsverzeichnis mit Finding-Referenzen?
- [ ] Executive Summary mit Risk-Box?
- [ ] Findings mit Severity-Bars und CVSS-Badges?
- [ ] Evidence-Blöcke mit echtem Tool-Output?
- [ ] Deutsche Texte (Beschreibung, Nachweis, Empfehlung)?
- [ ] CVSS-Scores realistisch (nicht alle HIGH/CRITICAL)?
- [ ] Positive Findings vorhanden (z.B. gute TLS-Config)?
- [ ] Recommendations-Tabelle mit Timeframes?
- [ ] Disclaimer am Ende?

---

## GitLab CI/CD — Benötigte Variablen

Unter **Settings → CI/CD → Variables** anlegen (Protected + Masked):

| Variable | Beispielwert | Beschreibung |
|----------|-------------|--------------|
| `DB_USER` | `vectiscan` | PostgreSQL-Benutzer |
| `DB_PASSWORD` | (sicheres Passwort) | PostgreSQL-Passwort |
| `DB_NAME` | `vectiscan` | Datenbankname |
| `MINIO_ACCESS_KEY` | (generiert) | MinIO Root-User |
| `MINIO_SECRET_KEY` | (generiert) | MinIO Root-Passwort |
| `ANTHROPIC_API_KEY` | `sk-ant-...` | Claude API Key für Reports |

---

## Deployment-Ersteinrichtung

```bash
# 1. Verzeichnis auf vectigal-docker02 anlegen
sudo mkdir -p /opt/apps/vectiscan
cd /opt/apps/vectiscan

# 2. docker-compose.yml und .env kopieren
# (wird automatisch durch CI/CD-Pipeline deployt)

# 3. .env aus Template erstellen und Werte eintragen
cp .env.template .env
nano .env

# 4. Traefik proxy-net muss existieren
docker network create proxy-net || true

# 5. Erster Start
docker compose pull
TAG=latest docker compose up -d

# 6. Logs prüfen
docker compose logs -f --tail=50
```
