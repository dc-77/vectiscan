# VectiScan Prototyp — Prompts für Claude Code

> Gib diese Prompts der Reihe nach in Claude Code ein.
> Jeder Task ist ein abgeschlossener Meilenstein — teste das Ergebnis, bevor du zum nächsten gehst.
> Nutze für jeden Task den Befehl: `/agents` um Agent-Teams zu aktivieren.

---

## Task 1: Projekt-Grundgerüst

```
Arbeite an Task 1: Projekt-Grundgerüst.

Nutze Agenten-Teams für parallele Arbeit an den vier Diensten.

Erstelle die Grundstruktur des Projekts mit vier Diensten:

1. api/ — Fastify + TypeScript
   - package.json mit: fastify, @fastify/cors, bullmq, pg, minio, pino, typescript, tsx
   - tsconfig.json (strict mode)
   - src/server.ts — Fastify-Server auf Port 4000, loggt "VectiScan API started"
   - Dockerfile (Multi-Stage: Build mit Node 22, Run mit Node 22-slim, Non-Root User)

2. frontend/ — Next.js 15 + Tailwind CSS
   - package.json mit Next.js 15, Tailwind CSS
   - Minimale App-Router-Struktur (src/app/page.tsx mit "VectiScan" Platzhalter)
   - Dockerfile (Multi-Stage: Build, dann standalone output, Non-Root User)

3. scan-worker/ — Python 3.12
   - requirements.txt: redis, minio, psycopg2-binary, structlog
   - scanner/worker.py — loggt "Scan-Worker started", wartet auf Queue
   - Dockerfile-Platzhalter (debian:bookworm-slim, nur Python + requirements)

4. report-worker/ — Python 3.12
   - requirements.txt: redis, minio, psycopg2-binary, anthropic, reportlab, structlog
   - reporter/worker.py — loggt "Report-Worker started", wartet auf Queue
   - Die Skill-Dateien unter reporter/pdf/ sind bereits vorhanden — NICHT anfassen.
   - Stelle sicher, dass reporter/pdf/__init__.py existiert (leere Datei), damit der Import funktioniert.

5. Infrastruktur
   - docker-compose.dev.yml (Postgres 16.4-alpine, Redis 7.4-alpine, MinIO) — siehe docs/
   - .env.dev mit Entwicklungs-Defaults — siehe docs/

6. Tests
   - api/: Jest-Setup mit ts-jest, ein Smoke-Test der prüft dass der Server startet
   - frontend/: Jest-Setup, ein Smoke-Test der prüft dass die Page rendert
   - scan-worker/: pytest-Setup, ein Smoke-Test der worker.py importiert
   - report-worker/: pytest-Setup, ein Smoke-Test der worker.py importiert

Lies die CLAUDE.md für Konventionen und Zielumgebung.
Am Ende soll `docker compose -f docker-compose.dev.yml up` die Infrastruktur starten
und jeder Dienst einzeln startbar sein (npm run dev / python worker.py).
```

---

## Task 2: Datenbank + API

```
Arbeite an Task 2: Datenbank + API.

Nutze Agenten-Teams — ein Agent für die DB-Schicht, einer für die Endpoints, einer für die Tests.

Lies docs/API-SPEC.md für die vollständige Endpoint-Spezifikation.
Lies docs/DB-SCHEMA.sql für das Datenbankschema.

Implementiere in api/src/:

1. DB-Schicht (lib/db.ts)
   - PostgreSQL-Verbindung über pg Pool
   - Connection-String aus DATABASE_URL Environment-Variable
   - Migrations-Script das die Tabellen aus docs/DB-SCHEMA.sql anlegt (beim Start prüfen)

2. Queue-Schicht (lib/queue.ts)
   - BullMQ-Verbindung über REDIS_URL
   - Queue "scan:pending" mit Retry-Config (3 Versuche, exponential Backoff)
   - Queue "report:pending"

3. MinIO-Schicht (lib/minio.ts)
   - MinIO-Client aus Environment-Variablen (MINIO_ENDPOINT, MINIO_PORT, etc.)
   - Bucket-Prüfung beim Start (scan-rawdata, scan-reports anlegen falls nicht vorhanden)
   - Funktion für Pre-Signed Download URLs (30 Tage Gültigkeit)

4. Endpoints (routes/)
   - GET /health — { status: "ok", timestamp }
   - POST /api/scans — Domain validieren (Regex aus API-SPEC), in DB speichern,
     Job in scan:pending Queue, Response 201 mit scanId
   - GET /api/scans/:id — Status + Fortschritt aus DB, 404 wenn nicht gefunden
   - GET /api/scans/:id/report — Pre-Signed URL aus MinIO, 404 wenn kein Report

5. Unit-Tests (tests/)
   - Domain-Validierung: gültige Domains, ungültige Domains (mit http://, mit Pfad, etc.)
   - POST /api/scans: Mock-DB, prüfe dass Job in Queue geschrieben wird
   - GET /api/scans/:id: Mock-DB mit verschiedenen Status-Werten
   - GET /api/scans/:id/report: Mock-MinIO, 200 mit URL vs. 404
   - Health-Check: prüfe Response-Format

Alle Responses im Format: { success: true, data: {...} } oder { success: false, error: "..." }
Logging mit pino (strukturiertes JSON).

Teste am Ende manuell:
  docker compose -f docker-compose.dev.yml up -d
  cd api && npm run dev
  curl -X POST http://localhost:4000/api/scans -H "Content-Type: application/json" -d '{"domain":"scanme.nmap.org"}'
  curl http://localhost:4000/api/scans/<id-from-response>
```

---

## Task 3: Frontend

```
Arbeite an Task 3: Frontend.

Nutze Agenten-Teams — ein Agent für die Komponenten, einer für die API-Integration, einer für die Tests.

Baue die Single-Page-App in frontend/src/:

1. Hauptseite (app/page.tsx)
   - Domain-Eingabefeld mit Start-Button
   - Nach Submit: POST an /api/scans, dann Polling-Modus
   - Fehler-Toast bei ungültiger Domain oder API-Fehler

2. Scan-Fortschritt (components/ScanProgress.tsx)
   - Polling alle 3 Sekunden gegen GET /api/scans/:id
   - Aktuelle Phase als Badge (DNS-Recon / Phase 1 / Phase 2 / Report-Generierung)
   - Aktuelles Tool + aktueller Host als Text
   - Fortschrittsbalken (Host X von Y)
   - Automatisch stoppen wenn status = report_complete oder failed

3. Host-Liste (components/HostList.tsx)
   - Zeigt entdeckte Hosts aus dem progress.discoveredHosts Array
   - Pro Host: IP, FQDNs, Status-Icon (⏳ pending / 🔄 scanning / ✅ completed)

4. Report-Download (components/ReportDownload.tsx)
   - Erscheint wenn status=report_complete
   - Ruft GET /api/scans/:id/report auf
   - Download-Button mit Dateiname

5. Fehleranzeige (components/ScanError.tsx)
   - Erscheint wenn status=failed
   - Zeigt error-Message aus der API
   - "Neuen Scan starten"-Button

6. Design
   - Dunkles Theme (Hintergrund #0f172a, Karten #1e293b, Akzent #3b82f6)
   - Clean, minimalistisch, passend zu Security-Tool
   - Responsive (funktioniert auch auf Tablet)
   - Tailwind CSS Utility-Klassen

7. Konfiguration
   - API-URL aus NEXT_PUBLIC_API_URL Environment-Variable
   - Kein Hardcoding von URLs

8. Unit-Tests
   - ScanProgress: Mock-API-Response mit verschiedenen Status, prüfe richtige Anzeige
   - HostList: Render mit 0 Hosts, 1 Host, 3 Hosts mit verschiedenen Status
   - Domain-Validierung im Eingabefeld
   - ReportDownload: prüfe dass Download-Button bei report_complete erscheint

Teste am Ende manuell:
  API muss laufen (Task 2)
  cd frontend && NEXT_PUBLIC_API_URL=http://localhost:4000 npm run dev
  Browser: http://localhost:3000
```

---

## Task 4: Scan-Worker Dockerfile

```
Arbeite an Task 4: Scan-Worker Dockerfile.

Baue das Docker-Image für den Scan-Worker basierend auf debian:bookworm-slim.
Lies docs/SCAN-TOOLS.md für die vollständige Tool-Liste.

Erstelle scan-worker/Dockerfile:

1. Base: debian:bookworm-slim

2. System-Pakete (apt):
   - ca-certificates, curl, wget, unzip, jq, dnsutils, git
   - python3, python3-pip, python3-venv
   - nmap, nikto, sslscan, openssl

3. Go-Binaries (statisch gelinkt, direkt von GitHub Releases):
   - nuclei (projectdiscovery) + nuclei -update-templates
   - gowitness (sensepost)
   - gobuster (OJ)
   - subfinder (projectdiscovery)
   - dnsx (projectdiscovery)
   - amass (owasp-amass)
   WICHTIG: Verwende konkrete Release-Versionen, nicht "latest" — damit der Build
   reproduzierbar ist. Prüfe die aktuellen Versionen auf GitHub.

4. Shell-Scripts:
   - testssl.sh via git clone --depth 1
   - PATH um /opt/testssl.sh erweitern

5. Python-Pakete (pip3 install --break-system-packages):
   - wafw00f, webtech

6. Wordlists:
   - /usr/share/wordlists/subdomains-top5000.txt (von SecLists)
   - /usr/share/wordlists/common.txt (von SecLists)

7. Scanner-Code:
   - COPY requirements.txt + pip install
   - COPY scanner/ nach /opt/scanner/

8. Security:
   - Non-Root User "scanner" (useradd -r -s /bin/false scanner)
   - USER scanner
   - WORKDIR /opt/scanner
   - ENTRYPOINT ["python3", "worker.py"]

9. Verifikation — füge RUN-Befehle am Ende ein die prüfen:
   - nmap --version
   - nuclei -version
   - subfinder -version
   - amass -version
   - gobuster version
   - dnsx -version
   - gowitness version
   - testssl.sh --help (exit 0)
   - nikto -Version
   - wafw00f --version
   - webtech --help

10. Tests:
    - Erstelle scan-worker/tests/test_dockerfile.py
    - Test der prüft dass das Dockerfile syntaktisch korrekt ist
    - Test der die erwarteten Tool-Binaries in einem dict listet und prüft
      dass sie im Dockerfile referenziert werden

Baue das Image lokal und prüfe die Größe:
  cd scan-worker && docker build -t vectiscan-scan-worker .
  docker images vectiscan-scan-worker
Zielgröße: unter 1.5 GB (Debian-Slim + Tools).
```

---

## Task 5: Scan-Worker Orchestrierung

```
Arbeite an Task 5: Scan-Worker Orchestrierung.

Nutze Agenten-Teams — ein Agent für Phase 0, einer für Phase 1+2, einer für die Tests.

Lies docs/SCAN-TOOLS.md für Tool-Argumente und Timeouts.
Lies docs/architecture.md für die Drei-Phasen-Orchestrierung und das Output-Format.

Implementiere in scan-worker/scanner/:

1. worker.py — Hauptschleife
   - Verbindung zu Redis (REDIS_URL), PostgreSQL (DATABASE_URL), MinIO
   - BullMQ Consumer auf Queue "scan:pending"
   - Pro Job: Phase 0 → Phase 1 pro Host → Phase 2 pro Host → Upload → report:pending
   - Gesamt-Timeout: 120 Minuten (abbrechen, status=failed setzen)
   - Fehlerbehandlung: bei jedem Tool-Fehler loggen, weitermachen mit nächstem Tool
   - Nach jedem Tool: update_progress() aufrufen

2. progress.py — Fortschritts-Updates
   - update_progress(scan_id, phase, tool, host, hosts_completed)
   - Schreibt in Redis (für schnelles Polling) UND in PostgreSQL (persistent)
   - Status-Übergänge: created→dns_recon→scan_phase1→scan_phase2→scan_complete

3. phase0.py — DNS-Reconnaissance
   - run_crtsh(domain) → Liste von Subdomains
   - run_subfinder(domain) → Liste von Subdomains
   - run_amass(domain) → Liste von Subdomains
   - run_gobuster_dns(domain) → Liste von Subdomains
   - run_zone_transfer(domain) → Ergebnis oder Fehler
   - run_dnsx(subdomains) → Validierte FQDNs mit aufgelösten IPs
   - collect_dns_records(domain) → SPF, DMARC, DKIM, MX, NS
   - merge_and_group(all_results) → host_inventory.json (gruppiert nach IP)
   - Max 10 Hosts für Phase 1+2 (Rest wird im Inventar vermerkt aber nicht gescannt)
   - Phase 0 Gesamt-Timeout: 10 Minuten

4. phase1.py — Technologie-Erkennung (pro Host)
   - run_nmap(ip) → nmap.xml + nmap.txt
   - run_webtech(fqdn) → webtech.json
   - run_wafw00f(fqdn) → wafw00f.json
   - build_tech_profile(nmap, webtech, wafw00f) → tech_profile.json

5. phase2.py — Tiefer Scan (pro Host)
   - run_testssl(fqdn) → testssl.json (nur wenn has_ssl=true)
   - run_nikto(fqdn) → nikto.json
   - run_nuclei(fqdn) → nuclei.json
   - run_gobuster_dir(fqdn) → gobuster_dir.txt
   - run_gowitness(fqdn) → screenshot.png
   - run_header_check(fqdn) → headers.json

6. tools.py — Tool-Runner Hilfsfunktionen
   - run_tool(cmd, timeout, output_path) → exit_code, duration_ms
   - Subprocess mit timeout (subprocess.run mit timeout=)
   - Stdout/Stderr-Logging
   - Ergebnis in scan_results-Tabelle speichern

7. upload.py — Ergebnis-Upload
   - pack_results(scan_dir) → tar.gz
   - upload_to_minio(tar_gz_path, scan_id) → minio_path
   - enqueue_report_job(scan_id, minio_path, host_inventory, tech_profiles)

8. Unit-Tests (tests/)
   - test_phase0.py: Mock subprocess, teste merge_and_group mit Beispiel-Daten
   - test_phase1.py: Mock subprocess, teste build_tech_profile
   - test_progress.py: Mock Redis+DB, teste update_progress
   - test_tools.py: Teste run_tool mit Timeout (mock subprocess)
   - test_upload.py: Mock MinIO, teste pack_results

Jede run_*-Funktion nutzt run_tool() mit dem Timeout aus docs/SCAN-TOOLS.md.
Alle Outputs landen unter /tmp/scan-{scanId}/ in der Verzeichnisstruktur aus docs/SCAN-TOOLS.md.
```

---

## Task 6: Report-Worker

```
Arbeite an Task 6: Report-Worker.

Nutze Agenten-Teams — ein Agent für parser.py, einer für claude_client.py + report_mapper.py, einer für die Tests.

Lies docs/architecture.md für den Claude-API-Prompt und die Mapping-Logik.
Lies report-worker/reporter/pdf/SKILL.md für die report_data-Struktur und Finding-Felder.

WICHTIG: Die Datei reporter/pdf/generate_report.py ist die fertige PDF-Engine.
NICHT verändern, nur importieren: from pdf.generate_report import generate_report, create_styles

Implementiere in report-worker/reporter/:

1. parser.py — Tool-Output-Parser
   - parse_scan_data(scan_dir) → dict mit host_inventory, tech_profiles, consolidated_findings
   - Pro Tool einen Parser:
     - parse_nmap_xml(path) → offene Ports, Services, Versionen
     - parse_nuclei_json(path) → Vulnerabilities mit Severity
     - parse_testssl_json(path) → SSL-Findings
     - parse_nikto_json(path) → Web-Findings
     - parse_headers_json(path) → Security-Header-Bewertung
   - Konsolidierung: Duplikate über Hosts mergen, nach Severity sortieren
   - Ergebnis: ein String consolidated_findings für den Claude-Prompt

2. claude_client.py — Claude API Integration
   - SYSTEM_PROMPT und USER_PROMPT aus docs/architecture.md (wortwörtlich übernehmen)
   - call_claude(domain, host_inventory, tech_profiles, consolidated_findings) → dict
   - Model: claude-sonnet-4-20250514
   - Max-Tokens: 4096
   - Response-Parsing: JSON aus content[0].text extrahieren
   - Fehlerbehandlung: Retry 3x bei Rate-Limit (429), Timeout nach 60 Sekunden
   - API-Key aus ANTHROPIC_API_KEY Environment-Variable

3. report_mapper.py — Claude-Output → report_data
   - map_to_report_data(claude_output, scan_meta, host_inventory) → dict
   - Mapping-Code aus docs/architecture.md übernehmen (Abschnitt Report-Pipeline)
   - Deutsche Labels für alle Finding-Felder
   - Cover mit "VectiScan — Automated Security Assessment"
   - TOC mit allen Findings
   - Executive Summary mit Risk-Box
   - Scope-Abschnitt mit Host-Inventar und Methodik
   - Findings (negative + positive)
   - Recommendations-Tabelle
   - Appendices: CVSS-Tabelle, Tool-Liste
   - Disclaimer

4. worker.py — Orchestrierung
   - BullMQ Consumer auf Queue "report:pending"
   - Rohdaten aus MinIO laden (scan-rawdata/<scanId>.tar.gz)
   - Entpacken nach /tmp/report-<scanId>/
   - parser.parse_scan_data() aufrufen
   - claude_client.call_claude() aufrufen
   - report_mapper.map_to_report_data() aufrufen
   - generate_report(report_data, pdf_path) aufrufen
   - PDF nach MinIO hochladen (scan-reports/<scanId>.pdf)
   - Report-Record in DB anlegen (reports-Tabelle)
   - Scan-Status auf report_complete setzen
   - /tmp aufräumen
   - Fehlerbehandlung: bei Fehler status=failed + error_message setzen

5. Unit-Tests (tests/)
   - test_parser.py:
     - Teste parse_nmap_xml mit Beispiel-XML (erstelle fixtures/)
     - Teste parse_nuclei_json mit Beispiel-Findings
     - Teste parse_headers_json mit guten und schlechten Headers
     - Teste Konsolidierung und Duplikat-Erkennung
   - test_claude_client.py:
     - Mock anthropic.Anthropic, teste dass Prompt korrekt gebaut wird
     - Teste JSON-Parsing der Response
     - Teste Retry bei 429
     - Teste Timeout-Handling
   - test_report_mapper.py:
     - Teste map_to_report_data mit Beispiel-Claude-Output
     - Prüfe dass alle Pflichtfelder in report_data vorhanden sind
     - Prüfe dass Finding-Labels auf Deutsch sind
     - Prüfe dass positive Findings als INFO gemappt werden
     - Prüfe dass TOC-Einträge mit Finding-IDs übereinstimmen
   - test_worker.py:
     - Mock alle Dependencies, teste den Orchestrierungs-Flow
     - Teste Fehlerfall: Claude-API nicht erreichbar → status=failed

Erstelle fixtures/ mit Beispiel-Daten:
   - fixtures/nmap_example.xml (realistischer Nmap-Output mit 3 offenen Ports)
   - fixtures/nuclei_example.json (2 Findings: 1 HIGH, 1 MEDIUM)
   - fixtures/headers_example.json (fehlender HSTS, vorhandener CSP)
   - fixtures/claude_response.json (vollständiger Claude-Output nach Schema)
```

---

## Task 7: Docker-Compose Produktion + CI/CD

```
Arbeite an Task 7: Docker-Compose Produktion + CI/CD.

Nutze Agenten-Teams — ein Agent für docker-compose.yml, einer für .gitlab-ci.yml.

Lies die CLAUDE.md für Traefik-Labels und Netzwerk-Architektur.
Orientiere dich am Betriebshandbuch-Muster (Beispiel C: Gutachten-KI).

1. docker-compose.yml (Produktion)
   Erstelle die Produktions-docker-compose.yml im Projekt-Root:

   EXTERN ERREICHBAR (proxy-net + vectiscan-internal):
   - frontend: scan.vectigal.tech, Port 3000, 1 CPU / 512M
     - NEXT_PUBLIC_API_URL=https://scan-api.vectigal.tech
     - Middlewares: security-headers@file, rate-limit@file, internal-only@file
   - api: scan-api.vectigal.tech, Port 4000, 1 CPU / 512M
     - Healthcheck: curl /health, 15s Interval
     - Middlewares: security-headers@file, rate-limit@file, internal-only@file
     - depends_on: postgres (healthy), redis (started)

   NUR INTERN (vectiscan-internal):
   - scan-worker: 2 CPU / 2G, braucht Internet-Outbound
     - depends_on: redis, minio
   - report-worker: 1 CPU / 1G
     - depends_on: redis, minio, postgres
   - postgres: 16.4-alpine, 1 CPU / 1G, Healthcheck pg_isready
     - Volume: vectiscan-pg-data
   - redis: 7.4-alpine, 0.5 CPU / 512M, appendonly yes, maxmemory 256mb
     - Volume: vectiscan-redis-data
   - minio: latest, 0.5 CPU / 512M
     - Volume: vectiscan-minio-data

   Networks: proxy-net (external: true), vectiscan-internal
   Kein certresolver-Label — LE HTTP-01 ist Traefik-Default.
   Images: git-extern.bergersysteme.com:5050/team/vectiscan/<dienst>:${TAG:-latest}
   Alle Secrets über ${VARIABLE} aus .env

2. .gitlab-ci.yml (Multi-Image-Build)
   Erstelle die CI/CD-Pipeline:

   Variables:
   - REGISTRY: git-extern.bergersysteme.com:5050
   - BASE_IMAGE: ${REGISTRY}/${CI_PROJECT_PATH}
   - APP_NAME: vectiscan
   - DEPLOY_PATH: /opt/apps/${APP_NAME}

   Stages: build, scan, test, deploy

   Build (parallel, je ein Job):
   - build-frontend: -f frontend/Dockerfile .
   - build-api: -f api/Dockerfile .
   - build-scan-worker: -f scan-worker/Dockerfile .
   - build-report-worker: -f report-worker/Dockerfile .
   Jeder baut :${CI_COMMIT_SHORT_SHA} + :latest, pusht beides.
   Rules: main Branch oder web Pipeline.

   Scan (parallel, je ein Job pro Image):
   - Trivy: --exit-code 1 --severity CRITICAL --ignore-unfixed
   - allow_failure: false

   Test:
   - Unit-Tests für api (npm test)
   - Unit-Tests für scan-worker (pytest)
   - Unit-Tests für report-worker (pytest)

   Deploy:
   - .deploy-base Template (identisch mit Betriebshandbuch)
   - deploy-auto: main Branch, TAG=latest
   - deploy-manual: web Pipeline, TAG=${CI_COMMIT_SHORT_SHA}, when: manual
   - sleep 15 nach docker compose up
   - Health-Check aller Container
   - Environment URL: https://scan.vectigal.tech

   Rollback:
   - when: manual
   - docker-compose.yml.bak + .env.bak restore

3. Tests:
   - Erstelle tests/test_docker_compose.py:
     - Parse docker-compose.yml mit PyYAML
     - Prüfe dass alle 7 Services definiert sind
     - Prüfe dass frontend und api in proxy-net + vectiscan-internal sind
     - Prüfe dass postgres, redis, minio NUR in vectiscan-internal sind
     - Prüfe dass Traefik-Labels korrekt gesetzt sind
     - Prüfe dass Resource-Limits gesetzt sind
   - Erstelle tests/test_gitlab_ci.py:
     - Parse .gitlab-ci.yml mit PyYAML
     - Prüfe dass alle 4 Build-Jobs existieren
     - Prüfe dass Trivy-Scan-Jobs existieren
     - Prüfe dass Deploy-Jobs existieren
```

---

## Task 8: Integration + End-to-End-Test

```
Arbeite an Task 8: Integration + End-to-End-Test.

Nutze Agenten-Teams — ein Agent für lokale Tests, einer für die Deployment-Prüfung.

1. Lokaler Integrationstest
   - docker compose -f docker-compose.dev.yml up -d
   - Starte API, Scan-Worker und Report-Worker lokal
   - Prüfe dass alle Dienste gesund sind
   - Teste den vollständigen Flow:
     a) POST /api/scans mit domain "scanme.nmap.org"
     b) Polling auf GET /api/scans/:id — beobachte Status-Übergänge
     c) Warte auf status=report_complete
     d) GET /api/scans/:id/report — Download-URL abrufen
     e) PDF herunterladen und prüfen

2. Integrationstests (tests/integration/)
   - test_e2e_flow.py:
     - Starte mit einer echten Domain (scanme.nmap.org)
     - Prüfe dass Status-Übergänge in korrekter Reihenfolge erfolgen
     - Prüfe dass discovered_hosts nach Phase 0 befüllt ist
     - Prüfe dass hosts_completed hochzählt
     - Prüfe dass am Ende ein Report in MinIO liegt
     - Prüfe dass die PDF-Datei gültiges PDF ist (magic bytes)
     - TIMEOUT: 15 Minuten für den gesamten Test

   - test_api_integration.py:
     - Teste POST mit ungültiger Domain → 400
     - Teste GET mit nicht existierender ID → 404
     - Teste GET /report bevor Report fertig → 404
     - Teste Health-Endpoint

3. PDF-Qualitätsprüfung (manuell, Checkliste)
   □ Cover vorhanden mit Domain und Datum?
   □ Inhaltsverzeichnis mit Finding-Referenzen?
   □ Executive Summary mit Risk-Box?
   □ Findings mit Severity-Bars und CVSS-Badges?
   □ Evidence-Blöcke mit echtem Tool-Output?
   □ Deutsche Texte (Beschreibung, Nachweis, Empfehlung)?
   □ CVSS-Scores realistisch (nicht alle HIGH/CRITICAL)?
   □ Positive Findings vorhanden (z.B. gute TLS-Config)?
   □ Recommendations-Tabelle mit Timeframes?
   □ Disclaimer am Ende?

4. Bekannte Probleme dokumentieren
   - Erstelle KNOWN-ISSUES.md im Projekt-Root
   - Dokumentiere alle gefundenen Probleme, Workarounds, und offene Punkte
   - Dokumentiere welche Tools gut funktionieren und welche Anpassungen brauchen

5. Deployment-Vorbereitung
   - Prüfe dass .env.template alle benötigten Variablen enthält
   - Prüfe dass .gitlab-ci.yml syntaktisch korrekt ist (gitlab-ci-lint)
   - Prüfe dass alle Dockerfiles bauen
   - Liste die GitLab CI/CD Variables die angelegt werden müssen:
     DB_USER, DB_PASSWORD, DB_NAME, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, ANTHROPIC_API_KEY
```

---

## Bonus: Einzelne Nachbesserungen

Falls nach den 8 Tasks noch Feinschliff nötig ist, hier Prompts für häufige Nachbesserungen:

### Report-Qualität verbessern

```
Der Claude-API-Prompt liefert überhöhte CVSS-Scores. Passe reporter/claude_client.py an:

1. Lies den SYSTEM_PROMPT in claude_client.py
2. Ergänze im Prompt konkretere Beispiele für korrekte Scores:
   - SSH Port 22 offen mit Key-Auth: INFO (nicht HIGH)
   - robots.txt enthält /admin: LOW 2.5 (nicht MEDIUM)
   - MySQL 3306 offen, Connection refused: INFO (Port offen aber kein Zugriff)
3. Füge eine Post-Processing-Funktion hinzu: validate_cvss_scores()
   - Prüfe ob der Score zum CVSS-Vektor passt (berechne Score aus Vektor)
   - Korrigiere Inkonsistenzen automatisch
4. Schreibe Tests für validate_cvss_scores mit Beispiel-Findings
```

### Frontend-Feinschliff

```
Verbessere das Frontend-Design:

1. Füge ein VectiScan-Logo/Schriftzug im Header hinzu (SVG, Security-Look)
2. Animiere den Fortschrittsbalken (smooth transition)
3. Zeige die geschätzte Restzeit basierend auf bisheriger Dauer
4. Füge einen "Scan abbrechen"-Button hinzu (ruft DELETE /api/scans/:id auf)
5. Zeige nach dem Download einen "Neuen Scan starten"-Button
6. Schreibe Tests für die neuen Komponenten
```

### Scan-Worker Robustheit

```
Mache den Scan-Worker robuster:

1. Manche Tools schreiben leere JSON-Dateien bei Fehlern. Ergänze in parser.py:
   - Prüfe ob die JSON-Datei valide und nicht-leer ist bevor du sie parst
   - Leere oder kaputte Dateien → loggen und überspringen, nicht crashen
2. Manche Domains haben hunderte Subdomains. Ergänze in phase0.py:
   - Logging: "X Subdomains gefunden, scanne die Top 10 nach IP-Gruppierung"
   - Sortierung: Hosts mit den meisten FQDNs zuerst (wichtiger)
3. Timeouts: Teste ob die Subprocess-Timeouts korrekt greifen
   - Erstelle einen Mock-Test der ein Tool simuliert das hängt
4. Schreibe Tests für alle Edge Cases
```