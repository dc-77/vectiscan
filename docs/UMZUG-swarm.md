# Umzug von vectigal-docker02 in den Swarm

Stand 06.10.2026. VectiScan bekommt zwei Felder im Swarm-Cluster, `vect-test`
und `vect-prod`, neben der laufenden Produktion auf docker02. Umgeschaltet wird
über DNS; bis dahin laufen beide Ziele aus derselben Pipeline.

| Datei | Inhalt |
|---|---|
| `stack.yml` | beide Felder, mit Begründungen im Kopf |
| `ci/swarm.yml` | Build, Lint, Deploy und ops-Jobs für den Swarm |
| `deploy/swarm/secrets-entrypoint.sh` | macht Docker-Secrets zu Umgebungsvariablen |
| `deploy/swarm/datenknoten-einrichten.sh` | Rolle und Datenbank auf docker-share01 |
| `tests/test_stack_swarm.py` | Admin-Schutz, Images, Feld-Trennung, ZAP-Paarung |

## 0. Was sich ändert und was bleibt

**In den Swarm ziehen:** frontend, api, webcheck-core, scan-worker mit zap-1
bis zap-4, precheck-worker, report-worker. In Prod laufen frontend,
webcheck-core, scan-worker, precheck-worker und report-worker je dreimal, eine
Replik je Knoten. Die api läuft genau einmal (Begründung unten).

**Zustand auf den Datenknoten `docker-share01`:**

| | docker02 heute | Swarm |
|---|---|---|
| Postgres | Container `postgres` | Instanz 5432 (Test) bzw. 5433 (Prod), direkt, nicht über den Pooler |
| Redis | Container `redis`, `allkeys-lru` | Listen und Pub/Sub auf `redis-queue` :6380, Cache auf `redis-cache` :6379, Nummer 1 (Test) bzw. 0 (Prod) |
| MinIO | Container `minio` | gemeinsames MinIO :9000, Buckets mit Präfix `vect-test-` bzw. `vect-prod-` |

**Bleibt vorerst auf docker02:** Uptime-Kuma (`status.`), Loki, Promtail,
Grafana (`logs.`), Keycloak (`id.`), oauth2-proxy und Twenty (`crm.`). Im
Swarm liefert der Stack `monitoring` jeder Anwendung Logs, Kennzahlen,
Erreichbarkeit und Alarme ohne eigene Zeile; Keycloak und oauth2-proxy
schützen nur Kuma und Grafana. Ob diese Dienste ersetzt werden oder
mitziehen, ist eine eigene Entscheidung (Abschnitt 4).

**Vor der Umstellung des Wildcards `*.vectigal.tech`** brauchen diese vier
Namen einen eigenen A-Record auf `62.217.52.165`, sonst landen sie im Swarm
und bekommen 404: `status`, `logs`, `id`, `crm`.

### Code-Änderungen für den Umzug

Alle mit leerer Vorgabe, auf docker02 ändert sich dadurch nichts.

| Variable | Wirkung |
|---|---|
| `MINIO_BUCKET_PREFIX` | Präfix vor jedem Bucket-Namen (api `lib/buckets.ts`, scan-worker `upload.py`, report-worker `worker.py`, `pdf/v3/pipeline.py`, `pdf/v3/screenshots.py`) |
| `REDIS_EVENT_PREFIX` | Präfix vor `scan:events:<id>`. Pub/Sub kennt keine Datenbank-Nummer; ohne Präfix empfingen Test und Prod gegenseitig ihre Ereignisse (api `lib/events.ts`, scan-worker `progress.py`, report-worker `worker.py`) |
| `REDIS_CACHE_URL` | KI-Cache, NVD, EPSS, KEV und CWE auf die Cache-Instanz statt auf die Warteschlangen-Instanz (`ai_cache.py` in beiden Workern, `threat_intel.py`, `cwe_api_client.py`); fehlt sie, gilt `REDIS_URL` |

### Warum die api nur einmal läuft

Analyse vom 06.10.2026: Der Scheduler (`scheduler.ts`) läuft je Instanz im
Minutentakt, und sein `FOR UPDATE SKIP LOCKED` läuft über `pool.query` im
Autocommit, die Sperre endet also mit der Abfrage. Zwei Instanzen legten
doppelte Abo-Aufträge an. Dazu abonniert jede Instanz `scan:events:*` und
verschickt die Fertig-Mail, die Rate-Limits liegen im Arbeitsspeicher, und
`initDb()` nimmt beim Start keine Sperre. Für drei Instanzen müsste der
Scheduler in einer Transaktion sperren (oder eine Advisory-Lock je Lauf
nehmen), der Mailversand eine Zustellung je Order atomar festhalten und
`initDb()` eine Advisory-Lock nehmen.

## 1. Vorbedingungen, einmalig je Feld

### 1.1 Postgres

Auf docker-share01, nach `git clone` dieses Repositorys:

```bash
bash deploy/swarm/datenknoten-einrichten.sh test
bash deploy/swarm/datenknoten-einrichten.sh prod
```

Das Skript legt Rolle und Datenbank `vectiscan` an und zeigt
`max_connections` und die Belegung. VectiScan kommt in Spitzen auf 80 bis
100 Verbindungen; ist die Instanz schon nah am Limit, vorher
`max_connections` erhöhen.

### 1.2 MinIO und Redis

Nichts anzulegen. Die Schlüssel `vect-test-app` und `vect-prod-app` mit
Präfix-Policy gibt es (README von `vectigal/data-services`, „Buckets und
Schlüssel“); die Buckets legen api und Worker selbst an. Redis braucht die
beiden Passwörter `REDIS_QUEUE_PASSWORD` und `REDIS_CACHE_PASSWORD` aus
data-services.

### 1.3 CI/CD-Variablen

Die vorhandenen Variablen ohne Scope beschreiben docker02, also Prod. Was im
Testfeld anders sein muss, bekommt eine zweite Variable mit Scope `vect-test`.
Alle Geheimnisse Masked und Protected.

| Variable | Scope `vect-test` | Scope `vect-prod` |
|---|---|---|
| `DATABASE_URL` | `postgresql://vectiscan:<pw>@datenknoten:5432/vectiscan` | `…@datenknoten:5433/vectiscan` |
| `REDIS_URL` | `redis://:<queue-pw>@datenknoten:6380/1` | `…:6380/0` |
| `REDIS_CACHE_URL` | `redis://:<cache-pw>@datenknoten:6379/1` | `…:6379/0` |
| `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY` | `vect-test-app` + Secret | `vect-prod-app` + Secret |
| `JWT_SECRET` | eigener Wert | ohne Scope, **derselbe wie auf docker02**, sonst sind alle Sitzungen ungültig |
| `ADMIN_PASSWORD` | eigener Wert | ohne Scope |
| `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` | Testschlüssel, Webhook auf `scan-api-test` | ohne Scope (Live) |
| `STRIPE_PRICE_PERIMETER`, `STRIPE_PRICE_DEFAULT`, `STRIPE_PRICE_PERIMETER_ONETIME` | Preise aus dem Stripe-Testmodus | ohne Scope |
| `CRM_API_KEY` | `-` | ohne Scope |

Für beide Felder ohne Scope, wie heute: `ANTHROPIC_API_KEY`,
`RESEND_API_KEY`, `WEBCHECK_TURNSTILE_SECRET`, `ADMIN_EMAIL`,
`SALES_LEAD_EMAIL`. Die optionalen Schlüssel `SHODAN_API_KEY`,
`ABUSEIPDB_API_KEY`, `SECURITYTRAILS_API_KEY`, `NVD_API_KEY` und
`WPSCAN_API_TOKEN` müssen im Swarm gesetzt sein, weil ein Docker-Secret nicht
leer sein darf. Wer einen nicht hat, setzt `-`; das Einsprungskript behandelt
den Wert als nicht gesetzt.

Die Feld-Sicherung (`FELD_PRUEFUNG` in `ci/swarm.yml`) bricht vor dem
Ausrollen ab, wenn `DATABASE_URL`, `REDIS_URL`, `REDIS_CACHE_URL`,
`MINIO_ACCESS_KEY` oder `STRIPE_SECRET_KEY` nicht zum Feld passen, etwa weil
die Variable mit Scope fehlt und GitLab still die Prod-Variable liefert.

`DATENKNOTEN_ADDR`, `SWARM_REGISTRY_USER` und `SWARM_REGISTRY_TOKEN` kommen aus
der Gruppe `vectigal`.

### 1.4 Turnstile und DNS

- Im Cloudflare-Widget von Turnstile `scan-test.vectigal.tech` als Domain
  ergänzen, sonst scheitert das CAPTCHA im Testfeld. Der Site-Key ist für
  beide Felder derselbe (Build-Argument).
- `scan-test.vectigal.tech` und `scan-api-test.vectigal.tech` brauchen einen
  A-Record auf `62.217.52.177`, solange der Wildcard noch auf docker02 zeigt.

### 1.5 Einschalten

Projektvariable `VECTISCAN_SWARM` auf `an`. Ab dem nächsten Push auf `main`
laufen `swarm:build`, `swarm:trivy`, `swarm:lint` und `swarm:deploy:test`
mit. Der Build dauert so lange wie der für docker02 und läuft parallel auf dem
Runner `vectigal-docker`.

## 2. Testfeld prüfen

1. `swarm:deploy:test` grün. Der Job wartet auf das Update und fragt
   `https://scan-test.vectigal.tech/` über jeden Knoten ab.
2. In `vectigal/ci-templates` die Pipeline auf `main` starten, Job
   `erreichbarkeit`: `scan-test` und `scan-api-test` auf allen drei Knoten ok.
3. Anmelden, einen WebCheck-Scan anlegen, im Admin freigeben. Der Fortschritt
   muss live im Browser ankommen (Pub/Sub mit Präfix), der Bericht in
   `vect-test-scan-reports` liegen und die Mail kommen.
4. Ein Live-Check auf der Startseite (webcheck-core).

## 3. Prod-Fenster

1. TTL des Wildcards und der beiden `vectiscan.de`-Namen mindestens eine alte
   TTL vorher auf 300 s senken.
2. Auf docker02 warten, bis kein Scan läuft und die Listen leer sind, dann
   api und Worker stoppen. Kuma, Grafana, Keycloak und Twenty laufen weiter.
   ```bash
   cd /opt/apps/vectiscan && sudo docker compose exec -T redis redis-cli LLEN scan-pending
   sudo docker compose stop frontend api scan-worker-1 scan-worker-2 scan-worker-3 precheck-worker-1 precheck-worker-2 report-worker
   ```
3. Datenbank sichern, auf docker02:
   ```bash
   cd /opt/apps/vectiscan && sudo docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --no-owner --no-privileges' > /tmp/vectiscan.dump
   ```
   Die Datei nach docker-share01 bringen (direkt, falls docker02 den
   Datenknoten erreicht, sonst über die PuTTY-Tunnel) und dort einspielen:
   ```bash
   sudo -u postgres pg_restore -p 5433 -d vectiscan --no-owner --role=vectiscan /tmp/vectiscan.dump
   sudo -u postgres psql -p 5433 -d vectiscan -c "UPDATE reports SET minio_bucket = 'vect-prod-' || minio_bucket WHERE minio_bucket NOT LIKE 'vect-prod-%'"
   ```
   Der zweite Befehl ist nötig, weil die api den Bucket eines Berichts aus
   `reports.minio_bucket` liest. Danach Zeilenzahlen von `orders`, `reports`
   und `users` gegen docker02 vergleichen.
4. MinIO spiegeln: die Buckets `scan-rawdata`, `scan-reports`,
   `scan-authorizations`, `scan-screenshots` und `scan-debug` nach
   `vect-prod-<name>`. `mc` liegt im MinIO-Image; auf docker02 mit
   `docker compose exec minio mc mirror` in ein Verzeichnis, Archiv
   übertragen, auf docker-share01 mit dem `mc` des data-node-MinIO hinein.
   Objektzahlen je Bucket vergleichen.
5. Redis wird nicht übertragen: Die Listen sind leer, der Cache füllt sich neu.
6. `swarm:deploy:prod` auslösen. Er prüft vorher auf aktive Scans.
7. Mit `--resolve` gegen einen Knoten prüfen, von außen: Anmeldung, ein
   bestehender Bericht lässt sich laden, ein neuer Scan läuft durch.
8. DNS: `scan` und `scan-api` kommen mit dem Wildcard (oder vorher je ein
   A-Record), `vectiscan.de` und `www.vectiscan.de` in ihrer eigenen Zone auf
   `62.217.52.177`. Die Zertifikate holt der cert-renewer selbst.
9. Twenty erreicht die api über `https://crm.vectigal.tech/rest/people`. Das
   setzt voraus, dass der Swarm docker02 über dessen öffentliche Adresse
   erreicht; einmal mit einem Testlead prüfen.

**Rückweg:** A-Records zurück auf `62.217.52.165` und auf docker02
`docker compose start`. Was in der Zwischenzeit im Swarm geschrieben wurde,
fehlt dort.

## 4. Offen

- **Kuma, Loki, Promtail, Grafana, Keycloak, oauth2-proxy.** Nach dem Umzug
  sehen Kuma und Grafana auf docker02 die Anwendung nicht mehr (Kuma prüft
  interne Containernamen, Promtail liest nur docker02). Empfehlung: durch den
  Stack `monitoring` ersetzen und den Alarm `report.notify_failed` (VEC-229)
  dorthin übertragen; dann fällt auch das eigene Keycloak weg. Ziehen sie
  doch mit, gehören die oauth2-proxy-Middlewares als Labels in den Stack und
  werden mit `@swarm` statt `@file` angesprochen, mit dem vollen Dienstnamen
  in der Adresse.
- **Twenty** als eigener Stack, mit Postgres auf dem Datenknoten und Ablage in
  MinIO statt `STORAGE_TYPE: local`.
- **ops-Jobs.** Alle `ops-*`, `rollback` und `cleanup-prod` arbeiten mit
  `docker compose exec` in `/opt/apps/vectiscan`. Im Swarm gibt es vorerst nur
  `swarm:rollback`, `swarm:logs` und `swarm:ps` je Feld.
- **Drei api-Instanzen**, siehe Abschnitt 0.
- **Trivy** ist für den Swarm nicht blockierend, wie die Jobs für docker02.
- **Ausgehende Adresse.** docker02 scannt von `62.217.52.174` aus
  (`report-prototype/spec/09-gegenlesen-scanrunde.md`). Der Swarm geht über
  eine andere Adresse hinaus; Kunden wird keine Adresse genannt, aber das
  Verhalten an Port 25 und gegenüber Drosselungen kann sich ändern.
