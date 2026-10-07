# Umzug von vectigal-docker02 in den Swarm

Stand 06.10.2026. VectiScan bekommt zwei Felder im Swarm-Cluster, `vect-test`
und `vect-prod`, neben der laufenden Produktion auf docker02. Umgeschaltet wird
über DNS; bis dahin laufen beide Ziele aus derselben Pipeline.

| Datei | Inhalt |
|---|---|
| `stack.yml` | beide Felder, mit Begründungen im Kopf |
| `ci/swarm.yml` | Build, Lint, Deploy und ops-Jobs für den Swarm |
| `deploy/swarm/secrets-entrypoint.sh` | macht Docker-Secrets zu Umgebungsvariablen |
| `deploy/swarm/datenknoten-einrichten.sh` | Rolle, Datenbank und Verbindungsgrenze auf docker-share01 |
| `tests/test_stack_swarm.py` | Admin-Schutz, Images, Feld-Trennung, ZAP-Paarung |

## 0. Was sich ändert

**In den Swarm ziehen:** frontend, api, webcheck-core, scan-worker mit zap-1
bis zap-4, precheck-worker, report-worker. In Prod laufen frontend,
webcheck-core, scan-worker, precheck-worker und report-worker je dreimal, eine
Replik je Knoten. Die api läuft genau einmal (Begründung unten).

**Zustand auf dem Datenknoten `docker-share01`:**

| | docker02 heute | Swarm |
|---|---|---|
| Postgres | Container `postgres` | Instanz 5432 (Test) bzw. 5433 (Prod), direkt, nicht über den Pooler |
| Redis | Container `redis`, `allkeys-lru` | Listen und Pub/Sub auf `redis-queue` :6380, Cache auf `redis-cache` :6379, Nummer 1 (Test) bzw. 0 (Prod) |
| MinIO | Container `minio` | gemeinsames MinIO :9000, Buckets mit Präfix `vect-test-` bzw. `vect-prod-` |

**Durch die Plattform ersetzt** (Entscheidung vom 06.10.2026): Uptime-Kuma,
Loki, Promtail und Grafana durch den Stack `monitoring`
(`vectigal/monitoring-services`), Keycloak und oauth2-proxy durch den Stack
`identity` (`vectigal/identity-services`). Abschnitt 1.6 beschreibt, was dafür
dort steht. Die Namen `status.`, `logs.` und `id.vectigal.tech` fallen nach dem
Prod-Fenster weg.

**Bleibt vorerst auf docker02:** Twenty (`crm.vectigal.tech`). Der Name braucht
vor der Umstellung des Wildcards `*.vectigal.tech` einen eigenen A-Record auf
`62.217.52.165`. Die api im Swarm erreicht Twenty über diesen Namen (am
06.10.2026 aus einem Swarm-Container geprüft: 403 ohne Schlüssel, also
erreichbar).

**Ausgehende Adresse:** Der Swarm geht wie docker02 über `62.217.52.174`
hinaus (geprüft am 06.10.2026). Für die gescannten Systeme ändert sich nichts.

### Code-Änderungen für den Umzug

Alle mit Vorgabe für docker02, dort ändert sich nichts.

| Variable | Wirkung |
|---|---|
| `MINIO_BUCKET_PREFIX` | Präfix vor jedem Bucket-Namen (api `lib/buckets.ts`, scan-worker `upload.py`, report-worker `worker.py`, `pdf/v3/pipeline.py`, `pdf/v3/screenshots.py`) |
| `REDIS_EVENT_PREFIX` | Präfix vor `scan:events:<id>`. Pub/Sub kennt keine Datenbank-Nummer; ohne Präfix empfingen Test und Prod gegenseitig ihre Ereignisse (api `lib/events.ts`, scan-worker `progress.py`, report-worker `worker.py`) |
| `REDIS_CACHE_URL` | KI-Cache, NVD, EPSS, KEV und CWE auf die Cache-Instanz statt auf die Warteschlangen-Instanz (`ai_cache.py` in beiden Workern, `threat_intel.py`, `cwe_api_client.py`); fehlt sie, gilt `REDIS_URL` |
| `PRECHECK_CIDR_MAX_PARALLEL` | Threads je precheck-worker bei CIDR-Zielen, Vorgabe 20, im Swarm 10 (`precheck/runner.py`), wegen des Verbindungsbudgets |

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

Das Skript legt Rolle und Datenbank `vectiscan` an, setzt eine
Verbindungsgrenze für die Rolle und zeigt die Belegung der Instanz.

**Das Verbindungsbudget auf 5433 reicht so nicht für drei Repliken.** Die
Rechnung mit den Werten vom 06.10.2026 (`max_connections` 100, belegt 37):

| | Verbindungen in Spitzen |
|---|---|
| precheck-worker, 3 Repliken × 10 Threads | 30 |
| scan-worker, 3 Repliken × 3 bis 8 (Phase 1 und 2) | 9 bis 24 |
| api, Pool-Vorgabe von node-postgres | bis 10 |
| report-worker, 3 Repliken × 1 bis 3 | 3 bis 9 |
| **VectiScan Prod zusammen** | **52 bis 73** |

Frei sind auf 5433 heute 100 − 3 (für den Superuser reserviert) − 37 = 60. Die
Spitze von VectiScan passt da nicht sicher hinein, und die anderen
Anwendungen wachsen unter Last ebenfalls (der Pooler allein darf bis zu 60
Server-Verbindungen öffnen). Deshalb zwei Schritte:

1. Die Rolle `vectiscan` bekommt eine Grenze, Vorgabe 55 in Prod und 40 in
   Test. Ein Ausreißer trifft dann nur VectiScan und nicht alle Anwendungen
   auf der Instanz.
2. Vor dem Prod-Fenster `max_connections` auf 5433 auf 200 anheben (braucht
   einen Neustart der Instanz, also eine kurze Unterbrechung aller
   Prod-Anwendungen darauf) und danach die Grenze nachziehen:
   `bash deploy/swarm/datenknoten-einrichten.sh prod 80`.

Im Testfeld sind es 10 + 3 bis 8 + 10 + 1 bis 3 = 24 bis 31, das passt unter
die Grenze 40.

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

### 1.5 Platz im Cluster

Drei Knoten mit je 4 CPU und 7,76 GiB, zusammen 12 CPU und 23,3 GiB
(06.10.2026). VectiScan Prod reserviert 3,5 CPU und 6,25 GiB; die Grenzen
(`limits`) aller Prod-Dienste ergeben zusammen 24,5 GiB, also mehr, als der
Cluster insgesamt hat. Swarm plant nur nach den Reservierungen, die Grenzen
greifen erst, wenn ein Container sie wirklich braucht. Ob das trägt, hängt am
tatsächlichen Verbrauch unter Last (auf docker02 messbar mit `docker stats`)
und daran, wie viel die übrigen Stacks schon belegen. Vor dem Prod-Fenster
messen; reicht es nicht, ist `REPLICAS` je Dienst die Stellschraube, und
zap-2 bis zap-4 hängen an den Scan-Workern.

### 1.6 Überwachung und Anmeldung über die Plattform

**Logs und Kennzahlen** kommen ohne eigene Zeile: Alloy liest die Logs jedes
Containers, cAdvisor CPU, Speicher und Neustarts, Traefik Anfragen und
Antwortzeiten. In Grafana (`grafana.vectigal.tech`) zeigt das Dashboard
**Anwendung** mit der Variable `stack` alles nebeneinander. Die bisherigen
Abfragen werden so übersetzt:

| docker02 (eigenes Loki) | Swarm (Loki der Plattform) |
|---|---|
| `{project="vectiscan", service="api"}` | `{stack="vect-prod-vectiscan", service="api"}` |
| Dienst `scan-worker-1` | `service="scan-worker"`, die Replik steht im Label `container` |

pino und structlog schreiben JSON mit `level`; Alloy übernimmt die Stufe als
Label, und der Alarm `VieleFehlerzeilen` zählt damit auch VectiScan.

**Alarme.** Die beiden eigenen Alarme aus `MONITORING.md` stehen jetzt in
`monitoring-services/datenknoten/loki/rules/fake/vectiscan.yml`, nur für Prod:

| Alarm | bisher | Auslöser |
|---|---|---|
| `VectiscanBerichtNichtZugestellt` | `report.notify_failed` (VEC-229) | Logzeile „Report delivery incomplete“ der api |
| `VectiscanWebcheckGedrosselt` | Velocity-Alarm (VEC-173) | Marker `webcheck_velocity_alert` der api |

Dazu kommen die Alarme der Plattform für jeden Dienst: nicht erreichbar über
eine Traefik-Instanz, Neustartschleife, Speicher am Limit, weniger Instanzen
als vorher. Zugestellt wird an die Betriebsadresse des Monitoring-Stacks,
nicht mehr an `ADMIN_EMAIL`. Ändert sich der Wortlaut einer der beiden
Logzeilen in der api, muss der Ausdruck in `vectiscan.yml` mit.

**Prüfung von außen.** In `monitoring-services/swarm/prom-agent/blackbox-targets.yml`
stehen die Einträge für `scan.vectigal.tech`, `vectiscan.de` und
`scan-api.vectigal.tech/health` auskommentiert bereit. Einkommentieren und
`deploy` in monitoring-services, sobald die Namen auf den Swarm zeigen; vorher
mäße die Prüfung docker02.

**Anmeldung.** Grafana meldet sich am Realm `vect-prod` des Stacks `identity`
an. Zugang gibt die Gruppe `grafana-editoren` (Rolle `editor` am Client
`grafana-api`, Schlüssel `gruppen` in `identity-services/anwendungen/grafana.yml`). Editor und nicht
Viewer, weil Grafana die Logsuche (Explore) erst ab Editor freigibt. Die
Personen legt man von Hand im Realm `vect-prod` an und nimmt sie in die Gruppe
auf (README von identity-services, „Den Realm-Admin anlegen“, gleiches
Vorgehen). Wer heute im Realm `vectiscan` des eigenen Keycloak steht, zeigt
der Job `ops-keycloak-list-users` auf docker02. Die App selbst meldet weiter
über ihr eigenes JWT an und braucht keinen Client im Stack `identity`.

### 1.7 Einschalten

Projektvariable `VECTISCAN_SWARM` auf `an`. Ab dem nächsten Push auf `main`
laufen `swarm:build`, `swarm:trivy`, `swarm:lint` und `swarm:deploy:test`
mit. Der Build dauert so lange wie der für docker02 und läuft parallel auf dem
Runner `vectigal-docker`.

Vorher eine Sache klären: Mit dem Schalter bindet die Pipeline das private
Projekt `vectigal/ci-templates` ein, und das gelingt nur, wenn der Auslöser es
lesen darf. Die Personen im Projekt dürfen das (Stand 07.10.2026), die drei
Projekt-Bots von vectiscan nicht. Eine Pipeline, die ein Projekt-Token
anstößt, scheitert dann schon beim Anlegen; heute betrifft das
`ops-rotate-crm-api-key` mit `GL_WRITE_TOKEN`. Abhilfe: dafür ein Token der
Gruppe `vectigal` nehmen, deren Bots ci-templates lesen dürfen.

## 2. Testfeld prüfen

1. `swarm:deploy:test` grün. Der Job wartet auf das Update und fragt
   `https://scan-test.vectigal.tech/` über jeden Knoten ab.
2. In `vectigal/ci-templates` die Pipeline auf `main` starten, Job
   `erreichbarkeit`: `scan-test` und `scan-api-test` auf allen drei Knoten ok.
3. Anmelden, einen WebCheck-Scan anlegen, im Admin freigeben. Der Fortschritt
   muss live im Browser ankommen (Pub/Sub mit Präfix), der Bericht in
   `vect-test-scan-reports` liegen und die Mail kommen.
4. Ein Live-Check auf der Startseite (webcheck-core).
5. In Grafana unter **Anwendung** den Stack `vect-test-vectiscan` wählen: Logs
   aller Dienste, Speicher und Neustarts müssen erscheinen.

## 3. Prod-Fenster

1. TTL des Wildcards und der beiden `vectiscan.de`-Namen mindestens eine alte
   TTL vorher auf 300 s senken. `max_connections` auf 5433 ist angehoben
   (Abschnitt 1.1).
2. Auf docker02 warten, bis kein Scan läuft und die Listen leer sind, dann
   die Anwendung stoppen. Twenty läuft weiter.
   ```bash
   cd /opt/apps/vectiscan && sudo docker compose exec -T redis redis-cli LLEN scan-pending
   sudo docker compose stop frontend api scan-worker-1 scan-worker-2 scan-worker-3 precheck-worker-1 precheck-worker-2 report-worker
   ```
3. Datenbank sichern, auf docker02:
   ```bash
   cd /opt/apps/vectiscan && sudo docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --no-owner --no-privileges' > /tmp/vectiscan.dump
   ```
   Die Datei nach docker-share01 bringen (direkt, falls docker02 den
   Datenknoten erreicht, sonst über die PuTTY-Tunnel) und dort in die leere
   Datenbank einspielen. Leer heißt: `swarm:deploy:prod` ist noch nicht
   gelaufen, sonst hat die api beim Start schon das Schema angelegt, und die
   Datenbank gehört vorher gelöscht und neu angelegt.
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
   bestehender Bericht lässt sich laden, ein neuer Scan läuft durch, ein
   Testlead kommt in Twenty an.
8. DNS: `scan` und `scan-api` kommen mit dem Wildcard (oder vorher je ein
   A-Record), `vectiscan.de` und `www.vectiscan.de` in ihrer eigenen Zone auf
   `62.217.52.177`. Die Zertifikate holt der cert-renewer selbst.
9. Die Prüfung von außen in monitoring-services einkommentieren (Abschnitt 1.6).
10. Nach ein paar Tagen auf docker02 auch die alten Hilfsdienste stoppen:
    `uptime-kuma`, `loki`, `promtail`, `grafana`, `keycloak`, `keycloak-db`,
    `oauth2-proxy`. Sie sehen die Anwendung nach dem Umzug ohnehin nicht mehr.

**Rückweg:** A-Records zurück auf `62.217.52.165` und auf docker02
`docker compose start`. Was in der Zwischenzeit im Swarm geschrieben wurde,
fehlt dort.

## 4. Offen

- **Twenty** als eigener Stack, mit Postgres auf dem Datenknoten und Ablage in
  MinIO statt `STORAGE_TYPE: local`.
- **ops-Jobs.** Alle `ops-*`, `rollback` und `cleanup-prod` arbeiten mit
  `docker compose exec` in `/opt/apps/vectiscan`. Im Swarm gibt es vorerst nur
  `swarm:rollback`, `swarm:logs` und `swarm:ps` je Feld.
- **Drei api-Instanzen**, siehe Abschnitt 0.
- **Trivy** ist für den Swarm nicht blockierend, wie die Jobs für docker02.
- **Alte Namen.** `status.`, `logs.` und `id.vectigal.tech` liefern nach der
  Umstellung des Wildcards 404. Wer Lesezeichen hat, braucht den Hinweis auf
  `grafana.vectigal.tech`; eine Umleitung wäre ein eigener Router.
