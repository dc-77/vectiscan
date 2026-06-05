# VectiScan — Monitoring, Logging & Alerting Runbook

Ticket: VEC-85 (Teil von VEC-52, A5 — Produktions-Infra). Deckt die Akzeptanz
**„Uptime/Health-Monitoring + Log-Aggregation + Alerting"** ab. Komplett
**self-hosted und spend-frei** auf `vectigal-docker02`.

## Überblick

| Aspekt           | Lösung |
|------------------|--------|
| Uptime/Health    | **Uptime-Kuma** — aktives Probing aller Services, Web-UI + Alerting |
| Log-Aggregation  | **Loki + Promtail** — Promtail tailt alle Container-Logs (Docker-API) → Loki |
| Log-Viewer       | **Grafana** — Loki als vorprovisionierte Datasource + Logs-Dashboard |
| Alerting-Kanal   | **Resend-Mail (SMTP)** — siehe Entscheidung unten |
| Spend            | 0 € — alle Images Open-Source, laufen im bestehenden Stack |
| Retention (Logs) | 14 Tage (synchron zur Backup-Retention) |

Alle Komponenten liegen in der zentralen `docker-compose.yml` (Block
`MONITORING-STACK`) und werden vom CI-Job `deploy-auto` automatisch mit
ausgerollt. Die Configs liegen unter `monitoring/` und werden im Deploy neben
`docker-compose.yml` auf den Server kopiert.

## Erreichbarkeit (intern, hinter Traefik `internal-only@file`)

| Dienst        | URL                          | Port (intern) |
|---------------|------------------------------|---------------|
| Uptime-Kuma   | `https://status.vectigal.tech` | 3001 |
| Grafana       | `https://logs.vectigal.tech`   | 3000 |
| Loki (API)    | nur `vectiscan-internal`, kein Ingress | 3100 |

DNS: `*.vectigal.tech` zeigt bereits auf den Server (Wildcard) — keine neuen
DNS-Records nötig. TLS via bestehendem Let's-Encrypt-Default-Resolver.

---

## Entscheidung: Alert-Ziel-Kanal → **Resend-Mail (SMTP)**

Die Issue-Frage „Resend-Mail vs. Webhook" ist als **Resend-Mail** entschieden
(CTO-Entscheidung, im Rahmen des Tickets):

- **Resend ist bereits integriert** (`RESEND_API_KEY` / `RESEND_FROM_EMAIL` in
  `api`) und produktiv für Customer-Mails → kein neuer Dienst, kein neuer Spend.
- **Kein bestehender Chat-/Webhook-Kanal** (kein Slack/Teams/Discord-Webhook im
  Stack), an den ein Webhook sinnvoll andocken könnte.
- Uptime-Kuma unterstützt SMTP nativ — Resend bietet einen SMTP-Endpoint, d. h.
  keine zusätzliche Bridge nötig.

Webhook bleibt als **leichtgewichtige Alternative** offen: sobald ein Ops-Chat
(Slack/Teams) existiert, kann in Kuma zusätzlich eine Webhook-Notification
angelegt werden (additive Änderung, kein Code).

### Resend-SMTP-Parameter für die Kuma-Notification

| Feld          | Wert |
|---------------|------|
| Notification-Typ | SMTP |
| Host          | `smtp.resend.com` |
| Port          | `465` (SSL) bzw. `587` (STARTTLS) |
| Security      | SSL/TLS |
| Username      | `resend` |
| Password      | der vorhandene `RESEND_API_KEY` |
| From          | `RESEND_FROM_EMAIL` (z. B. `noreply@vectigal.tech`) |
| To            | Ops-Postfach — **`ADMIN_EMAIL`** (bereits als Env vorhanden) |

> Hinweis Absender-Domain: Resend versendet nur von verifizierten Domains.
> `vectigal.tech` ist für die Customer-Mails bereits verifiziert, daher
> funktioniert `noreply@vectigal.tech` direkt.

---

## Einrichtung (einmalig, nach erstem Deploy)

Uptime-Kuma persistiert seine Konfiguration im Volume `vectiscan-kuma-data`,
d. h. das Setup ist **einmalig** und überlebt Redeploys/Restarts.

### 1. Admin-Account anlegen
`https://status.vectigal.tech` öffnen → beim ersten Aufruf Admin-User +
Passwort setzen (intern-only-Netz, aber bitte starkes Passwort).

### 2. Resend-SMTP-Notification anlegen
Settings → Notifications → Setup Notification → Typ **SMTP** → Parameter aus der
Tabelle oben → **Test** klicken → speichern. Als Default-Notification markieren,
damit neue Monitore sie automatisch verwenden.

### 3. Monitore anlegen
Pro Service einen Monitor (Typ je nach Erreichbarkeit). Empfohlene Baseline:

| Monitor                | Typ        | Ziel | Intervall |
|------------------------|------------|------|-----------|
| API `/health`          | HTTP(s)    | `https://scan-api.vectigal.tech/health` | 60 s |
| Frontend               | HTTP(s)    | `https://scan.vectigal.tech` | 60 s |
| Postgres               | TCP-Port   | `postgres:5432` | 60 s |
| Redis                  | TCP-Port   | `redis:6379` | 60 s |
| MinIO                  | HTTP(s)    | `http://minio:9000/minio/health/live` | 60 s |
| Loki                   | HTTP(s)    | `http://loki:3100/ready` | 120 s |
| scan-worker (heartbeat)| Push (opt.)| s. u. | — |

> Kuma hängt am Netz `vectiscan-internal`, kann also interne Service-Namen
> (`postgres`, `redis`, `minio`, `loki`) direkt erreichen. Für externe Sicht
> zusätzlich die `https://`-Routen (testet auch Traefik + TLS).

Retries pro Monitor auf 2–3 setzen, damit kurze Latenzspitzen keinen Fehlalarm
auslösen. „Notify" mit der Resend-SMTP-Notification verknüpfen.

### 4. (Optional) Status-Page
Kuma kann eine interne Status-Page bündeln (alle Monitore auf einen Blick) —
nice-to-have, nicht erforderlich.

---

## Logs ansehen (Grafana)

1. `https://logs.vectigal.tech` → Login (`GRAFANA_ADMIN_USER` /
   `GRAFANA_ADMIN_PASSWORD`, Default `admin` / `vectiscan-admin` —
   **nach erstem Login ändern**, siehe unten).
2. Dashboard **„VectiScan — Logs"** (Ordner *VectiScan*) ist vorprovisioniert:
   - Panel 1: Fehler & Warnungen über alle Services
   - Panel 2: Logs gefiltert nach Service (`$service`-Variable)
3. Ad-hoc: **Explore** → Datasource *Loki* → LogQL, z. B.
   `{project="vectiscan", service="api"} | json | level="error"`.

### Grafana-Admin-Passwort härten
Default ist `vectiscan-admin` (Grafana ist intern-only, read-only Logs → geringes
Risiko). Für Produktion sauber: CI/CD-Variable `GRAFANA_ADMIN_PASSWORD` setzen
und in `.deploy-base` (`.gitlab-ci.yml`) in den `.env`-Heredoc aufnehmen, dann
redeployen. Bis dahin reicht das Default hinter `internal-only`.

---

## WebCheck-Free Mail-Amplification-Alert (VEC-173)

Der öffentliche, anonyme Endpunkt `POST /api/webcheck/start` versendet eine
DOI-Bestätigungsmail. Schutz gegen Mail-Amplification/Spam-Relay (F2 aus
VEC-169) ist mehrschichtig: CAPTCHA (Turnstile) vor dem Versand + aggregierte
Velocity-Drossel (global + pro Empfänger-Mail-Domain), die per IP-Rotation NICHT
umgehbar ist.

Bei erreichter Velocity-Schwelle loggt `api` einen stabilen JSON-Marker
(zusätzlich zur `audit_log`-Zeile `webcheck.velocity_alert` für DB-Forensik):

```
{"event":"webcheck_velocity_alert","reasons":["global"|"recipient_domain"],...}
```

**Grafana-Alert (empfohlen, Loki-Query):** Spike auf den Marker alerten —
```
count_over_time({project="vectiscan", service="api"} | json | event="webcheck_velocity_alert" [5m])
```
Schwelle z. B. `> 0` über 5min ⇒ Mail an `ADMIN_EMAIL`. Ebenso optional auf
`event="webcheck_captcha_failed"`-Spikes (Bot-Flut-Indikator). Die Code-Schwellen
(`VELOCITY.maxGlobal` / `maxPerRecipientDomain` in `routes/webcheck.ts`) sind
konservativ vordimensioniert und post-Launch anhand realer Velocity nachzuschärfen.

**CAPTCHA-Config:** `WEBCHECK_TURNSTILE_SECRET` (docker-compose `api`-env). Unset
⇒ CAPTCHA deaktiviert (fail-open, nur Dev/Test). In Prod vor breitem
Funnel-Rollout setzen — Launch-Checkliste.

---

## Was deckt das ab — und was nicht

**Abgedeckt:**
- Aktives Uptime/Health-Probing aller Kern-Services inkl. externer TLS-Route.
- Zentrale Aggregation **aller** Container-Logs (pino/structlog-JSON wird
  geparst, `level` als Label) mit 14-Tage-Retention.
- Laufzeit-Alerts (Down/Recovery) per Resend-Mail an `ADMIN_EMAIL`.

**Bewusst nicht (Scope-Grenze / Folge-Tickets):**
- Metriken/APM (Prometheus, Tracing) — nicht Teil von VEC-85; bei Bedarf
  separates Ticket.
- Log-basiertes Alerting (z. B. „>N Errors/min") — Grafana-Alerting wäre der
  nächste Schritt; aktuell deckt Kuma das Uptime-Alerting ab.
- Off-Site-Backup — siehe `OFFSITE-BACKUP-EVAL.md`.

## Betrieb / Troubleshooting

```bash
cd ${DEPLOY_PATH}
docker compose ps uptime-kuma loki promtail grafana
docker compose logs --tail=50 promtail      # keine Logs in Loki? hier prüfen
docker compose logs --tail=50 loki
curl -s http://localhost:3100/ready          # nur vom Server / interne IP
```

Promtail liest über den **Docker-Socket** (`/var/run/docker.sock:ro`) — wenn
keine Logs ankommen, prüfen ob der Socket gemountet ist und Promtail Container
discovered (`docker compose logs promtail`).
