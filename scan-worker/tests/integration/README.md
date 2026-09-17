# ZAP-Integrationstests (S0b)

Reproduktion und Regressionsschutz fuer `zap_active`. Die Tests laufen nur
mit Docker und werden von `pytest` sonst uebersprungen, damit die
CI-Pipeline (`.gitlab-ci.yml`, ruft `pytest` ohne Marker-Filter) gruen bleibt.

## Umgebung

| Dienst | Zweck |
|---|---|
| `zap-a`, `zap-b` | zwei ZAP-Daemons, Flags identisch zur Produktion |
| `redis` | traegt die Leases aus `scanner/zap_pool.py` |
| `target` | eigenes, absichtlich angreifbares Testziel (`target_app.py`) |
| `runner` | python:3.12-slim, faehrt pytest im Compose-Netz |

Zwei ZAP-Instanzen, weil sich die Hypothese „Kontext in Instanz A, Scan in
Instanz B" sonst nicht pruefen laesst. Gescannt wird ausschliesslich der
eigene `target`-Container.

## Fahren

```bash
docker compose -f scan-worker/tests/integration/docker-compose.zap-it.yml up -d
docker compose -f scan-worker/tests/integration/docker-compose.zap-it.yml run --rm runner
docker compose -f scan-worker/tests/integration/docker-compose.zap-it.yml down -v
```

Diagnoselauf mit Protokoll (Scanner-IDs, Split-Fall, vollstaendiger Lauf):

```bash
docker compose -f scan-worker/tests/integration/docker-compose.zap-it.yml \
  run --rm runner sh -c \
  "pip install --quiet -r tests/integration/requirements-it.txt && \
   python -m tests.integration.repro_zap_active"
```

## Warum im Netz und nicht auf dem Host

ZAP bedient seine REST-API nur, wenn der Host-Header zum eigenen Listener
passt. Vom Host aus trifft `localhost:18090` auf einen Listener auf `:8090`;
ZAP haelt das fuer eine Proxy-Anfrage und antwortet mit `502`. Im Compose-Netz
heisst die Instanz `zap-a:8090`, genau wie in Produktion `zap-1:8090`.

Fuer manuelle Abfragen vom Host reicht ein passender Host-Header:

```bash
curl -H "Host: zap-a:8090" http://localhost:18090/JSON/ascan/view/scanners/
```

## Befund, den diese Umgebung erbracht hat

`enableScanners` lehnt den gesamten Aufruf ab, wenn auch nur eine der
uebergebenen Scanner-IDs im Image fehlt:

```
{"code":"does_not_exist","message":"Does Not Exist","detail":"IDs: [40024]"}
```

In Produktion steht `api.incerrordetails` auf `false`, damit faellt `detail`
weg und es bleibt genau der Text, der in 42 Scans in `scan_results` stand.
`zaproxy/zap-stable:2.17.0` bringt 52 aktive Regeln mit; `40024` (SQLi
SQLite) und `40046` (SSRF) sind nicht darunter. Der Regelsatz haengt am
Image, deshalb ist die ZAP-Version gepinnt.
