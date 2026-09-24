# M6 Deploy-Status (2026-05-13)

## Zustand am Morgen nach der Nachtschicht

**Code-Stand**:
- M5 (Schicht 3 + Anhaenge A-F) **fertig** + alle Tests gruen.
- M6.1 (Screenshot-Pipeline v2: Body-Hash-Dedup, Cap max. 2, Caption fuer
  Duplikate) **fertig** + 12 neue Tests gruen.
- M6.4 (Big-Bang-Cutover) **vorbereitet, nicht ausgefuehrt**:
  `docker-compose.yml` liefert nun
  `VECTISCAN_REPORT_LAYOUT: ${VECTISCAN_REPORT_LAYOUT:-v1}` als ENV-Hook.
  Der **Default bleibt v1** bis nach dem Pilot — Legacy-Removal kommt in
  einem Folge-Commit nach Pilot-Erfolg.

**Test-Suite**: 728 passed (676 baseline + 40 M5 + 12 M6.1); 12 pre-existing
`test_claude_client*` Mock-Issues unveraendert (unrelated zu M5/M6).

**Commits**:
- `e170a6c` `feat(report-redesign): M5 + M6.1 — Schicht 3 + Anhaenge + Screenshot-Pipeline v2`
  (auf `main` UND `feat/test-prep`)
- `<m6-prep>` `chore(m6): docker-compose VECTISCAN_REPORT_LAYOUT-Hook + Doku-Update`
  (auf `feat/test-prep`)

## Was BLOCKIERT war: GHCR_TOKEN abgelaufen

Pipeline 2449 (auf main, Commit `e170a6c`) ist sofort fehlgeschlagen mit:

```
$ echo "${GHCR_TOKEN}" | docker login ghcr.io -u dc-77 --password-stdin
Error response from daemon: Get "https://ghcr.io/v2/": denied: denied
ERROR: Job failed: exit status 1
```

**Pipeline-URL**: https://git-extern.bergersysteme.com/vectigal/vectiscan/-/pipelines/2449

`GHCR_TOKEN` ist eine GitLab-CI/CD-Variable, die der GHCR-Push beim Build
benoetigt. Der Token muss erneuert werden in GitLab-Project-Settings
`Settings → CI/CD → Variables`. Neuer Token aus GitHub
`Settings → Developer Settings → Personal Access Tokens → Tokens (classic)` mit
`write:packages` Scope.

## To-Do morgen (in Reihenfolge)

1. **GHCR_TOKEN rotieren** in GitLab CI/CD Variables.
2. **Pipeline 2449 retriggern** (oder neue Pipeline auf main starten — alles
   ist commited). Build dauert ~15-20 Min.
3. **deploy-auto** laeuft automatisch auf main bei erfolgreichem Build.
4. **Pilot v2** (ohne Risiko fuer aktuelle Kunden, weil ENV-Flag-Default v1):
   ```bash
   # Auf vectigal-docker02:
   cd /opt/apps/vectiscan
   # Test-Override fuer einen Re-Gen:
   VECTISCAN_REPORT_LAYOUT=v2 docker compose run --rm report-worker \
       python -m reporter.replay_order --order-id <ALTE-ORDER-ID>
   ```
   Oder im Dashboard "Report neu generieren" anstossen, nachdem der ENV-Flag
   im Container gesetzt wurde (kurz `VECTISCAN_REPORT_LAYOUT=v2` in `.env`
   setzen + `docker compose up -d report-worker`).
5. **10 Pilot-Re-Generations** (Master-Plan Empfehlung) — verschiedene Pakete:
   - 2-3 Perimeter (z.B. trunk-immobilien.de, heuel.com)
   - 1-2 WebCheck
   - 1-2 Compliance (NIS2)
   - 1-2 SupplyChain (ISO27001)
   - 1-2 Insurance
   PDFs in MinIO bzw. Frontend-Download pruefen, Layout gegen Doc-02-Mockups
   abgleichen.
6. **Tech-Lead-Review** der Pilot-PDFs.
7. **Big-Bang-Cutover-Commit** (Folge-PR):
   - `docker-compose.yml`: `VECTISCAN_REPORT_LAYOUT: v2` (Default-Flip)
   - **Optional sofort, sicher erst nach 1-2 Wochen Pilot-Erfahrung**:
     Legacy-Renderer entfernen:
     - `reporter/generate_report.py`: `build_finding`, `build_screenshots_section`,
       die Legacy-Cover-Renderer u.s.w. — nach `git grep generate_report\\.` pruefen,
       was noch konsumiert wird.
     - `reporter/report_mapper.py:1672-1751` Dispatch-Mapper, Legacy-`map_*`-
       Wrappers wenn ungenutzt.
     - `reporter/worker.py:667-682` Dispatch-Branch zu einem Aufruf reduzieren.
8. **CHANGELOG-Eintrag** "Report-Redesign v2 cut over, v1 retired".

## Risiken / Fall-back

- Wenn ein Pilot-PDF kritische Layoutprobleme zeigt: ENV-Flag wieder auf v1
  setzen (`VECTISCAN_REPORT_LAYOUT=v1` in `.env`), `docker compose up -d
  report-worker`. Kein Code-Change noetig.
- POLICY_VERSION ist auf `2026-06-01.1` bereits seit M2. Keine
  AI-Cache-Invalidate-Aktion noetig.
- Validation-Gate ist STRICT — v2-Reports muessen das Gate passieren.
  Bei Pilot-Fehlern: Gate-Output in `reports.validation_warnings` pruefen.

## Test-Daten fuer Pilot

Bekannte historische Orders (aus Memory):
- `7629dd77-260b-4b68-9f26-b4d806fabe09` — secumetrix.de · perimeter · 21 Seiten · HIGH
- `12bdbf3a-0691-42e4-933a-dad430f9fa0b` — heuel.com · perimeter · MEDIUM

Synthetische Fixtures (lokal):
- `report-worker/reporter/validation/tests/fixtures/replay_secumetrix_like.json`
- `report-worker/reporter/validation/tests/fixtures/replay_trunk_heuel_like.json`

Lokaler Doppel-Render-Test:
```bash
cd report-worker
python -m pytest tests/test_m5_layer3_appendix.py::TestM5DoppelRender -v
```

---

## Nachtrag S6 (2026-09-22): Umschaltung auf den Pruefkatalog

Der M6-Cutover oben schaltete zwischen zwei ReportLab-Renderern (v1 und v2).
Seit S6 ist der Bericht ein anderer: die Befunde kommen aus dem Pruefkatalog,
nicht mehr aus einer KI-Ausgabe, und gesetzt wird mit WeasyPrint. Vorgaben seit
diesem Stand:

| Variable | Vorgabe | Wirkung |
|---|---|---|
| `VECTISCAN_REPORT_ENGINE` | `catalog` | woher die Befunde kommen |
| `VECTISCAN_REPORT_LAYOUT` | `v3` | welcher Renderer setzt |
| `VECTISCAN_VALIDATION_LEVEL` | `strict` | Fehler halten den Bericht auf |

### Rueckweg

Drei Zeilen in `/opt/vectiscan/.env` auf vectigal-docker02, danach
`docker compose up -d report-worker`. Kein Code-Change, kein Build.

```
VECTISCAN_REPORT_ENGINE=legacy
VECTISCAN_REPORT_LAYOUT=v2
VECTISCAN_VALIDATION_LEVEL=warn
```

Die drei Zeilen stehen seit S6 auch in dem `.env`, das `deploy-auto` schreibt
(`.gitlab-ci.yml`, `.deploy-base`), jeweils mit einer CI-Variable als
Uebersteuerung. Dauerhaft gehoert der Rueckweg deshalb in die CI-Variablen und
nicht in die Datei auf dem Host: das naechste Deploy schreibt sie neu.

**Die drei Zeilen gehoeren zusammen.** `VECTISCAN_REPORT_ENGINE=catalog` mit
`VECTISCAN_REPORT_LAYOUT=v2` ist ein Startfehler und kein stiller Rueckfall:
der alte Renderer liest das Datenmodell der alten Kette, und das entsteht unter
`catalog` nicht. Ein unbekannter Wert ist ebenfalls ein Fehler, damit ein
Tippfehler in der Deploy-Konfiguration nicht unbemerkt den alten Weg faehrt.

### Was der Rueckweg kostet

Der Legacy-Weg faehrt KI#5 mit der Reparaturkette (Opus 4.7) und kostet rund
1,85 USD je Bericht; der Katalogweg liegt bei rund 0,54 USD (Prosa und
Recherche auf Opus 5). Der Rueckweg bringt ausserdem die Befunde zurueck, die
das Gegenlesen in `report-prototype/spec/08-gegenlesen-v3-pdfs.md` beanstandet
hat. Er ist als Notbremse gedacht, nicht als Betriebszustand, und verschwindet
eine Release nach S6 zusammen mit `severity_policy.py` und dem ReportLab-Pfad.

### Wenn das Gate blockiert

`strict` heisst: ein Fehler haelt den Bericht auf, die Order geht auf
`report_blocked`, es gibt kein PDF und keinen Upload. Die Defektliste steht in
`orders.report_defects` und im Admin-Review unter `/admin/review/<orderId>` im
Reiter "Defekte"; von dort fuehrt "Regenerieren nach Fix" den Lauf ohne neuen
Scan noch einmal aus. Erst wenn das nicht weiterhilft, ist
`VECTISCAN_VALIDATION_LEVEL=warn` der Zwischenschritt, und auch dann haengt die
Auslieferung weiter an der Admin-Freigabe.

Einzelheiten zur Pipeline: `docs/report-pipeline/`.

---

## Nachtrag S6a2 (2026-09-24): Abbilder nur aus der eigenen Registry

Am 24.09.2026 lieferte quay.io `minio/minio` nur noch mit Anmeldung (401), und
das pauschale `docker compose pull` in `deploy-auto` riss den ganzen Deploy mit
(Pipeline 3181). Seitdem gilt (Entscheidung DC, MR !93 und !94):

- **Jedes Abbild** in `docker-compose.yml`, `docker-compose.dev.yml` und
  `scan-worker/tests/integration/docker-compose.zap-it.yml` liegt unter
  `ghcr.io/dc-77/vectiscan/`.
- **Eigene Abbilder** (frontend, api, scan-worker, report-worker) sind
  **privat** und stehen mit `${TAG}` (Commit-SHA) in der Compose-Datei.
- **Fremdabbilder** (MinIO, postgres, redis, ZAP, web-check, uptime-kuma, loki,
  promtail, grafana, twenty, keycloak, oauth2-proxy, python) sind dorthin
  gespiegelt, per Digest gepinnt und **öffentlich**. `docker-compose.dev.yml`
  und der ZAP-Integrationstest brauchen damit kein `docker login`.
- **Deploy und Rollback** ziehen nur über `scripts/ops/pull-own-images.sh`,
  nie pauschal und nie mit `--ignore-pull-failures`. `tests/test_compose_images.py`
  (Job `test-edge`) hält die Regel fest.

### Neues Fremdabbild oder neue Version

1. Zeile in `scripts/ops/mirror-images.sh` eintragen (Quelle und Ziel
   `<name>:<tag>`).
2. Job `ops-mirror-images` auf einer API-Pipeline starten. Er spiegelt, was auf
   dem Host läuft, zieht nur Fehlendes, liest den Digest bei ghcr.io und prüft
   ihn mit `docker pull <name>@<digest>`. Ergebnis im Artefakt
   `mirror-images/digests.txt`.
3. **Ein neues Paket ist auf ghcr.io zunächst privat.** Die Sichtbarkeit lässt
   sich nicht per API ändern: auf github.com unter
   `https://github.com/users/dc-77/packages/container/vectiscan%2F<name>/settings`,
   Danger Zone, "Change visibility", Public. Nur für Fremdabbilder, nie für die
   vier eigenen. Ein öffentliches Paket lässt sich auf GitHub nicht wieder
   privat stellen. Der Job warnt, solange ein Spiegel nicht anonym ziehbar ist.
4. Digest in die Compose-Datei(en) eintragen, `pytest tests/test_compose_images.py`.

Falle: Der Host nutzt den containerd-Store. Dort ist die lokale Image-ID der
Digest des Multi-Plattform-Index, gepusht wird aber nur amd64. Nie die Image-ID
als Digest pinnen; der erste Versuch (Pipeline 3186) scheiterte daran mit
"not found".
