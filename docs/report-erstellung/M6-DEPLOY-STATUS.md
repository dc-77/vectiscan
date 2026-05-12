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
