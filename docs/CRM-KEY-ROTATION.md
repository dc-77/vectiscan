# CRM-API-Key-Rotation (Twenty) — Runbook

**Owner:** CTO (Carmack) · **Quelle:** VEC-398 (Board-Direktive VEC-397)

## Grundsatz: API-Only, kein Direkt-DB-Zugriff

Twenty wurde wegen seiner API ausgewählt. Es gibt **keinen** Direkt-DB-Zugriff
auf die Twenty-DB (`twenty-db` / `core.*` / `workspace_*`) und **keine**
auto-erstellten Tabellen mehr. Der Laufzeit-Lead-Sync läuft zu 100 % über
Twentys REST-API (`/rest/people`, Bearer `CRM_API_KEY`) in
`api/src/lib/crm.ts`.

## Warum die Rotation einen manuellen Schritt enthält

Recherche zu **Twenty self-hosted v2.9.0** (Stand VEC-398):

| Pfad | Vorhanden? | Tauglich für headless Prod-Rotation? |
|------|-----------|--------------------------------------|
| GraphQL-Mutation `createApiKey` (core API) | Ja | **Nein** — verlangt einen bereits gültigen Access-Token (`RequireAccessTokenGuard`; Henne/Ei genau wenn der Altkey tot ist) **und** gibt nur die `ApiKey`-Entity zurück, **nicht** den nutzbaren Token. Token-Minting ist via GraphQL nicht exponiert. |
| CLI `workspace:generate-api-key` (nest-commander) | Ja | **Nein** — liefert zwar `TOKEN:<token>`, ist aber hart auf `NODE_ENV` `development`/`test` gegated und wirft in production (`"This command is only available in development or test environments"`). |
| psql-INSERT ins `workspace_*`.`"apiKey"` + JWT mit `APP_SECRET` minten | (technisch möglich) | **Verboten** (VEC-397/398): Direkt-DB-Zugriff + Schema-Poking. Entfernt. |

→ Es gibt **keinen** produktionstauglichen, von Twenty unterstützten
headless-Weg, einen API-Key-**Token** zu erzeugen. Der Token wird deshalb
**manuell in der Twenty-UI** generiert. Die restliche Mechanik (Validieren,
CI-Var setzen, Redeploy) bleibt automatisiert und DB-frei.

## Rotation durchführen

Auslöser: `CRM_API_KEY` ist abgelaufen/widerrufen → Twenty antwortet mit `401`
und der Lead-Upsert loggt `crm-lookup-failed`.

1. **Token in Twenty erzeugen** (internes Netz, Twenty-Admin-Login):
   - Twenty-UI öffnen → **Settings → Developers → API Keys**
     (ggf. „Advanced mode" in den App-Settings aktivieren, damit der
     Developers-Bereich erscheint).
   - **„Create key"** → Name z. B. `vectiscan-lead-router` → optionale Expiry.
   - Den angezeigten Token **einmal kopieren** (wird nur einmal gezeigt).

2. **Job mit dem Token ausführen** — GitLab → CI/CD → Pipelines →
   „Run pipeline" auf `main` (oder bestehende Pipeline), Variable setzen:
   - `NEW_CRM_API_KEY` = `<kopierter Token>`
   - Den manuellen Job **`ops-rotate-crm-api-key`** starten.

   Der Job:
   - prüft Preflight (`GL_WRITE_TOKEN`, `NEW_CRM_API_KEY`),
   - **Smoke-Test**: `GET /rest/people?limit=1` mit dem neuen Token → erwartet
     `HTTP 200` (rollt **keinen** toten Key aus),
   - aktualisiert die maskierte CI-Var `CRM_API_KEY` (Wert nie geloggt),
   - triggert einen `main`-Redeploy; `deploy-auto` schreibt den Key frisch in
     die Container-`.env`.

3. **Verifizieren:** nach dem Deploy den Job **`ops-e2e-vec387`** laufen lassen —
   erwartet `crm=created` bzw. `crm=exists` (kein `crm-lookup-failed`).

## Secrets-Hygiene

- `NEW_CRM_API_KEY` wird **nie** geloggt (nur Länge); Übergabe an die GitLab-API
  per `--data-urlencode`, an den Smoke-Test per Container-Env (`-e TKN`).
- Den Altkey in Twenty erst nach erfolgreicher Verifikation widerrufen
  (Blast-Radius klein: ein fehlgeschlagener Rollout invalidiert keinen
  funktionierenden Altkey).

## Bootstrap — die einzige sanktionierte DB-Ausnahme

Die **einmalige** First-Admin-/Workspace-Anlage (VEC-324/326) lief direkt über
die Twenty-DB (`core."user"`, `core.workspace`, `userWorkspace`), weil Twenty
v2.9.0 **keine First-Setup-API** hat. Das ist die **einzige** sanktionierte
Direkt-DB-Berührung und ist **einmalig, nicht wiederkehrend** — es existiert
kein CI-Job, der dies regelmäßig ausführt. Jede neue Twenty-Schreiboperation
läuft ausschließlich über die API.
