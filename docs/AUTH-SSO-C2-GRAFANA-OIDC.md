# C2 — Grafana natives OIDC gegen Keycloak (VEC-438)

Parent: VEC-421 · Vorgänger: C1 (VEC-437, Keycloak live) · Nachgelagert: C4 (VEC-440
CI-Regression) → C5 (VEC-441 Security/QA) → C6 (VEC-442 Cutover, Hamilton).

Grafana (`logs.vectigal.tech`) bekommt natives OIDC (`GF_AUTH_GENERIC_OAUTH_*`)
gegen den Keycloak-Realm `vectiscan` (Client `vectiscan-grafana`). Basic-Auth
(`internal-auth@file`) **bleibt scharf bis zur QA-Verifikation** und wird erst im
Cutover (C6) entfernt.

## Was geändert wurde (Code)

`docker-compose.yml` — Service `grafana`, neue Env (additiv, kein Breaking Change):

| Variable | Wert |
|---|---|
| `GF_AUTH_GENERIC_OAUTH_ENABLED` | `true` |
| `GF_AUTH_GENERIC_OAUTH_NAME` | `Keycloak` |
| `GF_AUTH_GENERIC_OAUTH_CLIENT_ID` | `vectiscan-grafana` |
| `GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET` | `${KEYCLOAK_GRAFANA_SECRET:-}` (aus .env/CI) |
| `GF_AUTH_GENERIC_OAUTH_SCOPES` | `openid email profile` |
| `GF_AUTH_GENERIC_OAUTH_AUTH_URL` | `https://id.vectigal.tech/realms/vectiscan/protocol/openid-connect/auth` |
| `GF_AUTH_GENERIC_OAUTH_TOKEN_URL` | `https://id.vectigal.tech/realms/vectiscan/protocol/openid-connect/token` |
| `GF_AUTH_GENERIC_OAUTH_API_URL` | `https://id.vectigal.tech/realms/vectiscan/protocol/openid-connect/userinfo` |
| `GF_AUTH_GENERIC_OAUTH_USE_PKCE` | `true` |
| `GF_AUTH_GENERIC_OAUTH_LOGIN_ATTRIBUTE_PATH` | `preferred_username` |
| `GF_AUTH_GENERIC_OAUTH_NAME_ATTRIBUTE_PATH` | `name` |
| `GF_AUTH_GENERIC_OAUTH_EMAIL_ATTRIBUTE_PATH` | `email` |
| `GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH` | `contains(groups[*], 'vectiscan-admin') && 'Admin' \|\| 'Viewer'` |
| `GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_STRICT` | `false` |
| `GF_AUTH_GENERIC_OAUTH_ALLOW_ASSIGN_GRAFANA_ADMIN` | `false` |

`.gitlab-ci.yml` — `KEYCLOAK_GRAFANA_SECRET=${KEYCLOAK_GRAFANA_SECRET:-}` in den
`.env`-Heredoc des `deploy`-Templates aufgenommen, damit `deploy-auto`/`docker
compose up` das Client-Secret für Grafana interpoliert (CI-Var existiert bereits,
gesetzt in C1/VEC-452).

## Rollen-Mapping

- Keycloak-Gruppe `vectiscan-admin` → Group-Claim-Mapper liefert Claim
  `groups: ["vectiscan-admin", ...]` (full.path=false, im Realm-Import schon
  konfiguriert).
- JMESPath `contains(groups[*], 'vectiscan-admin') && 'Admin' || 'Viewer'`:
  Mitglieder → Grafana **Admin**, alle anderen authentifizierten User → **Viewer**.
- `STRICT=false` + `|| 'Viewer'`-Fallback: Login wird nie wegen fehlender Rolle
  verweigert.
- `ALLOW_ASSIGN_GRAFANA_ADMIN=false`: keine automatische Vergabe des
  Server-Admin (GrafanaAdmin); reicht für Org-Admin.

## Sicherheit / Blast-Radius

- **Additiv:** Bei leerem `KEYCLOAK_GRAFANA_SECRET` scheitert nur der „Sign in with
  Keycloak"-Button; die lokale `GF_SECURITY_ADMIN`-Anmeldung bleibt als Fallback.
- **Basic-Auth bleibt:** `internal-auth@file` am Traefik-Router `vectiscan-logs`
  ist unverändert. Beides koexistiert: Der Browser sendet weiter den Basic-Auth-
  Header (auch beim OIDC-Callback `/login/generic_oauth`), Keycloak selbst läuft
  auf anderem Host (`id.vectigal.tech`, ohne Basic-Auth) → der Flow geht durch.
- **Kein Secret im Repo:** Client-Secret kommt ausschließlich via `.env` aus der CI.

## Deploy (Owner: Hamilton)

Additiver, sicherer Deploy — kann jederzeit auf die nächste main-Pipeline:

1. Branch `feat/vec-438-grafana-oidc` → main (deploy-auto).
2. `deploy-auto` rollt `docker compose up -d` aus → Grafana-Container neu mit OIDC-Env.
3. CI-Var `KEYCLOAK_GRAFANA_SECRET` muss gesetzt sein (ist sie, aus C1/VEC-452).

Rollback: vorherige `docker-compose.yml` + `.env.bak` zurückspielen, Grafana neu
hochfahren. Basic-Auth war durchgehend aktiv → kein Sicherheitsfenster.

## Verifikation (für C5/VEC-441, Mitnick)

**Prerequisite:** Mindestens ein Test-User im Realm `vectiscan` existiert und ist
der Gruppe `vectiscan-admin` zugeordnet (Keycloak-Admin-Konsole
`https://id.vectigal.tech/admin/`, Login `KC_BOOTSTRAP_ADMIN_*`). Ein zweiter
User ohne Gruppe deckt den Viewer-Pfad ab.

1. `https://logs.vectigal.tech` öffnen (Basic-Auth durchlaufen) → Login-Seite
   zeigt Button **„Sign in with Keycloak"**.
2. Klick → Redirect auf `id.vectigal.tech` → Keycloak-Login → zurück nach Grafana.
3. Admin-User (in `vectiscan-admin`): Grafana-Rolle = **Admin**
   (Profil → Rolle, bzw. Admin-Menü sichtbar).
4. Viewer-User (ohne Gruppe): Grafana-Rolle = **Viewer**.
5. Fallback prüfen: lokaler `GF_SECURITY_ADMIN`-Login funktioniert weiter.
