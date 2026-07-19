# AUTH-SSO C3 — oauth2-proxy + Traefik forwardAuth (VEC-439)

Teil des Auth-Overhauls [VEC-421](../docs/AUTH-OVERHAUL-VEC-421.md). Baut auf
C1 ([VEC-437](AUTH-SSO-C1-KEYCLOAK.md), dedizierte Keycloak-Instanz) auf.

> **UPDATE Juli 2026 — Auth-Konsolidierung:** Das Edge-Gate vor
> `scan.vectigal.tech/admin` wurde wieder ENTFERNT. `/admin` ist eine Next.js-SPA,
> deren Autorisierung ohnehin ausschließlich über das App-JWT läuft (`useAdminGuard`
> + `/api/admin requireAdmin`, `users.role='admin'`); das vorgeschaltete
> oauth2-proxy/Keycloak-Gate war nur Defense-in-Depth für die HTML-Shell und erzwang
> eine zweite, separate Keycloak-Anmeldung (Doppel-Login). **Seitdem schützen
> oauth2-proxy/Keycloak nur noch `status.vectigal.tech` (Uptime-Kuma) und — via
> nativem OIDC — `logs.vectigal.tech` (Grafana).** Die untenstehende Beschreibung des
> `scan/admin`-forwardAuth-Flows ist damit historisch. Konkret entfernt:
> `oauth2-proxy-redirect@file` am Router `vectiscan-web-admin` und der
> `/oauth2/`-Router `vectiscan-oauth2-scan` (beide `docker-compose.yml`). Rollback =
> Middleware wieder anhängen (bleibt im File-Provider definiert).

## Ziel

Die Basic-Auth-Popups (`internal-auth@file`, VEC-143) auf den beiden
Browser-Flächen durch echtes SSO gegen den Keycloak-Realm `vectiscan` ablösen:

| Fläche | Host | vorher | nachher |
|---|---|---|---|
| Uptime-Kuma | `status.vectigal.tech` | Basic-Auth | SSO (Gruppe `vectiscan-admin`) |
| Frontend Admin | `scan.vectigal.tech/admin` | Basic-Auth | SSO (Gruppe `vectiscan-admin`) |

**NICHT umgestellt:** `scan-api.vectigal.tech/api/admin` bleibt App-JWT
(`requireAdmin`). Grund: forwardAuth würde unauthentifizierte SPA-`fetch()`-Calls
mit `302 → Keycloak-HTML` beantworten statt `401-JSON` — bricht das Frontend
(Root-Cause [VEC-370](../docs/...)). Der API-Router trägt daher bewusst **keine**
forwardAuth-Middleware.

## Architektur

```
Browser ──HTTPS──► Traefik (Host) ──proxy-net──► oauth2-proxy:4180
                      │                                  │
                      │  forwardAuth /oauth2/auth        │ OIDC
                      │  (oauth2-proxy-redirect@file)    ▼
                      │                          id.vectigal.tech
                      ▼                          (Realm vectiscan)
              Kuma / Frontend-Admin
```

- **Ein** oauth2-proxy bedient beide Domains (Multi-Domain via
  `--cookie-domain=.vectigal.tech` + `--whitelist-domain=.vectigal.tech` →
  eine SSO-Session für `status` + `scan`).
- `redirect_url` ist **nicht** gesetzt → pro Host aus `X-Forwarded-*` abgeleitet
  (`--reverse-proxy=true`). Beide Callback-URIs
  (`https://status…/oauth2/callback`, `https://scan…/oauth2/callback`) sind im
  Realm-Client `vectiscan-oauth2-proxy` registriert (C1).
- Autorisierung: nur Mitglieder der Keycloak-Gruppe `vectiscan-admin`
  (`--allowed-group=vectiscan-admin`; Realm-Mapper `groups`, `full.path=false`).

### Request-Fluss (unauthentifiziert)

1. `GET status.vectigal.tech/` → Router-Middleware `oauth2-proxy-redirect@file`.
2. `forwardAuth` ruft `oauth2-proxy:4180/oauth2/auth` → **401**.
3. `errors`-Middleware fängt 401 → `302` auf `/oauth2/sign_in?rd=<url>`.
4. `--skip-provider-button=true` → sofort `302` zu Keycloak-Login.
5. Login → Callback `…/oauth2/callback` (Router `vectiscan-oauth2-*`,
   Prio 110) → oauth2-proxy setzt Session-Cookie auf `.vectigal.tech`.
6. Redirect auf ursprüngliches Ziel → forwardAuth `200` → App.

## Bausteine (Repo)

| Datei | Änderung |
|---|---|
| `docker-compose.yml` | Service `oauth2-proxy` (`quay.io/oauth2-proxy/oauth2-proxy:v7.7.1`, Profil `sso`, proxy-net) + `/oauth2/`-Router für status+scan. Router `vectiscan-status` + `vectiscan-web-admin` von `internal-auth@file` → `oauth2-proxy-redirect@file`. |
| `traefik/dynamic/vectiscan-auth.yml` | Middlewares `oauth2-proxy-auth` (forwardAuth), `oauth2-proxy-errors` (errors→sign_in), `oauth2-proxy-redirect` (chain) + Service `oauth2-proxy`. `internal-auth` bleibt definiert (Rollback). |
| `.gitlab-ci.yml` | `ops-keycloak-provision`: Cookie-Secret-Check + Schritt 7 startet `oauth2-proxy` + `/ping`-Wait. |
| `.env.template` | SSO-Block inkl. `OAUTH2_PROXY_COOKIE_SECRET`. |

## Secrets (maskierte CI/CD-Variablen)

| Variable | Inhalt | erzeugen |
|---|---|---|
| `KEYCLOAK_OAUTH2_PROXY_SECRET` | Client-Secret `vectiscan-oauth2-proxy` (C1, bereits gesetzt) | — |
| `OAUTH2_PROXY_COOKIE_SECRET` | Cookie-Signatur, 16/24/32-Byte URL-safe base64 | `openssl rand -base64 32 \| tr -- '+/' '-_'` |

`OAUTH2_PROXY_COOKIE_SECRET` ist die **einzige neue** Variable für C3 und muss
vor dem nächsten `ops-keycloak-provision`-Lauf gesetzt sein (sonst Fail-fast im
Secret-Check). Kein Board-Gate — via Maintainer-PAT setzbar (vgl.
[VEC-452](/VEC/issues/VEC-452)).

## Aktivierung / Deploy

`ops-keycloak-provision` ist der einzige sso-Aktivierungspfad (manueller
main-/web-Job). Er importiert den Realm (idempotent) **und** startet jetzt
zusätzlich `oauth2-proxy`. Der reguläre `deploy-auto` (Profil nur `crm`) lässt
die sso-Container unangetastet (profil-gated → kein `--remove-orphans`-Kill,
kein Stop durch crm-only `up`). Die geänderten Router-Labels werden mit dem
normalen Compose-Rollout aktiv, sobald `oauth2-proxy` läuft.

## Verifikation (C5 / VEC-441, Live-QA)

1. `oauth2-proxy /ping` → `200` (Provision-Job-Log).
2. Inkognito `https://status.vectigal.tech/` → Redirect zu `id.vectigal.tech`
   (kein Basic-Auth-Popup mehr).
3. Login als `vectiscan-admin`-Member → Kuma erreichbar; Session-Cookie auf
   `.vectigal.tech`.
4. Ohne Logout `https://scan.vectigal.tech/admin` → **kein** erneuter Login
   (SSO-Session greift cross-domain).
5. Nutzer **ohne** Gruppe `vectiscan-admin` → `403` von oauth2-proxy.
6. `https://scan-api.vectigal.tech/api/admin/...` ohne JWT → weiterhin
   `401-JSON` (App-JWT, **keine** forwardAuth-Umleitung).
7. Negativ: direkter `…/oauth2/auth`-Call extern → 401/403 (kein Bypass).

## Rollback (Two-way-door)

Router-Labels in `docker-compose.yml` zurück auf
`security-headers@file,internal-auth@file` (Kuma + Frontend-Admin) und
Compose neu ausrollen. `internal-auth@file` bleibt im File-Provider definiert →
Basic-Auth ist sofort wieder aktiv. oauth2-proxy/Keycloak können laufen bleiben.

## Bekannte QA-Schwerpunkte (mangels Runtime-Test in der Sandbox)

- **Multi-Domain-redirect_url:** Ableitung aus `X-Forwarded-Host` setzt voraus,
  dass Traefik `X-Forwarded-Host/Proto` korrekt an `/oauth2/sign_in` (via
  errors-Middleware) **und** an `/oauth2/auth` (forwardAuth) durchreicht. Falls
  der Callback auf den falschen Host zeigt: `--redirect-url` je Host fixieren
  (zwei oauth2-proxy-Instanzen) **oder** auf einen kanonischen Callback-Host
  (z. B. nur `status`) konsolidieren (Cookie-Domain deckt beide ab).
- **Egress:** oauth2-proxy erreicht `https://id.vectigal.tech` über proxy-net →
  Internet → Traefik (Hairpin). Falls geblockt: oauth2-proxy zusätzlich an
  `keycloak-internal` hängen und Split-DNS/`--skip-oidc-discovery` mit internen
  Endpoints — verändert aber die `iss`-Validierung.
