# C1 — Dedizierte Keycloak-Instanz (VEC-437)

**Parent:** VEC-421 · **Spike:** VEC-430 (`docs/AUTH-SSO-VEC-430-SPIKE.md`)
**Owner:** Carmack (Config/Code) + Hamilton (Secrets/Deploy) · **Stand:** 2026-06-18

Board-Entscheid: **neue dedizierte Keycloak-Instanz** (kein Reuse). Dieses Doc
ist das Provisionierungs-Runbook für C1. Die eigentliche Edge-Cutover-Arbeit
(Grafana-OIDC, oauth2-proxy, `/admin`/`status`) ist C2/C3 und **nicht** Teil von C1.

---

## Was C1 liefert (im Repo, committet)

| Artefakt | Datei | Zweck |
|---|---|---|
| Keycloak + DB | `docker-compose.yml` (Services `keycloak`, `keycloak-db`) | dedizierte Instanz, eigene Postgres-DB, Profil-gated `sso` |
| Realm-Import | `keycloak/import/vectiscan-realm.json` | Realm `vectiscan`, Clients `vectiscan-grafana` + `vectiscan-oauth2-proxy`, Gruppe `vectiscan-admin`, Group-Claim-Mapper, Redirect-URIs. **Client-Secrets = Platzhalter** |
| Provision-Job | `.gitlab-ci.yml` Job `ops-keycloak-provision` | rendert Secrets, rollt Realm aus, startet `sso`-Profil |
| `.env`-Wiring | `.gitlab-ci.yml` `.deploy-base` | trägt KC-Vars für Reboot-Persistenz nach |

**Blast-Radius = null beim Standard-Deploy:** `keycloak`/`keycloak-db` hängen am
Compose-Profil `sso`. Der reguläre Deploy fährt mit `COMPOSE_PROFILES=crm` und
**überspringt** beide. Alle KC-Secrets sind `${VAR:-}`-Soft-Defaults — ein
fehlendes Secret bricht `docker compose` **nicht** (Lehre aus VEC-304, wo ein
`${VAR:?}` jeden main-Deploy blockierte). Scan-Worker-NAT (`iptables:false`,
`ens192`-MASQUERADE) bleibt unberührt.

## Subdomain / DNS

- Host: **`id.vectigal.tech`** (NICHT `api.vectigal.tech` — Kollision Gutachten-KI).
- `*.vectigal.tech` zeigt bereits auf den Server (CLAUDE.md) → **kein neuer
  DNS-Eintrag nötig**. LE-Cert via HTTP-01-Resolver `letsencrypt-http` (wie alle
  anderen Hosts). Browser-Redirect **und** docker02-Token/JWKS gehen beide über
  diesen HTTPS-Host.

---

## Schritt-für-Schritt-Aktivierung (Owner: Hamilton)

### 1. Maskierte CI/CD-Variablen setzen (Maintainer-only)

GitLab → Project → Settings → CI/CD → Variables. Alle **masked**, Scope `main`/prod:

| Variable | Inhalt | Quelle |
|---|---|---|
| `KC_DB_PASSWORD` | Postgres-PW der Keycloak-DB | frei generieren (`openssl rand -hex 24`) |
| `KC_BOOTSTRAP_ADMIN_PASSWORD` | Master-Admin-PW (nur Erststart wirksam) | frei generieren |
| `KEYCLOAK_GRAFANA_SECRET` | Client-Secret `vectiscan-grafana` | frei generieren (URL-safe) |
| `KEYCLOAK_OAUTH2_PROXY_SECRET` | Client-Secret `vectiscan-oauth2-proxy` | frei generieren (URL-safe) |
| `KC_BOOTSTRAP_ADMIN_USERNAME` | optional, Default `admin` | — |

> Die Client-Secrets werden in C2/C3 von Grafana bzw. oauth2-proxy als
> `${KEYCLOAK_GRAFANA_SECRET}` / `${KEYCLOAK_OAUTH2_PROXY_SECRET}` referenziert —
> identischer Wert beidseitig. **Kein Secret im Repo.** Der Dev-Token kann masked
> Vars nicht setzen → dieser Schritt ist Maintainer-/Hamilton-exklusiv.

### 2. Provision-Job spielen

main-Pipeline (oder web/api) → Job **`ops-keycloak-provision`** manuell starten.
Der Job:
1. prüft, dass alle 4 Secrets präsent sind (sonst `FATAL`, kein Teil-Provision),
2. rollt das aktuelle `docker-compose.yml` ins `DEPLOY_PATH`,
3. rendert `keycloak/import/vectiscan-realm.json` mit den echten Secrets nach
   `${DEPLOY_PATH}/keycloak/import/` (chmod 600),
4. startet `COMPOSE_PROFILES=crm,sso docker compose up -d keycloak-db keycloak`,
5. verifiziert die OIDC-Discovery extern.

**Idempotent:** Realm-Import-Strategie `IGNORE_EXISTING` — ein bestehender Realm
wird beim Re-Run **nicht** überschrieben.

### 3. Verifikation (Erfolgsbedingung C1)

```
# OIDC-Discovery erreichbar (Browser- + docker02-Pfad), 200 erwartet:
curl -sS https://id.vectigal.tech/realms/vectiscan/.well-known/openid-configuration | jq .issuer
# erwartet: "https://id.vectigal.tech/realms/vectiscan"

# Admin-Konsole erreichbar (Login mit KC_BOOTSTRAP_ADMIN_*):
https://id.vectigal.tech/admin/

# Im Realm vectiscan sichtbar: Clients vectiscan-grafana + vectiscan-oauth2-proxy,
# Gruppe vectiscan-admin. Mindestens einen Admin-User anlegen + der Gruppe zuweisen.
```

> LE-Cert für `id.vectigal.tech` kann beim Erststart 1–2 Min brauchen (HTTP-01).
> Bis dahin liefert der externe Discovery-Check ggf. ein Default-Self-Signed-Cert.

---

## Rollback (Two-way-Door)

```
cd ${DEPLOY_PATH}
docker compose --profile sso stop keycloak keycloak-db   # Instanz anhalten
# optional vollständig entfernen (Daten bleiben im Volume keycloak-pg-data):
docker compose --profile sso rm -f keycloak keycloak-db
```

Da `sso` ein eigenes Profil ist und keine bestehende Fläche umkonfiguriert,
berührt C1 **keine** Live-Auth — die 4 Edge-Gates bleiben bis C2/C3/C6 auf
Basic-Auth. Reversibel ohne Rebuild, ohne Daten-Risiko.

## Nächste Schritte (nach C1-Abnahme)

- **C2** (Carmack): Grafana natives OIDC (`GF_AUTH_GENERIC_OAUTH_*`) +
  `internal-auth@file` von `vectiscan-logs` entfernen. Nutzt `vectiscan-grafana` +
  `KEYCLOAK_GRAFANA_SECRET`.
- **C3** (Carmack): oauth2-proxy-Service + Traefik `forward-auth@file` für
  `status` + `/admin`. Nutzt `vectiscan-oauth2-proxy` + `KEYCLOAK_OAUTH2_PROXY_SECRET`.
- **C5** (Mitnick): Security-Review + Live-QA.
- **C6** (Hamilton): Cutover Fläche-für-Fläche + Rollback-Drill.
