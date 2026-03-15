# Plan: Benutzerverwaltung mit Rollen (Kunde / Admin)

## Ist-Zustand
- Kein echtes Auth-System — nur ein shared Password (`VECTISCAN_ACCESS_PASSWORD`) über `sessionStorage`
- `customers`-Tabelle existiert (Email + stripe_id), aber ohne Passwort/Rolle
- `GET /api/orders` gibt **alle** Orders zurück, ungeschützt
- Dashboard zeigt immer alle Orders an

## Ziel
- Kunden sehen nur ihre eigenen Scans/Orders
- Admins sehen alle Scans/Orders
- Saubere JWT-basierte Authentifizierung

---

## Schritt 1: DB-Migration `005_users.sql`

Neue Tabelle `users`:
```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    role            VARCHAR(20) NOT NULL DEFAULT 'customer',
    customer_id     UUID REFERENCES customers(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_users_role CHECK (role IN ('customer', 'admin'))
);
CREATE INDEX idx_users_email ON users(email);
```

- `customer_id` verknüpft den User mit dem bestehenden `customers`-Record
- Admins haben kein `customer_id` (nullable)
- Migration wird in `db.ts` wie die bisherigen Migrationen eingehängt

## Schritt 2: API — Auth-Middleware + JWT

**Neue Dependency:** `@fastify/jwt` (oder manuell mit `jsonwebtoken` + `bcryptjs`)

**Neue Datei: `api/src/lib/auth.ts`**
- `hashPassword(plain)` → bcrypt hash
- `verifyPasswordHash(plain, hash)` → boolean
- `generateJwt(userId, role)` → signed JWT (Secret aus `JWT_SECRET` env var)
- `verifyJwt(token)` → `{ userId, role, customerId }`

**Neue Datei: `api/src/middleware/requireAuth.ts`**
- Fastify `preHandler` Hook
- Liest `Authorization: Bearer <token>` Header
- Verifiziert JWT, hängt `request.user = { id, role, customerId }` an
- 401 bei fehlendem/ungültigem Token

**Neue Datei: `api/src/middleware/requireAdmin.ts`**
- Prüft `request.user.role === 'admin'`
- 403 bei Nicht-Admin

## Schritt 3: API — Auth-Routen überarbeiten (`routes/auth.ts`)

Bestehende `/api/auth/verify` (Password-Gate) ersetzen durch:

| Endpoint | Zweck |
|----------|-------|
| `POST /api/auth/register` | Registrierung (email, password) → User + Customer anlegen, JWT zurück |
| `POST /api/auth/login` | Login (email, password) → JWT zurück |
| `GET /api/auth/me` | Eigenes Profil (requireAuth) |

- Bei Register: `customers`-Record finden oder anlegen, `users`-Record erstellen
- JWT enthält: `{ sub: userId, role, customerId }`
- Initiales Admin-Konto: via Env-Var `ADMIN_EMAIL` + `ADMIN_PASSWORD` beim Start erstellen (Seed in `initDb`)

## Schritt 4: API — Orders-Routen absichern (`routes/orders.ts`)

**`GET /api/orders`** — requireAuth:
- Admin → alle Orders (wie bisher)
- Customer → `WHERE customer_id = $user.customerId`

**`POST /api/orders`** — requireAuth:
- `customer_id` kommt aus dem JWT, nicht mehr aus dem Body (Email nur noch zur Anzeige)
- Email-Feld im Body entfällt

**`GET /api/orders/:id`** — requireAuth:
- Admin → jede Order
- Customer → nur eigene (check `customer_id`)

**`GET /api/orders/:id/report`** — requireAuth:
- Gleiche Ownership-Prüfung

**`DELETE /api/orders/:id`** — requireAuth:
- Nur eigene oder Admin

## Schritt 5: Frontend — Auth-State modernisieren

**Neue Datei: `frontend/src/lib/auth.ts`** (Client-seitige Auth-Logik):
- `login(email, password)` → API-Call, JWT in `localStorage` speichern
- `register(email, password)` → API-Call, JWT in `localStorage` speichern
- `logout()` → Token entfernen
- `getToken()` → Token lesen
- `getUser()` → Decoded JWT (role, email)
- `isAdmin()` → boolean

**API-Client (`lib/api.ts`) erweitern:**
- `Authorization: Bearer <token>` Header an alle Requests anhängen
- 401-Response → automatisch zu Login redirecten

## Schritt 6: Frontend — Login/Register-Seite

**Seite: `frontend/src/app/login/page.tsx`**
- Tabs: Login / Registrierung
- Email + Passwort Formular
- Nach Erfolg → redirect zu `/dashboard`
- Ersetzt das bisherige Password-Gate im Dashboard

## Schritt 7: Frontend — Dashboard anpassen

- Password-Gate entfernen (durch JWT-Auth ersetzt)
- Auth-Check: kein Token → redirect zu `/login`
- Admin sieht alle Orders + eine Email-Spalte pro Order
- Customer sieht nur eigene Orders (API filtert serverseitig)
- Optional: Admin-Badge im Header

## Schritt 8: Frontend — Scanner-Seite anpassen (`page.tsx`)

- Auth-Check: kein Token → redirect zu `/login`
- Email-Feld entfällt (kommt aus dem JWT)
- Order-Erstellung nutzt Token statt Email im Body

## Schritt 9: Env-Variablen

Neue Variablen in `.env`:
```
JWT_SECRET=<random-secret>
ADMIN_EMAIL=admin@vectigal.tech
ADMIN_PASSWORD=<starkes-passwort>
```

`VECTISCAN_ACCESS_PASSWORD` kann nach Migration entfernt werden.

## Schritt 10: Tests anpassen

- Bestehende Tests in `api/src/__tests__/` aktualisieren (Auth-Header mitgeben)
- Neue Tests: Register, Login, Ownership-Prüfung, Admin-Zugriff

---

## Nicht im Scope (bewusst ausgeklammert)
- Passwort-Reset / "Forgot Password" (kein E-Mail-Versand im Prototyp)
- Refresh Tokens (JWT-Expiry reicht für internes Tool)
- CSRF (API ist stateless, CORS reicht für internes Netzwerk)
- Rate Limiting (bereits via Traefik-Middleware)

## Dateien, die geändert/erstellt werden

### Neue Dateien:
- `api/src/migrations/005_users.sql`
- `api/src/lib/auth.ts`
- `api/src/middleware/requireAuth.ts`
- `api/src/middleware/requireAdmin.ts`
- `frontend/src/app/login/page.tsx`
- `frontend/src/lib/auth.ts`

### Geänderte Dateien:
- `api/src/lib/db.ts` (Migration 005 einhängen, Admin-Seed)
- `api/src/routes/auth.ts` (komplett neu: register, login, me)
- `api/src/routes/orders.ts` (Auth-Middleware, Ownership-Filter)
- `api/src/server.ts` (Middleware registrieren)
- `frontend/src/lib/api.ts` (Auth-Header, neue API-Funktionen)
- `frontend/src/app/dashboard/page.tsx` (Password-Gate → JWT, Admin-View)
- `frontend/src/app/page.tsx` (Auth-Check, Email-Feld entfernen)
- `api/src/__tests__/*.test.ts` (Auth-Header in Tests)
- `docker-compose.yml` (neue Env-Vars)
