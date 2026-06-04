import { readdirSync, readFileSync } from 'fs';
import { join } from 'path';

/**
 * VEC-133 — Invarianz-Regressionstest gegen Broken Function-Level Authorization
 * am Edge (OWASP API5 / Defense-in-Depth-Luecke).
 *
 * Regel (nicht verhandelbar): JEDER Route-Handler, der `requireAdmin` im
 * `preHandler` fuehrt, MUSS unter dem Pfad-Prefix `/api/admin` registriert
 * sein. Nur so erfasst der Traefik-Edge-Admin-Shield
 * (`vectiscan-api-admin`, `PathPrefix(/api/admin)`) die Admin-Flaeche
 * vollstaendig — andernfalls haengt der Schutz allein an der In-App-
 * `requireAdmin`-Pruefung (keine zweite Schicht).
 *
 * Der Test parst die Route-Quellen statisch (kein Server-Boot noetig), damit
 * er den gesamten Dependency-Graph nicht mocken muss und als reine
 * Lint-artige Invariante laeuft. Schlaegt fehl, sobald eine admin-privilegierte
 * Route ausserhalb von /api/admin auftaucht — verhindert die Klasse
 * "Admin-Routen-Leak", nicht nur die heute bekannten Instanzen.
 */

interface AdminRoute {
  file: string;
  line: number;
  method: string;
  path: string;
}

const ROUTES_DIR = join(__dirname, '..', 'routes');

function collectAdminRoutes(): { routes: AdminRoute[]; unresolved: string[] } {
  const routes: AdminRoute[] = [];
  const unresolved: string[] = [];

  const files = readdirSync(ROUTES_DIR).filter((f) => f.endsWith('.ts'));

  for (const file of files) {
    const lines = readFileSync(join(ROUTES_DIR, file), 'utf8').split('\n');

    for (let i = 0; i < lines.length; i++) {
      // Nur echte preHandler-Registrierungen, nicht den Import von requireAdmin.
      if (!/requireAdmin/.test(lines[i]) || !/preHandler/.test(lines[i])) continue;

      // Rueckwaerts die naechste server.<method>(-Registrierung + Pfad-String suchen.
      let method: string | null = null;
      let path: string | null = null;

      for (let j = i; j >= Math.max(0, i - 8); j--) {
        const m = lines[j].match(/server\.(get|post|put|delete|patch)\b/);
        if (!m) continue;
        method = m[1].toUpperCase();
        for (let k = j; k <= i; k++) {
          const p = lines[k].match(/['"`](\/api\/[^'"`]+)['"`]/);
          if (p) {
            path = p[1];
            break;
          }
        }
        break;
      }

      if (!path || !method) {
        unresolved.push(`${file}:${i + 1}`);
        continue;
      }
      routes.push({ file, line: i + 1, method, path });
    }
  }

  return { routes, unresolved };
}

describe('Admin-Routen-Invariante (VEC-133)', () => {
  const { routes, unresolved } = collectAdminRoutes();

  it('findet ueberhaupt requireAdmin-Routen (Parser-Sanity)', () => {
    // Schutz gegen einen still kaputten Parser, der faelschlich 0 Routen liefert
    // und damit die eigentliche Invariante leerlaufen liesse.
    expect(routes.length).toBeGreaterThan(5);
  });

  it('konnte jede requireAdmin-Registrierung einem Pfad zuordnen', () => {
    expect(unresolved).toEqual([]);
  });

  it('jeder requireAdmin-Handler liegt unter /api/admin', () => {
    const leaks = routes.filter((r) => !r.path.startsWith('/api/admin'));
    const detail = leaks
      .map((r) => `  LEAK ${r.file}:${r.line}  ${r.method} ${r.path}`)
      .join('\n');
    expect(leaks).toEqual(
      [],
    );
    // Falls obige Assertion je entfernt wird: explizite Diagnose erhalten.
    if (leaks.length > 0) throw new Error(`Admin-Routen ausserhalb /api/admin:\n${detail}`);
  });
});
