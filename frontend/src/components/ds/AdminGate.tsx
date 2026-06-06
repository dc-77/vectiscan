'use client';

// ── DS-Primitive: AdminGate (VEC-294, VEC-306) ──────────────────
// Kanonische Permission-Sperre für Admin-Routen. Ersetzt den früheren
// stillen `router.replace('/dashboard')` (wirkte wie ein Bug/Sackgasse)
// durch das board-freigegebene StateView-Muster (VEC-285 §4.1):
//   • nicht eingeloggt        → Redirect /login (echte Auth-Grenze)
//   • eingeloggt, kein Admin  → StateView „denied" + „Zur Übersicht"
// Eine einzige Quelle, damit alle Admin-Seiten dieselbe Sprache sprechen.

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { isLoggedIn, isAdmin } from '@/lib/auth';
import StateView from './StateView';

export type AdminGuardState = 'checking' | 'denied' | 'ok';

/** Prüft Login + Admin-Rolle client-seitig.
 *  - `checking`: noch nicht entschieden (Render nichts / Skeleton)
 *  - `denied`:   eingeloggt, aber kein Admin → <AdminDenied/> rendern
 *  - `ok`:       Admin → Seite + Daten laden
 *  Nicht-eingeloggte Nutzer werden nach /login umgeleitet (kein StateView,
 *  da hier eine echte Auth-Grenze und kein Berechtigungs-Zustand vorliegt).
 */
export function useAdminGuard(): { ready: boolean; denied: boolean; state: AdminGuardState } {
  const router = useRouter();
  const [state, setState] = useState<AdminGuardState>('checking');

  useEffect(() => {
    if (!isLoggedIn()) {
      router.replace('/login');
      return;
    }
    setState(isAdmin() ? 'ok' : 'denied');
  }, [router]);

  return { ready: state === 'ok', denied: state === 'denied', state };
}

/** Geführter „Nur für Admins"-Zustand. Wird gerendert, wenn ein
 *  eingeloggter Nicht-Admin eine Admin-Route per Direkt-URL aufruft. */
export default function AdminDenied() {
  return (
    <main className="flex-1 px-4 py-8 md:px-8">
      <div className="max-w-2xl mx-auto">
        <StateView
          variant="denied"
          title="Diese Seite ist Administratoren vorbehalten"
          description="Dein Konto hat dafür keine Freigabe. Über die Übersicht kommst du zurück zu deinen Scans und Reports."
          actions={[{ label: 'Zur Übersicht', href: '/dashboard', variant: 'primary' }]}
        />
      </div>
    </main>
  );
}
