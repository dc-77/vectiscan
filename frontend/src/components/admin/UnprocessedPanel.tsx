'use client';

import type { ReviewReport } from '@/lib/api';

// S5: Beobachtungen, die keine Prüfung des Katalogs getroffen haben.
//
// Sie stehen bewusst nie im Kundenbericht. Lieber ein fehlender Befund, den der
// Admin sieht, als ein erfundener, den der Kunde sieht (spec/05 Abschnitt 10).
// Aus einem wiederkehrenden Eintrag wird später eine Prüfung mit Fixture.

const QUELLE_LABELS: Record<string, string> = {
  fakten: 'Faktenbauer',
  katalog: 'Prüfkatalog',
};

const KIND_LABELS: Record<string, string> = {
  service_unknown_port: 'Dienst auf unbekanntem Port',
  zap_alert_unmapped: 'Werkzeugmeldung ohne Zuordnung',
  passive_port_unverified: 'Passivquelle ohne Bestätigung',
};

export default function UnprocessedPanel({ report }: { report: ReviewReport | null }) {
  const entries = report?.unprocessed ?? [];
  const gesamt = report?.counts?.unprocessed ?? 0;

  return (
    <section className="space-y-4">
      <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-4 text-xs text-slate-400">
        {entries.length === 0 ? (
          <>Jede Beobachtung der Werkzeuge hat eine Prüfung getroffen.</>
        ) : (
          <>
            <strong className="text-white">{gesamt}</strong> Beobachtung{gesamt === 1 ? '' : 'en'} ohne Regel,
            in {entries.length} Gruppe{entries.length === 1 ? '' : 'n'}. Sie stehen nicht im Kundenbericht.
            Wiederkehrende Einträge gehören als Prüfung in den Katalog.
          </>
        )}
      </div>

      {entries.length > 0 && (
        <div className="bg-[#1e293b] rounded-lg border border-gray-800 overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-[#0f172a] text-xs text-slate-500 uppercase tracking-wider">
              <tr>
                <th className="text-left px-4 py-2 font-medium">Quelle</th>
                <th className="text-left px-4 py-2 font-medium">Art</th>
                <th className="text-left px-4 py-2 font-medium">Beobachtung</th>
                <th className="text-left px-4 py-2 font-medium">Host</th>
                <th className="text-right px-4 py-2 font-medium">Anzahl</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {entries.map((u, i) => (
                <tr key={`${u.kind}-${i}`} className="align-top">
                  <td className="px-4 py-2 text-xs text-slate-400 whitespace-nowrap">
                    {QUELLE_LABELS[u.quelle] || u.quelle}
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-300 whitespace-nowrap">
                    {KIND_LABELS[u.kind] || u.kind}
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-300">
                    {u.what}
                    {u.note && <span className="block text-slate-500 mt-0.5">{u.note}</span>}
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-500 font-mono whitespace-nowrap">
                    {u.host_ip || (u.fqdns && u.fqdns[0]) || '—'}
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-400 text-right">{u.count ?? 1}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
