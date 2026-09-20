'use client';

import { useState } from 'react';
import { ConfirmDialog } from '@/components/ds';
import { requeueReport, type ReviewReport } from '@/lib/api';

// S5: Defektliste des letzten Berichtslaufs.
//
// Sie trägt beide Engines: das alte Validation-Gate (v2) und den Prüfkatalog mit
// den Render-Prüfungen (v3). Woher ein Eintrag kommt, steht am Eintrag, damit
// niemand raten muss, welcher Teil der Kette gemeldet hat.

const ENGINE_LABELS: Record<string, string> = {
  v2: 'Bericht v2',
  v3: 'Bericht v3',
};

// Klartext für die Prüfungen, die S5 eingeführt hat. Alles andere wird als
// technischer Name gezeigt; ein unbekannter Name ist ehrlicher als ein falscher.
const CHECK_LABELS: Record<string, string> = {
  abdeckungskapitel_leer: 'Abdeckung fehlt',
  tech_widerspricht_befund: 'Technik widerspricht Befund',
  unprocessed_ueber_schwelle: 'Viele Beobachtungen ohne Regel',
  auftraggeber_fehlt: 'Auftraggeber fehlt',
  render: 'Darstellung',
};

export default function ReportDefectsPanel({
  orderId, report, onChanged,
}: {
  orderId: string;
  report: ReviewReport | null;
  onChanged: () => void;
}) {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const defects = report?.defects ?? [];
  const errors = defects.filter(d => d.severity === 'error');
  const warnings = defects.filter(d => d.severity !== 'error');
  const blocked = report?.status === 'report_blocked';

  const handleRegenerate = async () => {
    setBusy(true);
    const res = await requeueReport(orderId);
    setBusy(false);
    setConfirmOpen(false);
    if (res.success) {
      setMessage('Der Bericht wird neu erzeugt. Die Seite zeigt den neuen Stand, sobald der Lauf fertig ist.');
      onChanged();
    } else {
      setMessage(res.error || 'Neu erzeugen fehlgeschlagen.');
    }
  };

  return (
    <section className="space-y-4">
      <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-4 flex items-center justify-between gap-3 flex-wrap">
        <div className="text-xs text-slate-400">
          {blocked ? (
            <>Das Gate hat den Bericht angehalten. <strong className="text-white">{errors.length}</strong> Defekt{errors.length === 1 ? '' : 'e'} müssen behoben werden, bevor er ausgeliefert wird.</>
          ) : defects.length === 0 ? (
            <>Keine Defekte. Der letzte Lauf ist ohne Beanstandung durchgelaufen.</>
          ) : (
            <><strong className="text-white">{errors.length}</strong> Defekt{errors.length === 1 ? '' : 'e'} und <strong className="text-white">{warnings.length}</strong> Hinweis{warnings.length === 1 ? '' : 'e'}. Der Bericht wurde trotzdem gebaut (Stufe {report?.level || 'warn'}).</>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled
            title="Kommt in einer späteren Sitzung: Vorschlag für eine neue Prüfung aus einer Beobachtung."
            className="text-xs font-medium px-3 py-1.5 rounded-lg bg-slate-700/40 text-slate-500 cursor-not-allowed"
          >
            Regelvorschlag
          </button>
          <button
            type="button"
            onClick={() => setConfirmOpen(true)}
            disabled={busy}
            className="text-xs font-medium px-3 py-1.5 rounded-lg bg-blue-400/10 text-blue-400 hover:bg-blue-400/20 transition-colors disabled:cursor-not-allowed"
          >
            {busy ? 'Wird gestartet...' : 'Regenerieren nach Fix'}
          </button>
        </div>
      </div>

      {message && (
        <div className="bg-slate-800/60 border border-gray-800 text-slate-300 rounded-lg px-4 py-3 text-sm">
          {message}
        </div>
      )}

      {defects.length === 0 ? (
        <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-6 text-center text-sm text-slate-500">
          Keine Einträge.
        </div>
      ) : (
        <div className="bg-[#1e293b] rounded-lg border border-gray-800 overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-[#0f172a] text-xs text-slate-500 uppercase tracking-wider">
              <tr>
                <th className="text-left px-4 py-2 font-medium">Stufe</th>
                <th className="text-left px-4 py-2 font-medium">Herkunft</th>
                <th className="text-left px-4 py-2 font-medium">Prüfung</th>
                <th className="text-left px-4 py-2 font-medium">Meldung</th>
                <th className="text-left px-4 py-2 font-medium">Befund</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {defects.map((d, i) => (
                <tr key={`${d.check}-${i}`} className="align-top">
                  <td className="px-4 py-2">
                    <span className={`text-[10px] uppercase px-1.5 py-0.5 rounded ${
                      d.severity === 'error'
                        ? 'bg-red-400/10 text-red-400'
                        : 'bg-amber-400/10 text-amber-400'
                    }`}>
                      {d.severity === 'error' ? 'Defekt' : 'Hinweis'}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-400 whitespace-nowrap">
                    {ENGINE_LABELS[d.engine] || d.engine}
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-300 whitespace-nowrap">
                    {CHECK_LABELS[d.check] || d.check}
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-300">{d.message}</td>
                  <td className="px-4 py-2 text-xs text-slate-500 font-mono whitespace-nowrap">
                    {d.finding_id || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ConfirmDialog
        open={confirmOpen}
        title="Bericht neu erzeugen?"
        description="Der Bericht wird aus den vorhandenen Rohdaten neu gebaut. Es wird kein neuer Scan gefahren."
        confirmLabel="Neu erzeugen"
        busy={busy}
        onConfirm={handleRegenerate}
        onCancel={() => setConfirmOpen(false)}
      />
    </section>
  );
}
