'use client';

import { useMemo, useState } from 'react';
import { updateCustomerContext, type CustomerContext } from '@/lib/api';

// S5: Kundenkontext im Admin-Review pflegen.
//
// Jedes hier gespeicherte Feld trägt danach die Quelle "admin" und wird von der
// Recherche-KI nicht mehr angefasst. Ein geleertes Feld gibt es wieder frei.
// Wirksam wird die Änderung mit dem nächsten Berichtslauf.

const SOURCE_LABELS: Record<string, string> = {
  kunde: 'Kunde',
  recherche: 'Recherche',
  admin: 'Admin',
};

const LABEL_CLASS = 'block text-[10px] text-slate-500 uppercase tracking-wider mb-1';
const INPUT_CLASS = 'w-full bg-[#0f172a] border border-gray-800 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:border-blue-500 outline-none';

function Herkunft({ context, field }: { context: CustomerContext | null; field: string }) {
  const entry = context?.sources?.[field];
  if (!entry) return null;
  return (
    <span className="ml-2 text-[10px] text-slate-500 normal-case">
      {SOURCE_LABELS[entry.source] || entry.source}
      {entry.url && (
        <>
          {' · '}
          <a href={entry.url} target="_blank" rel="noopener noreferrer"
             className="text-blue-400 hover:text-blue-300">Fundstelle</a>
        </>
      )}
    </span>
  );
}

export default function CustomerContextForm({
  orderId, context, onSaved,
}: {
  orderId: string;
  context: CustomerContext | null;
  onSaved: () => void;
}) {
  const [firmenname, setFirmenname] = useState(context?.firmenname ?? '');
  const [kuerzel, setKuerzel] = useState(context?.kuerzel ?? '');
  const [branche, setBranche] = useState(context?.branche ?? '');
  const [mitarbeiter, setMitarbeiter] = useState(context?.mitarbeiter ?? '');
  const [systeme, setSysteme] = useState<Array<{ fqdn: string; zweck: string }>>(
    context?.systeme?.length ? context.systeme : [{ fqdn: '', zweck: '' }],
  );
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const geaendert = useMemo(() => {
    const alt = context ?? {};
    const altSysteme = JSON.stringify(alt.systeme ?? []);
    const neuSysteme = JSON.stringify(systeme.filter(s => s.fqdn.trim() && s.zweck.trim()));
    return (alt.firmenname ?? '') !== firmenname
      || (alt.kuerzel ?? '') !== kuerzel
      || (alt.branche ?? '') !== branche
      || (alt.mitarbeiter ?? '') !== mitarbeiter
      || altSysteme !== neuSysteme;
  }, [context, firmenname, kuerzel, branche, mitarbeiter, systeme]);

  const handleSave = async () => {
    setBusy(true);
    setError(null);
    setMessage(null);
    const res = await updateCustomerContext(orderId, {
      firmenname, kuerzel, branche, mitarbeiter,
      systeme: systeme.filter(s => s.fqdn.trim() && s.zweck.trim()),
    });
    setBusy(false);
    if (res.success) {
      setMessage('Gespeichert. Der nächste Berichtslauf übernimmt die Angaben.');
      onSaved();
    } else {
      setError(res.error || 'Speichern fehlgeschlagen.');
    }
  };

  const setSystem = (index: number, key: 'fqdn' | 'zweck', value: string) => {
    setSysteme(prev => prev.map((s, i) => (i === index ? { ...s, [key]: value } : s)));
  };

  return (
    <section className="space-y-4">
      <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-4 text-xs text-slate-400">
        Diese Angaben stehen im Bericht: der Firmenname auf dem Deckblatt, das Kürzel in
        den Befund-Nummern, Branche und Größe im Kontextabsatz. Pflicht ist nichts.
        Was hier gespeichert wird, überschreibt die automatische Recherche dauerhaft.
      </div>

      <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-4 space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label htmlFor="ctx-firmenname" className={LABEL_CLASS}>
              Firmenname<Herkunft context={context} field="firmenname" />
            </label>
            <input id="ctx-firmenname" className={INPUT_CLASS} value={firmenname}
                   onChange={e => setFirmenname(e.target.value)}
                   placeholder="Beispiel Maschinenbau GmbH" />
          </div>
          <div>
            <label htmlFor="ctx-kuerzel" className={LABEL_CLASS}>
              Kürzel für Befund-Nummern<Herkunft context={context} field="kuerzel" />
            </label>
            <input id="ctx-kuerzel" className={INPUT_CLASS} value={kuerzel}
                   onChange={e => setKuerzel(e.target.value)} placeholder="BSP" />
          </div>
          <div>
            <label htmlFor="ctx-branche" className={LABEL_CLASS}>
              Branche<Herkunft context={context} field="branche" />
            </label>
            <input id="ctx-branche" className={INPUT_CLASS} value={branche}
                   onChange={e => setBranche(e.target.value)} placeholder="Maschinenbau" />
          </div>
          <div>
            <label htmlFor="ctx-mitarbeiter" className={LABEL_CLASS}>
              Mitarbeiterzahl<Herkunft context={context} field="mitarbeiter" />
            </label>
            <input id="ctx-mitarbeiter" className={INPUT_CLASS} value={mitarbeiter}
                   onChange={e => setMitarbeiter(e.target.value)} placeholder="120" />
          </div>
        </div>

        <div className="space-y-2">
          <span className={LABEL_CLASS}>
            Systeme und ihr Zweck<Herkunft context={context} field="systeme" />
          </span>
          {systeme.map((s, i) => (
            <div key={i} className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <input className={INPUT_CLASS} value={s.fqdn}
                     onChange={e => setSystem(i, 'fqdn', e.target.value)}
                     aria-label={`Hostname ${i + 1}`} placeholder="www.beispiel.de" />
              <input className={INPUT_CLASS} value={s.zweck}
                     onChange={e => setSystem(i, 'zweck', e.target.value)}
                     aria-label={`Zweck ${i + 1}`} placeholder="Unternehmenswebsite" />
            </div>
          ))}
          <button type="button" onClick={() => setSysteme(prev => [...prev, { fqdn: '', zweck: '' }])}
                  className="text-xs text-slate-400 hover:text-slate-200">
            Weiteres System
          </button>
        </div>

        {error && <p className="text-xs text-red-400">{error}</p>}
        {message && <p className="text-xs text-green-400">{message}</p>}

        <div className="flex justify-end">
          <button
            type="button"
            onClick={handleSave}
            disabled={busy || !geaendert}
            className="text-sm font-medium px-4 py-2 rounded-lg bg-blue-400/10 text-blue-400 hover:bg-blue-400/20 transition-colors disabled:cursor-not-allowed disabled:text-slate-500 disabled:bg-slate-700/40"
          >
            {busy ? 'Wird gespeichert...' : 'Speichern'}
          </button>
        </div>
      </div>
    </section>
  );
}
