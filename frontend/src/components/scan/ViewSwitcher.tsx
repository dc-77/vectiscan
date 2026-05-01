'use client';

/**
 * ViewSwitcher — kleiner Toggle oben rechts: Modern (Default) <-> Hacker (Legacy).
 * Speichert die Wahl in localStorage unter 'scanView'.
 */

interface Props {
  value: 'modern' | 'hacker';
  onChange: (v: 'modern' | 'hacker') => void;
}

export default function ViewSwitcher({ value, onChange }: Props) {
  const baseBtn =
    'px-2.5 py-1 text-xs font-medium transition-colors first:rounded-l-md last:rounded-r-md';
  const activeBtn = 'bg-cyan-500/20 text-cyan-200 ring-1 ring-inset ring-cyan-500/40';
  const inactiveBtn = 'bg-slate-900/60 text-slate-400 hover:text-slate-200';

  return (
    <div className="inline-flex items-stretch rounded-md ring-1 ring-slate-700 overflow-hidden">
      <button
        type="button"
        title="Strukturierte Bericht-Ansicht (Standard)"
        onClick={() => onChange('modern')}
        className={`${baseBtn} ${value === 'modern' ? activeBtn : inactiveBtn}`}
      >
        Bericht
      </button>
      <button
        type="button"
        title="Klassische Hacker-Ansicht (Live-Terminal)"
        onClick={() => onChange('hacker')}
        className={`${baseBtn} ${value === 'hacker' ? activeBtn : inactiveBtn}`}
      >
        Live-Terminal
      </button>
    </div>
  );
}
