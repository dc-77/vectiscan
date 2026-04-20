'use client';

import { useState, useEffect } from 'react';
import type { Recommendation } from '@/lib/api';

const TIMEFRAME_ORDER = ['Sofort', 'Tag 1-3', 'Woche 1', 'Monat 1'];

const TIMEFRAME_STYLE: Record<string, { bg: string; text: string }> = {
  'Sofort':   { bg: 'bg-red-500/15',    text: 'text-red-400' },
  'Tag 1-3':  { bg: 'bg-slate-700/50',  text: 'text-slate-300' },
  'Woche 1':  { bg: 'bg-slate-700/50',  text: 'text-slate-400' },
  'Monat 1':  { bg: 'bg-slate-800',     text: 'text-slate-500' },
};

function sortRecommendations(recs: Recommendation[]): Recommendation[] {
  return [...recs].sort((a, b) => {
    const ai = TIMEFRAME_ORDER.indexOf(a.timeframe);
    const bi = TIMEFRAME_ORDER.indexOf(b.timeframe);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  });
}

interface RecommendationsViewerProps {
  recommendations: Recommendation[];
  orderId?: string;
}

export default function RecommendationsViewer({ recommendations, orderId }: RecommendationsViewerProps) {
  const sorted = sortRecommendations(recommendations);
  const storageKey = orderId ? `vectiscan-recs-${orderId}` : null;

  // Load checked state from localStorage
  const [checked, setChecked] = useState<Record<number, string>>({});
  useEffect(() => {
    if (!storageKey) return;
    try {
      const saved = localStorage.getItem(storageKey);
      if (saved) setChecked(JSON.parse(saved));
    } catch { /* ignore */ }
  }, [storageKey]);

  const toggle = (i: number) => {
    setChecked(prev => {
      const next = { ...prev };
      if (next[i]) {
        delete next[i];
      } else {
        next[i] = new Date().toLocaleDateString('de-DE');
      }
      if (storageKey) {
        try { localStorage.setItem(storageKey, JSON.stringify(next)); } catch { /* ignore */ }
      }
      return next;
    });
  };

  const doneCount = Object.keys(checked).length;
  const totalCount = sorted.length;
  const progress = totalCount > 0 ? Math.round((doneCount / totalCount) * 100) : 0;

  if (sorted.length === 0) {
    return (
      <div className="px-5 py-8 text-center text-slate-500 text-sm">
        Keine Empfehlungen vorhanden.
      </div>
    );
  }

  return (
    <div className="px-5 py-5 space-y-3">
      <div className="flex items-center justify-between mb-1">
        <h3 className="text-xs font-medium text-slate-500 uppercase tracking-wider">
          Priorisierter Maßnahmenplan
        </h3>
        <span className="text-xs font-medium" style={{ color: progress === 100 ? '#22C55E' : '#94A3B8' }}>
          {doneCount}/{totalCount} umgesetzt
        </span>
      </div>

      {/* Progress bar */}
      <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: '#0F172A' }}>
        <div className="h-full rounded-full transition-all duration-500"
          style={{ width: `${progress}%`, backgroundColor: progress === 100 ? '#22C55E' : '#2DD4BF' }} />
      </div>

      {sorted.map((rec, i) => {
        const style = TIMEFRAME_STYLE[rec.timeframe] || { bg: 'bg-slate-800', text: 'text-slate-500' };
        const isDone = !!checked[i];
        return (
          <div key={i} className={`rounded-xl p-3 flex items-start gap-3 transition-opacity duration-300 ${isDone ? 'opacity-50' : ''}`}
            style={{ backgroundColor: '#1E293B' }}>
            {/* Checkbox */}
            <button onClick={() => toggle(i)}
              className="mt-0.5 w-5 h-5 rounded border-2 flex items-center justify-center shrink-0 transition-colors"
              style={{
                borderColor: isDone ? '#22C55E' : '#475569',
                backgroundColor: isDone ? '#22C55E20' : 'transparent',
              }}
              title={isDone ? `Erledigt am ${checked[i]}` : 'Als erledigt markieren'}>
              {isDone && <span className="text-[10px]" style={{ color: '#22C55E' }}>✓</span>}
            </button>

            <span className={`${style.bg} ${style.text} text-xs font-bold px-2.5 py-1 rounded shrink-0 whitespace-nowrap`}>
              {rec.timeframe}
            </span>
            <div className="flex-1 min-w-0">
              <p className={`text-sm leading-relaxed ${isDone ? 'line-through' : ''}`} style={{ color: isDone ? '#64748B' : '#CBD5E1' }}>
                {rec.action}
              </p>
              <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                {rec.finding_refs?.length > 0 && (
                  <span className="text-xs text-slate-600 font-mono">
                    Ref: {rec.finding_refs.join(', ')}
                  </span>
                )}
                {rec.effort && (
                  <span className="text-xs text-slate-600">
                    Aufwand: {rec.effort}
                  </span>
                )}
                {isDone && checked[i] && (
                  <span className="text-[10px]" style={{ color: '#22C55E' }}>Erledigt am {checked[i]}</span>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
