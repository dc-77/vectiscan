'use client';

import type { Recommendation } from '@/lib/api';

const TIMEFRAME_ORDER = ['Sofort', 'Tag 1-3', 'Woche 1', 'Monat 1'];

const TIMEFRAME_STYLE: Record<string, { bg: string; text: string }> = {
  'Sofort':   { bg: 'bg-red-500/20',    text: 'text-red-400' },
  'Tag 1-3':  { bg: 'bg-orange-500/20',  text: 'text-orange-400' },
  'Woche 1':  { bg: 'bg-yellow-500/20',  text: 'text-yellow-400' },
  'Monat 1':  { bg: 'bg-blue-500/20',    text: 'text-blue-400' },
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
}

export default function RecommendationsViewer({ recommendations }: RecommendationsViewerProps) {
  const sorted = sortRecommendations(recommendations);

  if (sorted.length === 0) {
    return (
      <div className="px-4 py-8 text-center text-gray-500 text-sm">
        Keine Empfehlungen vorhanden.
      </div>
    );
  }

  return (
    <div className="px-4 py-4 space-y-2">
      <h3 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-3">
        Priorisierter Massnahmenplan
      </h3>
      {sorted.map((rec, i) => {
        const style = TIMEFRAME_STYLE[rec.timeframe] || { bg: 'bg-gray-500/20', text: 'text-gray-400' };
        return (
          <div key={i} className="bg-[#1e293b] rounded-lg p-3 flex items-start gap-3 border border-gray-800/50">
            <span className={`${style.bg} ${style.text} text-xs font-bold px-2.5 py-1 rounded shrink-0 whitespace-nowrap`}>
              {rec.timeframe}
            </span>
            <div className="flex-1 min-w-0">
              <p className="text-sm text-gray-300 leading-relaxed">{rec.action}</p>
              <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                {rec.finding_refs?.length > 0 && (
                  <span className="text-xs text-gray-500 font-mono">
                    Ref: {rec.finding_refs.map(r => `VS-${r}`).join(', ')}
                  </span>
                )}
                {rec.effort && (
                  <span className="text-xs text-gray-600">
                    Aufwand: {rec.effort}
                  </span>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
