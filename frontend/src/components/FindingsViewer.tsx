'use client';

import { useState } from 'react';
import type { FindingsData, Finding } from '@/lib/api';
import SeverityBar, { SEVERITY_CONFIG } from './SeverityBar';

const RISK_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-600',
  HIGH: 'bg-orange-600',
  MEDIUM: 'bg-yellow-600',
  LOW: 'bg-green-600',
};

const SEVERITY_BADGE: Record<string, { bg: string; text: string }> = {
  CRITICAL: { bg: 'bg-red-500/20',    text: 'text-red-400' },
  HIGH:     { bg: 'bg-orange-500/20',  text: 'text-orange-400' },
  MEDIUM:   { bg: 'bg-yellow-500/20',  text: 'text-yellow-400' },
  LOW:      { bg: 'bg-green-500/20',   text: 'text-green-400' },
  INFO:     { bg: 'bg-blue-500/20',    text: 'text-blue-400' },
};

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const ai = SEVERITY_ORDER.indexOf(a.severity?.toUpperCase() || 'INFO');
    const bi = SEVERITY_ORDER.indexOf(b.severity?.toUpperCase() || 'INFO');
    if (ai !== bi) return ai - bi;
    return parseFloat(b.cvss_score || '0') - parseFloat(a.cvss_score || '0');
  });
}

interface FindingsViewerProps {
  data: FindingsData;
}

export default function FindingsViewer({ data }: FindingsViewerProps) {
  const [filter, setFilter] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const sorted = sortFindings(data.findings);
  const filtered = filter ? sorted.filter(f => f.severity?.toUpperCase() === filter) : sorted;
  const isBasic = data.package === 'basic';

  const riskColor = RISK_COLORS[data.overall_risk?.toUpperCase()] || 'bg-gray-600';

  return (
    <div className="space-y-4">
      {/* Header: Risk + Summary */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-3 px-4 pt-4">
        <div className="flex items-center gap-3 min-w-0">
          <span className={`${riskColor} text-white text-xs font-bold px-3 py-1.5 rounded-lg uppercase tracking-wider`}>
            {data.overall_risk || 'N/A'}
          </span>
          <span className="text-sm text-gray-400">{data.findings.length} Befunde</span>
        </div>
        <div className="flex-1">
          <SeverityBar counts={data.severity_counts} />
        </div>
      </div>

      {data.overall_description && (
        <p className="text-sm text-gray-400 px-4 leading-relaxed">{data.overall_description}</p>
      )}

      {/* Filter Pills */}
      <div className="flex items-center gap-1.5 px-4 flex-wrap">
        <button
          onClick={() => setFilter(null)}
          className={`px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
            !filter ? 'bg-blue-600 text-white' : 'bg-[#1e293b] text-gray-400 hover:text-white'
          }`}
        >
          Alle ({data.findings.length})
        </button>
        {SEVERITY_CONFIG.map(({ key }) => {
          const count = data.severity_counts[key] || 0;
          if (count === 0) return null;
          const badge = SEVERITY_BADGE[key];
          return (
            <button
              key={key}
              onClick={() => setFilter(filter === key ? null : key)}
              className={`px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
                filter === key ? `${badge.bg} ${badge.text} ring-1 ring-current` : 'bg-[#1e293b] text-gray-400 hover:text-white'
              }`}
            >
              {key} ({count})
            </button>
          );
        })}
      </div>

      {/* Finding Cards */}
      <div className="space-y-1.5 px-4 pb-4">
        {filtered.map((finding) => {
          const sev = finding.severity?.toUpperCase() || 'INFO';
          const badge = SEVERITY_BADGE[sev] || SEVERITY_BADGE.INFO;
          const isOpen = expandedId === finding.id;

          return (
            <div key={finding.id} className="rounded-lg overflow-hidden border border-gray-800/50">
              {/* Collapsed Header */}
              <button
                onClick={() => setExpandedId(isOpen ? null : finding.id)}
                className="w-full bg-[#1e293b] hover:bg-[#253347] p-3 flex items-center gap-3 text-left transition-colors"
              >
                <span className={`${badge.bg} ${badge.text} text-xs font-bold px-2 py-0.5 rounded shrink-0 uppercase`}>
                  {sev}
                </span>
                <div className="min-w-0 flex-1">
                  <span className="text-sm text-white font-medium">
                    <span className="text-gray-500 font-mono mr-1.5">{finding.id}</span>
                    {finding.title}
                  </span>
                  {finding.affected && (
                    <span className="text-xs text-gray-500 block mt-0.5 truncate">{finding.affected}</span>
                  )}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {!isBasic && finding.cvss_score && (
                    <span className="text-xs font-mono font-bold text-gray-300 bg-gray-700/50 px-2 py-0.5 rounded">
                      {finding.cvss_score}
                    </span>
                  )}
                  {finding.nis2_ref && (
                    <span className="text-xs font-medium px-1.5 py-0.5 rounded bg-yellow-500/20 text-yellow-400">
                      {finding.nis2_ref}
                    </span>
                  )}
                  <span className="text-gray-600 text-xs">{isOpen ? '\u25B2' : '\u25BC'}</span>
                </div>
              </button>

              {/* Expanded Detail */}
              {isOpen && (
                <div className="bg-[#0f172a] p-4 space-y-4 border-t border-gray-800/50">
                  {/* Meta line */}
                  <div className="flex items-center gap-3 flex-wrap text-xs text-gray-500">
                    {!isBasic && finding.cvss_vector && (
                      <span className="font-mono bg-gray-800 px-2 py-0.5 rounded">{finding.cvss_vector}</span>
                    )}
                    {finding.cwe && (
                      <span className="font-mono bg-gray-800 px-2 py-0.5 rounded">{finding.cwe}</span>
                    )}
                  </div>

                  {/* Description */}
                  {finding.description && (
                    <div>
                      <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-1.5">Beschreibung</h4>
                      <p className="text-sm text-gray-300 leading-relaxed">{finding.description}</p>
                    </div>
                  )}

                  {/* Evidence */}
                  {finding.evidence && (
                    <div>
                      <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-1.5">Nachweis</h4>
                      <pre className="bg-[#0c1222] border border-gray-800 rounded-lg p-3 text-xs font-mono text-gray-400 overflow-x-auto max-h-60 overflow-y-auto whitespace-pre-wrap break-all"
                           style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>
                        {finding.evidence}
                      </pre>
                    </div>
                  )}

                  {/* Impact */}
                  {finding.impact && (
                    <div>
                      <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-1.5">Auswirkung</h4>
                      <p className="text-sm text-gray-300 leading-relaxed">{finding.impact}</p>
                    </div>
                  )}

                  {/* Recommendation */}
                  {finding.recommendation && (
                    <div>
                      <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-1.5">Empfehlung</h4>
                      <div
                        className="text-sm text-gray-300 leading-relaxed [&>b]:font-semibold [&>b]:text-white"
                        dangerouslySetInnerHTML={{ __html: finding.recommendation.replace(/\n/g, '<br/>') }}
                      />
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {/* Positive Findings */}
        {data.positive_findings.length > 0 && !filter && (
          <div className="mt-4 space-y-1.5">
            <h3 className="text-xs font-medium text-gray-500 uppercase tracking-wider px-1">Positive Befunde</h3>
            {data.positive_findings.map((pf, i) => (
              <div key={i} className="bg-[#1e293b] rounded-lg p-3 flex items-start gap-2.5 border border-gray-800/50">
                <span className="text-green-400 shrink-0 mt-0.5">{'\u2713'}</span>
                <div>
                  <span className="text-sm text-white font-medium">{pf.title}</span>
                  {pf.description && (
                    <p className="text-xs text-gray-400 mt-0.5">{pf.description}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
