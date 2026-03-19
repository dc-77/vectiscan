'use client';

import { useState } from 'react';
import type { FindingsData, Finding } from '@/lib/api';
import SeverityCounts from './SeverityCounts';

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const SEVERITY_BORDER: Record<string, string> = {
  CRITICAL: 'border-l-2 border-red-500',
  HIGH:     'border-l-2 border-red-500/60',
  MEDIUM:   'border-l-2 border-slate-500',
  LOW:      'border-l-2 border-slate-700',
  INFO:     'border-l-2 border-slate-700',
};

const RISK_STYLE: Record<string, string> = {
  CRITICAL: 'bg-red-500/10 text-red-400 border border-red-500/20',
  HIGH:     'bg-red-500/10 text-red-400/70 border border-red-500/15',
  MEDIUM:   'bg-slate-700/50 text-slate-400 border border-slate-600',
  LOW:      'bg-slate-800 text-slate-500 border border-slate-700',
};

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
  excludedIds?: string[];
  onExclude?: (findingId: string, reason: string) => void;
  onUnexclude?: (findingId: string) => void;
  onRegenerateReport?: () => void;
  lastReportExcludedFindings?: string[];
}

export default function FindingsViewer({ data, excludedIds = [], onExclude, onUnexclude, onRegenerateReport, lastReportExcludedFindings = [] }: FindingsViewerProps) {
  const [filter, setFilter] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const sorted = sortFindings(data.findings);
  const filtered = filter ? sorted.filter(f => f.severity?.toUpperCase() === filter) : sorted;
  const isBasic = data.package === 'basic' || data.package === 'webcheck';

  // Compute adjusted severity counts (excluding manually excluded findings)
  const adjustedCounts: Record<string, number> = { ...data.severity_counts };
  if (excludedIds.length > 0) {
    for (const f of data.findings) {
      if (excludedIds.includes(f.id)) {
        const sev = f.severity?.toUpperCase() || 'INFO';
        if (adjustedCounts[sev]) adjustedCounts[sev]--;
      }
    }
  }
  const hasExclusions = excludedIds.length > 0;

  // Determine if exclusions have changed since last report
  const lastReportExclusions = new Set(lastReportExcludedFindings);
  const currentExclusions = new Set(excludedIds);
  const hasExclusionChanges = currentExclusions.size !== lastReportExclusions.size ||
    [...currentExclusions].some(id => !lastReportExclusions.has(id));
  const exclusionDiff = currentExclusions.size - lastReportExclusions.size;

  const riskStyle = RISK_STYLE[data.overall_risk?.toUpperCase()] || 'bg-slate-700 text-slate-400';

  return (
    <div className="space-y-4">
      {/* Header: Risk + Severity Counts */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-3 px-5 pt-5">
        <div className="flex items-center gap-3 min-w-0">
          <span className={`${riskStyle} text-xs font-bold px-3 py-1.5 rounded uppercase tracking-wider`}>
            {data.overall_risk || 'N/A'}
          </span>
          <span className="text-sm text-slate-500">
            {data.findings.length} Befunde
            {hasExclusions && (
              <span className="text-slate-600 ml-1">({excludedIds.length} ausgeschlossen)</span>
            )}
          </span>
        </div>
        <div className="flex items-center gap-3 flex-1">
          <SeverityCounts counts={hasExclusions ? adjustedCounts : data.severity_counts} />
          {hasExclusionChanges && onRegenerateReport && (
            <button
              onClick={onRegenerateReport}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors ml-auto shrink-0"
            >
              {exclusionDiff > 0
                ? `Report neu generieren (${exclusionDiff} weitere FP)`
                : exclusionDiff < 0
                  ? `Report neu generieren (${Math.abs(exclusionDiff)} FP wiederhergestellt)`
                  : `Report neu generieren (FP ge\u00e4ndert)`}
            </button>
          )}
        </div>
      </div>

      {data.overall_description && (
        <p className="text-sm text-slate-400 px-5 leading-relaxed">{data.overall_description}</p>
      )}

      {/* Filter Pills */}
      <div className="flex items-center gap-1.5 px-5 flex-wrap">
        <button
          onClick={() => setFilter(null)}
          className={`px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
            !filter ? 'bg-blue-500/15 text-blue-400 ring-1 ring-blue-500/30' : 'text-slate-500 hover:text-slate-300'
          }`}
        >
          Alle ({data.findings.length})
        </button>
        {SEVERITY_ORDER.map(key => {
          const count = data.severity_counts[key] || 0;
          if (count === 0) return null;
          return (
            <button
              key={key}
              onClick={() => setFilter(filter === key ? null : key)}
              className={`px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
                filter === key ? 'bg-blue-500/15 text-blue-400 ring-1 ring-blue-500/30' : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              {key} ({count})
            </button>
          );
        })}
      </div>

      {/* Finding Cards */}
      <div className="space-y-1.5 px-5 pb-5">
        {filtered.map((finding) => {
          const sev = finding.severity?.toUpperCase() || 'INFO';
          const borderClass = SEVERITY_BORDER[sev] || SEVERITY_BORDER.INFO;
          const isOpen = expandedId === finding.id;
          const isExcluded = excludedIds.includes(finding.id);

          return (
            <div key={finding.id} className={`rounded-lg overflow-hidden border border-gray-800/50 ${borderClass} ${isExcluded ? 'opacity-50' : ''}`}>
              {/* Collapsed Header */}
              <button
                onClick={() => setExpandedId(isOpen ? null : finding.id)}
                className="w-full bg-[#1e293b] hover:bg-[#253347] p-3 flex items-center gap-3 text-left transition-colors"
              >
                <span className="text-xs font-mono font-bold text-slate-400 shrink-0 uppercase">
                  {sev}
                </span>
                <div className="min-w-0 flex-1">
                  <span className="text-sm text-white font-medium">
                    <span className="text-slate-600 font-mono mr-1.5">{finding.id}</span>
                    {finding.title}
                  </span>
                  {finding.affected && (
                    <span className="text-xs text-slate-600 block mt-0.5 truncate">{finding.affected}</span>
                  )}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {isExcluded && (
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
                      FALSE POSITIVE
                    </span>
                  )}
                  {!isBasic && finding.cvss_score && (
                    <span className="text-xs font-mono font-bold text-slate-300 bg-slate-700/50 px-2 py-0.5 rounded">
                      {finding.cvss_score}
                    </span>
                  )}
                  {finding.in_cisa_kev && (
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30" title="CISA Known Exploited Vulnerability">
                      KEV
                    </span>
                  )}
                  {finding.epss != null && finding.epss > 0.3 && (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-orange-500/15 text-orange-400" title={`EPSS: ${(finding.epss * 100).toFixed(0)}% Exploit-Wahrscheinlichkeit`}>
                      EPSS {(finding.epss * 100).toFixed(0)}%
                    </span>
                  )}
                  {finding.confidence != null && finding.confidence < 0.5 && (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-700 text-slate-500" title={`Confidence: ${(finding.confidence * 100).toFixed(0)}%`}>
                      {(finding.confidence * 100).toFixed(0)}%
                    </span>
                  )}
                  {finding.nis2_ref && (
                    <span className="text-xs font-medium px-1.5 py-0.5 rounded bg-slate-700 text-slate-400">
                      {finding.nis2_ref}
                    </span>
                  )}
                  {finding.iso27001_ref && (
                    <span className="text-xs font-medium px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-400">
                      {finding.iso27001_ref}
                    </span>
                  )}
                  <span className="text-slate-700 text-xs">{isOpen ? '\u25B2' : '\u25BC'}</span>
                </div>
              </button>

              {/* Expanded Detail */}
              {isOpen && (
                <div className="bg-[#0f172a] p-4 space-y-4 border-t border-gray-800/50">
                  {/* Meta line */}
                  <div className="flex items-center gap-3 flex-wrap text-xs text-slate-500">
                    {!isBasic && finding.cvss_vector && (
                      <span className="font-mono bg-slate-800 px-2 py-0.5 rounded">{finding.cvss_vector}</span>
                    )}
                    {finding.cwe && (
                      <span className="font-mono bg-slate-800 px-2 py-0.5 rounded">{finding.cwe}</span>
                    )}
                  </div>

                  {/* Description */}
                  {finding.description && (
                    <div>
                      <h4 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-1.5">Beschreibung</h4>
                      <p className="text-sm text-slate-300 leading-relaxed">{finding.description}</p>
                    </div>
                  )}

                  {/* Evidence */}
                  {finding.evidence && (
                    <div>
                      <h4 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-1.5">Nachweis</h4>
                      <pre className="bg-[#0c1222] border border-gray-800 rounded-lg p-3 text-xs font-mono text-slate-400 overflow-x-auto max-h-60 overflow-y-auto whitespace-pre-wrap break-all"
                           style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>
                        {finding.evidence}
                      </pre>
                    </div>
                  )}

                  {/* Impact */}
                  {finding.impact && (
                    <div>
                      <h4 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-1.5">Auswirkung</h4>
                      <p className="text-sm text-slate-300 leading-relaxed">{finding.impact}</p>
                    </div>
                  )}

                  {/* Recommendation */}
                  {finding.recommendation && (
                    <div>
                      <h4 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-1.5">Empfehlung</h4>
                      <div
                        className="text-sm text-slate-300 leading-relaxed [&>b]:font-semibold [&>b]:text-white"
                        dangerouslySetInnerHTML={{ __html: finding.recommendation.replace(/\n/g, '<br/>') }}
                      />
                    </div>
                  )}

                  {/* Exclude/Unexclude button */}
                  {(onExclude || onUnexclude) && (
                    <div className="pt-2 border-t border-gray-800/50">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          if (isExcluded && onUnexclude) {
                            onUnexclude(finding.id);
                          } else if (!isExcluded && onExclude) {
                            const reason = prompt('Begründung für False Positive:');
                            if (reason !== null && reason.trim() !== '') onExclude(finding.id, reason);
                          }
                        }}
                        className={`text-xs px-2 py-1 rounded transition-colors ${
                          isExcluded
                            ? 'bg-green-900/30 text-green-400 hover:bg-green-900/50'
                            : 'bg-red-900/30 text-red-400 hover:bg-red-900/50'
                        }`}
                        title={isExcluded ? 'False Positive aufheben' : 'Als False Positive markieren'}
                      >
                        {isExcluded ? 'Wiederherstellen' : 'False Positive'}
                      </button>
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
            <h3 className="text-xs font-medium text-slate-500 uppercase tracking-wider px-1">Positive Befunde</h3>
            {data.positive_findings.map((pf, i) => (
              <div key={i} className="bg-[#1e293b] rounded-lg p-3 flex items-start gap-2.5 border border-gray-800/50">
                <span className="text-green-400 shrink-0 mt-0.5">{'\u2713'}</span>
                <div>
                  <span className="text-sm text-white font-medium">{pf.title}</span>
                  {pf.description && (
                    <p className="text-xs text-slate-400 mt-0.5">{pf.description}</p>
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
