'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { COLORS, hostDisplayName } from './constants';
import type { HostNode } from './constants';
import type { AiStrategy, AiConfig } from '@/hooks/useWebSocket';

// ─── Types ─────────────────────────────────────────────

interface FeedEntry {
  id: string;
  ts: number;
  type: 'strategy' | 'config' | 'skip' | 'threat' | 'info' | 'correlation' | 'enrichment' | 'fp_filter';
  text: string;
}

const TYPE_STYLES: Record<string, { border: string; icon: string; color: string }> = {
  strategy: { border: COLORS.cyan, icon: '\u25C9', color: COLORS.cyan },
  config: { border: COLORS.cyanDim, icon: '\u2699', color: COLORS.cyanDim },
  skip: { border: COLORS.gray, icon: '\u2298', color: COLORS.gray },
  threat: { border: COLORS.red, icon: '\u26A0', color: COLORS.red },
  info: { border: COLORS.cyanDim, icon: '\u25B8', color: COLORS.cyanDim },
  correlation: { border: '#A78BFA', icon: '\u2194', color: '#A78BFA' },   // purple — cross-tool link
  enrichment: { border: '#34D399', icon: '\u2B06', color: '#34D399' },    // green — NVD/EPSS/KEV
  fp_filter: { border: '#F59E0B', icon: '\u2718', color: '#F59E0B' },     // amber — false-positive removed
};

function formatTime(ts: number): string {
  const d = new Date(ts);
  return d.toTimeString().slice(0, 8);
}

interface AiDecisionFeedProps {
  aiStrategy: AiStrategy | null;
  aiConfigs: Record<string, AiConfig>;
  hosts: HostNode[];
  toolOutputs: Array<{ tool: string; host: string; summary: string; ts: number }>;
}

export default function AiDecisionFeed({ aiStrategy, aiConfigs, hosts, toolOutputs }: AiDecisionFeedProps) {
  const [feed, setFeed] = useState<FeedEntry[]>([]);
  const containerRef = useRef<HTMLDivElement>(null);
  const prevStrategyRef = useRef<AiStrategy | null>(null);
  const prevConfigKeysRef = useRef<Set<string>>(new Set());
  const prevThreatCountRef = useRef(0);

  const labelForIp = (ip: string): string => {
    const h = hosts.find(host => host.ip === ip);
    return h ? hostDisplayName(h) : ip;
  };

  // Dedup helper — merge entries, skip existing IDs
  const mergeFeed = useCallback((prev: FeedEntry[], entries: FeedEntry[]): FeedEntry[] => {
    const existingIds = new Set(prev.map(e => e.id));
    const unique = entries.filter(e => !existingIds.has(e.id));
    if (unique.length === 0) return prev;
    return [...prev, ...unique].slice(-50);
  }, []);

  // Process aiStrategy changes
  useEffect(() => {
    if (!aiStrategy || aiStrategy === prevStrategyRef.current) return;
    prevStrategyRef.current = aiStrategy;
    const now = Date.now();
    const entries: FeedEntry[] = [];

    if (aiStrategy.strategy_notes) {
      entries.push({ id: 'strat-notes', ts: now, type: 'info', text: aiStrategy.strategy_notes });
    }

    aiStrategy.hosts.forEach(h => {
      const label = labelForIp(h.ip);
      if (h.action === 'skip') {
        entries.push({ id: `skip-${h.ip}`, ts: now, type: 'skip', text: `${label} \u2014 Skipped: ${h.reasoning}` });
      } else {
        entries.push({ id: `scan-${h.ip}`, ts: now, type: 'strategy', text: `Targeting ${label}${h.priority ? ` [P${h.priority}]` : ''} \u2014 ${h.reasoning}` });
      }
    });

    setFeed(prev => mergeFeed(prev, entries));
  }, [aiStrategy]); // eslint-disable-line react-hooks/exhaustive-deps

  // Process aiConfigs changes
  useEffect(() => {
    const currentKeys = new Set(Object.keys(aiConfigs));
    const newKeys = [...currentKeys].filter(k => !prevConfigKeysRef.current.has(k));
    prevConfigKeysRef.current = currentKeys;
    if (newKeys.length === 0) return;
    const now = Date.now();

    const entries: FeedEntry[] = newKeys.map(ip => {
      const cfg = aiConfigs[ip];
      const label = labelForIp(ip);
      const parts: string[] = [];
      if (cfg.nuclei_tags?.length) parts.push(`nuclei:[${cfg.nuclei_tags.join(',')}]`);
      if (cfg.gobuster_wordlist && cfg.gobuster_wordlist !== 'common') parts.push(`wordlist:${cfg.gobuster_wordlist}`);
      if (cfg.skip_tools?.length) parts.push(`skip:[${cfg.skip_tools.join(',')}]`);
      const detail = parts.length > 0 ? parts.join(' ') : 'default config';
      return { id: `cfg-${ip}`, ts: now, type: 'config' as const, text: `${label} \u2014 ${detail}${cfg.reasoning ? ` \u2014 ${cfg.reasoning}` : ''}` };
    });

    setFeed(prev => mergeFeed(prev, entries));
  }, [aiConfigs]); // eslint-disable-line react-hooks/exhaustive-deps

  // Process threat-related tool outputs
  useEffect(() => {
    const threats = toolOutputs.filter(t => /CVE-|critical|HIGH|vuln/i.test(t.summary));
    if (threats.length <= prevThreatCountRef.current) return;
    const newThreats = threats.slice(prevThreatCountRef.current);
    prevThreatCountRef.current = threats.length;
    const entries: FeedEntry[] = newThreats.map(t => ({
      id: `threat-${t.ts}-${t.tool}`, ts: t.ts, type: 'threat' as const,
      text: `${labelForIp(t.host)}: ${t.summary}`,
    }));
    setFeed(prev => [...prev, ...entries].slice(-50));
  }, [toolOutputs]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-scroll
  useEffect(() => {
    if (containerRef.current) containerRef.current.scrollTop = containerRef.current.scrollHeight;
  }, [feed]);

  // ─── Render (no internal header — parent panel provides it) ───
  return (
    <div ref={containerRef} className="h-full overflow-y-auto"
      style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>
      {feed.length === 0 ? (
        <div className="flex items-center justify-center h-full">
          <span className="text-[10px] font-mono text-slate-600">// awaiting AI data</span>
        </div>
      ) : (
        <div className="py-1">
          {feed.map((entry, i) => {
            const style = TYPE_STYLES[entry.type] || TYPE_STYLES.info;
            const isNew = i >= feed.length - 3;
            return (
              <div key={entry.id}
                className={`flex gap-2 py-1.5 px-2 border-l-[3px] ${isNew ? 'animate-feedSlideIn' : ''} ${entry.type === 'threat' ? 'animate-threat-pulse animate-glitch' : ''}`}
                style={{ borderColor: style.border }}>
                <span className="text-[10px] font-mono shrink-0 mt-0.5" style={{ color: COLORS.grayDim }}>
                  {formatTime(entry.ts)}
                </span>
                <span className="text-[11px] shrink-0 mt-0.5" style={{ color: style.color }}>
                  {style.icon}
                </span>
                <span className="text-[11px] font-mono leading-normal" style={{ color: COLORS.textDim }}>
                  {entry.text}
                </span>
              </div>
            );
          })}
        </div>
      )}

      <style jsx>{`
        @keyframes feedSlideIn {
          from { opacity: 0; transform: translateY(12px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .animate-feedSlideIn {
          animation: feedSlideIn 0.3s ease-out;
        }
      `}</style>
    </div>
  );
}
