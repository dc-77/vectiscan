'use client';

import { useState, useEffect, useRef } from 'react';
import { COLORS, hostDisplayName } from './constants';
import type { HostNode } from './constants';
import type { AiStrategy, AiConfig } from '@/hooks/useWebSocket';

// ─── Boot Sequence (shown while waiting for AI data) ───

const BOOT_LINES = [
  '> INITIALIZING NEURAL THREAT ENGINE...',
  '> LOADING CVE DATABASE [2024-2026]...',
  '> CALIBRATING SCAN VECTORS...',
  '> AWAITING HOST DISCOVERY DATA...',
];

function BootSequence() {
  const [lineIdx, setLineIdx] = useState(0);
  const [charIdx, setCharIdx] = useState(0);

  useEffect(() => {
    const line = BOOT_LINES[lineIdx];
    if (charIdx < line.length) {
      const t = setTimeout(() => setCharIdx(c => c + 1), 25 + Math.random() * 35);
      return () => clearTimeout(t);
    }
    // Line complete — pause then advance
    const t = setTimeout(() => {
      setLineIdx(i => (i + 1) % BOOT_LINES.length);
      setCharIdx(0);
    }, 1200);
    return () => clearTimeout(t);
  }, [lineIdx, charIdx]);

  return (
    <div className="space-y-1 py-2">
      {BOOT_LINES.slice(0, lineIdx + 1).map((line, i) => (
        <div key={i} className="text-[9px] font-mono leading-snug" style={{ color: i < lineIdx ? COLORS.grayDim : COLORS.amber }}>
          {i < lineIdx ? line : line.slice(0, charIdx)}
          {i === lineIdx && <span className="animate-pulse" style={{ color: COLORS.amber }}>{'\u2588'}</span>}
        </div>
      ))}
    </div>
  );
}

// ─── Types ─────────────────────────────────────────────

interface FeedEntry {
  id: string;
  ts: number;
  type: 'strategy' | 'config' | 'skip' | 'threat' | 'info';
  text: string;
}

const TYPE_STYLES: Record<string, { border: string; icon: string; color: string }> = {
  strategy: { border: COLORS.amber, icon: '\u25C9', color: COLORS.amber },
  config: { border: COLORS.cyan, icon: '\u2699', color: COLORS.cyan },
  skip: { border: COLORS.gray, icon: '\u2298', color: COLORS.gray },
  threat: { border: COLORS.red, icon: '\u26A0', color: COLORS.red },
  info: { border: COLORS.cyanDim, icon: '\u25B8', color: COLORS.cyanDim },
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

  // Helper: look up FQDN from hosts array by IP
  const labelForIp = (ip: string): string => {
    const h = hosts.find(host => host.ip === ip);
    return h ? hostDisplayName(h) : ip;
  };

  // Process aiStrategy changes
  useEffect(() => {
    if (!aiStrategy || aiStrategy === prevStrategyRef.current) return;
    prevStrategyRef.current = aiStrategy;
    const now = Date.now();

    const entries: FeedEntry[] = [];

    // Strategy notes
    if (aiStrategy.strategy_notes) {
      entries.push({
        id: `strat-notes-${now}`,
        ts: now,
        type: 'info',
        text: aiStrategy.strategy_notes,
      });
    }

    // Per-host decisions
    aiStrategy.hosts.forEach(h => {
      const label = labelForIp(h.ip);
      if (h.action === 'skip') {
        entries.push({
          id: `skip-${h.ip}-${now}`,
          ts: now,
          type: 'skip',
          text: `${label} \u2014 Skipped: ${h.reasoning}`,
        });
      } else {
        entries.push({
          id: `scan-${h.ip}-${now}`,
          ts: now,
          type: 'strategy',
          text: `Targeting ${label}${h.priority ? ` [P${h.priority}]` : ''} \u2014 ${h.reasoning}`,
        });
      }
    });

    setFeed(prev => [...prev, ...entries].slice(-50));
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

      return {
        id: `cfg-${ip}-${now}`,
        ts: now,
        type: 'config' as const,
        text: `${label} \u2014 ${detail}${cfg.reasoning ? ` \u2014 ${cfg.reasoning}` : ''}`,
      };
    });

    setFeed(prev => [...prev, ...entries].slice(-50));
  }, [aiConfigs]); // eslint-disable-line react-hooks/exhaustive-deps

  // Process threat-related tool outputs
  useEffect(() => {
    const threats = toolOutputs.filter(t => /CVE-|critical|HIGH|vuln/i.test(t.summary));
    if (threats.length <= prevThreatCountRef.current) return;

    const newThreats = threats.slice(prevThreatCountRef.current);
    prevThreatCountRef.current = threats.length;

    const entries: FeedEntry[] = newThreats.map(t => ({
      id: `threat-${t.ts}-${t.tool}`,
      ts: t.ts,
      type: 'threat' as const,
      text: `${t.tool} @ ${labelForIp(t.host)}: ${t.summary}`,
    }));

    setFeed(prev => [...prev, ...entries].slice(-50));
  }, [toolOutputs]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-scroll
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [feed]);

  return (
    <div className="mx-3 mb-2">
      <div className="flex items-center gap-1.5 mb-1">
        <span className="text-[9px] font-mono uppercase tracking-widest" style={{ color: COLORS.amber }}>
          AI Decision Log
        </span>
        <span className="flex-1 h-px" style={{ background: `linear-gradient(to right, ${COLORS.amber}40, transparent)` }} />
        {feed.length > 0 && (
          <span className="text-[8px] font-mono" style={{ color: COLORS.gray }}>{feed.length}</span>
        )}
      </div>
      <div ref={containerRef} className="overflow-hidden relative"
        style={{
          height: 140,
          maskImage: 'linear-gradient(to bottom, transparent, black 8%, black 92%, transparent)',
        }}>
        {feed.length === 0 ? (
          <BootSequence />
        ) : (
          <div className="space-y-0.5">
            {feed.map((entry, i) => {
              const style = TYPE_STYLES[entry.type] || TYPE_STYLES.info;
              const isNew = i >= feed.length - 3;
              return (
                <div key={entry.id}
                  className={`flex gap-1.5 py-0.5 pl-1.5 border-l-2 ${isNew ? 'animate-feedSlideIn' : ''}`}
                  style={{ borderColor: style.border }}>
                  <span className="text-[8px] font-mono shrink-0 mt-px" style={{ color: COLORS.grayDim }}>
                    {formatTime(entry.ts)}
                  </span>
                  <span className="text-[9px] shrink-0 mt-px" style={{ color: style.color }}>
                    {style.icon}
                  </span>
                  <span className="text-[9px] font-mono leading-snug" style={{ color: COLORS.textDim }}>
                    {entry.text}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>

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
