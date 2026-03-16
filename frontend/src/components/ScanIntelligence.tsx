'use client';

import { useState, useEffect, useRef } from 'react';
import type { AiStrategy, AiConfig } from '@/hooks/useWebSocket';
import { COLORS } from './intelligence/constants';
import type { HostNode, ToolOutputEntry } from './intelligence/constants';
import RadarTopology from './intelligence/RadarTopology';
import MetricsGrid from './intelligence/MetricsGrid';
import HostDiscoveryMatrix from './intelligence/HostDiscoveryMatrix';
import AiDecisionFeed from './intelligence/AiDecisionFeed';

// ─── Hex Divider ───────────────────────────────────────

function HexDivider() {
  const [hex, setHex] = useState(['0000', '0000']);
  useEffect(() => {
    const iv = setInterval(() => {
      const h = () => Math.random().toString(16).slice(2, 6).toUpperCase();
      setHex([h(), h()]);
    }, 1500);
    return () => clearInterval(iv);
  }, []);

  return (
    <div className="flex items-center gap-1 px-3 py-0.5 select-none">
      <span className="text-[7px] font-mono" style={{ color: COLORS.grayDim }}>0x{hex[0]}</span>
      <span className="flex-1 h-px" style={{ background: `linear-gradient(to right, ${COLORS.border}60, ${COLORS.border}20, ${COLORS.border}60)` }} />
      <span className="text-[7px] font-mono" style={{ color: COLORS.grayDim }}>0x{hex[1]}</span>
    </div>
  );
}

// ─── Main Component ────────────────────────────────────

interface ScanIntelligenceProps {
  domain: string;
  hosts: HostNode[];
  currentHost: string | null;
  currentTool: string | null;
  currentPhase: string | null;
  aiStrategy: AiStrategy | null;
  aiConfigs: Record<string, AiConfig>;
  toolOutputs: ToolOutputEntry[];
}

export default function ScanIntelligence({
  domain, hosts, currentHost, currentTool, currentPhase,
  aiStrategy, aiConfigs, toolOutputs,
}: ScanIntelligenceProps) {
  // Glitch effect on phase change
  const [glitch, setGlitch] = useState(false);
  const prevPhaseRef = useRef(currentPhase);

  useEffect(() => {
    if (currentPhase && currentPhase !== prevPhaseRef.current && prevPhaseRef.current !== null) {
      setGlitch(true);
      const t = setTimeout(() => setGlitch(false), 150);
      prevPhaseRef.current = currentPhase;
      return () => clearTimeout(t);
    }
    prevPhaseRef.current = currentPhase;
  }, [currentPhase]);

  return (
    <div className="h-full">
      <div className={`relative rounded-lg border overflow-hidden flex flex-col ${glitch ? 'intel-glitch' : ''}`}
        style={{
          borderColor: glitch ? COLORS.red : COLORS.borderDim,
          background: COLORS.base,
          backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(56,189,248,0.02) 2px, rgba(56,189,248,0.02) 4px)',
          boxShadow: `0 0 30px rgba(56,189,248,0.08), inset 0 0 30px rgba(0,0,0,0.3)`,
          height: 'calc(100vh - 280px)',
          minHeight: '400px',
          transition: 'border-color 0.15s',
        }}>

        {/* Scanline overlay */}
        <div className="absolute inset-0 pointer-events-none scanline-overlay" style={{ zIndex: 1 }} />

        {/* Header */}
        <div className="flex items-center justify-between px-3 py-1.5 border-b bg-[#0f172a]/80 shrink-0"
          style={{ borderColor: COLORS.borderDim, zIndex: 2 }}>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono uppercase tracking-widest" style={{ color: `${COLORS.cyan}B3` }}>
              Scan Intelligence
            </span>
            <span className="text-[8px] font-mono" style={{ color: COLORS.grayDim }}>
              //0x{Math.random().toString(16).slice(2, 8).toUpperCase()}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex gap-0.5">
              {[0, 1, 2].map(i => (
                <span key={i} className="w-1 h-3 rounded-sm animate-pulse"
                  style={{
                    backgroundColor: COLORS.cyan,
                    opacity: 0.3 + Math.random() * 0.4,
                    animationDelay: `${i * 0.3}s`,
                  }} />
              ))}
            </div>
            <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
            <span className="text-[9px] font-mono" style={{ color: COLORS.grayDim }}>LIVE</span>
          </div>
        </div>

        {/* Radar Topology — fixed height */}
        <div className="py-1 shrink-0">
          <RadarTopology
            domain={domain}
            hosts={hosts}
            currentHost={currentHost}
            toolOutputs={toolOutputs}
          />
        </div>

        <HexDivider />

        {/* Metrics Grid — fixed height */}
        <div className="shrink-0">
          <MetricsGrid
            currentPhase={currentPhase}
            currentTool={currentTool}
            hosts={hosts}
            toolOutputs={toolOutputs}
          />
        </div>

        <HexDivider />

        {/* Host Discovery Matrix — flex grow to fill space */}
        <div className="flex-1 min-h-0 overflow-hidden">
          <HostDiscoveryMatrix
            hosts={hosts}
            currentHost={currentHost}
            aiStrategy={aiStrategy}
          />
        </div>

        <HexDivider />

        {/* AI Decision Feed — fixed height */}
        <div className="shrink-0">
          <AiDecisionFeed
            aiStrategy={aiStrategy}
            aiConfigs={aiConfigs}
            hosts={hosts}
            toolOutputs={toolOutputs}
          />
        </div>
      </div>

      <style jsx>{`
        @keyframes scanlineScroll {
          from { background-position-y: 0; }
          to { background-position-y: 100px; }
        }
        .scanline-overlay {
          background: linear-gradient(transparent 50%, rgba(56,189,248,0.025) 50%);
          background-size: 100% 4px;
          animation: scanlineScroll 6s linear infinite;
        }
        @keyframes intelGlitch {
          0%   { transform: translateX(-1px); }
          33%  { transform: translateX(2px); }
          66%  { transform: translateX(-1px); }
          100% { transform: translateX(0); }
        }
        .intel-glitch {
          animation: intelGlitch 150ms steps(3);
        }
      `}</style>
    </div>
  );
}

export type { HostNode, ToolOutputEntry };
