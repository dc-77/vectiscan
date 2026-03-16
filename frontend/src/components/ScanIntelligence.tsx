'use client';

import type { AiStrategy, AiConfig } from '@/hooks/useWebSocket';
import { COLORS } from './intelligence/constants';
import type { HostNode, ToolOutputEntry } from './intelligence/constants';
import RadarTopology from './intelligence/RadarTopology';
import MetricsGrid from './intelligence/MetricsGrid';
import HostDiscoveryMatrix from './intelligence/HostDiscoveryMatrix';
import AiDecisionFeed from './intelligence/AiDecisionFeed';
import DataStream from './intelligence/DataStream';

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
  return (
    <div className="h-full">
      <div className="relative rounded-lg border overflow-hidden overflow-y-auto"
        style={{
          borderColor: COLORS.borderDim,
          background: COLORS.base,
          backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(56,189,248,0.02) 2px, rgba(56,189,248,0.02) 4px)',
          boxShadow: `0 0 30px rgba(56,189,248,0.08), inset 0 0 30px rgba(0,0,0,0.3)`,
          maxHeight: 'calc(100vh - 200px)',
        }}>

        {/* Scrolling scanline overlay */}
        <div className="absolute inset-0 pointer-events-none scanline-overlay" style={{ zIndex: 1 }} />

        {/* Header */}
        <div className="flex items-center justify-between px-3 py-1.5 border-b bg-[#0f172a]/80 sticky top-0"
          style={{ borderColor: COLORS.borderDim, zIndex: 2 }}>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono uppercase tracking-widest" style={{ color: `${COLORS.cyan}B3` }}>
              Scan Intelligence
            </span>
            {/* Animated hex fragment */}
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

        {/* Radar Topology */}
        <div className="py-2">
          <RadarTopology
            domain={domain}
            hosts={hosts}
            currentHost={currentHost}
            toolOutputs={toolOutputs}
          />
        </div>

        {/* Metrics Grid */}
        <MetricsGrid
          currentPhase={currentPhase}
          currentTool={currentTool}
          hosts={hosts}
          toolOutputs={toolOutputs}
        />

        {/* Host Discovery Matrix */}
        <HostDiscoveryMatrix
          hosts={hosts}
          currentHost={currentHost}
          aiStrategy={aiStrategy}
        />

        {/* AI Decision Feed */}
        <AiDecisionFeed
          aiStrategy={aiStrategy}
          aiConfigs={aiConfigs}
          hosts={hosts}
          toolOutputs={toolOutputs}
        />

        {/* Data Stream */}
        <DataStream
          toolOutputs={toolOutputs}
          currentTool={currentTool}
        />
      </div>

      <style jsx>{`
        @keyframes scanlineScroll {
          from { background-position-y: 0; }
          to { background-position-y: 100px; }
        }
        .scanline-overlay {
          background: linear-gradient(transparent 50%, rgba(56,189,248,0.012) 50%);
          background-size: 100% 4px;
          animation: scanlineScroll 8s linear infinite;
        }
      `}</style>
    </div>
  );
}

export type { HostNode, ToolOutputEntry };
