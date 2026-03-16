'use client';

import { useState, useEffect, useRef, useMemo } from 'react';
import { COLORS } from './constants';
import type { HostNode, ToolOutputEntry } from './constants';

// ─── Animated Number Hook ──────────────────────────────

function useAnimatedNumber(target: number, duration = 600): number {
  const [display, setDisplay] = useState(target);
  const prevRef = useRef(target);

  useEffect(() => {
    const from = prevRef.current;
    if (from === target) return;

    const start = performance.now();
    let frameId: number;

    const tick = (now: number) => {
      const t = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(Math.round(from + (target - from) * eased));
      if (t < 1) {
        frameId = requestAnimationFrame(tick);
      } else {
        prevRef.current = target;
      }
    };

    frameId = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frameId);
  }, [target, duration]);

  return display;
}

// ─── Component ─────────────────────────────────────────

interface MetricsGridProps {
  currentPhase: string | null;
  currentTool: string | null;
  hosts: HostNode[];
  toolOutputs: ToolOutputEntry[];
}

export default function MetricsGrid({ currentPhase, currentTool, hosts, toolOutputs }: MetricsGridProps) {
  const hostsActive = hosts.filter(h => h.status !== 'skipped').length;
  const hostsScanned = hosts.filter(h => h.status === 'scanned').length;
  const hostsScanning = hosts.filter(h => h.status === 'scanning').length;

  // Phase-aware progress
  const isDnsRecon = currentPhase === 'dns_recon';
  const isPhase1 = currentPhase === 'scan_phase1';
  const isPhase2 = currentPhase === 'scan_phase2';

  let progressValue: number;
  let progressMax: number;
  let progressLabel: string;

  if (isDnsRecon) {
    progressValue = 0;
    progressMax = 1;
    progressLabel = 'Discovering';
  } else if (isPhase1) {
    // During Phase 1: scanned means P1 done, scanning means currently in P1
    progressValue = hostsScanned + hostsScanning;
    progressMax = hostsActive;
    progressLabel = `P1: ${progressValue}/${progressMax}`;
  } else if (isPhase2) {
    progressValue = hostsScanned;
    progressMax = hostsActive;
    progressLabel = `P2: ${hostsScanned}/${progressMax}`;
  } else {
    progressValue = hostsScanned;
    progressMax = hostsActive || hosts.length;
    progressLabel = hostsActive > 0 ? `${hostsScanned}/${progressMax}` : '\u2014';
  }

  const animatedValue = useAnimatedNumber(progressValue);
  const progress = progressMax > 0 ? (progressValue / progressMax) * 100 : 0;

  // Threat level
  const { level, color, threatCount } = useMemo(() => {
    const count = toolOutputs.filter(t => /CVE-|critical|HIGH|vuln/i.test(t.summary)).length;
    if (count === 0) return { level: 'LOW', color: COLORS.green, threatCount: count };
    if (count < 3) return { level: 'MEDIUM', color: COLORS.amber, threatCount: count };
    return { level: 'HIGH', color: COLORS.red, threatCount: count };
  }, [toolOutputs]);

  const phaseLabel = isDnsRecon ? 'DNS Recon'
    : isPhase1 ? 'Tech Detect'
    : isPhase2 ? 'Deep Scan'
    : currentPhase || '\u2014';

  // Filter "starting" from tool display
  const displayTool = currentTool && currentTool !== 'starting' ? currentTool : '\u2014';

  return (
    <div className="grid grid-cols-2 gap-1.5 px-3 pb-2">
      {/* Phase */}
      <div className="rounded px-2 py-1 border"
        style={{ background: COLORS.panel, borderColor: COLORS.borderDim }}>
        <div className="text-[8px] uppercase tracking-wider mb-0.5" style={{ color: COLORS.grayDim }}>Phase</div>
        <div className="text-xs font-mono font-medium" style={{ color: COLORS.cyan }}>
          {phaseLabel}
        </div>
      </div>

      {/* Tool */}
      <div className="rounded px-2 py-1 border"
        style={{ background: COLORS.panel, borderColor: COLORS.borderDim }}>
        <div className="text-[8px] uppercase tracking-wider mb-0.5" style={{ color: COLORS.grayDim }}>Tool</div>
        <div className="text-xs font-mono font-medium truncate" style={{ color: COLORS.amber }}>
          {displayTool}
        </div>
      </div>

      {/* Hosts — phase-aware progress */}
      <div className="rounded px-2 py-1 border"
        style={{ background: COLORS.panel, borderColor: COLORS.borderDim }}>
        <div className="text-[8px] uppercase tracking-wider mb-0.5" style={{ color: COLORS.grayDim }}>Hosts</div>
        <div className="text-xs font-mono font-medium" style={{ color: COLORS.white }}>
          {isDnsRecon ? (
            <span className="animate-pulse" style={{ color: COLORS.cyan }}>Discovering...</span>
          ) : (
            progressLabel
          )}
        </div>
        {!isDnsRecon && progressMax > 0 && (
          <div className="mt-0.5 h-[2px] rounded-full overflow-hidden" style={{ background: COLORS.borderDim }}>
            <div className="h-full rounded-full transition-all duration-500"
              style={{
                width: `${progress}%`,
                background: COLORS.cyan,
                boxShadow: `0 0 6px ${COLORS.cyanGlow}`,
              }} />
          </div>
        )}
        {isDnsRecon && (
          <div className="mt-0.5 h-[2px] rounded-full overflow-hidden" style={{ background: COLORS.borderDim }}>
            <div className="h-full rounded-full animate-pulse"
              style={{ width: '60%', background: COLORS.cyan, opacity: 0.5 }} />
          </div>
        )}
      </div>

      {/* Threat Level */}
      <div className="rounded px-2 py-1 border"
        style={{ background: COLORS.panel, borderColor: COLORS.borderDim }}>
        <div className="text-[8px] uppercase tracking-wider mb-0.5" style={{ color: COLORS.grayDim }}>Threat Level</div>
        <div className="flex items-center gap-1.5">
          <span className="text-xs font-mono font-bold" style={{ color, textShadow: `0 0 6px ${color}40` }}>
            {level}
          </span>
          {threatCount > 0 && (
            <span className="text-[8px] font-mono" style={{ color: COLORS.grayDim }}>
              ({threatCount})
            </span>
          )}
        </div>
        <div className="mt-0.5 flex gap-px">
          {[0, 1, 2, 3, 4].map(i => (
            <div key={i} className="h-[2px] flex-1 rounded-full transition-all duration-300"
              style={{
                background: i < Math.min(threatCount, 5) ? color : COLORS.borderDim,
                boxShadow: i < Math.min(threatCount, 5) ? `0 0 4px ${color}60` : undefined,
              }} />
          ))}
        </div>
      </div>
    </div>
  );
}
