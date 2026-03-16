'use client';

import { COLORS, STATUS_COLORS, hostDisplayName, truncate } from './constants';
import type { HostNode } from './constants';
import type { AiStrategy } from '@/hooks/useWebSocket';

interface HostDiscoveryMatrixProps {
  hosts: HostNode[];
  currentHost: string | null;
  aiStrategy: AiStrategy | null;
}

export default function HostDiscoveryMatrix({ hosts, currentHost, aiStrategy }: HostDiscoveryMatrixProps) {
  if (hosts.length === 0) return null;

  const actionMap = new Map<string, string>();
  aiStrategy?.hosts.forEach(h => actionMap.set(h.ip, h.action.toUpperCase()));

  return (
    <div className="mx-3 mb-2">
      <div className="flex items-center gap-1.5 mb-1">
        <span className="text-[9px] font-mono uppercase tracking-widest" style={{ color: COLORS.cyan }}>
          Discovered Hosts
        </span>
        <span className="flex-1 h-px" style={{ background: `linear-gradient(to right, ${COLORS.cyan}40, transparent)` }} />
        <span className="text-[8px] font-mono" style={{ color: COLORS.gray }}>{hosts.length}</span>
      </div>

      <div className="overflow-y-auto rounded border"
        style={{
          maxHeight: '100%',
          borderColor: COLORS.borderDim,
          background: `${COLORS.panel}80`,
        }}>
        {/* Header */}
        <div className="flex items-center gap-2 px-2 py-0.5 border-b text-[8px] font-mono uppercase tracking-wider"
          style={{ borderColor: COLORS.borderDim, color: COLORS.grayDim }}>
          <span className="w-3" />
          <span className="flex-1 min-w-0">Subdomain</span>
          <span className="w-24 shrink-0 text-right">IP</span>
          <span className="w-10 shrink-0 text-center">AI</span>
        </div>

        {/* Host rows */}
        {hosts.map(h => {
          const isActive = h.ip === currentHost;
          const color = STATUS_COLORS[h.status] || COLORS.cyan;
          const action = actionMap.get(h.ip);

          return (
            <div key={h.ip}
              className="flex items-center gap-2 px-2 py-[3px] transition-colors"
              style={{
                borderLeft: isActive ? `2px solid ${COLORS.amber}` : '2px solid transparent',
                background: isActive ? 'rgba(234,179,8,0.04)' : undefined,
                boxShadow: isActive ? `inset 0 0 20px ${COLORS.amberGlow}` : undefined,
              }}>
              {/* Status indicator */}
              <span className="w-3 flex items-center justify-center shrink-0">
                {h.status === 'scanning' ? (
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-50"
                      style={{ backgroundColor: color }} />
                    <span className="relative inline-flex rounded-full h-2 w-2"
                      style={{ backgroundColor: color, boxShadow: `0 0 6px ${COLORS.amberGlow}` }} />
                  </span>
                ) : h.status === 'scanned' ? (
                  <span className="text-[10px]" style={{ color: COLORS.green }}>{'\u2713'}</span>
                ) : h.status === 'skipped' ? (
                  <span className="text-[10px]" style={{ color: COLORS.gray }}>{'\u2717'}</span>
                ) : (
                  <span className="inline-block w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color, opacity: 0.6 }} />
                )}
              </span>

              {/* Subdomain */}
              <span className="flex-1 min-w-0 text-[9px] font-mono truncate"
                style={{
                  color: h.status === 'skipped' ? COLORS.gray
                    : isActive ? COLORS.amber
                    : COLORS.cyanDim,
                  opacity: h.status === 'skipped' ? 0.6 : 1,
                }}>
                {truncate(hostDisplayName(h), 28)}
              </span>

              {/* IP */}
              <span className="w-24 shrink-0 text-right text-[8px] font-mono"
                style={{ color: COLORS.grayDim }}>
                {h.ip}
              </span>

              {/* AI action */}
              <span className="w-10 shrink-0 text-center text-[8px] font-mono font-medium"
                style={{
                  color: action === 'SKIP' ? COLORS.gray
                    : action === 'SCAN' ? COLORS.cyan
                    : COLORS.grayDim,
                }}>
                {action || '\u2014'}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
