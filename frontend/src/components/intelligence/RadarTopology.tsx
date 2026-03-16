'use client';

import { useMemo } from 'react';
import { COLORS, STATUS_COLORS, hostDisplayName, truncate } from './constants';
import type { HostNode, ToolOutputEntry } from './constants';

interface RadarTopologyProps {
  domain: string;
  hosts: HostNode[];
  currentHost: string | null;
  toolOutputs: ToolOutputEntry[];
}

export default function RadarTopology({ domain, hosts, currentHost, toolOutputs }: RadarTopologyProps) {
  const size = 280;
  const cx = size / 2;
  const cy = size / 2;
  const radius = 105;

  // Hosts with threat indicators (CVE/critical mentions)
  const threatHosts = useMemo(() => {
    const set = new Set<string>();
    toolOutputs.forEach(t => {
      if (/CVE-|critical|HIGH|vuln/i.test(t.summary)) set.add(t.host);
    });
    return set;
  }, [toolOutputs]);

  const hostPositions = useMemo(() => {
    return hosts.map((h, i) => {
      const angle = (i / Math.max(hosts.length, 1)) * 2 * Math.PI - Math.PI / 2;
      const x = cx + radius * Math.cos(angle);
      const y = cy + radius * Math.sin(angle);
      // Position label above or below based on y position
      const labelBelow = y < cy;
      return { ...h, x, y, angle, labelBelow };
    });
  }, [hosts, cx, cy]);

  return (
    <div className="relative" style={{ width: size, height: size + 20, margin: '0 auto' }}>
      <svg width={size} height={size} className="absolute inset-0">
        <defs>
          <radialGradient id="radarGrad2" cx="50%" cy="50%">
            <stop offset="0%" stopColor={COLORS.cyan} stopOpacity="0.35" />
            <stop offset="100%" stopColor={COLORS.cyan} stopOpacity="0" />
          </radialGradient>
          <radialGradient id="centerGlow" cx="50%" cy="50%">
            <stop offset="0%" stopColor={COLORS.cyan} stopOpacity="0.15" />
            <stop offset="100%" stopColor={COLORS.cyan} stopOpacity="0" />
          </radialGradient>
          <filter id="glow">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <filter id="glowStrong">
            <feGaussianBlur stdDeviation="3.5" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>

        {/* Center glow */}
        <circle cx={cx} cy={cy} r={60} fill="url(#centerGlow)" />

        {/* Grid circles — 4 rings with pulse on outer */}
        {[35, 60, 85, 110].map((r, i) => (
          <circle key={r} cx={cx} cy={cy} r={r} fill="none"
            stroke={COLORS.border} strokeWidth="0.5" opacity={0.2 + i * 0.05}>
            {i === 3 && (
              <animate attributeName="opacity" values="0.15;0.35;0.15" dur="6s" repeatCount="indefinite" />
            )}
          </circle>
        ))}

        {/* Grid crosshair lines */}
        {[0, 45, 90, 135].map(deg => {
          const rad = (deg * Math.PI) / 180;
          return (
            <line key={deg}
              x1={cx - 115 * Math.cos(rad)} y1={cy - 115 * Math.sin(rad)}
              x2={cx + 115 * Math.cos(rad)} y2={cy + 115 * Math.sin(rad)}
              stroke={COLORS.border} strokeWidth="0.5" opacity="0.15" />
          );
        })}

        {/* Connection lines + animated particles */}
        {hostPositions.map(h => {
          const isSkipped = h.status === 'skipped';
          const isActive = h.ip === currentHost;
          const lineColor = isSkipped ? COLORS.grayDim
            : isActive ? COLORS.amber
            : COLORS.border;

          return (
            <g key={`conn-${h.ip}`}>
              {/* Connection line */}
              <line x1={cx} y1={cy} x2={h.x} y2={h.y}
                stroke={lineColor} strokeWidth={isActive ? 1.5 : 1}
                strokeDasharray={isSkipped ? '4,4' : undefined}
                opacity={isSkipped ? 0.3 : 0.5} />

              {/* Data particles traveling along line — only for non-skipped */}
              {!isSkipped && (
                <>
                  <circle r="1.5" fill={isActive ? COLORS.amber : COLORS.cyan} opacity="0.8" filter="url(#glow)">
                    <animateMotion dur={isActive ? '1.5s' : '2.5s'} repeatCount="indefinite"
                      path={`M${cx},${cy} L${h.x},${h.y}`} />
                  </circle>
                  {isActive && (
                    <circle r="1" fill={COLORS.amber} opacity="0.5">
                      <animateMotion dur="1.5s" repeatCount="indefinite" begin="0.7s"
                        path={`M${cx},${cy} L${h.x},${h.y}`} />
                    </circle>
                  )}
                </>
              )}
            </g>
          );
        })}

        {/* Center domain node */}
        <circle cx={cx} cy={cy} r={9} fill={COLORS.cyan} opacity="0.9" filter="url(#glow)">
          <animate attributeName="r" values="8;10;8" dur="2s" repeatCount="indefinite" />
        </circle>
        <circle cx={cx} cy={cy} r={16} fill="none" stroke={COLORS.cyan} strokeWidth="0.5" opacity="0.3">
          <animate attributeName="r" values="14;20;14" dur="3s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.3;0.08;0.3" dur="3s" repeatCount="indefinite" />
        </circle>

        {/* Host nodes */}
        {hostPositions.map(h => {
          const isActive = h.ip === currentHost;
          const hasThreat = threatHosts.has(h.ip);
          const color = STATUS_COLORS[h.status] || COLORS.cyan;

          return (
            <g key={`node-${h.ip}`}>
              {/* Threat ring */}
              {hasThreat && h.status !== 'skipped' && (
                <circle cx={h.x} cy={h.y} r={14} fill="none"
                  stroke={COLORS.red} strokeWidth="1" strokeDasharray="3,3" opacity="0.5">
                  <animate attributeName="opacity" values="0.6;0.2;0.6" dur="2s" repeatCount="indefinite" />
                  <animate attributeName="r" values="13;16;13" dur="2s" repeatCount="indefinite" />
                </circle>
              )}

              {/* Active host halo */}
              {isActive && (
                <circle cx={h.x} cy={h.y} r={12} fill="none"
                  stroke={COLORS.amber} strokeWidth="1" opacity="0.3">
                  <animate attributeName="r" values="9;18;9" dur="1.5s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.4;0;0.4" dur="1.5s" repeatCount="indefinite" />
                </circle>
              )}

              {/* Host dot */}
              <circle cx={h.x} cy={h.y} r={5} fill={color}
                opacity={h.status === 'skipped' ? 0.35 : 0.85}
                filter={isActive ? 'url(#glowStrong)' : undefined}>
                {isActive && (
                  <animate attributeName="r" values="4;7;4" dur="1s" repeatCount="indefinite" />
                )}
              </circle>
            </g>
          );
        })}

        {/* Radar sweep */}
        <g style={{ transformOrigin: `${cx}px ${cy}px`, animation: 'radarSpin 4s linear infinite' }}>
          <path
            d={`M${cx},${cy} L${cx},${cy - 110} A110,110 0 0,1 ${cx + 110 * Math.sin(Math.PI / 5)},${cy - 110 * Math.cos(Math.PI / 5)} Z`}
            fill="url(#radarGrad2)" opacity="0.35" />
        </g>
      </svg>

      {/* Host FQDN labels */}
      {hostPositions.map(h => {
        const name = truncate(hostDisplayName(h), 18);
        const isActive = h.ip === currentHost;
        const color = h.status === 'skipped' ? COLORS.gray
          : isActive ? COLORS.amber
          : COLORS.cyanDim;

        return (
          <div key={`label-${h.ip}`} className="absolute font-mono whitespace-nowrap group"
            style={{
              left: h.x,
              top: h.labelBelow ? h.y + 10 : h.y - 20,
              transform: 'translateX(-50%)',
            }}>
            {/* Primary: FQDN */}
            <div className="text-[9px] text-center leading-tight"
              style={{ color, opacity: h.status === 'skipped' ? 0.5 : 1 }}>
              {name}
            </div>
            {/* Secondary: IP on hover (only if we showed FQDN) */}
            {h.fqdns.length > 0 && (
              <div className="text-[8px] text-center leading-tight opacity-0 group-hover:opacity-70 transition-opacity"
                style={{ color: COLORS.gray }}>
                {h.ip}
              </div>
            )}
          </div>
        );
      })}

      {/* Center domain label */}
      <div className="absolute text-[10px] font-mono font-medium text-center"
        style={{
          left: cx, top: cy + 20, transform: 'translateX(-50%)',
          color: COLORS.cyan,
          textShadow: `0 0 8px ${COLORS.cyanGlow}`,
        }}>
        {truncate(domain, 20)}
      </div>

      <style jsx>{`
        @keyframes radarSpin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
