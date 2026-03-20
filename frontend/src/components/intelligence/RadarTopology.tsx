'use client';

import { useMemo, useState, useEffect } from 'react';
import { COLORS, STATUS_COLORS, hostDisplayName, truncate } from './constants';
import type { HostNode, ToolOutputEntry } from './constants';

const HEX = '0123456789ABCDEF';
function rHex(n: number) { let s = ''; for (let i = 0; i < n; i++) s += HEX[Math.floor(Math.random() * 16)]; return s; }

interface RadarTopologyProps {
  domain: string;
  hosts: HostNode[];
  currentHost: string | null;
  toolOutputs: ToolOutputEntry[];
  /** Map of host IP to assigned lane color from parallel scanning. */
  hostColorMap?: Record<string, string>;
  /** IP of host where a threat was just found — triggers expanding red rings. */
  threatHost?: string;
  /** When true, pulse the center domain node (AI decision event). */
  aiPulse?: boolean;
}

export default function RadarTopology({ domain, hosts, currentHost, toolOutputs, hostColorMap, threatHost, aiPulse }: RadarTopologyProps) {
  const size = 210;
  const cx = size / 2;
  const cy = size / 2;
  const radius = 80;

  // Rotating hex coordinates in corners
  const [hexCorners, setHexCorners] = useState(['0000', '0000', '0000', '0000']);
  useEffect(() => {
    const iv = setInterval(() => setHexCorners([rHex(4), rHex(4), rHex(4), rHex(4)]), 2000);
    return () => clearInterval(iv);
  }, []);

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
    <div className="relative" style={{ width: size, height: size + 16, margin: '0 auto' }}>
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

        {/* Hex corner coordinates */}
        {[[6, 8], [size - 6, 8], [6, size - 4], [size - 6, size - 4]].map(([hx, hy], i) => (
          <text key={`hex-${i}`} x={hx} y={hy} fill={COLORS.grayDim} fontSize="7"
            fontFamily="monospace" textAnchor={i % 2 === 0 ? 'start' : 'end'}>
            0x{hexCorners[i]}
          </text>
        ))}

        {/* Grid circles — 4 rings with pulse on outer */}
        {[25, 45, 65, 85].map((r, i) => (
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
              x1={cx - 90 * Math.cos(rad)} y1={cy - 90 * Math.sin(rad)}
              x2={cx + 90 * Math.cos(rad)} y2={cy + 90 * Math.sin(rad)}
              stroke={COLORS.border} strokeWidth="0.5" opacity="0.15" />
          );
        })}

        {/* Connection lines + animated particles */}
        {hostPositions.map(h => {
          const isSkipped = h.status === 'skipped';
          const isActive = h.ip === currentHost;
          const laneColor = hostColorMap?.[h.ip];
          const lineColor = isSkipped ? COLORS.grayDim
            : laneColor || (isActive ? COLORS.amber : COLORS.border);
          const particleColor = laneColor || (isActive ? COLORS.amber : COLORS.cyan);

          return (
            <g key={`conn-${h.ip}`}>
              {/* Connection line */}
              <line x1={cx} y1={cy} x2={h.x} y2={h.y}
                stroke={lineColor} strokeWidth={isActive ? 1.5 : 1}
                strokeDasharray={isSkipped ? '4,4' : undefined}
                opacity={isSkipped ? 0.3 : 0.6} />

              {/* Data particles traveling along line — only for non-skipped */}
              {!isSkipped && (
                <>
                  <circle r="1.5" fill={particleColor} opacity="0.8" filter="url(#glow)">
                    <animateMotion dur={isActive ? '1.5s' : '2.5s'} repeatCount="indefinite"
                      path={`M${cx},${cy} L${h.x},${h.y}`} />
                  </circle>
                  {isActive && (
                    <circle r="1" fill={particleColor} opacity="0.5">
                      <animateMotion dur="1.5s" repeatCount="indefinite" begin="0.7s"
                        path={`M${cx},${cy} L${h.x},${h.y}`} />
                    </circle>
                  )}
                </>
              )}
            </g>
          );
        })}

        {/* Center domain node — with AI pulse */}
        <circle cx={cx} cy={cy} r={aiPulse ? 14 : 9} fill={COLORS.cyan} opacity="0.9" filter="url(#glow)"
          style={{ transition: 'r 0.3s ease-out' }}>
          <animate attributeName="r" values={aiPulse ? '12;14;12' : '8;10;8'} dur="2s" repeatCount="indefinite" />
        </circle>
        <circle cx={cx} cy={cy} r={16} fill="none" stroke={COLORS.cyan} strokeWidth="0.5" opacity="0.3">
          <animate attributeName="r" values="14;20;14" dur="3s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.3;0.08;0.3" dur="3s" repeatCount="indefinite" />
        </circle>
        {aiPulse && (
          <circle cx={cx} cy={cy} r={14} fill="none" stroke="#A78BFA" strokeWidth="1" opacity="0">
            <animate attributeName="r" values="14;30;40" dur="1s" fill="freeze" />
            <animate attributeName="opacity" values="0.6;0.3;0" dur="1s" fill="freeze" />
          </circle>
        )}

        {/* Host nodes */}
        {hostPositions.map(h => {
          const isActive = h.ip === currentHost;
          const hasThreat = threatHosts.has(h.ip);
          const laneColor = hostColorMap?.[h.ip];
          // Use lane color if assigned, otherwise fall back to status color
          const dotColor = h.status === 'skipped' ? COLORS.gray
            : h.status === 'scanned' ? COLORS.green
            : laneColor || STATUS_COLORS[h.status] || COLORS.cyan;
          const haloColor = laneColor || COLORS.amber;

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

              {/* Active host halo — uses lane color */}
              {isActive && (
                <circle cx={h.x} cy={h.y} r={12} fill="none"
                  stroke={haloColor} strokeWidth="1" opacity="0.3">
                  <animate attributeName="r" values="9;18;9" dur="1.5s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.4;0;0.4" dur="1.5s" repeatCount="indefinite" />
                </circle>
              )}

              {/* Host dot — uses lane color */}
              <circle cx={h.x} cy={h.y} r={5} fill={dotColor}
                opacity={h.status === 'skipped' ? 0.35 : 0.85}
                filter={isActive ? 'url(#glowStrong)' : undefined}>
                {isActive && (
                  <animate attributeName="r" values="4;7;4" dur="1s" repeatCount="indefinite" />
                )}
              </circle>

              {/* Lock-on reticle for active host */}
              {h.ip === currentHost && (
                <g>
                  <rect x={h.x-12} y={h.y-12} width={24} height={24}
                        fill="none" stroke={dotColor} strokeWidth="0.5" opacity="0.7"
                        style={{ transformOrigin: `${h.x}px ${h.y}px`, animation: 'lockOnSpin 0.8s ease-out forwards' }} />
                  <rect x={h.x-8} y={h.y-8} width={16} height={16}
                        fill="none" stroke={dotColor} strokeWidth="0.3" opacity="0.5"
                        style={{ transformOrigin: `${h.x}px ${h.y}px`, animation: 'lockOnSpin 0.8s 0.1s ease-out forwards' }} />
                </g>
              )}

              {/* Vulnerability strike rings */}
              {threatHost && h.ip === threatHost && (
                <g>
                  {[0, 0.2, 0.4].map((delay, i) => (
                    <circle key={i} cx={h.x} cy={h.y} r={5} fill="none" stroke="#EF4444" strokeWidth="1.5"
                            opacity="0" style={{ animation: `vulnRing 1.5s ${delay}s ease-out forwards` }} />
                  ))}
                </g>
              )}
            </g>
          );
        })}

        {/* Radar sweep */}
        <g style={{ transformOrigin: `${cx}px ${cy}px`, animation: 'radarSpin 4s linear infinite' }}>
          <path
            d={`M${cx},${cy} L${cx},${cy - 85} A110,110 0 0,1 ${cx + 85 * Math.sin(Math.PI / 5)},${cy - 85 * Math.cos(Math.PI / 5)} Z`}
            fill="url(#radarGrad2)" opacity="0.35" />
        </g>
      </svg>

      {/* Host FQDN labels */}
      {hostPositions.map(h => {
        const name = truncate(hostDisplayName(h), 18);
        const isActive = h.ip === currentHost;
        const laneColor = hostColorMap?.[h.ip];
        const color = h.status === 'skipped' ? COLORS.gray
          : laneColor || (isActive ? COLORS.amber : COLORS.cyanDim);

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
