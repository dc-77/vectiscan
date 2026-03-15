'use client';

import { useState, useEffect, useRef, useMemo } from 'react';
import type { AiStrategy, AiConfig } from '@/hooks/useWebSocket';

// ─── Types ──────────────────────────────────────────────

interface HostNode {
  ip: string;
  fqdns: string[];
  status: 'discovered' | 'scanning' | 'scanned' | 'skipped';
  reasoning?: string;
}

interface ToolOutputEntry {
  tool: string;
  host: string;
  summary: string;
  ts: number;
}

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

// ─── Data Stream Generator ──────────────────────────────

const HEX_CHARS = '0123456789ABCDEF';
const PROTOCOLS = ['TCP', 'UDP', 'TLS', 'HTTPS', 'DNS', 'SMTP', 'SSH'];
const FRAGMENTS = [
  'SYN/ACK seq=', 'GET / HTTP/1.1', 'RSA-2048 SHA256:', 'TLS_AES_256_GCM',
  'X-Frame-Options:', 'Content-Security-Policy:', 'Server: nginx/',
  'Set-Cookie: PHPSESSID=', 'Location: /admin', 'WWW-Authenticate:',
  'SSH-2.0-OpenSSH_', 'EHLO smtp.', 'STARTTLS', '220 mail.',
  'nuclei:matched ', 'CVE-20', 'CVSS:3.1/AV:N/', 'wp-login.php',
  'robots.txt', 'sitemap.xml', '.git/config', '/api/v1/',
];

function randomHex(len: number): string {
  let s = '';
  for (let i = 0; i < len; i++) s += HEX_CHARS[Math.floor(Math.random() * 16)];
  return s;
}

function generateDataLine(realSnippets: string[]): string {
  const r = Math.random();
  if (r < 0.3 && realSnippets.length > 0) {
    return realSnippets[Math.floor(Math.random() * realSnippets.length)];
  }
  if (r < 0.6) {
    const proto = PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)];
    const port = [22, 80, 443, 3306, 8080, 8443, 25, 587][Math.floor(Math.random() * 8)];
    return `${proto}:${port} \u2550\u2550\u2550 0x${randomHex(8)}`;
  }
  return FRAGMENTS[Math.floor(Math.random() * FRAGMENTS.length)] + randomHex(6);
}

// ─── Radar Component ────────────────────────────────────

function RadarTopology({ domain, hosts, currentHost }: {
  domain: string;
  hosts: HostNode[];
  currentHost: string | null;
}) {
  const size = 220;
  const cx = size / 2;
  const cy = size / 2;
  const radius = 80;

  const hostPositions = useMemo(() => {
    return hosts.map((h, i) => {
      const angle = (i / Math.max(hosts.length, 1)) * 2 * Math.PI - Math.PI / 2;
      return {
        ...h,
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
      };
    });
  }, [hosts, cx, cy]);

  return (
    <div className="relative" style={{ width: size, height: size, margin: '0 auto' }}>
      {/* Grid background */}
      <svg width={size} height={size} className="absolute inset-0">
        {/* Grid circles */}
        {[30, 60, 90].map(r => (
          <circle key={r} cx={cx} cy={cy} r={r} fill="none" stroke="#1E3A5F" strokeWidth="0.5" opacity="0.3" />
        ))}
        {/* Grid lines */}
        {[0, 45, 90, 135].map(deg => {
          const rad = (deg * Math.PI) / 180;
          return (
            <line key={deg} x1={cx - 95 * Math.cos(rad)} y1={cy - 95 * Math.sin(rad)}
              x2={cx + 95 * Math.cos(rad)} y2={cy + 95 * Math.sin(rad)}
              stroke="#1E3A5F" strokeWidth="0.5" opacity="0.2" />
          );
        })}

        {/* Connection lines */}
        {hostPositions.map(h => (
          <line key={`line-${h.ip}`} x1={cx} y1={cy} x2={h.x} y2={h.y}
            stroke={h.status === 'skipped' ? '#475569' : '#1E3A5F'}
            strokeWidth="1" strokeDasharray={h.status === 'skipped' ? '4,4' : undefined}
            opacity="0.5" />
        ))}

        {/* Center domain node */}
        <circle cx={cx} cy={cy} r={8} fill="#38BDF8" opacity="0.9">
          <animate attributeName="r" values="7;9;7" dur="2s" repeatCount="indefinite" />
        </circle>
        <circle cx={cx} cy={cy} r={14} fill="none" stroke="#38BDF8" strokeWidth="0.5" opacity="0.4">
          <animate attributeName="r" values="12;18;12" dur="3s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.4;0.1;0.4" dur="3s" repeatCount="indefinite" />
        </circle>

        {/* Host nodes */}
        {hostPositions.map(h => {
          const isActive = h.ip === currentHost;
          const color = h.status === 'skipped' ? '#64748B'
            : h.status === 'scanned' ? '#16A34A'
            : isActive ? '#EAB308'
            : '#38BDF8';

          return (
            <g key={h.ip}>
              <circle cx={h.x} cy={h.y} r={5} fill={color} opacity={h.status === 'skipped' ? 0.4 : 0.8}>
                {isActive && <animate attributeName="r" values="4;7;4" dur="1s" repeatCount="indefinite" />}
              </circle>
              {isActive && (
                <circle cx={h.x} cy={h.y} r={12} fill="none" stroke={color} strokeWidth="1" opacity="0.3">
                  <animate attributeName="r" values="8;16;8" dur="1.5s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.4;0;0.4" dur="1.5s" repeatCount="indefinite" />
                </circle>
              )}
            </g>
          );
        })}

        {/* Radar sweep */}
        <g style={{ transformOrigin: `${cx}px ${cy}px`, animation: 'spin 4s linear infinite' }}>
          <path d={`M${cx},${cy} L${cx},${cy - 90} A90,90 0 0,1 ${cx + 90 * Math.sin(Math.PI / 6)},${cy - 90 * Math.cos(Math.PI / 6)} Z`}
            fill="url(#radarGrad)" opacity="0.3" />
        </g>
        <defs>
          <radialGradient id="radarGrad" cx="0%" cy="0%">
            <stop offset="0%" stopColor="#38BDF8" stopOpacity="0.4" />
            <stop offset="100%" stopColor="#38BDF8" stopOpacity="0" />
          </radialGradient>
        </defs>
      </svg>

      {/* Host labels */}
      {hostPositions.map(h => (
        <div key={`label-${h.ip}`} className="absolute text-[9px] font-mono whitespace-nowrap"
          style={{
            left: h.x, top: h.y + 10,
            transform: 'translateX(-50%)',
            color: h.status === 'skipped' ? '#64748B' : h.ip === currentHost ? '#EAB308' : '#7DD3FC',
            opacity: h.status === 'skipped' ? 0.5 : 1,
          }}>
          {h.ip}
        </div>
      ))}

      {/* Center label */}
      <div className="absolute text-[10px] font-mono text-cyan-400 font-medium"
        style={{ left: cx, top: cy + 18, transform: 'translateX(-50%)' }}>
        {domain.length > 18 ? domain.slice(0, 16) + '..' : domain}
      </div>

      <style jsx>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}

// ─── Data Stream Component ──────────────────────────────

function DataStream({ toolOutputs }: { toolOutputs: ToolOutputEntry[] }) {
  const [lines, setLines] = useState<string[]>([]);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const snippets = toolOutputs.map(t => `${t.tool}: ${t.summary}`);
    const interval = setInterval(() => {
      setLines(prev => {
        const next = [...prev, generateDataLine(snippets)];
        return next.length > 30 ? next.slice(-30) : next;
      });
    }, 400);
    return () => clearInterval(interval);
  }, [toolOutputs]);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [lines]);

  return (
    <div ref={containerRef}
      className="h-32 overflow-hidden font-mono text-[10px] leading-relaxed text-green-500/30 select-none"
      style={{ maskImage: 'linear-gradient(to bottom, transparent, black 20%, black 80%, transparent)' }}>
      {lines.map((line, i) => (
        <div key={i} className="truncate">{line}</div>
      ))}
    </div>
  );
}

// ─── Main Component ─────────────────────────────────────

export default function ScanIntelligence({
  domain, hosts, currentHost, currentTool, currentPhase,
  aiStrategy, aiConfigs, toolOutputs,
}: ScanIntelligenceProps) {
  const activeConfig = currentHost ? aiConfigs[currentHost] : null;

  return (
    <div className="space-y-3 h-full">
      {/* Scanlines overlay container */}
      <div className="relative rounded-lg border border-gray-800 bg-[#0a0f1e] overflow-hidden"
        style={{
          backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(56,189,248,0.02) 2px, rgba(56,189,248,0.02) 4px)',
          boxShadow: '0 0 30px rgba(56,189,248,0.08), inset 0 0 30px rgba(0,0,0,0.3)',
        }}>

        {/* Header */}
        <div className="flex items-center justify-between px-3 py-1.5 border-b border-gray-800/50 bg-[#0f172a]/80">
          <span className="text-[10px] font-mono text-cyan-400/70 uppercase tracking-widest">Scan Intelligence</span>
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
            <span className="text-[9px] font-mono text-gray-600">LIVE</span>
          </div>
        </div>

        {/* Radar Topology */}
        <div className="py-2">
          <RadarTopology domain={domain} hosts={hosts} currentHost={currentHost} />
        </div>

        {/* AI Strategy Summary (when available) */}
        {aiStrategy && (
          <div className="mx-3 mb-2 rounded border border-amber-500/20 bg-amber-500/5 px-2.5 py-2">
            <div className="text-[10px] font-mono text-amber-400 font-medium mb-1">
              AI STRATEGY
            </div>
            <div className="text-[10px] text-gray-400">
              {aiStrategy.hosts.filter(h => h.action === 'scan').length} scan,{' '}
              {aiStrategy.hosts.filter(h => h.action === 'skip').length} skip
              {aiStrategy.strategy_notes && (
                <span className="text-gray-600"> — {aiStrategy.strategy_notes}</span>
              )}
            </div>
          </div>
        )}

        {/* Live Metrics */}
        <div className="grid grid-cols-2 gap-1.5 px-3 pb-2">
          <div className="bg-[#0f172a] rounded px-2 py-1.5 border border-gray-800/30">
            <div className="text-[9px] text-gray-600 uppercase">Phase</div>
            <div className="text-xs font-mono text-cyan-400">
              {currentPhase === 'dns_recon' ? 'DNS Recon' :
               currentPhase === 'scan_phase1' ? 'Tech Detect' :
               currentPhase === 'scan_phase2' ? 'Deep Scan' :
               currentPhase || '—'}
            </div>
          </div>
          <div className="bg-[#0f172a] rounded px-2 py-1.5 border border-gray-800/30">
            <div className="text-[9px] text-gray-600 uppercase">Tool</div>
            <div className="text-xs font-mono text-amber-400 truncate">{currentTool || '—'}</div>
          </div>
          <div className="bg-[#0f172a] rounded px-2 py-1.5 border border-gray-800/30">
            <div className="text-[9px] text-gray-600 uppercase">Host</div>
            <div className="text-xs font-mono text-white truncate">{currentHost || '—'}</div>
          </div>
          <div className="bg-[#0f172a] rounded px-2 py-1.5 border border-gray-800/30">
            <div className="text-[9px] text-gray-600 uppercase">Hosts</div>
            <div className="text-xs font-mono text-white">
              {hosts.filter(h => h.status === 'scanned').length}/{hosts.length}
            </div>
          </div>
        </div>

        {/* Active AI Config */}
        {activeConfig && (
          <div className="mx-3 mb-2 rounded border border-amber-500/20 bg-amber-500/5 px-2.5 py-2">
            <div className="text-[10px] font-mono text-amber-400 font-medium mb-1">
              AI CONFIG — {currentHost}
            </div>
            {activeConfig.nuclei_tags && activeConfig.nuclei_tags.length > 0 && (
              <div className="text-[10px] text-gray-400">
                nuclei: <span className="text-cyan-400">{activeConfig.nuclei_tags.join(', ')}</span>
              </div>
            )}
            {activeConfig.gobuster_wordlist && activeConfig.gobuster_wordlist !== 'common' && (
              <div className="text-[10px] text-gray-400">
                wordlist: <span className="text-cyan-400">{activeConfig.gobuster_wordlist}</span>
              </div>
            )}
            {activeConfig.skip_tools && activeConfig.skip_tools.length > 0 && (
              <div className="text-[10px] text-gray-400">
                skip: <span className="text-red-400">{activeConfig.skip_tools.join(', ')}</span>
              </div>
            )}
          </div>
        )}

        {/* Data Stream */}
        <div className="px-3 pb-2">
          <DataStream toolOutputs={toolOutputs} />
        </div>
      </div>
    </div>
  );
}

export type { HostNode, ToolOutputEntry };
