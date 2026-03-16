'use client';

import { useState, useEffect, useRef } from 'react';
import { COLORS, TIMING } from './constants';
import type { ToolOutputEntry } from './constants';

// ─── Data Generation ───────────────────────────────────
const HEX_CHARS = '0123456789ABCDEF';
const PROTOCOLS = ['TCP', 'UDP', 'TLS', 'HTTPS', 'DNS', 'SMTP', 'SSH', 'ICMP'];
const FRAGMENTS = [
  'SYN/ACK seq=', 'GET / HTTP/1.1', 'RSA-2048 SHA256:', 'TLS_AES_256_GCM',
  'X-Frame-Options:', 'Content-Security-Policy:', 'Server: nginx/',
  'Set-Cookie: PHPSESSID=', 'Location: /admin', 'WWW-Authenticate:',
  'SSH-2.0-OpenSSH_', 'EHLO smtp.', 'STARTTLS', '220 mail.',
  'nuclei:matched ', 'CVE-20', 'CVSS:3.1/AV:N/', 'wp-login.php',
  'robots.txt', 'sitemap.xml', '.git/config', '/api/v1/',
  'X-Powered-By:', 'Strict-Transport-Security:', 'Access-Control-',
];

const BURST_LINES = [
  '>>> NUCLEI MATCH: CVE-2024-{HEX} [critical] <<<',
  '!!! SSL CERT EXPIRED — {HEX} !!!',
  '>>> OPEN REDIRECT: /login?next={HEX} <<<',
  '!!! EXPOSED .env — DB_PASSWORD={HEX} !!!',
  '>>> XSS REFLECTED: <script>{HEX}</script> <<<',
  '!!! DIRECTORY LISTING ENABLED: /backup/ !!!',
  '>>> SQL INJECTION: id=1 OR 1=1-- {HEX} <<<',
];

function randomHex(len: number): string {
  let s = '';
  for (let i = 0; i < len; i++) s += HEX_CHARS[Math.floor(Math.random() * 16)];
  return s;
}

function generateLine(snippets: string[]): string {
  const r = Math.random();
  if (r < 0.3 && snippets.length > 0) {
    return snippets[Math.floor(Math.random() * snippets.length)];
  }
  if (r < 0.6) {
    const proto = PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)];
    const port = [22, 80, 443, 3306, 8080, 8443, 25, 587, 9200, 6379][Math.floor(Math.random() * 10)];
    return `${proto}:${port} \u2550\u2550\u2550 0x${randomHex(8)}`;
  }
  return FRAGMENTS[Math.floor(Math.random() * FRAGMENTS.length)] + randomHex(6);
}

function generateBurstLine(snippets: string[]): string {
  // 50% chance to use a real tool output if available
  if (Math.random() < 0.5 && snippets.length > 0) {
    return `>>> ${snippets[Math.floor(Math.random() * snippets.length)]} <<<`;
  }
  const template = BURST_LINES[Math.floor(Math.random() * BURST_LINES.length)];
  return template.replace('{HEX}', randomHex(6));
}

// ─── Component ─────────────────────────────────────────

interface DataStreamLine {
  text: string;
  isBurst: boolean;
  age: number; // tick when created
}

interface DataStreamProps {
  toolOutputs: ToolOutputEntry[];
  currentTool: string | null;
}

export default function DataStream({ toolOutputs, currentTool }: DataStreamProps) {
  const [lines, setLines] = useState<DataStreamLine[]>([]);
  const [glitch, setGlitch] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const tickRef = useRef(0);
  const prevToolRef = useRef<string | null>(null);
  const burstModeRef = useRef(false);
  const burstTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Detect tool change → burst mode + glitch
  useEffect(() => {
    if (currentTool && currentTool !== prevToolRef.current && prevToolRef.current !== null) {
      burstModeRef.current = true;
      setGlitch(true);

      // End glitch after 150ms
      setTimeout(() => setGlitch(false), TIMING.glitchDuration);

      // End burst mode after 2s
      if (burstTimerRef.current) clearTimeout(burstTimerRef.current);
      burstTimerRef.current = setTimeout(() => {
        burstModeRef.current = false;
      }, TIMING.burstCooldown);
    }
    prevToolRef.current = currentTool;
  }, [currentTool]);

  // Main data stream loop
  useEffect(() => {
    const snippets = toolOutputs.map(t => `${t.tool}: ${t.summary}`);

    const tick = () => {
      tickRef.current++;
      const isBurst = Math.random() < TIMING.burstProbability || burstModeRef.current;
      const text = isBurst ? generateBurstLine(snippets) : generateLine(snippets);

      setLines(prev => {
        const next = [...prev, { text, isBurst, age: tickRef.current }];
        return next.length > 35 ? next.slice(-35) : next;
      });
    };

    const interval = setInterval(tick,
      burstModeRef.current ? TIMING.dataStreamBurstInterval : TIMING.dataStreamInterval
    );
    return () => clearInterval(interval);
  }, [toolOutputs]);

  // Auto-scroll
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [lines]);

  return (
    <div className="mx-3 mb-2">
      <div className="flex items-center gap-1.5 mb-1">
        <span className="text-[9px] font-mono uppercase tracking-widest" style={{ color: COLORS.green }}>
          Data Stream
        </span>
        <span className="flex-1 h-px" style={{ background: `linear-gradient(to right, ${COLORS.green}40, transparent)` }} />
        <span className="text-[8px] font-mono animate-pulse" style={{ color: COLORS.green }}>
          {'\u25CF'} RECV
        </span>
      </div>

      <div ref={containerRef}
        className={`overflow-hidden font-mono text-[10px] leading-relaxed select-none rounded border transition-all ${glitch ? 'glitch-border' : ''}`}
        style={{
          height: 100,
          borderColor: glitch ? COLORS.red : COLORS.borderDim,
          background: `${COLORS.base}80`,
          maskImage: 'linear-gradient(to bottom, transparent, black 10%, black 90%, transparent)',
          transform: glitch ? `translateX(${Math.random() > 0.5 ? 1 : -1}px)` : undefined,
        }}>
        {lines.map((line, i) => (
          <div key={i} className={`truncate px-2 ${line.isBurst ? 'data-burst' : ''}`}
            style={{
              color: line.isBurst ? COLORS.cyan : 'rgba(34,197,94,0.3)',
              textShadow: line.isBurst ? `0 0 8px ${COLORS.cyanGlow}` : undefined,
              fontWeight: line.isBurst ? 600 : 400,
            }}>
            {line.text}
          </div>
        ))}
      </div>

      <style jsx>{`
        @keyframes glitchBorder {
          0%   { border-color: ${COLORS.cyan}; transform: translateX(-1px); }
          33%  { border-color: ${COLORS.red}; transform: translateX(2px); }
          66%  { border-color: ${COLORS.amber}; transform: translateX(-1px); }
          100% { border-color: ${COLORS.borderDim}; transform: translateX(0); }
        }
        .glitch-border {
          animation: glitchBorder 150ms steps(3);
        }
        .data-burst {
          animation: burstFade 2s ease-out forwards;
        }
        @keyframes burstFade {
          0% { color: ${COLORS.cyan}; text-shadow: 0 0 10px ${COLORS.cyanGlow}; }
          100% { color: rgba(34,197,94,0.3); text-shadow: none; }
        }
      `}</style>
    </div>
  );
}
