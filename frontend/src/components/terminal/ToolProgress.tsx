'use client';

import { useEffect, useState, useRef, useMemo } from 'react';

interface ToolProgressProps {
  tool: string;
  host?: string;
}

// Hex-style data fragments that cycle through
const DATA_FRAGMENTS = [
  '0x4E554C4C', 'SYN→ACK', 'TCP:443', 'GET /', 'TLS1.3',
  'RSA-2048', 'SHA-256', 'CVE-scan', 'dns:query', 'HTTP/2',
  'cert:x509', 'PORT:open', 'SSL:check', 'hdr:parse', 'vuln:chk',
  'ECDHE', 'AES-256', 'probe:ok', '→ 200 OK', 'fin:scan',
  'CONNECT', 'handshake', 'cipher:ok', 'TLS:recv', 'ACK:sent',
  'dns:AAAA', 'PTR:query', 'HTTPS/1.1', 'X-Fwd-For', 'CSP:chk',
];

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

// Burst characters for flash effects
const BURST_CHARS = '█▓▒░▓█░▒▓█';

export default function ToolProgress({ tool, host }: ToolProgressProps) {
  const [frame, setFrame] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  const [burst, setBurst] = useState<{ pos: number; age: number } | null>(null);
  const startRef = useRef(Date.now());

  useEffect(() => {
    startRef.current = Date.now();
    setFrame(0);
    setElapsed(0);
  }, [tool, host]);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame(f => f + 1);
      setElapsed(Math.floor((Date.now() - startRef.current) / 1000));

      // Random burst — ~3% chance per tick
      if (Math.random() < 0.03) {
        setBurst({ pos: Math.floor(Math.random() * 18), age: 0 });
      }
      // Age out bursts
      setBurst(prev => {
        if (!prev) return null;
        if (prev.age >= 4) return null;
        return { ...prev, age: prev.age + 1 };
      });
    }, 80);
    return () => clearInterval(interval);
  }, []);

  const spinner = SPINNER_FRAMES[frame % SPINNER_FRAMES.length];

  // Cycling data fragment
  const fragmentIdx = Math.floor(frame / 12) % DATA_FRAGMENTS.length;
  const fragment1 = DATA_FRAGMENTS[fragmentIdx];
  const fragment2 = DATA_FRAGMENTS[(fragmentIdx + 7) % DATA_FRAGMENTS.length];

  // Glitch bar with burst support
  const glitchBar = useMemo(() => {
    const seed = frame;
    const chars: string[] = [];
    for (let i = 0; i < 20; i++) {
      const v = ((seed * 7 + i * 13) % 256);
      // Burst effect — bright flash near burst position
      if (burst && Math.abs(i - burst.pos) <= 2 - burst.age) {
        const burstChar = BURST_CHARS[Math.floor(Math.random() * BURST_CHARS.length)];
        chars.push(burstChar);
      } else {
        const bright = ((seed + i) % 5) === 0;
        chars.push(bright ? v.toString(16).padStart(2, '0').toUpperCase() : '··');
      }
    }
    return chars;
  }, [frame, burst]);

  // Display "scanning" instead of "starting"
  const displayTool = tool === 'starting' ? 'scanning' : tool;
  const targetLabel = host ? `${displayTool} → ${host}` : displayTool;
  const elapsedStr = elapsed > 0 ? `${elapsed}s` : '';

  return (
    <div className="space-y-0.5">
      {/* Main tool line with spinner */}
      <div className="flex items-start gap-0">
        <span className="text-[#4B7399] shrink-0 select-none">
          [{new Date().toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}]
        </span>
        <span className="ml-1">
          <span className="text-[#EAB308]">{spinner}</span>
          {' '}
          <span className="text-[#38BDF8] font-bold animate-tool-glow">{targetLabel}</span>
          {elapsedStr && (
            <span className="text-[#1E3A5F] ml-2">{elapsedStr}</span>
          )}
        </span>
      </div>

      {/* Data stream line — hex with bursts and dual fragments */}
      <div className="flex items-start gap-0 overflow-hidden">
        <span className="text-[#4B7399] shrink-0 select-none invisible">
          [00:00:00]
        </span>
        <span className="ml-1 select-none whitespace-nowrap" style={{ fontSize: '0.65rem' }}>
          {'   '}
          {glitchBar.slice(0, 8).map((ch, i) => (
            <span key={i} className={burst && Math.abs(i - burst.pos) <= 2 - burst.age ? 'text-[#38BDF8]' : 'text-[#1E3A5F]'}>
              {ch}{' '}
            </span>
          ))}
          <span className="text-[#38BDF8] opacity-80">{fragment1}</span>
          {' '}
          {glitchBar.slice(8, 14).map((ch, i) => (
            <span key={i + 8} className={burst && Math.abs(i + 8 - burst.pos) <= 2 - burst.age ? 'text-[#38BDF8]' : 'text-[#1E3A5F]'}>
              {ch}{' '}
            </span>
          ))}
          <span className="text-[#4B7399] opacity-60">{fragment2}</span>
          {' '}
          {glitchBar.slice(14).map((ch, i) => (
            <span key={i + 14} className={burst && Math.abs(i + 14 - burst.pos) <= 2 - burst.age ? 'text-[#38BDF8]' : 'text-[#1E3A5F]'}>
              {ch}{' '}
            </span>
          ))}
        </span>
      </div>
    </div>
  );
}
