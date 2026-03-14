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
];

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

export default function ToolProgress({ tool, host }: ToolProgressProps) {
  const [frame, setFrame] = useState(0);
  const [elapsed, setElapsed] = useState(0);
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
    }, 80);
    return () => clearInterval(interval);
  }, []);

  const spinner = SPINNER_FRAMES[frame % SPINNER_FRAMES.length];

  // Cycling data fragment
  const fragmentIdx = Math.floor(frame / 12) % DATA_FRAGMENTS.length;
  const fragment = DATA_FRAGMENTS[fragmentIdx];

  // Glitch bar — random hex bytes that shift
  const glitchBar = useMemo(() => {
    const seed = frame;
    const chars: string[] = [];
    for (let i = 0; i < 20; i++) {
      const v = ((seed * 7 + i * 13) % 256);
      // Some positions show bright, others dim
      const bright = ((seed + i) % 5) === 0;
      chars.push(bright ? v.toString(16).padStart(2, '0').toUpperCase() : '··');
    }
    return chars.join(' ');
  }, [frame]);

  const targetLabel = host ? `${tool} → ${host}` : tool;
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
          <span className="text-[#38BDF8] font-bold">{targetLabel}</span>
          {elapsedStr && (
            <span className="text-[#1E3A5F] ml-2">{elapsedStr}</span>
          )}
        </span>
      </div>

      {/* Data stream line — scrolling hex with fragment highlight */}
      <div className="flex items-start gap-0 overflow-hidden">
        <span className="text-[#4B7399] shrink-0 select-none invisible">
          [00:00:00]
        </span>
        <span className="ml-1 text-[#0E3B5C] select-none whitespace-nowrap" style={{ fontSize: '0.65rem' }}>
          {'   '}
          <span className="text-[#1E3A5F]">{glitchBar.slice(0, 30)}</span>
          {' '}
          <span className="text-[#38BDF8] opacity-70">{fragment}</span>
          {' '}
          <span className="text-[#1E3A5F]">{glitchBar.slice(30)}</span>
        </span>
      </div>
    </div>
  );
}
