'use client';

import { useEffect, useState, useRef } from 'react';

interface ToolProgressProps {
  tool: string;
  host?: string;
}

export default function ToolProgress({ tool, host }: ToolProgressProps) {
  const [frame, setFrame] = useState(0);
  const animRef = useRef<number>(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame(f => (f + 1) % 40);
    }, 100);
    return () => clearInterval(interval);
  }, []);

  // Build animated progress bar from block chars
  const barLength = 30;
  const bar = Array.from({ length: barLength }, (_, i) => {
    const pos = (frame + i) % barLength;
    // Create a wave pattern
    const wave = Math.sin((pos / barLength) * Math.PI * 2) * 0.5 + 0.5;
    if (wave > 0.7) return '█';
    if (wave > 0.4) return '▓';
    if (wave > 0.2) return '▒';
    return '░';
  }).join('');

  const targetLabel = host ? `${tool} ${host}` : tool;
  // Pad with dots
  const dots = '.'.repeat(Math.max(2, 40 - targetLabel.length));

  return (
    <div className="flex items-start gap-0">
      <span className="text-[#4B7399] shrink-0 select-none">
        [{new Date().toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}]
      </span>
      <span className="ml-1 text-[#38BDF8]">
        {'  '}{targetLabel} <span className="text-[#1E3A5F]">{dots}</span>{' '}
      </span>
      <span className="text-[#38BDF8] opacity-60 shrink-0">
        {bar}
      </span>
      <span className="ml-1 text-[#4B7399] text-xs">
        (scanning...)
      </span>
    </div>
  );
}
