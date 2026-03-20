'use client';

import { useEffect, useState } from 'react';

const SCRAMBLE_CHARS = '█▓▒░╔╗╚╝║═0123456789abcdef';

export interface TerminalLineData {
  id: string;
  timestamp: string;         // HH:MM:SS.mmm
  text: string;              // Main text content
  status?: 'done' | 'running' | 'error' | 'command' | 'warning' | 'system';
  detail?: string;           // Additional detail (e.g. "12 Subdomains")
  isHeader?: boolean;        // Phase headers get special styling
  isHost?: boolean;          // Host discovery lines
  indent?: number;           // Indentation level (0, 1, 2)
  hostColor?: string;        // Colored left border for parallel host tracking
  hostLabel?: string;        // Short host name for context
}

interface TerminalLineProps {
  line: TerminalLineData;
  animate?: boolean;         // Whether to animate entry
  dimmed?: boolean;          // Phosphor decay — older lines get slightly dimmer
}

export default function TerminalLine({ line, animate = true, dimmed = false }: TerminalLineProps) {
  // Phase headers skip scramble animation — they're navigation landmarks
  const skipScramble = !animate || line.isHeader;
  const [display, setDisplay] = useState(skipScramble ? line.text : '');
  const [resolved, setResolved] = useState(skipScramble);

  useEffect(() => {
    if (skipScramble) return;

    // Scramble resolve effect
    const target = line.text;
    const startTime = Date.now();
    const duration = Math.min(target.length * 8, 300);

    const interval = setInterval(() => {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const resolvedCount = Math.floor(progress * target.length);

      const result = target.split('').map((char, i) => {
        if (i < resolvedCount) return char;
        if (char === ' ') return ' ';
        return SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)];
      }).join('');

      setDisplay(result);

      if (progress >= 1) {
        clearInterval(interval);
        setDisplay(target);
        setResolved(true);
      }
    }, 25);

    return () => clearInterval(interval);
  }, [skipScramble, line.text]);

  const indent = '  '.repeat(line.indent || 0);
  const statusIcon = line.status === 'done' ? '✓'
    : line.status === 'error' ? '✗'
    : line.status === 'warning' ? '⚠'
    : '';
  const statusColor = line.status === 'done'
    ? 'text-green-500'
    : line.status === 'error'
    ? 'text-red-500'
    : line.status === 'warning'
    ? 'text-orange-400'
    : '';

  // Status-based text color
  const textColor = line.status === 'command'
    ? 'text-green-400'
    : line.status === 'warning'
    ? 'text-orange-400'
    : line.status === 'system'
    ? 'text-slate-500'
    : line.status === 'error'
    ? 'text-red-400'
    : line.isHeader
    ? 'text-[#38BDF8] font-bold'
    : line.isHost
    ? 'text-[#7DD3FC]'
    : 'text-[#38BDF8]';

  return (
    <div
      className={`${line.isHeader ? 'mt-3 mb-1' : ''} ${line.status === 'error' ? 'animate-glitch' : ''} ${line.isHeader ? 'animate-headerFlash' : ''}`}
      style={{
        borderLeft: line.hostColor ? `3px solid ${line.hostColor}` : undefined,
        paddingLeft: line.hostColor ? '6px' : undefined,
        opacity: dimmed ? 0.82 : 1,
      }}
    >
      {/* Timestamp — above content on mobile, inline on desktop */}
      <span className="text-[#4B7399] shrink-0 select-none block md:hidden text-[9px]">
        [{line.timestamp}]
      </span>
      <div className="flex items-start gap-0">
        <span className="text-[#4B7399] shrink-0 select-none hidden md:inline">
          [{line.timestamp}]
        </span>

        {/* Content */}
        <span className={`md:ml-1 ${textColor}`}>
          {indent}{display}
        </span>

        {/* Detail text */}
        {line.detail && resolved && (
          <span className="ml-1 text-[#4B7399]">{line.detail}</span>
        )}

        {/* Status icon */}
        {statusIcon && resolved && (
          <span className={`ml-2 ${statusColor} shrink-0`}>{statusIcon}</span>
        )}
      </div>
    </div>
  );
}
