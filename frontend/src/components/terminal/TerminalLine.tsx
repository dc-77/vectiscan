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
}

interface TerminalLineProps {
  line: TerminalLineData;
  animate?: boolean;         // Whether to animate entry
}

export default function TerminalLine({ line, animate = true }: TerminalLineProps) {
  const [display, setDisplay] = useState(animate ? '' : line.text);
  const [resolved, setResolved] = useState(!animate);

  useEffect(() => {
    if (!animate) return;

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
  }, [animate, line.text]);

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

  // Command prefix for command-style lines
  const prefix = line.status === 'command' ? '$ ' : '';

  return (
    <div className={`flex items-start gap-0 ${line.isHeader ? 'mt-3 mb-1' : ''} ${line.status === 'error' ? 'animate-glitch' : ''}`}>
      {/* Timestamp */}
      <span className="text-[#4B7399] shrink-0 select-none">
        [{line.timestamp}]
      </span>

      {/* Content */}
      <span className={`ml-1 ${textColor}`}>
        {indent}{prefix}{display}
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
  );
}
