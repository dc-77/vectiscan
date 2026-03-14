'use client';

import { useEffect, useRef } from 'react';
import TerminalLine from './TerminalLine';
import ToolProgress from './ToolProgress';

import type { TerminalLine as TerminalLineData } from './useTerminalFeed';

interface ScanTerminalProps {
  lines: TerminalLineData[];
  currentTool: string | null;
  currentHost: string | null;
  isScanning: boolean;
  isComplete: boolean;
  isError: boolean;
}

export default function ScanTerminal({
  lines,
  currentTool,
  currentHost,
  isScanning,
  isComplete,
  isError,
}: ScanTerminalProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom on new lines
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [lines.length]);

  // Border glow when actively scanning
  const borderClass = isScanning
    ? 'border-[#1E3A5F] shadow-[0_0_15px_rgba(56,189,248,0.15)]'
    : isError
    ? 'border-red-900/50'
    : isComplete
    ? 'border-green-900/50'
    : 'border-[#1E3A5F]';

  return (
    <div
      className={`relative w-full max-w-4xl mx-auto rounded-lg border ${borderClass} transition-all duration-500`}
      style={{ backgroundColor: 'rgba(12, 18, 34, 0.95)' }}
    >
      {/* Title bar — terminal dots */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-[#1E3A5F]">
        <span className="w-3 h-3 rounded-full bg-red-500/70" />
        <span className="w-3 h-3 rounded-full bg-yellow-500/70" />
        <span className="w-3 h-3 rounded-full bg-green-500/70" />
        <span className="ml-3 text-[#4B7399] text-xs font-mono select-none">
          VectiScan Terminal
        </span>
      </div>

      {/* Terminal content */}
      <div
        ref={scrollRef}
        className="p-4 overflow-y-auto font-mono text-sm leading-relaxed"
        style={{
          fontFamily: "'Fira Mono', 'Consolas', 'Liberation Mono', monospace",
          maxHeight: '500px',
          minHeight: '300px',
          // Custom scrollbar
          scrollbarWidth: 'thin',
          scrollbarColor: '#1E3A5F #0C1222',
        }}
      >
        {lines.map((line, i) => (
          <TerminalLine
            key={line.id}
            line={line}
            animate={i >= lines.length - 5} // Only animate last 5 lines
          />
        ))}

        {/* Show animated progress for current tool */}
        {isScanning && currentTool && (
          <ToolProgress tool={currentTool} host={currentHost || undefined} />
        )}

        {/* Blinking cursor */}
        {isScanning && (
          <div className="mt-1">
            <span className="text-[#38BDF8] animate-pulse">▌</span>
          </div>
        )}
      </div>

      {/* Status bar */}
      <div className="flex items-center gap-3 px-4 py-2 border-t border-[#1E3A5F] text-xs font-mono">
        <span className={`w-2 h-2 rounded-full ${
          isScanning ? 'bg-[#38BDF8] animate-pulse' :
          isComplete ? 'bg-green-500' :
          isError ? 'bg-red-500' :
          'bg-[#4B7399]'
        }`} />
        <span className="text-[#4B7399]">
          {isScanning ? 'Scanning...' :
           isComplete ? 'Complete' :
           isError ? 'Error' :
           'Ready'}
        </span>
        <span className="ml-auto text-[#1E3A5F]">
          {lines.length} lines
        </span>
      </div>
    </div>
  );
}
