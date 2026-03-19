'use client';

import { useEffect, useState } from 'react';
import type { HostStream } from './useTerminalFeed';

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

interface ActiveOperationsProps {
  hostStreams: Map<string, HostStream>;
}

function ActiveLane({ stream }: { stream: HostStream }) {
  const [frame, setFrame] = useState(0);
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame(f => f + 1);
      setElapsed(Math.floor((Date.now() - stream.toolStartedAt) / 1000));
    }, 80);
    return () => clearInterval(interval);
  }, [stream.toolStartedAt]);

  const spinner = SPINNER_FRAMES[frame % SPINNER_FRAMES.length];
  const hostName = stream.fqdns.length > 0 ? stream.fqdns[0] : stream.ip;
  // Truncate long hostnames
  const displayHost = hostName.length > 28 ? hostName.slice(0, 25) + '...' : hostName;
  const elapsedStr = elapsed > 0 ? `${elapsed}s` : '';

  return (
    <div
      className="flex items-center gap-2 px-2 py-0.5 font-mono text-[10px] animate-laneEntry"
      style={{ borderLeft: `3px solid ${stream.color}` }}
    >
      <span style={{ color: stream.color }}>{spinner}</span>
      <span className="text-slate-400 shrink-0 w-[180px] truncate">{displayHost}</span>
      <span className="text-[#38BDF8] animate-tool-glow flex-1 truncate">
        {stream.toolLabel || 'INITIALIZING'}
      </span>
      {elapsedStr && (
        <span className="text-[#1E3A5F] shrink-0 tabular-nums">{elapsedStr}</span>
      )}
    </div>
  );
}

export default function ActiveOperations({ hostStreams }: ActiveOperationsProps) {
  // Filter to only actively scanning hosts
  const activeStreams = Array.from(hostStreams.values()).filter(
    s => s.status === 'scanning' && s.currentTool
  );

  if (activeStreams.length === 0) return null;

  return (
    <div
      className="rounded-lg border overflow-hidden"
      style={{
        borderColor: 'rgba(30,58,95,0.3)',
        background: 'rgba(12,18,34,0.8)',
      }}
    >
      {activeStreams.map(stream => (
        <ActiveLane key={stream.ip} stream={stream} />
      ))}
    </div>
  );
}
