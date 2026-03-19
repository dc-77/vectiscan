'use client';

import { useRef, useCallback, useState } from 'react';
import { getToolLabel, getHostColor } from '@/lib/toolLabels';

// Must match the ScanStatus from lib/api.ts
interface ScanProgress {
  phase: string | null;
  currentTool: string | null;
  currentHost: string | null;
  hostsTotal: number;
  hostsCompleted: number;
  discoveredHosts: Array<{ ip: string; fqdns: string[]; status: string }>;
  toolOutput: string | null;
  lastCompletedTool: string | null;
}

interface ScanStatus {
  id: string;
  domain: string;
  status: string;
  package: string;
  estimatedDuration: string;
  progress: ScanProgress;
  startedAt: string | null;
  finishedAt: string | null;
  error: string | null;
  hasReport: boolean;
}

export interface TerminalLine {
  id: string;
  timestamp: string;
  text: string;
  status?: 'done' | 'running' | 'error' | 'command' | 'warning' | 'system';
  detail?: string;
  isHeader?: boolean;
  isHost?: boolean;
  indent?: number;
  hostColor?: string;
  hostLabel?: string;
}

export interface HostStream {
  ip: string;
  fqdns: string[];
  currentTool: string | null;
  toolLabel: string | null;
  toolStartedAt: number;
  status: 'idle' | 'scanning' | 'done' | 'error';
  color: string;
  toolsCompleted: number;
}

type ScanPhase = 'idle' | 'starting' | 'queued' | 'dns_recon' | 'passive_intel'
  | 'scan_phase1' | 'scan_phase2' | 'scan_phase3'
  | 'scan_complete' | 'report_generating' | 'report_complete' | 'failed';

const PACKAGE_LABELS: Record<string, string> = {
  basic: 'WebCheck',
  webcheck: 'WebCheck',
  professional: 'PerimeterScan',
  perimeter: 'PerimeterScan',
  nis2: 'ComplianceScan',
  compliance: 'ComplianceScan',
  supplychain: 'SupplyChainScan',
  insurance: 'InsuranceScan',
};

const PACKAGE_MAX_HOSTS: Record<string, number> = {
  basic: 3, webcheck: 3,
  professional: 15, perimeter: 15,
  nis2: 15, compliance: 15,
  supplychain: 15, insurance: 15,
};

function ts(): string {
  const d = new Date();
  const hms = d.toLocaleTimeString('de-DE', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
  const ms = String(d.getMilliseconds()).padStart(3, '0');
  return `${hms}.${ms}`;
}

let lineCounter = 0;
function lineId(): string {
  return `line-${++lineCounter}`;
}

function storageKey(orderId: string): string {
  return `vectiscan-terminal-${orderId}`;
}

interface TerminalState {
  lines: TerminalLine[];
  lastStatus: string;
  lastTool: string;
  lastHost: string;
  hostsCompleted: number;
  hostsShown: boolean;
  initialized: boolean;
  phase0Done: boolean;
  phase1Done: boolean;
  lastToolOutput: string;
  hostStreams: Record<string, HostStream>;
  hostColorIndex: number;
}

function saveTerminalState(orderId: string | null, state: TerminalState): void {
  if (!orderId) return;
  try {
    sessionStorage.setItem(storageKey(orderId), JSON.stringify(state));
  } catch { /* quota exceeded — ignore */ }
}

function loadTerminalState(orderId: string | null): TerminalState | null {
  if (!orderId) return null;
  try {
    const raw = sessionStorage.getItem(storageKey(orderId));
    if (raw) return JSON.parse(raw) as TerminalState;
  } catch { /* corrupt data — ignore */ }
  return null;
}

/** Get the primary FQDN for display (shortest non-IP). */
function hostDisplayName(ip: string, fqdns?: string[]): string {
  if (fqdns && fqdns.length > 0) {
    return fqdns[0];
  }
  return ip;
}

export function useTerminalFeed(orderId?: string | null) {
  const restored = useRef(false);
  const initialState = useRef<TerminalState | null>(null);
  if (!restored.current && orderId) {
    initialState.current = loadTerminalState(orderId);
    restored.current = true;
  }
  const cached = initialState.current;

  const [lines, setLines] = useState<TerminalLine[]>(cached?.lines || []);
  const lastStatusRef = useRef<string>(cached?.lastStatus || '');
  const lastToolRef = useRef<string>(cached?.lastTool || '');
  const lastHostRef = useRef<string>(cached?.lastHost || '');
  const lastHostsCompletedRef = useRef<number>(cached?.hostsCompleted || 0);
  const hostsShownRef = useRef(cached?.hostsShown || false);
  const initializedRef = useRef(cached?.initialized || false);
  const phase0DoneRef = useRef(cached?.phase0Done || false);
  const phase1DoneRef = useRef(cached?.phase1Done || false);
  const lastToolOutputRef = useRef<string>(cached?.lastToolOutput || '');

  // Per-host parallel tracking
  const hostStreamsRef = useRef<Map<string, HostStream>>(
    new Map(Object.entries(cached?.hostStreams || {}))
  );
  const hostColorIndexRef = useRef<number>(cached?.hostColorIndex || 0);
  const [hostStreams, setHostStreams] = useState<Map<string, HostStream>>(hostStreamsRef.current);

  // Restore lineCounter
  if (cached?.lines.length) {
    const maxId = Math.max(...cached.lines.map(l => {
      const m = l.id.match(/^line-(\d+)$/);
      return m ? parseInt(m[1], 10) : 0;
    }));
    if (maxId > lineCounter) lineCounter = maxId;
  }

  const orderIdRef = useRef(orderId);
  orderIdRef.current = orderId;

  const persistState = useCallback((updatedLines: TerminalLine[]) => {
    saveTerminalState(orderIdRef.current || null, {
      lines: updatedLines,
      lastStatus: lastStatusRef.current,
      lastTool: lastToolRef.current,
      lastHost: lastHostRef.current,
      hostsCompleted: lastHostsCompletedRef.current,
      hostsShown: hostsShownRef.current,
      initialized: initializedRef.current,
      phase0Done: phase0DoneRef.current,
      phase1Done: phase1DoneRef.current,
      lastToolOutput: lastToolOutputRef.current,
      hostStreams: Object.fromEntries(hostStreamsRef.current),
      hostColorIndex: hostColorIndexRef.current,
    });
  }, []);

  const addLines = useCallback((newLines: TerminalLine[]) => {
    setLines(prev => {
      const updated = [...prev, ...newLines];
      const trimmed = updated.length > 200 ? updated.slice(updated.length - 200) : updated;
      persistState(trimmed);
      return trimmed;
    });
  }, [persistState]);

  /** Get or create a host stream with assigned color. */
  const getOrCreateStream = useCallback((ip: string, fqdns?: string[]): HostStream => {
    const existing = hostStreamsRef.current.get(ip);
    if (existing) {
      if (fqdns && fqdns.length > 0 && existing.fqdns.length === 0) {
        existing.fqdns = fqdns;
      }
      return existing;
    }
    const stream: HostStream = {
      ip,
      fqdns: fqdns || [],
      currentTool: null,
      toolLabel: null,
      toolStartedAt: Date.now(),
      status: 'idle',
      color: getHostColor(hostColorIndexRef.current),
      toolsCompleted: 0,
    };
    hostColorIndexRef.current++;
    hostStreamsRef.current.set(ip, stream);
    setHostStreams(new Map(hostStreamsRef.current));
    return stream;
  }, []);

  const initTerminal = useCallback((domain: string, pkg: string) => {
    if (initializedRef.current) return;
    initializedRef.current = true;
    lastStatusRef.current = '';
    lastToolRef.current = '';
    lastHostRef.current = '';
    lastHostsCompletedRef.current = 0;
    hostsShownRef.current = false;
    phase0DoneRef.current = false;
    phase1DoneRef.current = false;

    const now = ts();
    const label = PACKAGE_LABELS[pkg] || 'Scan';
    const maxHosts = PACKAGE_MAX_HOSTS[pkg] || 15;

    // Boot sequence lines — staggered via addLines batches
    const bootLines: TerminalLine[] = [
      { id: lineId(), timestamp: now, text: 'VectiScan v2.0 — Security Assessment System', isHeader: true },
      { id: lineId(), timestamp: now, text: '━'.repeat(50) },
      { id: lineId(), timestamp: now, text: '[SYS] Initializing scan modules...', status: 'system' },
      { id: lineId(), timestamp: now, text: '  ✓ Network stack online', indent: 1, status: 'done' },
      { id: lineId(), timestamp: now, text: '  ✓ DNS resolver online', indent: 1, status: 'done' },
      { id: lineId(), timestamp: now, text: '  ✓ Vulnerability database synced', indent: 1, status: 'done' },
      { id: lineId(), timestamp: now, text: '  ✓ AI orchestration ready', indent: 1, status: 'done' },
      { id: lineId(), timestamp: now, text: `[SYS] Package: ${label} // Max ${maxHosts} hosts`, status: 'system' },
      { id: lineId(), timestamp: now, text: `[SYS] Target: ${domain}`, status: 'system' },
      { id: lineId(), timestamp: now, text: '━'.repeat(50) },
    ];
    addLines(bootLines);
  }, [addLines]);

  /** Handle a tool_starting WebSocket event — emit cinematic label line. */
  const handleToolStarting = useCallback((tool: string, host: string) => {
    const now = ts();
    const label = getToolLabel(tool);
    const newLines: TerminalLine[] = [];

    // Determine host color for parallel visualization
    let hostColor: string | undefined;
    let hostName: string | undefined;

    if (host) {
      const stream = getOrCreateStream(host);

      // Mark previous tool as done for this host
      if (stream.currentTool && stream.status === 'scanning') {
        const prevLabel = stream.toolLabel || getToolLabel(stream.currentTool);
        newLines.push({
          id: lineId(), timestamp: now,
          text: `  ${prevLabel} ${'·'.repeat(Math.max(2, 42 - prevLabel.length))} DONE`,
          indent: 1, status: 'done',
          hostColor: stream.color,
          hostLabel: hostDisplayName(stream.ip, stream.fqdns),
        });
        stream.toolsCompleted++;
      }

      // Update stream state
      stream.currentTool = tool;
      stream.toolLabel = label;
      stream.toolStartedAt = Date.now();
      stream.status = 'scanning';
      hostStreamsRef.current.set(host, stream);
      setHostStreams(new Map(hostStreamsRef.current));

      hostColor = stream.color;
      hostName = hostDisplayName(stream.ip, stream.fqdns);
    }

    // Emit the cinematic label line
    const hostSuffix = hostName ? ` ── ${hostName}` : '';
    newLines.push({
      id: lineId(), timestamp: now,
      text: `  ${label}${hostSuffix}`,
      indent: 1,
      hostColor,
      hostLabel: hostName,
    });

    if (newLines.length > 0) {
      addLines(newLines);
    }
  }, [addLines, getOrCreateStream]);

  /** Handle a tool_output WebSocket event — mark tool completion. */
  const handleToolOutput = useCallback((tool: string, host: string, summary: string) => {
    const now = ts();
    const newLines: TerminalLine[] = [];

    if (host) {
      const stream = hostStreamsRef.current.get(host);
      if (stream && stream.currentTool === tool) {
        const label = stream.toolLabel || getToolLabel(tool);
        newLines.push({
          id: lineId(), timestamp: now,
          text: `  ${label} ${'·'.repeat(Math.max(2, 42 - label.length))} DONE`,
          indent: 1, status: 'done',
          hostColor: stream.color,
          hostLabel: hostDisplayName(stream.ip, stream.fqdns),
        });
        stream.toolsCompleted++;
        stream.currentTool = null;
        stream.toolLabel = null;
        hostStreamsRef.current.set(host, stream);
        setHostStreams(new Map(hostStreamsRef.current));
      }
    }

    // Show summary
    if (summary) {
      const stream = host ? hostStreamsRef.current.get(host) : undefined;
      newLines.push({
        id: lineId(), timestamp: now,
        text: `    └ ${summary}`,
        indent: 2,
        hostColor: stream?.color,
      });
    }

    if (newLines.length > 0) {
      addLines(newLines);
    }
  }, [addLines]);

  const processStatus = useCallback((scan: ScanStatus) => {
    const { status, progress, domain } = scan;
    const pkg = scan.package || 'perimeter';
    const newLines: TerminalLine[] = [];
    const now = ts();

    if (!initializedRef.current) {
      initTerminal(domain, pkg);
    }

    // Phase/host transitions
    const currentHost = progress.currentHost || '';
    const phaseHostKey = `${status}:${currentHost}`;
    const lastPhaseHostKey = `${lastStatusRef.current}:${lastHostRef.current}`;
    const phaseOrHostChanged = phaseHostKey !== lastPhaseHostKey;

    if (phaseOrHostChanged) {
      lastStatusRef.current = status;
      lastHostRef.current = currentHost;

      switch (status) {
        case 'queued':
          newLines.push({
            id: lineId(), timestamp: now,
            text: 'QUEUED — AWAITING AVAILABLE WORKER',
            status: 'running',
          });
          break;

        case 'passive_intel':
          newLines.push({
            id: lineId(), timestamp: now,
            text: 'PHASE 0a /// PASSIVE INTELLIGENCE', isHeader: true,
          });
          break;

        case 'dns_recon':
          if (!phase0DoneRef.current) {
            newLines.push({
              id: lineId(), timestamp: now,
              text: 'PHASE 0b /// ACTIVE DISCOVERY', isHeader: true,
            });
          }
          break;

        case 'scan_phase1':
          if (!phase0DoneRef.current) {
            phase0DoneRef.current = true;
            // Show discovered hosts
            if (!hostsShownRef.current && progress.discoveredHosts.length > 0) {
              hostsShownRef.current = true;
              newLines.push({ id: lineId(), timestamp: now, text: '' });
              newLines.push({
                id: lineId(), timestamp: now,
                text: 'DISCOVERED HOSTS', isHeader: true,
              });
              newLines.push({
                id: lineId(), timestamp: now,
                text: '─'.repeat(50),
              });
              for (const host of progress.discoveredHosts) {
                const fqdns = host.fqdns.join(', ');
                const skip = host.status === 'skipped' ? ' [SKIP]' : '';
                newLines.push({
                  id: lineId(), timestamp: now,
                  text: `  ${host.ip}  ${fqdns}${skip}`, isHost: true, indent: 1,
                });
                // Initialize host streams with color assignment
                if (host.status !== 'skipped') {
                  getOrCreateStream(host.ip, host.fqdns);
                }
              }
              // Show selected count
              const selected = progress.discoveredHosts.filter(h => h.status !== 'skipped');
              if (selected.length < progress.discoveredHosts.length) {
                newLines.push({ id: lineId(), timestamp: now, text: '' });
                newLines.push({
                  id: lineId(), timestamp: now,
                  text: `TARGETS SELECTED: ${selected.length} OF ${progress.discoveredHosts.length} HOSTS`,
                  isHeader: true,
                });
              }
              newLines.push({ id: lineId(), timestamp: now, text: '' });
            }
          }
          // Phase 1 header — no host suffix (parallel)
          newLines.push({
            id: lineId(), timestamp: now,
            text: 'PHASE 1 /// TECHNOLOGY FINGERPRINTING',
            isHeader: true,
          });
          break;

        case 'scan_phase2':
          newLines.push({ id: lineId(), timestamp: now, text: '' });
          newLines.push({
            id: lineId(), timestamp: now,
            text: 'PHASE 2 /// DEEP SCAN',
            isHeader: true,
          });
          break;

        case 'scan_phase3':
          newLines.push({ id: lineId(), timestamp: now, text: '' });
          newLines.push({
            id: lineId(), timestamp: now,
            text: 'PHASE 3 /// CORRELATION & ENRICHMENT', isHeader: true,
          });
          break;

        case 'scan_complete':
          newLines.push({ id: lineId(), timestamp: now, text: '' });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '══════════════════════════════════════════',
          });
          newLines.push({
            id: lineId(), timestamp: now,
            text: 'SCAN COMPLETE', isHeader: true,
          });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '══════════════════════════════════════════',
          });
          newLines.push({
            id: lineId(), timestamp: now,
            text: `  Hosts scanned ${'·'.repeat(10)} ${progress.hostsTotal}`,
            indent: 1,
          });
          break;

        case 'report_generating':
          newLines.push({ id: lineId(), timestamp: now, text: '' });
          newLines.push({
            id: lineId(), timestamp: now,
            text: 'GENERATING REPORT', isHeader: true,
          });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '─'.repeat(50),
          });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '  Consolidating raw data', indent: 1, status: 'done',
          });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '  AI analysis in progress', indent: 1, status: 'running',
          });
          break;

        case 'report_complete':
          newLines.push({
            id: lineId(), timestamp: now,
            text: '  AI analysis complete', indent: 1, status: 'done',
          });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '  PDF generation complete', indent: 1, status: 'done',
          });
          newLines.push({ id: lineId(), timestamp: now, text: '' });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '══════════════════════════════════════════',
          });
          newLines.push({
            id: lineId(), timestamp: now,
            text: 'ASSESSMENT COMPLETE', isHeader: true,
          });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '══════════════════════════════════════════',
          });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '  Report ready for download', indent: 1,
          });
          break;

        case 'failed':
          newLines.push({ id: lineId(), timestamp: now, text: '' });
          newLines.push({
            id: lineId(), timestamp: now,
            text: `[ERROR] ${scan.error || 'Scan failed'}`,
            status: 'error',
          });
          break;
      }
    }

    // Tool changes via progress events (fallback for phases without tool_starting)
    const currentTool = progress.currentTool || '';
    if (currentTool && currentTool !== lastToolRef.current) {
      lastToolRef.current = currentTool;
    }

    // Tool output via progress (not via tool_output WS event)
    if (progress.toolOutput && progress.toolOutput !== lastToolOutputRef.current) {
      newLines.push({
        id: lineId(), timestamp: now,
        text: `    └ ${progress.toolOutput}`,
        indent: 2,
      });
      lastToolOutputRef.current = progress.toolOutput;
    }

    // Host completion tracking
    if (progress.hostsCompleted > lastHostsCompletedRef.current) {
      lastHostsCompletedRef.current = progress.hostsCompleted;
    }

    if (newLines.length > 0) {
      addLines(newLines);
    }
  }, [addLines, initTerminal, getOrCreateStream]);

  const reset = useCallback(() => {
    setLines([]);
    lastStatusRef.current = '';
    lastToolRef.current = '';
    lastHostRef.current = '';
    lastHostsCompletedRef.current = 0;
    hostsShownRef.current = false;
    initializedRef.current = false;
    phase0DoneRef.current = false;
    phase1DoneRef.current = false;
    lastToolOutputRef.current = '';
    hostStreamsRef.current.clear();
    hostColorIndexRef.current = 0;
    setHostStreams(new Map());
    lineCounter = 0;
    if (orderIdRef.current) {
      try { sessionStorage.removeItem(storageKey(orderIdRef.current)); } catch { /* ignore */ }
    }
  }, []);

  return {
    lines,
    hostStreams,
    processStatus,
    initTerminal,
    reset,
    handleToolStarting,
    handleToolOutput,
  };
}
