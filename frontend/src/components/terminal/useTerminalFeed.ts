'use client';

import { useRef, useCallback, useState } from 'react';

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
  status?: 'done' | 'running' | 'error';
  detail?: string;
  isHeader?: boolean;
  isHost?: boolean;
  indent?: number;
}

type ScanPhase = 'idle' | 'starting' | 'queued' | 'dns_recon' | 'scan_phase1' | 'scan_phase2'
  | 'scan_complete' | 'report_generating' | 'report_complete' | 'failed';

const PACKAGE_LABELS: Record<string, string> = {
  basic: 'Basic Scan',
  professional: 'Professional Scan',
  nis2: 'NIS2 Compliance Scan',
};

// Tools expected per phase (for generating terminal lines)
const PHASE0_TOOLS_BASIC = ['crt.sh', 'subfinder'];
const PHASE0_TOOLS_PRO = ['crt.sh', 'subfinder', 'amass', 'gobuster DNS', 'Zone-Transfer', 'dnsx Validierung'];
const PHASE1_TOOLS = ['nmap', 'webtech', 'wafw00f'];
const PHASE2_TOOLS_BASIC = ['testssl.sh', 'headers', 'gowitness', 'httpx'];
const PHASE2_TOOLS_PRO = ['testssl.sh', 'nikto', 'nuclei', 'gobuster dir', 'gowitness', 'headers', 'httpx', 'katana', 'wpscan'];

function ts(): string {
  return new Date().toLocaleTimeString('de-DE', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

let lineCounter = 0;
function lineId(): string {
  return `line-${++lineCounter}`;
}

export function useTerminalFeed() {
  const [lines, setLines] = useState<TerminalLine[]>([]);
  const lastStatusRef = useRef<string>('');
  const lastToolRef = useRef<string>('');
  const lastHostRef = useRef<string>('');
  const lastHostsCompletedRef = useRef<number>(0);
  const hostsShownRef = useRef(false);
  const initializedRef = useRef(false);
  const phase0DoneRef = useRef(false);
  const phase1DoneRef = useRef(false);
  const lastToolOutputRef = useRef<string>('');

  const addLines = useCallback((newLines: TerminalLine[]) => {
    setLines(prev => {
      const updated = [...prev, ...newLines];
      // Keep max 200 lines in DOM
      if (updated.length > 200) {
        return updated.slice(updated.length - 200);
      }
      return updated;
    });
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
    addLines([
      { id: lineId(), timestamp: now, text: `VectiScan v1.0 — ${label}`, isHeader: true },
      { id: lineId(), timestamp: now, text: `Target: ${domain}`, isHeader: false },
      { id: lineId(), timestamp: now, text: '─'.repeat(50), isHeader: false },
    ]);
  }, [addLines]);

  const processStatus = useCallback((scan: ScanStatus) => {
    const { status, progress, domain } = scan;
    const pkg = scan.package || 'perimeter';
    const newLines: TerminalLine[] = [];
    const now = ts();

    // Initialize if not done
    if (!initializedRef.current) {
      initTerminal(domain, pkg);
    }

    // Phase/host transitions — emit when phase OR host changes
    const currentHost = progress.currentHost || '';
    const phaseHostKey = `${status}:${currentHost}`;
    const lastPhaseHostKey = `${lastStatusRef.current}:${lastHostRef.current}`;
    const phaseOrHostChanged = phaseHostKey !== lastPhaseHostKey;

    if (phaseOrHostChanged) {
      const prevStatus = lastStatusRef.current;
      lastStatusRef.current = status;
      lastHostRef.current = currentHost;

      switch (status) {
        case 'queued':
          newLines.push({
            id: lineId(), timestamp: now,
            text: '⏳ Scan in Warteschlange — wird gestartet, sobald ein Worker frei ist',
            status: 'running',
          });
          break;

        case 'dns_recon':
          if (!phase0DoneRef.current) {
            newLines.push({
              id: lineId(), timestamp: now,
              text: '▸ Phase 0: DNS-Reconnaissance', isHeader: true,
            });
          }
          break;

        case 'scan_phase1':
          if (!phase0DoneRef.current) {
            phase0DoneRef.current = true;
            // Show discovered hosts + selected hosts
            if (!hostsShownRef.current && progress.discoveredHosts.length > 0) {
              hostsShownRef.current = true;
              newLines.push({ id: lineId(), timestamp: now, text: '' });
              newLines.push({
                id: lineId(), timestamp: now,
                text: '▸ Hosts entdeckt:', isHeader: true,
              });
              for (const host of progress.discoveredHosts) {
                const fqdns = host.fqdns.join(', ');
                const skip = host.status === 'skipped' ? ' [SKIP]' : '';
                newLines.push({
                  id: lineId(), timestamp: now,
                  text: `  ${host.ip}  ${fqdns}${skip}`, isHost: true, indent: 1,
                });
              }
              // Show selected hosts (non-skipped)
              const selected = progress.discoveredHosts.filter(h => h.status !== 'skipped');
              if (selected.length < progress.discoveredHosts.length) {
                newLines.push({ id: lineId(), timestamp: now, text: '' });
                newLines.push({
                  id: lineId(), timestamp: now,
                  text: `▸ Hosts ausgewählt: ${selected.length} von ${progress.discoveredHosts.length}`, isHeader: true,
                });
                for (const host of selected) {
                  const fqdns = host.fqdns.join(', ');
                  newLines.push({
                    id: lineId(), timestamp: now,
                    text: `  ${host.ip}  ${fqdns}`, isHost: true, indent: 1,
                  });
                }
              }
              newLines.push({ id: lineId(), timestamp: now, text: '' });
            }
          }
          // Phase 1 header with host info
          newLines.push({
            id: lineId(), timestamp: now,
            text: `▸ Phase 1: Technologie-Erkennung${currentHost ? ` [${currentHost}]` : ''}`,
            isHeader: true,
          });
          break;

        case 'scan_phase2': {
          const hostLabel = progress.hostsTotal > 0
            ? ` [Host ${progress.hostsCompleted + 1}/${progress.hostsTotal}]`
            : '';
          newLines.push({
            id: lineId(), timestamp: now,
            text: `▸ Phase 2: Deep Scan${currentHost ? ` [${currentHost}]` : ''}${hostLabel}`,
            isHeader: true,
          });
          break;
        }

        case 'scan_complete':
          newLines.push({ id: lineId(), timestamp: now, text: '' });
          newLines.push({
            id: lineId(), timestamp: now,
            text: `▸ Scan abgeschlossen. ${progress.hostsTotal} Hosts gescannt.`,
            isHeader: true,
          });
          break;

        case 'report_generating':
          newLines.push({ id: lineId(), timestamp: now, text: '' });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '▸ Report-Generierung...', isHeader: true,
          });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '  Rohdaten konsolidieren', indent: 1, status: 'done',
          });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '  KI-Analyse (Claude)', indent: 1, status: 'done',
          });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '  PDF generieren', indent: 1, status: 'running',
          });
          break;

        case 'report_complete':
          newLines.push({
            id: lineId(), timestamp: now,
            text: '  ✓ PDF generieren', indent: 1, status: 'done',
          });
          newLines.push({ id: lineId(), timestamp: now, text: '' });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '─'.repeat(50),
          });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '  ▸ ASSESSMENT COMPLETE', isHeader: true, indent: 1,
          });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '  Report bereit zum Download', indent: 1,
          });
          break;

        case 'failed':
          newLines.push({ id: lineId(), timestamp: now, text: '' });
          newLines.push({
            id: lineId(), timestamp: now,
            text: `[ERROR] ${scan.error || 'Scan fehlgeschlagen'}`,
            status: 'error',
          });
          break;
      }
    }

    // Tool changes within a phase
    const currentTool = progress.currentTool || '';
    if (currentTool && currentTool !== 'starting' && currentTool !== lastToolRef.current) {
      // Mark previous tool as done
      if (lastToolRef.current) {
        const host = progress.currentHost || '';
        const toolLabel = lastToolRef.current;
        newLines.push({
          id: lineId(), timestamp: now,
          text: `  ✓ ${toolLabel}${host ? ' → ' + host : ''}`,
          indent: 1, status: 'done',
        });
        // Show tool output summary if available
        if (progress.toolOutput && progress.toolOutput !== lastToolOutputRef.current) {
          newLines.push({
            id: lineId(), timestamp: now,
            text: `    └ ${progress.toolOutput}`,
            indent: 2,
          });
          lastToolOutputRef.current = progress.toolOutput;
        }
      }
      lastToolRef.current = currentTool;
    } else if (progress.toolOutput && progress.toolOutput !== lastToolOutputRef.current) {
      // Tool output arrived but tool hasn't changed yet — show it
      newLines.push({
        id: lineId(), timestamp: now,
        text: `    └ ${progress.toolOutput}`,
        indent: 2,
      });
      lastToolOutputRef.current = progress.toolOutput;
    }

    // Host completion changes
    if (progress.hostsCompleted > lastHostsCompletedRef.current) {
      lastHostsCompletedRef.current = progress.hostsCompleted;
    }

    // Discovered hosts (show when first discovered, during dns_recon)
    if (status === 'dns_recon' && !hostsShownRef.current && progress.discoveredHosts.length > 0) {
      // Don't show yet — wait for phase transition to show them together
    }

    if (newLines.length > 0) {
      addLines(newLines);
    }
  }, [addLines, initTerminal]);

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
    lineCounter = 0;
  }, []);

  return { lines, processStatus, initTerminal, reset };
}
