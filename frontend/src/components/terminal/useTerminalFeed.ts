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

type ScanPhase = 'idle' | 'starting' | 'dns_recon' | 'scan_phase1' | 'scan_phase2'
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
const PHASE2_TOOLS_BASIC = ['testssl.sh', 'headers', 'gowitness'];
const PHASE2_TOOLS_PRO = ['testssl.sh', 'nikto', 'nuclei', 'gobuster dir', 'gowitness', 'headers'];

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
    const pkg = scan.package || 'professional';
    const newLines: TerminalLine[] = [];
    const now = ts();

    // Initialize if not done
    if (!initializedRef.current) {
      initTerminal(domain, pkg);
    }

    // Phase transitions — only emit when phase changes
    if (status !== lastStatusRef.current) {
      const prevStatus = lastStatusRef.current;
      lastStatusRef.current = status;

      switch (status) {
        case 'dns_recon':
          newLines.push({
            id: lineId(), timestamp: now,
            text: '▸ Phase 0: DNS-Reconnaissance', isHeader: true,
          });
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
                text: '▸ Hosts entdeckt:', isHeader: true,
              });
              for (const host of progress.discoveredHosts) {
                const fqdns = host.fqdns.join(', ');
                newLines.push({
                  id: lineId(), timestamp: now,
                  text: `  ${host.ip}  ${fqdns}`, isHost: true, indent: 1,
                });
              }
              newLines.push({ id: lineId(), timestamp: now, text: '' });
            }
          }
          // Phase 1 header with host info
          const p1Host = progress.currentHost || '';
          newLines.push({
            id: lineId(), timestamp: now,
            text: `▸ Phase 1: Technologie-Erkennung${p1Host ? ` [${p1Host}]` : ''}`,
            isHeader: true,
          });
          break;

        case 'scan_phase2': {
          if (!phase1DoneRef.current) {
            phase1DoneRef.current = true;
          }
          const hostLabel = progress.hostsTotal > 0
            ? ` [Host ${progress.hostsCompleted + 1}/${progress.hostsTotal}]`
            : '';
          const p2Host = progress.currentHost || '';
          newLines.push({
            id: lineId(), timestamp: now,
            text: `▸ Phase 2: Deep Scan${p2Host ? ` [${p2Host}]` : ''}${hostLabel}`,
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
            text: '  PDF generieren', indent: 1, status: 'done',
          });
          newLines.push({ id: lineId(), timestamp: now, text: '' });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '  ██████████████████████████████████████ 100%', indent: 1,
          });
          newLines.push({ id: lineId(), timestamp: now, text: '' });
          newLines.push({
            id: lineId(), timestamp: now,
            text: '  REPORT FERTIG ✓', isHeader: true, indent: 1,
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
    if (currentTool && currentTool !== lastToolRef.current) {
      // Mark previous tool as done
      if (lastToolRef.current) {
        const host = progress.currentHost || '';
        const toolLabel = lastToolRef.current;
        const dots = '.'.repeat(Math.max(2, 40 - toolLabel.length - (host ? host.length + 1 : 0)));
        newLines.push({
          id: lineId(), timestamp: now,
          text: `  ${toolLabel}${host ? ' ' + host : ''} ${dots}`,
          indent: 1, status: 'done',
        });
      }
      lastToolRef.current = currentTool;
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
    lineCounter = 0;
  }, []);

  return { lines, processStatus, initTerminal, reset };
}
