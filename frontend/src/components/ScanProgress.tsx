'use client';

import { ScanStatus } from '@/lib/api';

const PHASE_LABELS: Record<string, string> = {
  created: 'Erstellt',
  dns_recon: 'DNS-Reconnaissance',
  scan_phase1: 'Phase 1 — Technologie-Erkennung',
  scan_phase2: 'Phase 2 — Tiefer Scan',
  scan_complete: 'Scan abgeschlossen',
  report_generating: 'Report wird generiert',
  report_complete: 'Fertig',
  failed: 'Fehlgeschlagen',
};

const PHASE_COLORS: Record<string, string> = {
  created: 'bg-gray-500',
  dns_recon: 'bg-purple-500',
  scan_phase1: 'bg-blue-500',
  scan_phase2: 'bg-cyan-500',
  scan_complete: 'bg-teal-500',
  report_generating: 'bg-amber-500',
  report_complete: 'bg-green-500',
  failed: 'bg-red-500',
};

interface Props {
  scan: ScanStatus;
}

export default function ScanProgress({ scan }: Props) {
  const { status, progress, domain } = scan;
  const label = PHASE_LABELS[status] || status;
  const color = PHASE_COLORS[status] || 'bg-gray-500';
  const percent = progress.hostsTotal > 0
    ? Math.round((progress.hostsCompleted / progress.hostsTotal) * 100)
    : 0;

  return (
    <div className="rounded-lg bg-[#1e293b] p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">{domain}</h2>
        <span className={`${color} text-white text-xs font-medium px-3 py-1 rounded-full`}>
          {label}
        </span>
      </div>

      {progress.currentTool && (
        <div className="text-sm text-gray-400">
          <span className="text-gray-300">Tool:</span>{' '}
          <span className="font-mono text-blue-400">{progress.currentTool}</span>
          {progress.currentHost && (
            <>
              {' → '}
              <span className="font-mono text-gray-300">{progress.currentHost}</span>
            </>
          )}
        </div>
      )}

      {progress.hostsTotal > 0 && (
        <div className="space-y-2">
          <div className="flex justify-between text-sm text-gray-400">
            <span>Host-Fortschritt</span>
            <span>{progress.hostsCompleted} / {progress.hostsTotal}</span>
          </div>
          <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
            <div
              className="h-full bg-blue-500 rounded-full transition-all duration-500"
              style={{ width: `${percent}%` }}
            />
          </div>
        </div>
      )}
    </div>
  );
}
