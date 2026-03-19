'use client';

import { OrderStatus } from '@/lib/api';

const PHASE_LABELS: Record<string, string> = {
  created: 'Created',
  queued: 'Queued',
  passive_intel: 'Passive Intel',
  dns_recon: 'DNS Recon',
  scan_phase1: 'Phase 1 — Fingerprinting',
  scan_phase2: 'Phase 2 — Deep Scan',
  scan_phase3: 'Phase 3 — Correlation',
  scan_complete: 'Scan Complete',
  report_generating: 'Generating Report',
  report_complete: 'Complete',
  failed: 'Failed',
  cancelled: 'Cancelled',
};

const PHASE_COLORS: Record<string, { bg: string; text: string }> = {
  created:            { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  queued:             { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  passive_intel:      { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  dns_recon:          { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  scan_phase1:        { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  scan_phase2:        { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  scan_phase3:        { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  scan_complete:      { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  report_generating:  { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  report_complete:    { bg: 'bg-slate-700',   text: 'text-slate-300' },
  failed:             { bg: 'bg-red-500/15',  text: 'text-red-400' },
  cancelled:          { bg: 'bg-red-500/15',  text: 'text-red-400' },
};

const PACKAGE_LABELS: Record<string, string> = {
  basic: 'WEBCHECK',
  webcheck: 'WEBCHECK',
  professional: 'PERIMETER',
  perimeter: 'PERIMETER',
  nis2: 'COMPLIANCE',
  compliance: 'COMPLIANCE',
  supplychain: 'SUPPLYCHAIN',
  insurance: 'INSURANCE',
};

function formatDuration(seconds: number): string {
  if (seconds < 60) return '< 1 min';
  const m = Math.round(seconds / 60);
  if (m < 60) return `~${m} min`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return `~${h}h ${rm}m`;
}

interface Props {
  scan: OrderStatus;
  onCancel?: () => void;
  cancelling?: boolean;
}

export default function ScanProgress({ scan, onCancel, cancelling }: Props) {
  const { status, progress, domain, startedAt } = scan;
  const label = PHASE_LABELS[status] || status;
  const phaseStyle = PHASE_COLORS[status] || { bg: 'bg-slate-700', text: 'text-slate-400' };
  const pkgLabel = PACKAGE_LABELS[scan.package] || scan.package.toUpperCase();
  const isActive = !['report_complete', 'failed', 'cancelled'].includes(status);

  const percent = progress.hostsTotal > 0
    ? Math.round((progress.hostsCompleted / progress.hostsTotal) * 100)
    : 0;

  let estimatedRemaining: string | null = null;
  if (startedAt && progress.hostsTotal > 0 && progress.hostsCompleted > 0) {
    const elapsedSec = (Date.now() - new Date(startedAt).getTime()) / 1000;
    const perHost = elapsedSec / progress.hostsCompleted;
    const remaining = perHost * (progress.hostsTotal - progress.hostsCompleted);
    const reportBuffer = status.startsWith('scan_') ? 120 : 0;
    estimatedRemaining = formatDuration(remaining + reportBuffer);
  }

  return (
    <div className="rounded-lg bg-[#1e293b] px-5 py-3 space-y-2">
      {/* Single row: domain + package + phase */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <h2 className="text-base font-semibold text-white truncate">{domain}</h2>
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500">{pkgLabel}</span>
        </div>
        <span className={`${phaseStyle.bg} ${phaseStyle.text} text-xs font-medium px-2.5 py-0.5 rounded inline-flex items-center gap-1.5`}>
          {isActive && <span className="w-1.5 h-1.5 bg-current rounded-full animate-pulse" />}
          {label}
        </span>
      </div>

      {/* Progress bar */}
      {progress.hostsTotal > 0 && (
        <div className="space-y-1">
          <div className="flex justify-between text-xs text-slate-500">
            <span className="font-mono">
              {progress.hostsCompleted}/{progress.hostsTotal} hosts complete
            </span>
            {estimatedRemaining && (
              <span>ETA: {estimatedRemaining}</span>
            )}
          </div>
          <div className="h-1 bg-gray-700 rounded-full overflow-hidden">
            <div className="h-full bg-blue-500 rounded-full transition-all duration-1000"
                 style={{ width: `${percent}%` }} />
          </div>
        </div>
      )}

      {/* Cancel button — inline */}
      {onCancel && (
        <button onClick={onCancel} disabled={cancelling}
          className="text-red-400 hover:text-red-300 hover:bg-red-400/10 disabled:text-slate-600 text-xs font-medium px-3 py-1.5 rounded-lg border border-red-900/50 transition-colors">
          {cancelling ? 'Cancelling...' : 'Cancel scan'}
        </button>
      )}
    </div>
  );
}
