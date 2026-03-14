'use client';

import { OrderStatus } from '@/lib/api';

const PHASE_LABELS: Record<string, string> = {
  created: 'Erstellt',
  dns_recon: 'DNS-Reconnaissance',
  scan_phase1: 'Phase 1 — Technologie-Erkennung',
  scan_phase2: 'Phase 2 — Tiefer Scan',
  scan_complete: 'Scan abgeschlossen',
  report_generating: 'Report wird generiert',
  report_complete: 'Fertig',
  failed: 'Fehlgeschlagen',
  cancelled: 'Abgebrochen',
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
  cancelled: 'bg-orange-500',
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

const PACKAGE_LABELS: Record<string, { label: string; color: string; textColor: string }> = {
  basic:        { label: 'Basic',        color: '#38BDF8', textColor: '#0F172A' },
  professional: { label: 'Professional', color: '#38BDF8', textColor: '#0F172A' },
  nis2:         { label: 'NIS2',         color: '#EAB308', textColor: '#0F172A' },
};

export default function ScanProgress({ scan, onCancel, cancelling }: Props) {
  const { status, progress, domain, startedAt } = scan;
  const label = PHASE_LABELS[status] || status;
  const color = PHASE_COLORS[status] || 'bg-gray-500';
  const pkgInfo = PACKAGE_LABELS[scan.package] || PACKAGE_LABELS.professional;
  const scanLabel = scan.package === 'basic' ? 'Quick Scan läuft' : 'Scan läuft';
  const percent = progress.hostsTotal > 0
    ? Math.round((progress.hostsCompleted / progress.hostsTotal) * 100)
    : 0;

  // Estimate remaining time based on elapsed time and progress
  let estimatedRemaining: string | null = null;
  if (startedAt && progress.hostsTotal > 0 && progress.hostsCompleted > 0) {
    const elapsedMs = Date.now() - new Date(startedAt).getTime();
    const elapsedSec = elapsedMs / 1000;
    const perHost = elapsedSec / progress.hostsCompleted;
    const remaining = perHost * (progress.hostsTotal - progress.hostsCompleted);
    // Add ~2min buffer for report generation if still scanning
    const reportBuffer = status.startsWith('scan_') ? 120 : 0;
    estimatedRemaining = formatDuration(remaining + reportBuffer);
  }

  return (
    <div className="rounded-lg bg-[#1e293b] p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-semibold text-white">{domain}</h2>
          <span
            className="text-xs font-bold px-2.5 py-0.5 rounded-full"
            style={{ backgroundColor: pkgInfo.color, color: pkgInfo.textColor }}
            data-testid="package-badge"
          >
            {pkgInfo.label}
          </span>
        </div>
        <span className={`${color} text-white text-xs font-medium px-3 py-1 rounded-full`}>
          {label}
        </span>
      </div>
      {scan.estimatedDuration && status !== 'report_complete' && (
        <div className="text-sm text-gray-400" data-testid="scan-label">
          {scanLabel} — geschätzte Dauer: {scan.estimatedDuration}
        </div>
      )}

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
              className="h-full bg-blue-500 rounded-full transition-all duration-1000 ease-in-out"
              style={{ width: `${percent}%` }}
            />
          </div>
          {estimatedRemaining && (
            <div className="text-xs text-gray-500 text-right" data-testid="time-estimate">
              Geschätzte Restzeit: {estimatedRemaining}
            </div>
          )}
        </div>
      )}

      {onCancel && (
        <div className="pt-2 border-t border-gray-700">
          <button
            onClick={onCancel}
            disabled={cancelling}
            className="text-red-400 hover:text-red-300 disabled:text-gray-600 text-sm transition-colors"
          >
            {cancelling ? 'Wird abgebrochen...' : 'Scan abbrechen'}
          </button>
        </div>
      )}
    </div>
  );
}
