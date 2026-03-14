'use client';

import { useEffect, useState } from 'react';
import { getScanReport, getReportDownloadUrl, ReportData } from '@/lib/api';

interface Props {
  scanId: string;
  onNewScan?: () => void;
}

export default function ReportDownload({ scanId, onNewScan }: Props) {
  const [report, setReport] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getScanReport(scanId).then((res) => {
      if (res.success && res.data) {
        setReport(res.data);
      }
      setLoading(false);
    });
  }, [scanId]);

  if (loading) {
    return (
      <div className="rounded-lg bg-[#1e293b] p-6 text-center text-gray-400">
        Report wird geladen...
      </div>
    );
  }

  if (!report) return null;

  const sizeKB = report.fileSize ? Math.round(report.fileSize / 1024) : 0;

  return (
    <div className="rounded-lg bg-[#1e293b] p-6 text-center space-y-4">
      <div className="text-green-400 text-4xl">✅</div>
      <h3 className="text-lg font-semibold text-white">Report fertig</h3>
      <p className="text-sm text-gray-400">
        {report.fileName}{sizeKB > 0 && ` (${sizeKB} KB)`}
      </p>
      <div className="flex flex-col items-center gap-3">
        <a
          href={getReportDownloadUrl(scanId)}
          download={report.fileName}
          className="inline-block bg-blue-600 hover:bg-blue-500 text-white font-medium px-6 py-3 rounded-lg transition-colors"
        >
          PDF herunterladen
        </a>
        {onNewScan && (
          <button
            onClick={onNewScan}
            className="text-blue-400 hover:text-blue-300 text-sm transition-colors"
          >
            Neuen Scan starten
          </button>
        )}
      </div>
    </div>
  );
}
