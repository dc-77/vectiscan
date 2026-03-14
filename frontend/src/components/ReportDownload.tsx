'use client';

import Link from 'next/link';
import { getReportDownloadUrl } from '@/lib/api';

interface Props {
  orderId: string;
  domain: string;
  onNewScan?: () => void;
}

export default function ReportDownload({ orderId, domain, onNewScan }: Props) {
  const dateStr = new Date().toISOString().split('T')[0];
  const fileName = `vectiscan-${domain}-${dateStr}.pdf`;

  return (
    <div className="rounded-lg bg-[#1e293b] p-6 text-center space-y-4">
      <div className="text-green-400 text-4xl">✅</div>
      <h3 className="text-lg font-semibold text-white">Report fertig</h3>
      <p className="text-sm text-gray-400">{fileName}</p>
      <div className="flex flex-col items-center gap-3">
        <a
          href={getReportDownloadUrl(orderId)}
          download={fileName}
          className="inline-block bg-blue-600 hover:bg-blue-500 text-white font-medium px-6 py-3 rounded-lg transition-colors"
        >
          PDF herunterladen
        </a>
        <Link
          href="/dashboard"
          className="inline-block bg-[#1e293b] hover:bg-[#253347] text-gray-300 hover:text-white text-sm font-medium px-4 py-2 rounded-lg border border-gray-700 transition-colors"
        >
          Dashboard
        </Link>
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
