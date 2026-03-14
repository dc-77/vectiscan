'use client';

interface Props {
  error: string | null;
  onRetry: () => void;
}

function isTimeoutError(error: string | null): boolean {
  return !!error && (error.includes('Timeout') || error.includes('timeout'));
}

export default function ScanError({ error, onRetry }: Props) {
  const isTimeout = isTimeoutError(error);

  return (
    <div className="rounded-lg bg-[#1e293b] p-6 text-center space-y-4">
      <div className="text-red-400 text-4xl">{isTimeout ? '\u23F1' : '\u274C'}</div>
      <h3 className="text-lg font-semibold text-white">
        {isTimeout ? 'Scan-Zeitlimit erreicht' : 'Scan fehlgeschlagen'}
      </h3>
      {error && (
        <p className="text-sm text-gray-400 font-mono bg-[#0f172a] rounded p-3">
          {error}
        </p>
      )}
      {isTimeout && (
        <p className="text-sm text-gray-500">
          Die Ziel-Domain hat mehr Hosts oder Dienste als erwartet.
          Versuchen Sie es erneut oder wählen Sie ein Paket mit längerem Zeitlimit.
        </p>
      )}
      <button
        onClick={onRetry}
        className="bg-blue-600 hover:bg-blue-500 text-white font-medium px-6 py-3 rounded-lg transition-colors"
      >
        Neuen Scan starten
      </button>
    </div>
  );
}
