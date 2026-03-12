'use client';

interface Props {
  error: string | null;
  onRetry: () => void;
}

export default function ScanError({ error, onRetry }: Props) {
  return (
    <div className="rounded-lg bg-[#1e293b] p-6 text-center space-y-4">
      <div className="text-red-400 text-4xl">❌</div>
      <h3 className="text-lg font-semibold text-white">Scan fehlgeschlagen</h3>
      {error && (
        <p className="text-sm text-gray-400 font-mono bg-[#0f172a] rounded p-3">
          {error}
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
