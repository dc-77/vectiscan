'use client';

interface Props {
  className?: string;
}

export default function VectiScanLogo({ className = '' }: Props) {
  return (
    <div className={`flex items-center justify-center gap-3 ${className}`}>
      <svg
        width="44"
        height="44"
        viewBox="0 0 44 44"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden="true"
      >
        {/* Shield outline */}
        <path
          d="M22 2L4 10v12c0 11 8 18 18 20 10-2 18-9 18-20V10L22 2z"
          fill="#1e293b"
          stroke="#3b82f6"
          strokeWidth="2"
        />
        {/* Inner shield glow */}
        <path
          d="M22 6L8 12.5v9c0 8.8 6.2 14.5 14 16 7.8-1.5 14-7.2 14-16v-9L22 6z"
          fill="#0f172a"
          stroke="#60a5fa"
          strokeWidth="1"
          opacity="0.6"
        />
        {/* Scan crosshair - horizontal */}
        <line x1="12" y1="22" x2="32" y2="22" stroke="#3b82f6" strokeWidth="1.5" opacity="0.8" />
        {/* Scan crosshair - vertical */}
        <line x1="22" y1="12" x2="22" y2="32" stroke="#3b82f6" strokeWidth="1.5" opacity="0.8" />
        {/* Center target dot */}
        <circle cx="22" cy="22" r="3" fill="#3b82f6" opacity="0.9" />
        <circle cx="22" cy="22" r="1.5" fill="#60a5fa" />
        {/* Scan ring */}
        <circle
          cx="22"
          cy="22"
          r="7"
          fill="none"
          stroke="#3b82f6"
          strokeWidth="1"
          strokeDasharray="3 3"
          opacity="0.5"
        />
      </svg>
      <div className="flex flex-col">
        <span className="text-2xl font-bold text-white tracking-tight leading-none">
          Vecti<span className="text-blue-400">Scan</span>
        </span>
        <span className="text-[10px] text-gray-500 tracking-widest uppercase leading-none mt-0.5">
          Security Scanner
        </span>
      </div>
    </div>
  );
}
