'use client';

import { HostInfo } from '@/lib/api';

const STATUS_ICONS: Record<string, string> = {
  pending: '⏳',
  scanning: '🔄',
  completed: '✅',
};

interface Props {
  hosts: HostInfo[];
}

export default function HostList({ hosts }: Props) {
  if (hosts.length === 0) return null;

  return (
    <div className="rounded-lg bg-[#1e293b] p-6">
      <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
        Entdeckte Hosts ({hosts.length})
      </h3>
      <div className="space-y-2">
        {hosts.map((host) => (
          <div
            key={host.ip}
            className="flex items-center gap-3 rounded-md bg-[#0f172a] px-4 py-2"
          >
            <span className="text-lg" role="img" aria-label={host.status}>
              {STATUS_ICONS[host.status] || '⏳'}
            </span>
            <div className="flex-1 min-w-0">
              <span className="font-mono text-sm text-white">{host.ip}</span>
              {host.fqdns.length > 0 && (
                <span className="ml-2 text-xs text-gray-500">
                  {host.fqdns.join(', ')}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
