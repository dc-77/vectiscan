'use client';

/**
 * ThreatIntelBadge — kleine Badge-Reihe pro Finding mit Threat-Intel-Signalen.
 *
 * Datenquelle: finding.threat_intel = { cisa_kev, epss, nvd, exploitdb }
 * (durchgereicht aus correlation_data.enrichment im /findings-Endpoint).
 *
 * Render-Logik: nur Badges zeigen die wirklich Inhalt haben — bei
 * leerem threat_intel rendert die Komponente nichts.
 */

interface ThreatIntel {
  cisa_kev?: { cveID?: string; knownRansomwareCampaignUse?: string } | unknown;
  epss?: { epss?: number; percentile?: number } | unknown;
  nvd?: { cvss_score?: number; cwe?: string } | unknown;
  exploitdb?: Array<{ id: string }> | unknown;
}

interface Props {
  threatIntel?: ThreatIntel | null;
}

export default function ThreatIntelBadge({ threatIntel }: Props) {
  if (!threatIntel || typeof threatIntel !== 'object') return null;

  const kev = threatIntel.cisa_kev as Record<string, unknown> | undefined;
  const epss = threatIntel.epss as { epss?: number } | undefined;
  const nvd = threatIntel.nvd as { cvss_score?: number } | undefined;
  const edb = threatIntel.exploitdb as Array<unknown> | undefined;

  const isRansomware =
    kev && typeof kev === 'object' &&
    String((kev as Record<string, string>).knownRansomwareCampaignUse ?? '').toLowerCase() === 'known';

  const epssScore = typeof epss?.epss === 'number' ? epss.epss : null;
  const nvdScore = typeof nvd?.cvss_score === 'number' ? nvd.cvss_score : null;
  const edbCount = Array.isArray(edb) ? edb.length : 0;

  const badges: Array<{ key: string; label: string; cls: string; title: string }> = [];

  if (kev && Object.keys(kev as object).length > 0) {
    badges.push({
      key: 'kev',
      label: 'CISA KEV',
      cls: 'bg-red-500/20 text-red-200 ring-red-500/40',
      title: 'In CISA Known Exploited Vulnerabilities — aktive Ausnutzung beobachtet',
    });
  }
  if (isRansomware) {
    badges.push({
      key: 'rans',
      label: 'Ransomware',
      cls: 'bg-fuchsia-500/20 text-fuchsia-200 ring-fuchsia-500/40',
      title: 'CVE wird in Ransomware-Kampagnen genutzt (CISA KEV)',
    });
  }
  if (epssScore !== null) {
    const intensity =
      epssScore >= 0.7 ? 'bg-orange-500/25 text-orange-200 ring-orange-500/40'
      : epssScore >= 0.3 ? 'bg-yellow-500/20 text-yellow-200 ring-yellow-500/40'
      : 'bg-slate-700/30 text-slate-300 ring-slate-600/40';
    badges.push({
      key: 'epss',
      label: `EPSS ${(epssScore * 100).toFixed(0)}%`,
      cls: intensity,
      title: `Exploit Probability Score (FIRST.org): ${(epssScore * 100).toFixed(1)}%`,
    });
  }
  if (nvdScore !== null) {
    const intensity =
      nvdScore >= 9.0 ? 'bg-red-500/20 text-red-200 ring-red-500/40'
      : nvdScore >= 7.0 ? 'bg-orange-500/20 text-orange-200 ring-orange-500/40'
      : 'bg-slate-700/30 text-slate-300 ring-slate-600/40';
    badges.push({
      key: 'nvd',
      label: `NVD ${nvdScore.toFixed(1)}`,
      cls: intensity,
      title: `Authoritative CVSS aus NVD: ${nvdScore.toFixed(2)}`,
    });
  }
  if (edbCount > 0) {
    badges.push({
      key: 'edb',
      label: `ExploitDB ×${edbCount}`,
      cls: 'bg-amber-500/20 text-amber-200 ring-amber-500/40',
      title: `${edbCount} oeffentliche Exploit(s) in ExploitDB`,
    });
  }

  if (badges.length === 0) return null;

  return (
    <div className="flex flex-wrap gap-1.5">
      {badges.map((b) => (
        <span
          key={b.key}
          title={b.title}
          className={`inline-flex items-center rounded-md ring-1 px-1.5 py-0.5 font-mono text-[10px] font-semibold ${b.cls}`}
        >
          {b.label}
        </span>
      ))}
    </div>
  );
}
