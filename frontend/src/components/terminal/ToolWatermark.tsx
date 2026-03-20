'use client';

import { useEffect, useState } from 'react';

// Tool category -> SVG path data (24x24 viewBox, simple icons)
const TOOL_ICONS: Record<string, string> = {
  // Crosshair -- port scanning (nmap)
  port_scan: 'M12 2v4m0 12v4M2 12h4m12 0h4m-8-6a6 6 0 100 12 6 6 0 000-12zm0 2a4 4 0 110 8 4 4 0 010-8z',
  // Spider web -- web crawling (zap_spider, katana, feroxbuster)
  web_crawl: 'M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5',
  // Shield with exclamation -- vulnerability scanning (nuclei, nikto, dalfox)
  vulnerability: 'M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5zm0 6v4m0 4h.01',
  // Lock -- encryption (testssl)
  encryption: 'M19 11H5a2 2 0 00-2 2v7a2 2 0 002 2h14a2 2 0 002-2v-7a2 2 0 00-2-2zm-2 0V7a5 5 0 00-10 0v4m5 3v3',
  // Globe with connections -- DNS (dnsx, subfinder, crtsh)
  dns: 'M12 2a10 10 0 100 20 10 10 0 000-20zm0 2c1.66 0 3 3.58 3 8s-1.34 8-3 8-3-3.58-3-8 1.34-8 3-8zM2 12h20',
  // Signal noise -- fuzzing (ffuf, gobuster)
  fuzzing: 'M4 12h2l2-6 2 12 2-8 2 10 2-4h2M2 6h4m12 0h4M2 18h4m12 0h4',
};

function getToolCategory(tool: string): string {
  if (/nmap/i.test(tool)) return 'port_scan';
  if (/zap|spider|crawl|ferox|katana/i.test(tool)) return 'web_crawl';
  if (/nuclei|nikto|dalfox|vuln/i.test(tool)) return 'vulnerability';
  if (/testssl|ssl|tls/i.test(tool)) return 'encryption';
  if (/dns|subfinder|crtsh|amass|gobuster_dns/i.test(tool)) return 'dns';
  if (/ffuf|fuzz|gobuster_dir|param/i.test(tool)) return 'fuzzing';
  return 'vulnerability'; // default
}

interface ToolWatermarkProps {
  currentTool: string;
}

export default function ToolWatermark({ currentTool }: ToolWatermarkProps) {
  const [visible, setVisible] = useState(false);
  const [category, setCategory] = useState('');

  useEffect(() => {
    if (!currentTool) return;
    const cat = getToolCategory(currentTool);
    setCategory(cat);
    setVisible(true);

    const timer = setTimeout(() => setVisible(false), 3000);
    return () => clearTimeout(timer);
  }, [currentTool]);

  const path = TOOL_ICONS[category];
  if (!path) return null;

  return (
    <div
      className="absolute bottom-4 right-4 pointer-events-none select-none"
      style={{
        width: 180,
        height: 180,
        opacity: visible ? 0.04 : 0,
        transition: visible ? 'opacity 0.3s ease-in' : 'opacity 2s ease-out',
      }}
    >
      <svg viewBox="0 0 24 24" fill="none" stroke="#38BDF8" strokeWidth="0.5"
           strokeLinecap="round" strokeLinejoin="round" className="w-full h-full">
        <path d={path} />
      </svg>
    </div>
  );
}
