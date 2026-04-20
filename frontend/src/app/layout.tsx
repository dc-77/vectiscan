import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import AppHeader from '@/components/AppHeader';

const inter = Inter({ subsets: ['latin'], display: 'swap' });

export const metadata: Metadata = {
  title: 'VectiScan — Automatisierte Security-Analyse',
  description: 'Automatisierte Perimeter-Analyse fur Ihre IT-Infrastruktur. Regelmaessige Scans, professionelle Reports, Compliance-Nachweise. Made in Germany.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="de" className="dark">
      <body className={`${inter.className} min-h-screen bg-[#0C1222] text-gray-200 antialiased flex flex-col`}>
        <AppHeader />
        <div className="flex-1 flex flex-col">
          {children}
        </div>
        {/* Trust footer (app-wide) */}
        <div className="text-center py-3 text-[10px] tracking-wide" style={{ color: '#475569', borderTop: '1px solid rgba(45,212,191,0.05)' }}>
          🔒 AES-256 verschlüsselt · Hosting in Deutschland · DSGVO-konform
        </div>
        {/* Global scanline overlay */}
        <div className="scanline-overlay" />
      </body>
    </html>
  );
}
