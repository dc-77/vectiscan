import type { Metadata } from 'next';
import { Suspense } from 'react';
import { Inter } from 'next/font/google';
import './globals.css';
import AppHeader from '@/components/AppHeader';
import { ToastProvider } from '@/components/Toast';
import CookieConsent from '@/components/CookieConsent';
import AnalyticsBeacon from '@/components/AnalyticsBeacon';

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
        <ToastProvider>
        <Suspense fallback={null}>
          <AnalyticsBeacon />
        </Suspense>
        <AppHeader />
        <div className="flex-1 flex flex-col">
          {children}
        </div>
        {/* Trust footer (app-wide) */}
        <div className="text-center py-3 px-4 text-[10px] tracking-wide flex flex-col sm:flex-row items-center justify-center gap-1.5 sm:gap-3" style={{ color: '#475569', borderTop: '1px solid rgba(45,212,191,0.05)' }}>
          <span>🔒 AES-256 verschlüsselt · Hosting in Deutschland · DSGVO-konform</span>
          <span className="hidden sm:inline" style={{ color: '#334155' }}>·</span>
          <span className="flex items-center gap-3">
            <a href="/impressum" className="hover:text-gray-300 transition-colors">Impressum</a>
            <a href="/datenschutz" className="hover:text-gray-300 transition-colors">Datenschutz</a>
            <a href="/agb" className="hover:text-gray-300 transition-colors">AGB</a>
          </span>
        </div>
        <CookieConsent />
        </ToastProvider>
        {/* Global scanline overlay */}
        <div className="scanline-overlay" />
      </body>
    </html>
  );
}
