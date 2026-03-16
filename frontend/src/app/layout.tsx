import type { Metadata } from 'next';
import './globals.css';
import AppHeader from '@/components/AppHeader';

export const metadata: Metadata = {
  title: 'VectiScan',
  description: 'Automated Security Scan Platform',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="de" className="dark">
      <body className="min-h-screen bg-[#0C1222] text-gray-200 antialiased flex flex-col">
        <AppHeader />
        <div className="flex-1 flex flex-col">
          {children}
        </div>
        {/* Global scanline overlay */}
        <div className="scanline-overlay" />
      </body>
    </html>
  );
}
