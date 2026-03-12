import type { Metadata } from 'next';
import './globals.css';

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
      <body className="min-h-screen bg-[#0f172a] text-gray-200 antialiased">
        {children}
      </body>
    </html>
  );
}
