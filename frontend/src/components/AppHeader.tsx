'use client';

import { useState, useEffect } from 'react';
import { usePathname } from 'next/navigation';
import Link from 'next/link';
import { isLoggedIn, isAdmin, clearToken } from '@/lib/auth';
import { VectiScanShield } from '@/components/VectiScanLogo';

const AUTH_PATHS = ['/login', '/forgot-password', '/reset-password'];

export default function AppHeader() {
  const pathname = usePathname();
  const isAuthPage = AUTH_PATHS.some(p => pathname.startsWith(p));
  const [authed, setAuthed] = useState(false);
  const [admin, setAdmin] = useState(false);

  useEffect(() => {
    setAuthed(isLoggedIn());
    setAdmin(isAdmin());
  }, [pathname]);

  const handleLogout = () => {
    clearToken();
    window.location.href = '/login';
  };

  // Build nav items based on auth + role
  const navItems: Array<{ href: string; label: string; highlight?: boolean }> = [];
  if (authed) {
    if (admin) {
      navItems.push({ href: '/scan', label: 'Neuer Scan' });
    }
    navItems.push({ href: '/subscribe', label: 'Neues Abo', highlight: true });
    navItems.push({ href: '/dashboard', label: 'Dashboard' });
    if (admin) {
      navItems.push({ href: '/schedules', label: 'Zeitpläne' });
    }
    navItems.push({ href: '/profile', label: 'Profil' });
  } else {
    navItems.push({ href: '/pricing', label: 'Pakete & Preise' });
    navItems.push({ href: '/login', label: 'Anmelden', highlight: true });
  }

  return (
    <header className="h-12 shrink-0 flex items-center justify-between px-5 sticky top-0 z-50"
      style={{
        backgroundColor: 'rgba(15, 23, 42, 0.85)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        borderBottom: '1px solid rgba(45, 212, 191, 0.08)',
      }}>
      {/* Left: Logo + Wordmark */}
      <Link href="/" className="flex items-center gap-2.5 hover:opacity-90 transition-opacity">
        <VectiScanShield size={24} variant="teal" />
        <span className="text-sm font-bold tracking-tight" style={{ letterSpacing: '-0.5px' }}>
          <span style={{ color: '#F8FAFC' }}>vecti</span>
          <span style={{ color: '#2DD4BF' }}>scan</span>
        </span>
      </Link>

      {/* Right: Nav */}
      {!isAuthPage && (
        <nav className="flex items-center gap-1">
          {navItems.map(item => {
            const isActive = pathname === item.href || (item.href !== '/' && pathname.startsWith(item.href));
            return (
              <Link key={item.href} href={item.href}
                className="text-xs font-medium px-3 py-1.5 rounded-md transition-colors"
                style={
                  isActive
                    ? { color: '#2DD4BF', backgroundColor: 'rgba(45, 212, 191, 0.08)' }
                    : item.highlight
                      ? { color: '#2DD4BF' }
                      : { color: '#94A3B8' }
                }
                onMouseEnter={e => {
                  if (!isActive) (e.currentTarget.style.color = '#F8FAFC');
                }}
                onMouseLeave={e => {
                  if (!isActive) (e.currentTarget.style.color = item.highlight ? '#2DD4BF' : '#94A3B8');
                }}>
                {item.label}
              </Link>
            );
          })}
          {admin && (
            <Link href="/admin"
              className="text-xs font-medium px-3 py-1.5 rounded-md transition-colors"
              style={
                pathname.startsWith('/admin')
                  ? { color: '#2DD4BF', backgroundColor: 'rgba(45, 212, 191, 0.08)' }
                  : { color: '#94A3B8' }
              }>
              Admin
            </Link>
          )}
          {authed && (
            <button onClick={handleLogout}
              className="text-xs font-medium px-3 py-1.5 rounded-md transition-colors"
              style={{ color: '#64748B' }}
              onMouseEnter={e => { e.currentTarget.style.color = '#EF4444'; }}
              onMouseLeave={e => { e.currentTarget.style.color = '#64748B'; }}>
              Abmelden
            </button>
          )}
        </nav>
      )}
    </header>
  );
}
