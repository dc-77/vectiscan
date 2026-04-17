'use client';

import { useState, useEffect } from 'react';
import { usePathname } from 'next/navigation';
import Link from 'next/link';
import { isLoggedIn, isAdmin, clearToken } from '@/lib/auth';

const HEX = '0123456789ABCDEF';
function rHex(n: number) { let s = ''; for (let i = 0; i < n; i++) s += HEX[Math.floor(Math.random() * 16)]; return s; }

const AUTH_PATHS = ['/login', '/forgot-password', '/reset-password'];
const TEAL = '#2DD4BF';
const TEAL_HOVER = '#5EEAD4';

export default function AppHeader() {
  const pathname = usePathname();
  const isAuthPage = AUTH_PATHS.some(p => pathname.startsWith(p));
  const [hex, setHex] = useState('0000');
  const [authed, setAuthed] = useState(false);
  const [admin, setAdmin] = useState(false);

  useEffect(() => {
    setAuthed(isLoggedIn());
    setAdmin(isAdmin());
  }, [pathname]);

  useEffect(() => {
    const iv = setInterval(() => setHex(rHex(4)), 2000);
    return () => clearInterval(iv);
  }, []);

  const handleLogout = () => {
    clearToken();
    window.location.href = '/login';
  };

  // Build nav items based on auth + role
  const navItems: Array<{ href: string; label: string; highlight?: boolean }> = [];
  if (authed) {
    if (admin) {
      navItems.push({ href: '/scan', label: 'Neuer Scan', highlight: true });
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
    <header className="h-10 shrink-0 flex items-center justify-between px-4"
      style={{ backgroundColor: '#0C1222', borderBottom: '1px solid rgba(30,58,95,0.3)' }}>
      {/* Left: Logo */}
      <Link href="/" className="flex items-center gap-2 hover:opacity-90 transition-opacity">
        <svg width="22" height="22" viewBox="0 0 44 44" fill="none" aria-hidden="true">
          <path d="M22 2L4 10v12c0 11 8 18 18 20 10-2 18-9 18-20V10L22 2z" fill="#1e293b" stroke={TEAL} strokeWidth="2" />
          <line x1="12" y1="22" x2="32" y2="22" stroke={TEAL} strokeWidth="1.5" opacity="0.8" />
          <line x1="22" y1="12" x2="22" y2="32" stroke={TEAL} strokeWidth="1.5" opacity="0.8" />
          <circle cx="22" cy="22" r="3" fill={TEAL} opacity="0.9" />
          <circle cx="22" cy="22" r="1.5" fill={TEAL_HOVER} />
        </svg>
        <span className="text-sm font-bold text-white tracking-tight">
          Vecti<span style={{ color: TEAL }}>Scan</span>
        </span>
        <span className="text-[8px] font-mono text-slate-700 hidden sm:inline">//0x{hex}</span>
      </Link>

      {/* Right: Nav */}
      {!isAuthPage && (
        <nav className="flex items-center gap-0.5">
          {navItems.map(item => {
            const isActive = pathname === item.href || (item.href !== '/' && pathname.startsWith(item.href));
            return (
              <Link key={item.href} href={item.href}
                className={`text-xs px-2.5 py-1.5 rounded transition-colors ${
                  isActive
                    ? 'text-white font-medium'
                    : item.highlight
                      ? 'font-medium hover:text-white'
                      : 'text-slate-500 hover:text-slate-200'
                }`}
                style={
                  isActive
                    ? { color: TEAL, borderBottom: `2px solid ${TEAL}` }
                    : item.highlight && !isActive
                      ? { color: TEAL }
                      : undefined
                }>
                {item.label}
              </Link>
            );
          })}
          {admin && (
            <Link href="/admin"
              className="text-xs px-2.5 py-1.5 rounded transition-colors"
              style={
                pathname.startsWith('/admin')
                  ? { color: TEAL, borderBottom: `2px solid ${TEAL}` }
                  : { color: '#64748B' }
              }>
              Admin
            </Link>
          )}
          {authed && (
            <button onClick={handleLogout}
              className="text-xs text-slate-600 hover:text-red-400 px-2.5 py-1.5 ml-1 transition-colors">
              Abmelden
            </button>
          )}
        </nav>
      )}
    </header>
  );
}
