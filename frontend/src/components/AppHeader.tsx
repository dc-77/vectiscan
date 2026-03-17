'use client';

import { useState, useEffect } from 'react';
import { usePathname } from 'next/navigation';
import Link from 'next/link';
import { isLoggedIn, isAdmin, clearToken } from '@/lib/auth';

const HEX = '0123456789ABCDEF';
function rHex(n: number) { let s = ''; for (let i = 0; i < n; i++) s += HEX[Math.floor(Math.random() * 16)]; return s; }

const AUTH_PATHS = ['/login', '/forgot-password', '/reset-password'];

export default function AppHeader() {
  const pathname = usePathname();
  const isAuth = AUTH_PATHS.some(p => pathname.startsWith(p));
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

  const navItems = [
    { href: '/', label: 'Neuer Scan', exact: true, highlight: true },
    { href: '/dashboard', label: 'Dashboard' },
    { href: '/schedules', label: 'Zeitpläne' },
    { href: '/profile', label: 'Profil' },
  ] as const;

  return (
    <header className="h-10 shrink-0 flex items-center justify-between px-4"
      style={{ backgroundColor: '#0C1222', borderBottom: '1px solid rgba(30,58,95,0.3)' }}>
      {/* Left: Logo + text */}
      <Link href="/" className="flex items-center gap-2 hover:opacity-90 transition-opacity">
        <svg width="22" height="22" viewBox="0 0 44 44" fill="none" aria-hidden="true">
          <path d="M22 2L4 10v12c0 11 8 18 18 20 10-2 18-9 18-20V10L22 2z" fill="#1e293b" stroke="#3b82f6" strokeWidth="2" />
          <line x1="12" y1="22" x2="32" y2="22" stroke="#3b82f6" strokeWidth="1.5" opacity="0.8" />
          <line x1="22" y1="12" x2="22" y2="32" stroke="#3b82f6" strokeWidth="1.5" opacity="0.8" />
          <circle cx="22" cy="22" r="3" fill="#3b82f6" opacity="0.9" />
          <circle cx="22" cy="22" r="1.5" fill="#60a5fa" />
        </svg>
        <span className="text-sm font-bold text-white tracking-tight">
          Vecti<span className="text-blue-400">Scan</span>
        </span>
        <span className="text-[8px] font-mono text-slate-700 hidden sm:inline">//0x{hex}</span>
      </Link>

      {/* Right: Nav (only if authenticated and not on auth page) */}
      {!isAuth && authed && (
        <nav className="flex items-center gap-1">
          {navItems.map(item => {
            const isActive = 'exact' in item && item.exact ? pathname === item.href : pathname.startsWith(item.href);
            const isHighlight = 'highlight' in item && item.highlight;
            return (
              <Link key={item.href} href={item.href}
                className={`text-xs font-mono px-2 py-1.5 transition-colors ${
                  isHighlight && !isActive
                    ? 'text-[#38BDF8] hover:text-[#7DD3FC]'
                    : isActive
                      ? 'text-blue-400 border-b-2 border-blue-500'
                      : 'text-slate-500 hover:text-slate-200'
                }`}>
                {item.label}
              </Link>
            );
          })}
          {admin && (
            <Link href="/admin"
              className={`text-xs font-mono px-2 py-1.5 transition-colors ${
                pathname.startsWith('/admin')
                  ? 'text-blue-400 border-b-2 border-blue-500'
                  : 'text-slate-500 hover:text-slate-200'
              }`}>
              Admin
            </Link>
          )}
          <button onClick={handleLogout}
            className="text-xs font-mono text-slate-600 hover:text-red-400 px-2 py-1.5 ml-1 transition-colors">
            Abmelden
          </button>
        </nav>
      )}
    </header>
  );
}
