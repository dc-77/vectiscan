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
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => { setAuthed(isLoggedIn()); setAdmin(isAdmin()); }, [pathname]);
  useEffect(() => { setMenuOpen(false); }, [pathname]);
  useEffect(() => {
    document.body.style.overflow = menuOpen ? 'hidden' : '';
    return () => { document.body.style.overflow = ''; };
  }, [menuOpen]);
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') setMenuOpen(false); };
    window.addEventListener('keydown', h); return () => window.removeEventListener('keydown', h);
  }, []);

  const handleLogout = () => { clearToken(); window.location.href = '/login'; };

  const navItems: Array<{ href: string; label: string; highlight?: boolean }> = [];
  if (authed) {
    if (admin) navItems.push({ href: '/scan', label: 'Neuer Scan' });
    navItems.push({ href: '/subscribe', label: 'Neues Abo', highlight: true });
    navItems.push({ href: '/dashboard', label: 'Dashboard' });
    if (admin) navItems.push({ href: '/schedules', label: 'Zeitpläne' });
    navItems.push({ href: '/profile', label: 'Profil' });
  } else {
    navItems.push({ href: '/pricing', label: 'Pakete & Preise' });
    navItems.push({ href: '/login', label: 'Anmelden', highlight: true });
  }

  const linkStyle = (href: string, highlight?: boolean) => {
    const isActive = pathname === href || (href !== '/' && pathname.startsWith(href));
    return {
      color: isActive ? '#2DD4BF' : highlight ? '#2DD4BF' : '#94A3B8',
      backgroundColor: isActive ? 'rgba(45,212,191,0.08)' : 'transparent',
    };
  };

  return (
    <>
      <header className="h-12 shrink-0 flex items-center justify-between px-5 sticky top-0 z-50"
        style={{ backgroundColor: 'rgba(15,23,42,0.85)', backdropFilter: 'blur(20px)', WebkitBackdropFilter: 'blur(20px)', borderBottom: '1px solid rgba(45,212,191,0.08)' }}>
        <Link href="/" className="flex items-center gap-2.5 hover:opacity-90 transition-opacity">
          <VectiScanShield size={24} variant="teal" />
          <span className="text-sm font-bold tracking-tight" style={{ letterSpacing: '-0.5px' }}>
            <span style={{ color: '#F8FAFC' }}>vecti</span><span style={{ color: '#2DD4BF' }}>scan</span>
          </span>
        </Link>

        {/* Desktop nav */}
        {!isAuthPage && (
          <nav className="hidden md:flex items-center gap-1">
            {navItems.map(item => (
              <Link key={item.href} href={item.href}
                className="text-xs font-medium px-3 py-1.5 rounded-md transition-colors hover:text-white"
                style={linkStyle(item.href, item.highlight)}>
                {item.label}
              </Link>
            ))}
            {admin && (
              <Link href="/admin" className="text-xs font-medium px-3 py-1.5 rounded-md transition-colors hover:text-white"
                style={linkStyle('/admin')}>Admin</Link>
            )}
            {authed && (
              <button onClick={handleLogout}
                className="text-xs font-medium px-3 py-1.5 rounded-md transition-colors hover:text-red-400"
                style={{ color: '#64748B' }}>Abmelden</button>
            )}
          </nav>
        )}

        {/* Hamburger */}
        {!isAuthPage && (
          <button onClick={() => setMenuOpen(p => !p)}
            className="md:hidden relative w-8 h-8 flex items-center justify-center"
            aria-label={menuOpen ? 'Menü schließen' : 'Menü öffnen'} aria-expanded={menuOpen}>
            <span className="absolute w-5 h-[1.5px] rounded-full transition-all duration-300 ease-out"
              style={{ backgroundColor: '#F8FAFC', transform: menuOpen ? 'rotate(45deg)' : 'translateY(-6px)' }} />
            <span className="absolute w-5 h-[1.5px] rounded-full transition-all duration-300 ease-out"
              style={{ backgroundColor: '#F8FAFC', opacity: menuOpen ? 0 : 1, transform: menuOpen ? 'scaleX(0)' : 'scaleX(1)' }} />
            <span className="absolute w-5 h-[1.5px] rounded-full transition-all duration-300 ease-out"
              style={{ backgroundColor: '#F8FAFC', transform: menuOpen ? 'rotate(-45deg)' : 'translateY(6px)' }} />
          </button>
        )}
      </header>

      {/* Mobile overlay */}
      {!isAuthPage && (
        <div className="md:hidden fixed inset-0 z-40 transition-all duration-300 ease-out"
          style={{
            top: 48, pointerEvents: menuOpen ? 'auto' : 'none', opacity: menuOpen ? 1 : 0,
            backgroundColor: 'rgba(15,23,42,0.95)', backdropFilter: 'blur(24px)', WebkitBackdropFilter: 'blur(24px)',
          }}>
          <nav className="flex flex-col items-center gap-2 pt-16 px-6">
            {navItems.map((item, i) => (
              <Link key={item.href} href={item.href} onClick={() => setMenuOpen(false)}
                className="text-lg font-medium py-3 px-6 rounded-xl w-full max-w-xs text-center transition-all duration-300"
                style={{ ...linkStyle(item.href, item.highlight), transform: menuOpen ? 'translateY(0)' : 'translateY(-8px)', transitionDelay: `${i * 50}ms` }}>
                {item.label}
              </Link>
            ))}
            {admin && (
              <Link href="/admin" onClick={() => setMenuOpen(false)}
                className="text-lg font-medium py-3 px-6 rounded-xl w-full max-w-xs text-center"
                style={linkStyle('/admin')}>Admin</Link>
            )}
            {authed && (
              <button onClick={() => { handleLogout(); setMenuOpen(false); }}
                className="text-lg font-medium py-3 px-6 rounded-xl w-full max-w-xs text-center mt-4"
                style={{ color: '#64748B' }}>Abmelden</button>
            )}
          </nav>
        </div>
      )}
    </>
  );
}
