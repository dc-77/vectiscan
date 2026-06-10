'use client';

// ── AppShell (VEC-306, behebt H4/H5) ────────────────────────────
// Ersetzt rollen-/zustandsblindes Top-Nav für eingeloggte App-Bereiche.
// Entscheidet anhand des Pfads: App-Seiten → Sidebar+Content, sonst
// öffentlicher Top-Header via AppHeader.
//
// Strukturen:
//   Desktop: [Sidebar 240px fixed links] + [main flex-1 scroll]
//   Mobile:  [Top slim bar] + [main scroll] + [Bottom Tab-Bar 4 Tabs]
//            + Drawer (Hamburger für Zusatz-Links)
//
// "Calm shell": kein Scanline-/Glow-Effekt hier; sie bleiben /scan/[id]-only.

import { useState, useEffect, useCallback } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import Link from 'next/link';
import { isLoggedIn, isAdmin, clearToken } from '@/lib/auth';
import { VectiScanShield } from '@/components/VectiScanLogo';
import AppHeader from '@/components/AppHeader';

// ─── Routen, für die die AppShell statt des Top-Headers greift ───
const APP_PREFIXES = [
  '/dashboard', '/scan', '/scans', '/profile', '/schedules',
  '/subscribe', '/verify', '/welcome', '/admin',
  '/subscription', '/subscriptions',
];

function isAppPath(pathname: string) {
  return APP_PREFIXES.some(p => pathname === p || pathname.startsWith(p + '/'));
}

// ─── Nav-Items Definition ─────────────────────────────────────────
interface NavItem {
  href: string;
  label: string;
  icon: React.ReactNode;
  adminOnly?: boolean;
  mobileTab?: boolean; // zeigt auf mobile Bottom-Tab
}

function ShieldIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}
function DashboardIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden>
      <rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" />
    </svg>
  );
}
function ScanListIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden>
      <path d="M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2" />
      <rect x="9" y="3" width="6" height="4" rx="1" />
      <path d="M9 12h6" /><path d="M9 16h4" />
    </svg>
  );
}
function SubscribeIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden>
      <path d="M12 2L2 7l10 5 10-5-10-5z" /><path d="M2 17l10 5 10-5" /><path d="M2 12l10 5 10-5" />
    </svg>
  );
}
function PlusCircleIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden>
      <circle cx="12" cy="12" r="9" /><path d="M12 8v8" /><path d="M8 12h8" />
    </svg>
  );
}
function UserIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden>
      <circle cx="12" cy="8" r="4" /><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7" />
    </svg>
  );
}
function AdminIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14" />
    </svg>
  );
}
function LogoutIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden>
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><polyline points="16 17 21 12 16 7" /><line x1="21" y1="12" x2="9" y2="12" />
    </svg>
  );
}
function MenuIcon({ open }: { open: boolean }) {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden>
      {open
        ? <><path d="M18 6 6 18" /><path d="M6 6l12 12" /></>
        : <><path d="M3 6h18" /><path d="M3 12h18" /><path d="M3 18h18" /></>}
    </svg>
  );
}

// ─── Pill — aktiver Zustand im Nav (nicht nur Farbe) ─────────────
function NavPill({
  item, pathname, onClick, collapsed,
}: {
  item: NavItem; pathname: string; onClick?: () => void; collapsed?: boolean;
}) {
  const isActive = pathname === item.href || (item.href !== '/' && pathname.startsWith(item.href + '/'))
    || (item.href === '/scans' && pathname.startsWith('/scans'));
  const color = 'var(--tone-active)';

  return (
    <Link
      href={item.href}
      onClick={onClick}
      className="relative flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors min-h-[44px] group"
      style={{
        color: isActive ? color : 'var(--text-muted)',
        backgroundColor: isActive ? `color-mix(in srgb, ${color} 10%, transparent)` : 'transparent',
      }}
      aria-current={isActive ? 'page' : undefined}
    >
      {isActive && (
        <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-6 rounded-r-full" style={{ backgroundColor: color }} />
      )}
      <span className="shrink-0">{item.icon}</span>
      {!collapsed && <span className="text-sm font-medium truncate">{item.label}</span>}
    </Link>
  );
}

// ─── Bottom-Tab (Mobile) ─────────────────────────────────────────
function BottomTab({ item, pathname }: { item: NavItem; pathname: string }) {
  const isActive = pathname === item.href || (item.href !== '/' && pathname.startsWith(item.href + '/'));
  const color = 'var(--tone-active)';
  return (
    <Link href={item.href}
      className="flex flex-col items-center gap-0.5 px-3 py-2 transition-colors min-w-[60px]"
      style={{ color: isActive ? color : 'var(--text-dim)' }}
      aria-current={isActive ? 'page' : undefined}
    >
      {item.icon}
      <span className="text-[10px] font-medium">{item.label}</span>
      {isActive && <span className="w-4 h-0.5 rounded-full mt-0.5" style={{ backgroundColor: color }} />}
    </Link>
  );
}

// ─── AppShell ────────────────────────────────────────────────────
export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [authed, setAuthed] = useState(false);
  const [admin, setAdmin] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);

  useEffect(() => {
    setAuthed(isLoggedIn());
    setAdmin(isAdmin());
  }, [pathname]);

  useEffect(() => { setDrawerOpen(false); }, [pathname]);

  useEffect(() => {
    document.body.style.overflow = drawerOpen ? 'hidden' : '';
    return () => { document.body.style.overflow = ''; };
  }, [drawerOpen]);

  const handleLogout = useCallback(() => {
    clearToken();
    router.replace('/login');
  }, [router]);

  // Öffentliche Seiten / Auth → normaler AppHeader
  if (!isAppPath(pathname) || !authed) {
    return (
      <>
        <AppHeader />
        <div className="flex-1 flex flex-col">{children}</div>
      </>
    );
  }

  // ─── NAV-Items (rollenabhängig) ─────────────────────────────
  const primaryTabs: NavItem[] = [
    { href: '/dashboard', label: 'Dashboard', icon: <DashboardIcon />, mobileTab: true },
    { href: '/scans', label: 'Meine Scans', icon: <ScanListIcon />, mobileTab: true },
    { href: '/subscribe', label: 'Abos & Zeitpläne', icon: <SubscribeIcon />, mobileTab: true },
    { href: '/scan/new', label: 'Neuer Scan', icon: <PlusCircleIcon />, mobileTab: true },
  ];

  const secondaryItems: NavItem[] = [
    { href: '/profile', label: 'Profil', icon: <UserIcon /> },
    ...(admin ? [{ href: '/admin', label: 'Admin', icon: <AdminIcon />, adminOnly: true as const }] : []),
  ];

  const mobileTabs = primaryTabs.filter(i => i.mobileTab);

  // ─── DESKTOP: Sidebar + Content ────────────────────────────
  return (
    <div className="flex-1 flex overflow-hidden">
      {/* ── Sidebar (Desktop only) ──────────────────────── */}
      <aside
        className="hidden md:flex flex-col shrink-0 border-r"
        style={{
          width: 240,
          backgroundColor: 'var(--surface)',
          borderColor: 'var(--border-muted)',
        }}
      >
        {/* Logo */}
        <div className="px-4 py-4 border-b flex items-center gap-2.5" style={{ borderColor: 'var(--border-muted)' }}>
          <Link href="/" className="flex items-center gap-2.5 hover:opacity-90 transition-opacity">
            <VectiScanShield size={28} variant="teal" />
            <span className="text-[15px] font-bold tracking-tight">
              <span style={{ color: 'var(--text)' }}>vecti</span>
              <span style={{ color: 'var(--tone-active)' }}>scan</span>
            </span>
          </Link>
        </div>

        {/* Primary nav */}
        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-0.5" aria-label="Hauptnavigation">
          {primaryTabs.map(item => (
            <NavPill key={item.href} item={item} pathname={pathname} />
          ))}
          <div className="h-px my-3" style={{ backgroundColor: 'var(--border-muted)' }} />
          {secondaryItems.map(item => (
            <NavPill key={item.href} item={item} pathname={pathname} />
          ))}
        </nav>

        {/* Bottom: Support + Logout */}
        <div className="px-3 py-3 border-t space-y-1" style={{ borderColor: 'var(--border-muted)' }}>
          <Link href="/contact"
            className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors min-h-[44px]"
            style={{ color: 'var(--text-dim)' }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden>
              <circle cx="12" cy="12" r="9" /><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" /><path d="M12 17h.01" />
            </svg>
            Support
          </Link>
          <button onClick={handleLogout}
            className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors min-h-[44px] w-full text-left"
            style={{ color: 'var(--text-dim)' }}>
            <LogoutIcon />
            Abmelden
          </button>
        </div>
      </aside>

      {/* ── Mobile Top Bar ────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <div className="md:hidden flex items-center justify-between px-4 h-12 shrink-0 border-b z-20"
          style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border-muted)' }}>
          <Link href="/" className="flex items-center gap-2">
            <VectiScanShield size={24} variant="teal" />
            <span className="text-sm font-bold">
              <span style={{ color: 'var(--text)' }}>vecti</span>
              <span style={{ color: 'var(--tone-active)' }}>scan</span>
            </span>
          </Link>
          <button onClick={() => setDrawerOpen(p => !p)} aria-label={drawerOpen ? 'Menü schließen' : 'Menü öffnen'} aria-expanded={drawerOpen}
            className="p-2 rounded-md transition-colors min-h-[44px] min-w-[44px] flex items-center justify-center"
            style={{ color: 'var(--text-muted)' }}>
            <MenuIcon open={drawerOpen} />
          </button>
        </div>

        {/* Mobile Drawer */}
        {drawerOpen && (
          <div className="md:hidden fixed inset-0 z-40"
            style={{ top: 48, backgroundColor: 'rgba(15,23,42,0.95)', backdropFilter: 'blur(16px)' }}>
            <nav className="flex flex-col px-4 pt-6 gap-1" aria-label="Mobilnavigation">
              {[...primaryTabs, ...secondaryItems].map(item => (
                <NavPill key={item.href} item={item} pathname={pathname} onClick={() => setDrawerOpen(false)} />
              ))}
              <div className="h-px my-3" style={{ backgroundColor: 'var(--border-muted)' }} />
              <button onClick={handleLogout}
                className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm min-h-[44px]"
                style={{ color: 'var(--text-dim)' }}>
                <LogoutIcon /> Abmelden
              </button>
            </nav>
          </div>
        )}

        {/* ── Page Content ─────────────────────────────── */}
        <main className="flex-1 overflow-y-auto pb-[72px] md:pb-0">
          {children}
        </main>

        {/* ── Mobile Bottom Tab-Bar ──────────────────────── */}
        <nav aria-label="Hauptnavigation (Mobile)"
          className="md:hidden fixed bottom-0 left-0 right-0 flex items-center justify-around px-2 z-30 border-t"
          style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border-muted)', paddingBottom: 'env(safe-area-inset-bottom)' }}>
          {mobileTabs.map(item => (
            <BottomTab key={item.href} item={item} pathname={pathname} />
          ))}
        </nav>
      </div>
    </div>
  );
}
