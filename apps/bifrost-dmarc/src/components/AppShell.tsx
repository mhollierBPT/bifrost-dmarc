import { BifrostHeader } from "bifrost";
import { Building2, FileBarChart, GitCompareArrows, Globe2, LayoutDashboard, LoaderCircle, Menu, Settings, X } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";

import { BifrostSignature } from "./bifrost/BifrostSignature";
import { BfIconButton } from "./bifrost/BfButton";
import { relativeTime } from "../lib/format";
import type { IngestStatus } from "../types";

const navigation = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/organizations", label: "Organizations", icon: Building2 },
  { to: "/domains", label: "Domains", icon: Globe2 },
  { to: "/migration", label: "Migration", icon: GitCompareArrows },
  { to: "/reports", label: "Reports", icon: FileBarChart },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function AppShell({ children, ingest, loading = false }: { children: ReactNode; ingest?: IngestStatus | null; loading?: boolean }) {
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  const mainRef = useRef<HTMLElement>(null);

  useEffect(() => {
    setMenuOpen(false);
    mainRef.current?.scrollTo({ top: 0 });
  }, [location.pathname]);

  return (
    <div className="app-shell">
      <BifrostHeader
        className="app-header"
        title="DMARC"
        logo={null}
        action={(
          <BfIconButton className="header-menu-button" label="Toggle Navigation" icon={menuOpen ? <X /> : <Menu />} onClick={() => setMenuOpen((open) => !open)} aria-expanded={menuOpen} />
        )}
      />
      <aside className={`sidebar ${menuOpen ? "is-open" : ""}`} aria-label="DMARC navigation">
        <div>
          <NavLink className="sidebar-brand" to="/" aria-label="Bifrost DMARC home"><BifrostSignature /></NavLink>
          <nav>
            {navigation.map(({ to, label, icon: Icon }) => (
              <NavLink key={to} to={to} end={to === "/"}>
                <Icon aria-hidden="true" />
                <span>{label}</span>
              </NavLink>
            ))}
          </nav>
        </div>
        <div className="sidebar-foot">
          <div className="ingest-status">
            <span className={`status-dot ${ingest?.status === "failed" ? "is-error" : ""}`} />
            <div>
              <strong>Resend Inbound</strong>
              <span>{relativeTime(ingest?.completed_at)}</span>
            </div>
          </div>
        </div>
      </aside>
      {menuOpen ? <button className="sidebar-scrim" type="button" onClick={() => setMenuOpen(false)} aria-label="Close navigation" /> : null}
      <main className="main-content" ref={mainRef}>
        {loading ? <div className="global-loading" role="status" aria-live="polite"><LoaderCircle aria-hidden="true" /><span>Updating DMARC data</span></div> : null}
        {children}
      </main>
      <div id="dmarc-drawer-root" className="drawer-root" />
    </div>
  );
}
