"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  ChevronDown,
  CircleHelp,
  FileBarChart2,
  FolderKanban,
  Menu,
  ScanEye,
  ShieldCheck,
  Upload,
  X,
} from "lucide-react";
import "./workspace.css";

const navigation = [
  { label: "Overview", href: "/dashboard", icon: Activity },
  { label: "Projects", href: "/dashboard#projects", icon: FolderKanban },
  { label: "Scan findings", href: "/scans/demo-scan", icon: ScanEye },
  { label: "Verified fixes", href: "/remediation", icon: ShieldCheck },
  { label: "Reports", href: "/reports", icon: FileBarChart2 },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <div className="workspace-shell">
      <aside className={`workspace-sidebar ${menuOpen ? "sidebar-open" : ""}`}>
        <div className="sidebar-top">
          <Link className="workspace-brand" href="/dashboard" onClick={() => setMenuOpen(false)}>
            <span className="workspace-brand-mark"><ScanEye size={19} /></span><span>ARGUS<span>.</span></span>
          </Link>
          <button className="mobile-close icon-button" aria-label="Close navigation" onClick={() => setMenuOpen(false)}><X size={17} /></button>
        </div>
        <button className="workspace-switcher" aria-label="Current workspace">
          <span className="workspace-avatar">A</span><span><b>ARGUS preview</b><small>Demo workspace</small></span><ChevronDown size={14} />
        </button>
        <div className="sidebar-label">WORKSPACE</div>
        <nav className="workspace-nav" aria-label="Workspace navigation">
          {navigation.map(({ label, href, icon: Icon }) => {
            const active = label !== "Projects" && (pathname === href || (href !== "/dashboard" && pathname.startsWith(href)));
            return <Link key={href} className={`workspace-nav-link ${active ? "nav-active" : ""}`} href={href} onClick={() => setMenuOpen(false)}><Icon size={16} strokeWidth={1.8} /><span>{label}</span>{label === "Scan findings" ? <i className="nav-count">31</i> : null}</Link>;
          })}
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-status"><span className="status-dot" /><span><b>Backend disconnected</b><small>Preview mode</small></span></div>
          <Link className="sidebar-help" href="/#workflow"><CircleHelp size={15} /> Product workflow</Link>
          <div className="sidebar-user"><span className="user-avatar">P</span><span><b>Preview user</b><small>Local demo</small></span><button aria-label="User menu" className="icon-button"><ChevronDown size={14} /></button></div>
        </div>
      </aside>
      {menuOpen ? <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setMenuOpen(false)} /> : null}
      <div className="workspace-main">
        <header className="workspace-topbar">
          <button className="mobile-menu icon-button" aria-label="Open navigation" onClick={() => setMenuOpen(true)}><Menu size={19} /></button>
          <div className="topbar-context"><span>Workspace</span><i>/</i><b>{navigation.find((item) => item.href === pathname)?.label ?? (pathname.startsWith("/upload") ? "Upload project" : pathname.startsWith("/vulnerabilities") ? "Finding details" : pathname.startsWith("/remediation") ? "Verified fixes" : pathname.startsWith("/reports") ? "Reports" : "Scan findings")}</b></div>
          <div className="topbar-right"><span className="topbar-mode"><i /> DEMO MODE</span><Link className="topbar-upload" href="/upload"><Upload size={15} /><span>New scan</span></Link></div>
        </header>
        <main className="workspace-content">{children}</main>
      </div>
    </div>
  );
}