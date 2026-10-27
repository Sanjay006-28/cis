import {
  Activity,
  BookOpenText,
  Cpu,
  LayoutDashboard,
  ScanSearch,
  Shield,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";

const navigation: Array<{ to: string; label: string; icon: LucideIcon }> = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/analyze", label: "Analyze APK", icon: ScanSearch },
  { to: "/dynamic", label: "Dynamic Analysis", icon: Activity },
  { to: "/environment", label: "Environment & Emulator", icon: Cpu },
  { to: "/research", label: "Research & Benchmarks", icon: BookOpenText },
  { to: "/about", label: "About & Methodology", icon: ShieldCheck },
];

export function Layout() {
  return (
    <div className="app-shell">
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="brand">
          <div className="brand-mark"><Shield size={19} /></div>
          <div>
            <span className="brand-name">SENTINEL</span>
            <span className="brand-caption">ANDROID THREAT ANALYSIS</span>
          </div>
        </div>
        <div className="nav-heading">WORKSPACE</div>
        <nav className="nav-list">
          {navigation.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) => `nav-link${isActive ? " nav-active" : ""}`}
            >
              <Icon size={17} strokeWidth={1.8} aria-hidden="true" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <span className="footer-dot" />
          Local analysis workspace
        </div>
      </aside>
      <main className="main-shell">
        <header className="topbar">
          <div className="topbar-label">SECURITY ANALYSIS PLATFORM</div>
          <div className="topbar-status">
            <span className="status-dot" />
            Local environment
          </div>
        </header>
        <div className="page-content">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
