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
import { NavLink, Outlet, useLocation } from "react-router-dom";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  badge?: string;
}

const analysisNav: NavItem[] = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/analyze", label: "Static Analysis", icon: ScanSearch, badge: "Drebin-215" },
  { to: "/dynamic", label: "Dynamic Sandbox", icon: Activity, badge: "strace" },
];

const researchNav: NavItem[] = [
  { to: "/research", label: "Research & Benchmarks", icon: BookOpenText },
  { to: "/environment", label: "Environment & AVD", icon: Cpu },
  { to: "/about", label: "About & Methodology", icon: ShieldCheck },
];

export function Layout() {
  const location = useLocation();

  const getPageTitle = (path: string) => {
    switch (path) {
      case "/": return "SECURITY OVERVIEW";
      case "/analyze": return "STATIC DREBIN ANALYSIS";
      case "/dynamic": return "DYNAMIC SANDBOX TRACING";
      case "/research": return "RESEARCH & BENCHMARKS";
      case "/environment": return "ENVIRONMENT READINESS";
      case "/about": return "SYSTEM METHODOLOGY";
      default: return "SECURITY ANALYSIS PLATFORM";
    }
  };

  return (
    <div className="app-shell">
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="brand">
          <div className="brand-mark">
            <Shield size={20} strokeWidth={2.2} />
          </div>
          <div>
            <span className="brand-name">SENTINEL AI</span>
            <span className="brand-caption">ANDROID THREAT INTELLIGENCE</span>
          </div>
        </div>

        <div className="nav-heading">DETECTION ENGINES</div>
        <nav className="nav-list">
          {analysisNav.map(({ to, label, icon: Icon, badge }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) => `nav-link${isActive ? " nav-active" : ""}`}
            >
              <Icon size={16} strokeWidth={1.9} aria-hidden="true" />
              <span>{label}</span>
              {badge && <span className="nav-badge">{badge}</span>}
            </NavLink>
          ))}
        </nav>

        <div className="nav-heading" style={{ marginTop: "18px" }}>AUDIT &amp; PLATFORM</div>
        <nav className="nav-list">
          {researchNav.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) => `nav-link${isActive ? " nav-active" : ""}`}
            >
              <Icon size={16} strokeWidth={1.9} aria-hidden="true" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <span className="footer-dot pulse-glow" />
          <span>Local Engine Active</span>
        </div>
      </aside>

      <main className="main-shell">
        <header className="topbar">
          <div className="topbar-left">
            <span className="topbar-breadcrumb">SENTINEL</span>
            <span className="topbar-divider">/</span>
            <span className="topbar-label">{getPageTitle(location.pathname)}</span>
          </div>
          <div className="topbar-status">
            <span className="status-badge">
              <span className="status-dot good" />
              <span>READY</span>
            </span>
            <span className="topbar-env-pill">Dual Pipeline (Static + Dynamic)</span>
          </div>
        </header>

        <div className="page-content">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
