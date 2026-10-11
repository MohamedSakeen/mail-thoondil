import React from "react";
import { Link, useLocation } from "react-router-dom";
import { LayoutDashboard, Upload, History, Shield } from "lucide-react";

interface SidebarProps {
  analysisCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ analysisCount }) => {
  const location = useLocation();

  const isActive = (path: string) => {
    if (path === "/" && location.pathname === "/") return "active";
    if (path !== "/" && location.pathname.startsWith(path)) return "active";
    return "";
  };

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-logo">
          <Shield size={22} className="brand-icon" />
        </div>
        <div className="brand-text">
          <span className="brand-title">mail thoondil</span>
          <span className="brand-subtitle">Email Security Platform</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-label">NAVIGATION</div>
        <Link to="/" className={`nav-item ${isActive("/")}`}>
          <LayoutDashboard size={18} />
          <span>Dashboard</span>
        </Link>
        <Link to="/upload" className={`nav-item ${isActive("/upload")}`}>
          <Upload size={18} />
          <span>Analyze Email</span>
        </Link>
        <Link to="/history" className={`nav-item ${isActive("/history")}`}>
          <History size={18} />
          <span>Analysis History</span>
          {analysisCount !== undefined && analysisCount > 0 && (
            <span className="nav-badge">{analysisCount}</span>
          )}
        </Link>
      </nav>

      <div className="sidebar-footer">
        <div className="system-status">
          <span className="status-dot online"></span>
          <div className="status-info">
            <span className="status-title">Detection Engine</span>
            <span className="status-detail">v0.1.0 • Operational</span>
          </div>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
