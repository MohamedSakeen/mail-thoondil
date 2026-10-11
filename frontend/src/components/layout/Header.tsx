import React from "react";
import { Link, useLocation } from "react-router-dom";
import { ShieldCheck, Plus, ArrowLeft } from "lucide-react";

interface HeaderProps {
  title?: string;
  subtitle?: string;
}

export const Header: React.FC<HeaderProps> = ({ title, subtitle }) => {
  const location = useLocation();

  const getPageTitle = () => {
    if (title) return title;
    if (location.pathname === "/") return "Security Dashboard";
    if (location.pathname === "/upload") return "Analyze Email";
    if (location.pathname === "/history") return "Analysis History";
    if (location.pathname.startsWith("/result/")) return "Analysis Deep Dive";
    return "Phishing Detector";
  };

  const isResultPage = location.pathname.startsWith("/result/");

  return (
    <header className="main-header">
      <div className="header-left">
        {isResultPage && (
          <Link to="/history" className="header-back-btn">
            <ArrowLeft size={16} />
            <span>History</span>
          </Link>
        )}
        <div>
          <h1 className="header-title">{getPageTitle()}</h1>
          {subtitle && <p className="header-subtitle">{subtitle}</p>}
        </div>
      </div>

      <div className="header-right">
        <div className="header-status-tag">
          <ShieldCheck size={16} className="text-accent-green" />
          <span>Rules & ML Active</span>
        </div>
        {location.pathname !== "/upload" && (
          <Link to="/upload" className="btn btn-primary btn-sm">
            <Plus size={16} />
            <span>New Scan</span>
          </Link>
        )}
      </div>
    </header>
  );
};

export default Header;
