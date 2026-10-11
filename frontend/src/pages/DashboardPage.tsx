import React, { useState, useEffect } from "react";
import { Shield, ShieldAlert, ShieldCheck, AlertTriangle } from "lucide-react";
import StatCard from "../components/ui/StatCard";
import RiskDistributionChart from "../components/dashboard/RiskDistributionChart";
import QuickUploadWidget from "../components/dashboard/QuickUploadWidget";
import RecentActivityTable from "../components/dashboard/RecentActivityTable";
import LoadingSpinner from "../components/ui/LoadingSpinner";
import { listAnalyses, type AnalysisListItem } from "../api";

export const DashboardPage: React.FC = () => {
  const [analyses, setAnalyses] = useState<AnalysisListItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listAnalyses(50, 0)
      .then(setAnalyses)
      .catch((err) => console.error("Failed to load analyses for dashboard:", err))
      .finally(() => setLoading(false));
  }, []);

  // Compute stat counts
  const totalScans = analyses.length;
  const counts = {
    benign: 0,
    suspicious: 0,
    high_suspicious: 0,
    phishing: 0,
  };

  analyses.forEach((item) => {
    const norm = (item.classification || "").toLowerCase().replace(/\s+/g, "_");
    if (norm in counts) {
      counts[norm as keyof typeof counts]++;
    } else {
      counts.benign++;
    }
  });

  const threatCount = counts.phishing + counts.high_suspicious;
  const threatRate = totalScans > 0 ? ((threatCount / totalScans) * 100).toFixed(0) : "0";

  if (loading) {
    return <LoadingSpinner label="Loading security dashboard metrics..." />;
  }

  return (
    <div className="dashboard-page">
      {/* Top Stat KPI Grid */}
      <div className="stat-grid">
        <StatCard
          title="Total Scans"
          value={totalScans}
          subtitle="Processed emails"
          icon={<Shield size={20} />}
          accentColor="var(--accent-blue)"
        />
        <StatCard
          title="Phishing Threats"
          value={counts.phishing}
          subtitle={`${threatRate}% overall threat rate`}
          icon={<ShieldAlert size={20} />}
          accentColor="var(--accent-red)"
        />
        <StatCard
          title="Suspicious Mails"
          value={counts.suspicious + counts.high_suspicious}
          subtitle="Requires analyst review"
          icon={<AlertTriangle size={20} />}
          accentColor="var(--accent-yellow)"
        />
        <StatCard
          title="Benign Emails"
          value={counts.benign}
          subtitle="Verified clean"
          icon={<ShieldCheck size={20} />}
          accentColor="var(--accent-green)"
        />
      </div>

      {/* Main Grid: Upload Widget + Risk Chart */}
      <div className="dashboard-main-grid">
        <QuickUploadWidget />
        <RiskDistributionChart counts={counts} />
      </div>

      {/* Bottom Table: Recent Activity */}
      <div className="dashboard-bottom-section">
        <RecentActivityTable items={analyses} />
      </div>
    </div>
  );
};

export default DashboardPage;
