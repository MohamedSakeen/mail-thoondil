import React from "react";
import Card from "../ui/Card";

interface RiskDistributionChartProps {
  counts: {
    benign: number;
    suspicious: number;
    high_suspicious: number;
    phishing: number;
  };
}

export const RiskDistributionChart: React.FC<RiskDistributionChartProps> = ({ counts }) => {
  const total = counts.benign + counts.suspicious + counts.high_suspicious + counts.phishing;

  const items = [
    { label: "Benign", count: counts.benign, color: "var(--accent-green)", class: "benign" },
    { label: "Suspicious", count: counts.suspicious, color: "var(--accent-yellow)", class: "suspicious" },
    { label: "High Suspicious", count: counts.high_suspicious, color: "var(--accent-orange)", class: "high_suspicious" },
    { label: "Phishing", count: counts.phishing, color: "var(--accent-red)", class: "phishing" },
  ];

  return (
    <Card title="Threat Classification Breakdown" subtitle="Distribution across all analyzed emails">
      {total === 0 ? (
        <div style={{ padding: "20px 0", textAlign: "center", color: "var(--text-muted)" }}>
          No threat classification data recorded yet.
        </div>
      ) : (
        <div className="chart-container">
          {/* Stacked Progress Bar Chart */}
          <div className="stacked-bar">
            {items.map((item) => {
              const pct = total > 0 ? (item.count / total) * 100 : 0;
              if (pct === 0) return null;
              return (
                <div
                  key={item.label}
                  className={`bar-segment bar-${item.class}`}
                  style={{ width: `${pct}%`, backgroundColor: item.color }}
                  title={`${item.label}: ${item.count} (${pct.toFixed(1)}%)`}
                />
              );
            })}
          </div>

          {/* Metric Breakdown Grid */}
          <div className="chart-legend-grid">
            {items.map((item) => {
              const pct = total > 0 ? (item.count / total) * 100 : 0;
              return (
                <div key={item.label} className="legend-item">
                  <div className="legend-header">
                    <span className="legend-dot" style={{ backgroundColor: item.color }} />
                    <span className="legend-label">{item.label}</span>
                  </div>
                  <div className="legend-stats">
                    <span className="legend-count">{item.count}</span>
                    <span className="legend-pct">({pct.toFixed(0)}%)</span>
                  </div>
                  <div className="legend-bar-track">
                    <div
                      className="legend-bar-fill"
                      style={{ width: `${pct}%`, backgroundColor: item.color }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </Card>
  );
};

export default RiskDistributionChart;
