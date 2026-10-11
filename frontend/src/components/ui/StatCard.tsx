import React from "react";

interface StatCardProps {
  title: string;
  value: number | string;
  subtitle?: string;
  icon?: React.ReactNode;
  accentColor?: string;
  trend?: string;
  trendPositive?: boolean;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  accentColor = "var(--accent-blue)",
  trend,
  trendPositive,
}) => {
  return (
    <div className="stat-card" style={{ borderTop: `3px solid ${accentColor}` }}>
      <div className="stat-card-top">
        <span className="stat-card-title">{title}</span>
        {icon && <span className="stat-card-icon" style={{ color: accentColor }}>{icon}</span>}
      </div>
      <div className="stat-card-value">{value}</div>
      {(subtitle || trend) && (
        <div className="stat-card-bottom">
          {trend && (
            <span className={`stat-trend ${trendPositive ? "trend-up" : "trend-down"}`}>
              {trend}
            </span>
          )}
          {subtitle && <span className="stat-subtitle">{subtitle}</span>}
        </div>
      )}
    </div>
  );
};

export default StatCard;
