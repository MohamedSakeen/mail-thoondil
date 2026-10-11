import React from "react";

interface LoadingSpinnerProps {
  label?: string;
  sublabel?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  label = "Loading...",
  sublabel,
}) => {
  return (
    <div className="loading">
      <div className="spinner" />
      <p style={{ marginTop: 12, fontWeight: 500 }}>{label}</p>
      {sublabel && <p style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 4 }}>{sublabel}</p>}
    </div>
  );
};

export default LoadingSpinner;
