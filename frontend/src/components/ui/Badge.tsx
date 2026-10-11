import React from "react";

export type ClassificationType = "benign" | "suspicious" | "high_suspicious" | "phishing" | string;

interface BadgeProps {
  classification: ClassificationType;
  size?: "sm" | "md" | "lg";
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({ classification, size = "md", className = "" }) => {
  const norm = (classification || "benign").toLowerCase().replace(/\s+/g, "_");
  
  const displayLabel = {
    benign: "Benign",
    suspicious: "Suspicious",
    high_suspicious: "High Suspicious",
    phishing: "Phishing",
  }[norm] || classification;

  return (
    <span className={`badge badge-${norm} badge-${size} ${className}`}>
      {displayLabel}
    </span>
  );
};

export default Badge;
