import React from "react";
import Card from "../ui/Card";
import Badge from "../ui/Badge";
import { type AnalysisResult } from "../../api";

interface RiskHeaderCardProps {
  result: AnalysisResult;
}

export const RiskHeaderCard: React.FC<RiskHeaderCardProps> = ({ result }) => {
  const classification = result.risk.classification;
  const score = result.risk.score;
  const confidence = result.risk.confidence;
  const explanation = result.explanation;

  return (
    <Card className="risk-header-card">
      <div className="risk-header-grid">
        {/* Risk Score Ring Gauge */}
        <div className="risk-gauge-box">
          <div className={`score-ring score-${classification.toLowerCase().replace(/\s+/g, "_")}`}>
            <span className="score-number">{Math.round(score)}</span>
            <span className="score-max">/100</span>
          </div>
        </div>

        {/* Classification & Verdict Meta */}
        <div className="risk-meta-box">
          <div className="risk-badge-row">
            <Badge classification={classification} size="lg" />
            {confidence != null && (
              <span className="confidence-pill">
                Confidence: {(confidence * 100).toFixed(0)}%
              </span>
            )}
          </div>
          <h2 className="verdict-title">
            {explanation?.risk_label || classification.toUpperCase()}
          </h2>
          <p className="email-subject-line">
            <strong>Subject:</strong> {result.metadata.subject || "(No Subject)"}
          </p>
          <div className="email-meta-pills">
            <span><strong>From:</strong> {result.metadata.from || "Unknown"}</span>
            <span><strong>To:</strong> {result.metadata.to || "Unknown"}</span>
            <span><strong>Date:</strong> {result.metadata.date || "Unknown"}</span>
          </div>
        </div>
      </div>
    </Card>
  );
};

export default RiskHeaderCard;
