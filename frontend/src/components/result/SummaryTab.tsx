import React from "react";
import { Shield, AlertTriangle, CheckCircle } from "lucide-react";
import Card from "../ui/Card";
import { type AnalysisResult } from "../../api";

interface SummaryTabProps {
  result: AnalysisResult;
}

export const SummaryTab: React.FC<SummaryTabProps> = ({ result }) => {
  const explanation = result.explanation;
  const primaryIndicators = explanation?.primary_indicators || [];

  return (
    <div className="tab-pane-grid">
      {/* Executive Narrative */}
      {explanation?.narrative && (
        <Card
          title={
            <span className="card-title-with-icon">
              <Shield size={18} className="text-accent-blue" /> Executive Summary
            </span>
          }
        >
          <p className="narrative-text">{explanation.narrative}</p>

          {explanation.recommended_action && (
            <div className="recommended-action-box">
              <CheckCircle size={18} className="text-accent-blue flex-shrink-0" />
              <div>
                <strong>Recommended Action:</strong>
                <p>{explanation.recommended_action}</p>
              </div>
            </div>
          )}
        </Card>
      )}

      {/* Primary Indicators */}
      {primaryIndicators.length > 0 ? (
        <Card
          title={
            <span className="card-title-with-icon">
              <AlertTriangle size={18} className="text-accent-yellow" /> Key Threat Indicators
            </span>
          }
          subtitle="Top contributing factors to the overall risk calculation"
        >
          <ul className="signal-list">
            {primaryIndicators.map((ind, i) => (
              <li key={i} className="signal-item">
                <span className="signal-category">{ind.category}</span>
                <span className="signal-explanation">{ind.explanation}</span>
                <span
                  className="signal-risk"
                  style={{
                    color:
                      ind.risk_contribution >= 10
                        ? "var(--accent-red)"
                        : ind.risk_contribution >= 5
                        ? "var(--accent-yellow)"
                        : "var(--text-muted)",
                  }}
                >
                  +{ind.risk_contribution.toFixed(1)}
                </span>
              </li>
            ))}
          </ul>
        </Card>
      ) : (
        <Card title="Threat Indicators">
          <p style={{ color: "var(--text-muted)", padding: "10px 0" }}>
            No high-priority threat indicators detected in this email.
          </p>
        </Card>
      )}
    </div>
  );
};

export default SummaryTab;
