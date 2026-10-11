import React from "react";
import { Cpu, AlertCircle, BarChart3 } from "lucide-react";
import Card from "../ui/Card";
import { type AnalysisResult } from "../../api";

interface SignalsMLTabProps {
  result: AnalysisResult;
}

export const SignalsMLTab: React.FC<SignalsMLTabProps> = ({ result }) => {
  const signals = result.signals || [];
  const mlPrediction = result.ml_prediction;
  const breakdown = result.risk.breakdown;

  return (
    <div className="tab-pane-grid">
      {/* ML Prediction Model Output */}
      {mlPrediction && (
        <Card
          title={
            <span className="card-title-with-icon">
              <Cpu size={18} className="text-accent-blue" /> Machine Learning Model Verdict
            </span>
          }
        >
          <div className="ml-card-body">
            <div className="ml-stat-row">
              <span className="ml-stat-label">Model Probability Output:</span>
              <span className="ml-stat-value">
                {(mlPrediction.probability * 100).toFixed(1)}% Phishing
              </span>
            </div>
            <div className="ml-progress-track">
              <div
                className="ml-progress-fill"
                style={{
                  width: `${mlPrediction.probability * 100}%`,
                  backgroundColor:
                    mlPrediction.probability > 0.7
                      ? "var(--accent-red)"
                      : mlPrediction.probability > 0.4
                      ? "var(--accent-yellow)"
                      : "var(--accent-green)",
                }}
              />
            </div>
            <div className="ml-meta-footer">
              <span>Model Architecture: {mlPrediction.model_version}</span>
              <span>
                Engine Status: {mlPrediction.is_ml_prediction ? "Trained ML Model" : "Fallback Heuristic Engine"}
              </span>
            </div>
          </div>
        </Card>
      )}

      {/* Category Breakdown Matrix */}
      {breakdown && Object.keys(breakdown).length > 0 && (
        <Card
          title={
            <span className="card-title-with-icon">
              <BarChart3 size={18} className="text-accent-yellow" /> Score Category Breakdown
            </span>
          }
        >
          <div className="breakdown-grid">
            {Object.entries(breakdown).map(([cat, val]) => (
              <div key={cat} className="breakdown-card">
                <div className="breakdown-score">{(val as number).toFixed(1)}</div>
                <div className="breakdown-name">{cat.replace(/_/g, " ")}</div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Complete Detection Signals Audit */}
      <Card
        title={
          <span className="card-title-with-icon">
            <AlertCircle size={18} className="text-accent-purple" /> Full Rule & Signal Audit ({signals.length})
          </span>
        }
        subtitle="Individual rule violations and weighted risk contributions"
      >
        {signals.length === 0 ? (
          <p style={{ color: "var(--text-muted)", padding: "10px 0" }}>No signals triggered.</p>
        ) : (
          <ul className="signal-list">
            {signals
              .slice()
              .sort((a, b) => b.risk_contribution - a.risk_contribution)
              .map((s) => (
                <li key={s.signal_id} className="signal-item">
                  <span className="signal-category">{s.category}</span>
                  <span className="signal-explanation">
                    <strong className="font-mono">{s.signal_id}</strong> — {s.explanation}
                    <span className="signal-source-tag">[{s.source}]</span>
                  </span>
                  <span
                    className="signal-risk"
                    style={{
                      color:
                        s.risk_contribution >= 10
                          ? "var(--accent-red)"
                          : s.risk_contribution >= 5
                          ? "var(--accent-yellow)"
                          : "var(--text-muted)",
                    }}
                  >
                    +{s.risk_contribution.toFixed(1)}
                  </span>
                </li>
              ))}
          </ul>
        )}
      </Card>
    </div>
  );
};

export default SignalsMLTab;
