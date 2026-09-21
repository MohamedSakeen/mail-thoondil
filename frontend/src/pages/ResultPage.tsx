import { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft, ExternalLink, Shield, AlertTriangle } from "lucide-react";
import { getAnalysis, type AnalysisResult } from "../api";

export default function ResultPage() {
  const { id } = useParams<{ id: string }>();
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;

    // Try sessionStorage first (for fresh analysis)
    const cached = sessionStorage.getItem(`analysis-${id}`);
    if (cached) {
      setResult(JSON.parse(cached));
      setLoading(false);
      return;
    }

    // Fetch from API
    getAnalysis(id)
      .then(setResult)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner" />
        <p style={{ marginTop: 12 }}>Loading analysis...</p>
      </div>
    );
  }

  if (error || !result) {
    return (
      <div>
        <Link to="/" style={{ display: "inline-flex", alignItems: "center", gap: 6, marginBottom: 16 }}>
          <ArrowLeft size={16} /> Back
        </Link>
        <div className="card" style={{ color: "var(--accent-red)" }}>
          {error || "Analysis not found"}
        </div>
      </div>
    );
  }

  const classification = result.risk.classification;
  const score = result.risk.score;
  const explanation = result.explanation;

  return (
    <div>
      <Link to="/" style={{ display: "inline-flex", alignItems: "center", gap: 6, marginBottom: 16 }}>
        <ArrowLeft size={16} /> New Analysis
      </Link>

      {/* Risk Score Header */}
      <div className="card" style={{ textAlign: "center" }}>
        <div className={`score-ring score-${classification}`}>
          {Math.round(score)}
        </div>
        <h1 style={{ marginBottom: 4 }}>
          {explanation?.risk_label || classification.toUpperCase()}
        </h1>
        <span className={`badge badge-${classification}`}>{classification}</span>
        {result.risk.confidence != null && (
          <p style={{ color: "var(--text-muted)", marginTop: 8, fontSize: 14 }}>
            Confidence: {(result.risk.confidence * 100).toFixed(0)}%
          </p>
        )}
      </div>

      {/* Narrative */}
      {explanation?.narrative && (
        <div className="card">
          <h2>
            <Shield size={16} style={{ display: "inline", marginRight: 6 }} />
            Analysis Summary
          </h2>
          <p style={{ color: "var(--text-secondary)", lineHeight: 1.8 }}>
            {explanation.narrative}
          </p>
          {explanation.recommended_action && (
            <div
              style={{
                marginTop: 12,
                padding: "10px 14px",
                background: "rgba(91,141,239,0.1)",
                borderRadius: "var(--radius)",
                fontSize: 14,
              }}
            >
              <strong>Recommended action:</strong> {explanation.recommended_action}
            </div>
          )}
        </div>
      )}

      {/* Primary Indicators */}
      {explanation?.primary_indicators && explanation.primary_indicators.length > 0 && (
        <div className="card">
          <h2>
            <AlertTriangle
              size={16}
              style={{ display: "inline", marginRight: 6, color: "var(--accent-yellow)" }}
            />
            Primary Indicators
          </h2>
          <ul className="signal-list">
            {explanation.primary_indicators.map((ind, i) => (
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
        </div>
      )}

      {/* Email Metadata */}
      <div className="card">
        <h2>Email Details</h2>
        <table>
          <tbody>
            <tr>
              <td style={{ color: "var(--text-muted)", width: 140 }}>Subject</td>
              <td>{result.metadata.subject || "(none)"}</td>
            </tr>
            <tr>
              <td style={{ color: "var(--text-muted)" }}>From</td>
              <td>{result.metadata.from || "(none)"}</td>
            </tr>
            <tr>
              <td style={{ color: "var(--text-muted)" }}>To</td>
              <td>{result.metadata.to || "(none)"}</td>
            </tr>
            <tr>
              <td style={{ color: "var(--text-muted)" }}>Date</td>
              <td>{result.metadata.date || "(none)"}</td>
            </tr>
            <tr>
              <td style={{ color: "var(--text-muted)" }}>Message-ID</td>
              <td style={{ fontSize: 13, wordBreak: "break-all" }}>
                {result.metadata.message_id || "(none)"}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* Authentication */}
      <div className="card">
        <h2>Authentication</h2>
        <div style={{ display: "flex", gap: 24 }}>
          {["spf", "dkim", "dmarc"].map((method) => {
            const status = result.authentication[method] as string;
            return (
              <div key={method} style={{ textAlign: "center" }}>
                <div
                  style={{
                    width: 60,
                    height: 60,
                    borderRadius: "50%",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontSize: 14,
                    fontWeight: 600,
                    margin: "0 auto 6px",
                    background:
                      status === "pass"
                        ? "rgba(52,211,153,0.12)"
                        : status === "fail"
                        ? "rgba(248,113,113,0.12)"
                        : "rgba(42,51,61,0.5)",
                    color:
                      status === "pass"
                        ? "var(--accent-green)"
                        : status === "fail"
                        ? "var(--accent-red)"
                        : "var(--text-muted)",
                  }}
                >
                  {status.toUpperCase()}
                </div>
                <div style={{ fontSize: 12, color: "var(--text-muted)", textTransform: "uppercase" }}>
                  {method}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Sender */}
      <div className="card">
        <h2>Sender Analysis</h2>
        <table>
          <tbody>
            <tr>
              <td style={{ color: "var(--text-muted)", width: 160 }}>Display Name</td>
              <td>{(result.sender as Record<string, unknown>).display_name as string || "(none)"}</td>
            </tr>
            <tr>
              <td style={{ color: "var(--text-muted)" }}>From Domain</td>
              <td>{(result.sender as Record<string, unknown>).from_domain as string || "(none)"}</td>
            </tr>
            <tr>
              <td style={{ color: "var(--text-muted)" }}>Reply-To</td>
              <td>{(result.sender as Record<string, unknown>).reply_to as string || "(same as From)"}</td>
            </tr>
            <tr>
              <td style={{ color: "var(--text-muted)" }}>Return-Path</td>
              <td>{(result.sender as Record<string, unknown>).return_path as string || "(same as From)"}</td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* URLs */}
      {result.urls.length > 0 && (
        <div className="card">
          <h2>URLs ({result.urls.length})</h2>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>URL</th>
                  <th>HTTPS</th>
                  <th>IP</th>
                  <th>Shortener</th>
                  <th>Suspicious</th>
                </tr>
              </thead>
              <tbody>
                {result.urls.map((u) => (
                  <tr key={u.id}>
                    <td style={{ maxWidth: 400, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      <a href={u.raw_url} target="_blank" rel="noopener noreferrer">
                        {u.raw_url} <ExternalLink size={12} />
                      </a>
                    </td>
                    <td>{u.features.is_https ? "✓" : "✗"}</td>
                    <td>{u.features.is_ip_address ? "⚠" : "—"}</td>
                    <td>{u.features.shortener_detected ? "⚠" : "—"}</td>
                    <td>
                      {(u.features.suspicious_keyword_count as number) > 0
                        ? `${u.features.suspicious_keyword_count} hits`
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Attachments */}
      {result.attachments.length > 0 && (
        <div className="card">
          <h2>Attachments ({result.attachments.length})</h2>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Filename</th>
                  <th>Type</th>
                  <th>Size</th>
                  <th>Executable</th>
                  <th>Macro</th>
                  <th>Double Ext</th>
                </tr>
              </thead>
              <tbody>
                {result.attachments.map((a) => (
                  <tr key={a.id}>
                    <td>{a.filename}</td>
                    <td>{a.mime_type}</td>
                    <td>{(a.size_bytes / 1024).toFixed(1)} KB</td>
                    <td>{a.features.executable ? "⚠ YES" : "—"}</td>
                    <td>{a.features.macro_document ? "⚠ YES" : "—"}</td>
                    <td>{a.features.double_extension ? "⚠ YES" : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* All Signals */}
      {result.signals.length > 0 && (
        <div className="card">
          <h2>All Signals ({result.signals.length})</h2>
          <ul className="signal-list">
            {result.signals
              .sort((a, b) => b.risk_contribution - a.risk_contribution)
              .map((s) => (
                <li key={s.signal_id} className="signal-item">
                  <span className="signal-category">{s.category}</span>
                  <span className="signal-explanation">
                    <strong>{s.signal_id}</strong> — {s.explanation}
                    <span style={{ color: "var(--text-muted)", marginLeft: 8, fontSize: 12 }}>
                      [{s.source}]
                    </span>
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
        </div>
      )}

      {/* ML Prediction */}
      {result.ml_prediction && (
        <div className="card">
          <h2>ML Prediction</h2>
          <p style={{ color: "var(--text-secondary)" }}>
            Phishing probability:{" "}
            <strong>{(result.ml_prediction.probability * 100).toFixed(1)}%</strong>
            <span style={{ marginLeft: 12, fontSize: 13, color: "var(--text-muted)" }}>
              (model: {result.ml_prediction.model_version}
              {result.ml_prediction.is_ml_prediction ? "" : " — fallback heuristic"})
            </span>
          </p>
        </div>
      )}

      {/* Score Breakdown */}
      {result.risk.breakdown && (
        <div className="card">
          <h2>Score Breakdown</h2>
          <div style={{ display: "flex", gap: 32, flexWrap: "wrap" }}>
            {Object.entries(result.risk.breakdown).map(([key, val]) => (
              <div key={key} style={{ textAlign: "center" }}>
                <div style={{ fontSize: 24, fontWeight: 700 }}>{(val as number).toFixed(1)}</div>
                <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  {key.replace(/_/g, " ")}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
