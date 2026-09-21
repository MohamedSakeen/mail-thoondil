import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { History } from "lucide-react";
import { listAnalyses, type AnalysisListItem } from "../api";

export default function HistoryPage() {
  const [analyses, setAnalyses] = useState<AnalysisListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listAnalyses()
      .then(setAnalyses)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner" />
        <p style={{ marginTop: 12 }}>Loading history...</p>
      </div>
    );
  }

  return (
    <>
      <h1>
        <History size={24} style={{ display: "inline", marginRight: 8 }} />
        Analysis History
      </h1>
      <h2>Recent email analyses</h2>

      {error && (
        <div className="card" style={{ color: "var(--accent-red)" }}>
          {error}
        </div>
      )}

      {analyses.length === 0 ? (
        <div className="empty-state">
          <p>No analyses yet. Upload an email to get started.</p>
        </div>
      ) : (
        <div className="card">
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Subject</th>
                  <th>Classification</th>
                  <th>Risk Score</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {analyses.map((a) => (
                  <tr key={a.analysis_id}>
                    <td>
                      <Link to={`/result/${a.analysis_id}`}>
                        {a.subject || "(no subject)"}
                      </Link>
                    </td>
                    <td>
                      <span className={`badge badge-${a.classification}`}>
                        {a.classification}
                      </span>
                    </td>
                    <td style={{ fontWeight: 600 }}>{a.risk_score.toFixed(1)}</td>
                    <td style={{ color: "var(--text-muted)" }}>
                      {a.created_at
                        ? new Date(a.created_at).toLocaleString()
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  );
}
