import React from "react";
import { Link } from "react-router-dom";
import { ArrowRight, FileText } from "lucide-react";
import Card from "../ui/Card";
import Badge from "../ui/Badge";
import { type AnalysisListItem } from "../../api";

interface RecentActivityTableProps {
  items: AnalysisListItem[];
}

export const RecentActivityTable: React.FC<RecentActivityTableProps> = ({ items }) => {
  return (
    <Card
      title="Recent Analyses"
      subtitle="Latest email threats and inspection reports"
      action={
        <Link to="/history" className="card-action-link">
          <span>View All</span>
          <ArrowRight size={14} />
        </Link>
      }
    >
      {items.length === 0 ? (
        <div style={{ padding: "30px 0", textAlign: "center", color: "var(--text-muted)" }}>
          No recent analysis activity.
        </div>
      ) : (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Subject</th>
                <th>Classification</th>
                <th>Risk Score</th>
                <th>Date</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {items.slice(0, 5).map((item) => (
                <tr key={item.analysis_id}>
                  <td className="cell-subject">
                    <FileText size={14} className="cell-icon" />
                    <Link to={`/result/${item.analysis_id}`} className="subject-link">
                      {item.subject || "(no subject)"}
                    </Link>
                  </td>
                  <td>
                    <Badge classification={item.classification} />
                  </td>
                  <td className="cell-score">
                    <span>{item.risk_score.toFixed(1)}</span>
                  </td>
                  <td className="cell-date">
                    {item.created_at
                      ? new Date(item.created_at).toLocaleDateString(undefined, {
                          month: "short",
                          day: "numeric",
                          hour: "2-digit",
                          minute: "2-digit",
                        })
                      : "—"}
                  </td>
                  <td>
                    <Link to={`/result/${item.analysis_id}`} className="btn-table-action">
                      Inspect
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
};

export default RecentActivityTable;
