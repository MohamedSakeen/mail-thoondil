import React from "react";
import { Link } from "react-router-dom";
import { FileText, ArrowRight } from "lucide-react";
import Card from "../ui/Card";
import Badge from "../ui/Badge";
import { type AnalysisListItem } from "../../api";

interface HistoryTableProps {
  items: AnalysisListItem[];
}

export const HistoryTable: React.FC<HistoryTableProps> = ({ items }) => {
  if (items.length === 0) {
    return (
      <Card>
        <div className="empty-state">
          <p>No matching email analyses found.</p>
        </div>
      </Card>
    );
  }

  return (
    <Card>
      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Subject</th>
              <th>Classification</th>
              <th>Risk Score</th>
              <th>Date Analyzed</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
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
                  {item.created_at ? new Date(item.created_at).toLocaleString() : "—"}
                </td>
                <td>
                  <Link to={`/result/${item.analysis_id}`} className="btn-table-action">
                    <span>Inspect</span>
                    <ArrowRight size={12} />
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
};

export default HistoryTable;
