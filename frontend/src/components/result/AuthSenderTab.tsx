import React from "react";
import { CheckCircle2, XCircle, HelpCircle, UserCheck } from "lucide-react";
import Card from "../ui/Card";
import { type AnalysisResult } from "../../api";

interface AuthSenderTabProps {
  result: AnalysisResult;
}

export const AuthSenderTab: React.FC<AuthSenderTabProps> = ({ result }) => {
  const auth = result.authentication || {};
  const sender = (result.sender || {}) as Record<string, unknown>;

  const getStatusBadge = (status: string) => {
    const norm = (status || "none").toLowerCase();
    if (norm === "pass") {
      return (
        <div className="auth-card auth-pass">
          <CheckCircle2 size={24} className="text-accent-green" />
          <span className="auth-status-text">PASS</span>
        </div>
      );
    }
    if (norm === "fail") {
      return (
        <div className="auth-card auth-fail">
          <XCircle size={24} className="text-accent-red" />
          <span className="auth-status-text">FAIL</span>
        </div>
      );
    }
    return (
      <div className="auth-card auth-none">
        <HelpCircle size={24} className="text-text-muted" />
        <span className="auth-status-text">NONE / UNKNOWN</span>
      </div>
    );
  };

  return (
    <div className="tab-pane-grid">
      {/* Email Authentication Protocols */}
      <Card
        title={
          <span className="card-title-with-icon">
            <UserCheck size={18} className="text-accent-blue" /> Domain Authentication Protocols
          </span>
        }
        subtitle="SPF, DKIM, and DMARC verification results"
      >
        <div className="auth-grid">
          {["spf", "dkim", "dmarc"].map((method) => {
            const status = (auth[method] as string) || "none";
            return (
              <div key={method} className="auth-protocol-item">
                <div className="auth-protocol-label">{method.toUpperCase()}</div>
                {getStatusBadge(status)}
              </div>
            );
          })}
        </div>
      </Card>

      {/* Sender Identity Details */}
      <Card title="Sender Identity & Headers Analysis">
        <table className="info-table">
          <tbody>
            <tr>
              <td className="info-label">Display Name</td>
              <td className="info-val">{(sender.display_name as string) || "(none)"}</td>
            </tr>
            <tr>
              <td className="info-label">From Domain</td>
              <td className="info-val font-mono">{(sender.from_domain as string) || "(none)"}</td>
            </tr>
            <tr>
              <td className="info-label">Reply-To Header</td>
              <td className="info-val font-mono">
                {(sender.reply_to as string) || "(same as From address)"}
              </td>
            </tr>
            <tr>
              <td className="info-label">Return-Path Header</td>
              <td className="info-val font-mono">
                {(sender.return_path as string) || "(same as From address)"}
              </td>
            </tr>
            <tr>
              <td className="info-label">Message ID</td>
              <td className="info-val font-mono text-break">
                {result.metadata.message_id || "(none)"}
              </td>
            </tr>
          </tbody>
        </table>
      </Card>
    </div>
  );
};

export default AuthSenderTab;
