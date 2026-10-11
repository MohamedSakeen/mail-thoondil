import React from "react";
import { ExternalLink, Paperclip, ShieldAlert, Link as LinkIcon } from "lucide-react";
import Card from "../ui/Card";
import { type AnalysisResult } from "../../api";

interface LinksFilesTabProps {
  result: AnalysisResult;
}

export const LinksFilesTab: React.FC<LinksFilesTabProps> = ({ result }) => {
  const urls = result.urls || [];
  const attachments = result.attachments || [];

  return (
    <div className="tab-pane-grid">
      {/* Extracted URLs Table */}
      <Card
        title={
          <span className="card-title-with-icon">
            <LinkIcon size={18} className="text-accent-blue" /> Extracted URLs ({urls.length})
          </span>
        }
        subtitle="Security features extracted from hyperlinked domain targets"
      >
        {urls.length === 0 ? (
          <p style={{ color: "var(--text-muted)", padding: "10px 0" }}>No URLs found in email body.</p>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>URL Target</th>
                  <th>HTTPS</th>
                  <th>IP Host</th>
                  <th>Shortener</th>
                  <th>Suspicious Keywords</th>
                </tr>
              </thead>
              <tbody>
                {urls.map((u) => (
                  <tr key={u.id}>
                    <td className="cell-url">
                      <a
                        href={u.raw_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="external-link"
                      >
                        <span className="url-text">{u.raw_url}</span>
                        <ExternalLink size={12} />
                      </a>
                    </td>
                    <td>
                      {u.features.is_https ? (
                        <span className="tag-pass">YES</span>
                      ) : (
                        <span className="tag-fail">NO</span>
                      )}
                    </td>
                    <td>{u.features.is_ip_address ? <span className="tag-warn">IP HOST</span> : "—"}</td>
                    <td>{u.features.shortener_detected ? <span className="tag-warn">SHORTENER</span> : "—"}</td>
                    <td>
                      {(u.features.suspicious_keyword_count as number) > 0 ? (
                        <span className="tag-warn">
                          {u.features.suspicious_keyword_count as number} match(es)
                        </span>
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Attachments Table */}
      <Card
        title={
          <span className="card-title-with-icon">
            <Paperclip size={18} className="text-accent-purple" /> File Attachments ({attachments.length})
          </span>
        }
        subtitle="Static file analysis, MIME type validation, and macro detection"
      >
        {attachments.length === 0 ? (
          <p style={{ color: "var(--text-muted)", padding: "10px 0" }}>
            No file attachments included in this email.
          </p>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Filename</th>
                  <th>MIME Type</th>
                  <th>Size</th>
                  <th>Executable</th>
                  <th>Macro Embedded</th>
                  <th>Double Extension</th>
                </tr>
              </thead>
              <tbody>
                {attachments.map((a) => (
                  <tr key={a.id}>
                    <td className="font-medium">{a.filename}</td>
                    <td className="font-mono text-muted">{a.mime_type}</td>
                    <td>{(a.size_bytes / 1024).toFixed(1)} KB</td>
                    <td>
                      {a.features.executable ? (
                        <span className="tag-fail">
                          <ShieldAlert size={12} /> YES
                        </span>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      {a.features.macro_document ? (
                        <span className="tag-warn">
                          <ShieldAlert size={12} /> YES
                        </span>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      {a.features.double_extension ? (
                        <span className="tag-fail">
                          <ShieldAlert size={12} /> YES
                        </span>
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
};

export default LinksFilesTab;
