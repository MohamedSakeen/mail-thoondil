import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { Upload, FileText } from "lucide-react";
import { analyzeEmail, type AnalysisResult } from "../api";

export default function UploadPage() {
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleFile = useCallback(
    async (file: File) => {
      setFileName(file.name);
      setLoading(true);
      setError(null);
      try {
        const result: AnalysisResult = await analyzeEmail(file);
        // Store result in sessionStorage for the result page
        sessionStorage.setItem(
          `analysis-${result.analysis_id}`,
          JSON.stringify(result)
        );
        navigate(`/result/${result.analysis_id}`);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Analysis failed");
      } finally {
        setLoading(false);
      }
    },
    [navigate]
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile]
  );

  const onFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) handleFile(file);
    },
    [handleFile]
  );

  return (
    <>
      <h1>Analyze Email</h1>
      <h2>Upload a .eml file to detect phishing indicators</h2>

      <div
        className={`upload-zone ${dragging ? "dragging" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => document.getElementById("file-input")?.click()}
      >
        {loading ? (
          <div className="loading">
            <div className="spinner" />
            <p style={{ marginTop: 12 }}>Analyzing {fileName}...</p>
          </div>
        ) : (
          <>
            <Upload
              size={48}
              style={{ marginBottom: 16, color: "var(--text-muted)" }}
            />
            <p style={{ fontSize: 16, marginBottom: 8 }}>
              Drop an .eml file here or click to browse
            </p>
            <p style={{ color: "var(--text-muted)", fontSize: 13 }}>
              Maximum file size: 10 MB
            </p>
          </>
        )}
        <input
          id="file-input"
          type="file"
          accept=".eml,.msg"
          style={{ display: "none" }}
          onChange={onFileSelect}
        />
      </div>

      {error && (
        <div className="card" style={{ color: "var(--accent-red)" }}>
          <p>{error}</p>
        </div>
      )}

      <div className="card" style={{ marginTop: 24 }}>
        <h2 style={{ marginBottom: 8 }}>
          <FileText size={16} style={{ display: "inline", marginRight: 6 }} />
          What gets analyzed?
        </h2>
        <ul
          style={{
            color: "var(--text-secondary)",
            paddingLeft: 20,
            fontSize: 14,
            lineHeight: 2,
          }}
        >
          <li>Email headers (SPF, DKIM, DMARC, Reply-To mismatches)</li>
          <li>Sender identity and brand impersonation</li>
          <li>URL analysis (IP addresses, punycode, shorteners)</li>
          <li>Content analysis (urgency, credential requests, threats)</li>
          <li>HTML structure (forms, iframes, hidden elements)</li>
          <li>Attachment analysis (executables, macros, double extensions)</li>
          <li>Cross-component relationship correlation</li>
          <li>ML-based phishing probability</li>
        </ul>
      </div>
    </>
  );
}
