import React, { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { Upload, FileText, CheckCircle2, Code2 } from "lucide-react";
import Card from "../components/ui/Card";
import LoadingSpinner from "../components/ui/LoadingSpinner";
import { analyzeEmail } from "../api";

export const UploadPage: React.FC = () => {
  const [activeMode, setActiveMode] = useState<"file" | "raw">("file");
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [rawText, setRawText] = useState("");
  const navigate = useNavigate();

  const handleFile = useCallback(
    async (file: File) => {
      setFileName(file.name);
      setLoading(true);
      setError(null);
      try {
        const result = await analyzeEmail(file);
        sessionStorage.setItem(`analysis-${result.analysis_id}`, JSON.stringify(result));
        navigate(`/result/${result.analysis_id}`);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Analysis failed");
      } finally {
        setLoading(false);
      }
    },
    [navigate]
  );

  const handleRawSubmit = useCallback(async () => {
    if (!rawText.trim()) {
      setError("Please paste raw email headers or content first.");
      return;
    }
    const blob = new Blob([rawText], { type: "message/rfc822" });
    const file = new File([blob], "raw_email.eml", { type: "message/rfc822" });
    handleFile(file);
  }, [rawText, handleFile]);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile]
  );

  return (
    <div className="upload-page">
      {/* Tab mode selection */}
      <div className="upload-mode-switcher">
        <button
          className={`mode-btn ${activeMode === "file" ? "active" : ""}`}
          onClick={() => setActiveMode("file")}
        >
          <Upload size={16} />
          <span>Upload .eml File</span>
        </button>
        <button
          className={`mode-btn ${activeMode === "raw" ? "active" : ""}`}
          onClick={() => setActiveMode("raw")}
        >
          <Code2 size={16} />
          <span>Paste Raw Headers / Body</span>
        </button>
      </div>

      {loading ? (
        <Card>
          <LoadingSpinner
            label={`Analyzing ${fileName || "email"}...`}
            sublabel="Extracting headers, URLs, attachments, and calculating risk score"
          />
        </Card>
      ) : activeMode === "file" ? (
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
          <Upload size={48} className="upload-icon" />
          <p className="upload-prompt">Drop an .eml or .msg file here, or click to browse</p>
          <p className="upload-subtext">Maximum supported file size: 10 MB</p>
          <input
            id="file-input"
            type="file"
            accept=".eml,.msg"
            style={{ display: "none" }}
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) handleFile(file);
            }}
          />
        </div>
      ) : (
        <Card title="Raw Email Content Inspection">
          <textarea
            className="raw-textarea"
            rows={12}
            placeholder="Paste complete raw email source code (including MIME headers, Received headers, and body)..."
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
          />
          <div className="raw-actions">
            <button onClick={handleRawSubmit} className="btn btn-primary" disabled={!rawText.trim()}>
              <FileText size={16} />
              <span>Analyze Raw Content</span>
            </button>
          </div>
        </Card>
      )}

      {error && <div className="error-banner mt-4">{error}</div>}

      {/* Capabilities Info Card */}
      <Card
        title={
          <span className="card-title-with-icon">
            <CheckCircle2 size={18} className="text-accent-blue" /> Detection Capabilities
          </span>
        }
        className="mt-4"
      >
        <div className="capabilities-grid">
          <div className="capability-item">
            <strong>Header Verification</strong>
            <p>SPF, DKIM, DMARC, and Reply-To mismatch checks</p>
          </div>
          <div className="capability-item">
            <strong>URL & Domain Analysis</strong>
            <p>Punycode, shorteners, IP host detection & keyword flags</p>
          </div>
          <div className="capability-item">
            <strong>Attachment Inspection</strong>
            <p>Executable extensions, double extensions, and office macros</p>
          </div>
          <div className="capability-item">
            <strong>Explainable AI & ML</strong>
            <p>Probability scoring with transparent rule justification</p>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default UploadPage;
