import React, { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { FileUp, Loader2 } from "lucide-react";
import Card from "../ui/Card";
import { analyzeEmail } from "../../api";

export const QuickUploadWidget: React.FC = () => {
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleFile = useCallback(
    async (file: File) => {
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
    <Card title="Quick Email Analysis" subtitle="Upload .eml file for instantaneous risk assessment">
      <div
        className={`quick-upload-box ${dragging ? "dragging" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => document.getElementById("quick-file-input")?.click()}
      >
        <input
          id="quick-file-input"
          type="file"
          accept=".eml,.msg"
          style={{ display: "none" }}
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFile(file);
          }}
        />

        {loading ? (
          <div className="quick-upload-content">
            <Loader2 className="spinner-icon text-accent-blue" size={32} />
            <p className="quick-upload-text">Running risk engine analysis...</p>
          </div>
        ) : (
          <div className="quick-upload-content">
            <FileUp size={32} className="quick-upload-icon" />
            <p className="quick-upload-text">
              <strong>Drop .eml file</strong> or click to browse
            </p>
            <p className="quick-upload-subtext">Supports header & body analysis up to 10MB</p>
          </div>
        )}
      </div>
      {error && <div className="error-banner">{error}</div>}
    </Card>
  );
};

export default QuickUploadWidget;
