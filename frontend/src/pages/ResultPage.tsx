import React, { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import Card from "../components/ui/Card";
import LoadingSpinner from "../components/ui/LoadingSpinner";
import RiskHeaderCard from "../components/result/RiskHeaderCard";
import TabNav, { type ResultTabType } from "../components/result/TabNav";
import SummaryTab from "../components/result/SummaryTab";
import AuthSenderTab from "../components/result/AuthSenderTab";
import LinksFilesTab from "../components/result/LinksFilesTab";
import SignalsMLTab from "../components/result/SignalsMLTab";
import { getAnalysis, type AnalysisResult } from "../api";

export const ResultPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<ResultTabType>("overview");

  useEffect(() => {
    if (!id) return;

    // Try session cache first
    const cached = sessionStorage.getItem(`analysis-${id}`);
    if (cached) {
      try {
        setResult(JSON.parse(cached));
        setLoading(false);
        return;
      } catch {
        // Fallthrough to fetch
      }
    }

    // Fetch API
    getAnalysis(id)
      .then((data) => {
        setResult(data);
        sessionStorage.setItem(`analysis-${id}`, JSON.stringify(data));
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) {
    return <LoadingSpinner label="Fetching analysis data..." sublabel={`Inspection ID: ${id}`} />;
  }

  if (error || !result) {
    return (
      <div>
        <Link to="/history" className="btn btn-secondary btn-sm mb-4">
          <ArrowLeft size={16} /> Back to History
        </Link>
        <Card className="error-card">
          <p>{error || "Analysis report not found."}</p>
        </Card>
      </div>
    );
  }

  return (
    <div className="result-page">
      {/* Risk Gauge & Metadata Header Card */}
      <RiskHeaderCard result={result} />

      {/* Tab Navigation */}
      <TabNav
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        urlCount={(result.urls || []).length}
        attachmentCount={(result.attachments || []).length}
        signalCount={(result.signals || []).length}
      />

      {/* Modular Tab Panes */}
      <div className="tab-content-area">
        {activeTab === "overview" && <SummaryTab result={result} />}
        {activeTab === "auth" && <AuthSenderTab result={result} />}
        {activeTab === "links_files" && <LinksFilesTab result={result} />}
        {activeTab === "signals" && <SignalsMLTab result={result} />}
      </div>
    </div>
  );
};

export default ResultPage;
