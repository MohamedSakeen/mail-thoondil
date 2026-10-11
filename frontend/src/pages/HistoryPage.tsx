import React, { useState, useEffect, useMemo } from "react";
import LoadingSpinner from "../components/ui/LoadingSpinner";
import HistoryFilterBar from "../components/history/HistoryFilterBar";
import HistoryTable from "../components/history/HistoryTable";
import { listAnalyses, type AnalysisListItem } from "../api";

export const HistoryPage: React.FC = () => {
  const [analyses, setAnalyses] = useState<AnalysisListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [searchQuery, setSearchQuery] = useState("");
  const [selectedFilter, setSelectedFilter] = useState("all");

  useEffect(() => {
    listAnalyses(100, 0)
      .then(setAnalyses)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  const filteredAnalyses = useMemo(() => {
    return analyses.filter((item) => {
      // Classification filter
      if (selectedFilter !== "all") {
        const norm = (item.classification || "").toLowerCase().replace(/\s+/g, "_");
        if (norm !== selectedFilter) return false;
      }

      // Search query filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const subjectMatch = (item.subject || "").toLowerCase().includes(q);
        const idMatch = (item.analysis_id || "").toLowerCase().includes(q);
        if (!subjectMatch && !idMatch) return false;
      }

      return true;
    });
  }, [analyses, selectedFilter, searchQuery]);

  const handleExportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filteredAnalyses, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `phishing_analysis_history_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  if (loading) {
    return <LoadingSpinner label="Loading analysis history log..." />;
  }

  return (
    <div className="history-page">
      {error && <div className="error-banner mb-4">{error}</div>}

      <HistoryFilterBar
        searchQuery={searchQuery}
        setSearchQuery={setSearchQuery}
        selectedFilter={selectedFilter}
        setSelectedFilter={setSelectedFilter}
        onExport={handleExportJSON}
        totalCount={filteredAnalyses.length}
      />

      <HistoryTable items={filteredAnalyses} />
    </div>
  );
};

export default HistoryPage;
