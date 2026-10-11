import React from "react";
import { Search, Filter, Download } from "lucide-react";

interface HistoryFilterBarProps {
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  selectedFilter: string;
  setSelectedFilter: (f: string) => void;
  onExport: () => void;
  totalCount: number;
}

export const HistoryFilterBar: React.FC<HistoryFilterBarProps> = ({
  searchQuery,
  setSearchQuery,
  selectedFilter,
  setSelectedFilter,
  onExport,
  totalCount,
}) => {
  const filterOptions = [
    { id: "all", label: "All Records" },
    { id: "phishing", label: "Phishing" },
    { id: "high_suspicious", label: "High Suspicious" },
    { id: "suspicious", label: "Suspicious" },
    { id: "benign", label: "Benign" },
  ];

  return (
    <div className="filter-bar">
      <div className="filter-search-box">
        <Search size={16} className="search-icon" />
        <input
          type="text"
          placeholder="Search by subject or email ID..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="search-input"
        />
      </div>

      <div className="filter-pills">
        <Filter size={14} className="text-muted mr-1" />
        {filterOptions.map((opt) => (
          <button
            key={opt.id}
            className={`filter-pill ${selectedFilter === opt.id ? "active" : ""}`}
            onClick={() => setSelectedFilter(opt.id)}
          >
            {opt.label}
          </button>
        ))}
      </div>

      <div className="filter-actions">
        <button onClick={onExport} className="btn btn-secondary btn-sm" disabled={totalCount === 0}>
          <Download size={14} />
          <span>Export JSON</span>
        </button>
      </div>
    </div>
  );
};

export default HistoryFilterBar;
