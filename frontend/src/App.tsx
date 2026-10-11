import { useState, useEffect } from "react";
import { Routes, Route } from "react-router-dom";
import Sidebar from "./components/layout/Sidebar";
import Header from "./components/layout/Header";
import DashboardPage from "./pages/DashboardPage";
import UploadPage from "./pages/UploadPage";
import HistoryPage from "./pages/HistoryPage";
import ResultPage from "./pages/ResultPage";
import { listAnalyses } from "./api";

export default function App() {
  const [analysisCount, setAnalysisCount] = useState<number>(0);

  useEffect(() => {
    listAnalyses(100, 0)
      .then((items) => setAnalysisCount(items.length))
      .catch(() => {});
  }, []);

  return (
    <div className="layout">
      <Sidebar analysisCount={analysisCount} />
      <div className="main-wrapper">
        <Header />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/upload" element={<UploadPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/result/:id" element={<ResultPage />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
