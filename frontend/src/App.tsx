import { Routes, Route, Link, useLocation } from "react-router-dom";
import { Upload, History, Shield } from "lucide-react";
import UploadPage from "./pages/UploadPage";
import HistoryPage from "./pages/HistoryPage";
import ResultPage from "./pages/ResultPage";

export default function App() {
  const location = useLocation();

  const isActive = (path: string) =>
    location.pathname === path ? "active" : "";

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-title">
          <Shield size={20} style={{ display: "inline", marginRight: 8 }} />
          mail thoondil
        </div>
        <nav>
          <Link to="/" className={isActive("/")}>
            <Upload size={18} /> Analyze
          </Link>
          <Link to="/history" className={isActive("/history")}>
            <History size={18} /> History
          </Link>
        </nav>
      </aside>
      <main className="main-content">
        <Routes>
          <Route path="/" element={<UploadPage />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/result/:id" element={<ResultPage />} />
        </Routes>
      </main>
    </div>
  );
}
