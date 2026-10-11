import React from "react";
import { Shield, Lock, Link as LinkIcon, Cpu } from "lucide-react";

export type ResultTabType = "overview" | "auth" | "links_files" | "signals";

interface TabNavProps {
  activeTab: ResultTabType;
  setActiveTab: (tab: ResultTabType) => void;
  urlCount?: number;
  attachmentCount?: number;
  signalCount?: number;
}

export const TabNav: React.FC<TabNavProps> = ({
  activeTab,
  setActiveTab,
  urlCount = 0,
  attachmentCount = 0,
  signalCount = 0,
}) => {
  const tabs = [
    {
      id: "overview" as ResultTabType,
      label: "Overview & Verdict",
      icon: <Shield size={16} />,
    },
    {
      id: "auth" as ResultTabType,
      label: "Authentication & Sender",
      icon: <Lock size={16} />,
    },
    {
      id: "links_files" as ResultTabType,
      label: `Links & Files (${urlCount + attachmentCount})`,
      icon: <LinkIcon size={16} />,
    },
    {
      id: "signals" as ResultTabType,
      label: `Risk Signals & ML (${signalCount})`,
      icon: <Cpu size={16} />,
    },
  ];

  return (
    <div className="tab-nav">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          className={`tab-item ${activeTab === tab.id ? "active" : ""}`}
          onClick={() => setActiveTab(tab.id)}
        >
          {tab.icon}
          <span>{tab.label}</span>
        </button>
      ))}
    </div>
  );
};

export default TabNav;
