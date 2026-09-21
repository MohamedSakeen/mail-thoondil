const API_BASE = "/api/v1";

export interface AnalysisResult {
  schema_version: string;
  analysis_id: string;
  metadata: {
    message_id?: string;
    subject?: string;
    date?: string;
    from?: string;
    to?: string;
    parser_version?: string;
    rule_version?: string;
    model_version?: string;
  };
  sender: Record<string, unknown>;
  authentication: Record<string, unknown>;
  headers: Record<string, unknown>;
  urls: Array<{
    id: string;
    raw_url: string;
    normalized: Record<string, unknown>;
    features: Record<string, unknown>;
  }>;
  content: Record<string, unknown>;
  html: Record<string, unknown>;
  attachments: Array<{
    id: string;
    filename: string;
    mime_type: string;
    size_bytes: number;
    hashes: { sha256: string };
    features: Record<string, unknown>;
  }>;
  relationships: Record<string, unknown>;
  signals: Array<{
    signal_id: string;
    category: string;
    severity: number;
    risk_contribution: number;
    source: string;
    explanation: string;
    evidence: Record<string, unknown>;
  }>;
  risk: {
    score: number;
    confidence: number | null;
    classification: string;
    breakdown?: Record<string, number>;
  };
  verdict: {
    classification: string;
    reasons: string[];
    recommended_action?: string;
  };
  explanation?: {
    risk_label: string;
    narrative: string;
    recommended_action: string;
    primary_indicators: Array<{
      category: string;
      explanation: string;
      severity: number;
      risk_contribution: number;
    }>;
    signals_by_category: Record<string, Array<{ explanation: string; risk: number }>>;
    total_signals: number;
    categories_triggered: number;
  };
  ml_prediction?: {
    probability: number;
    model_version: string;
    is_ml_prediction: boolean;
  };
}

export interface AnalysisListItem {
  analysis_id: string;
  subject: string | null;
  risk_score: number;
  classification: string;
  created_at: string | null;
}

export async function analyzeEmail(file: File): Promise<AnalysisResult> {
  const formData = new FormData();
  formData.append("email", file);

  const response = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: "Unknown error" }));
    throw new Error(err.detail || `Analysis failed: ${response.status}`);
  }

  return response.json();
}

export async function listAnalyses(
  limit = 50,
  offset = 0
): Promise<AnalysisListItem[]> {
  const response = await fetch(
    `${API_BASE}/analyses?limit=${limit}&offset=${offset}`
  );
  if (!response.ok) throw new Error("Failed to list analyses");
  return response.json();
}

export async function getAnalysis(
  id: string
): Promise<AnalysisResult> {
  const response = await fetch(`${API_BASE}/analyses/${id}`);
  if (!response.ok) throw new Error("Analysis not found");
  return response.json();
}

export async function submitFeedback(
  analysisId: string,
  data: {
    analyst_id?: string;
    verdict_agreement: "agree" | "disagree" | "partial";
    actual_classification?: string;
    notes?: string;
  }
): Promise<{ feedback_id: string; status: string }> {
  const response = await fetch(`${API_BASE}/analyses/${analysisId}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!response.ok) throw new Error("Failed to submit feedback");
  return response.json();
}
