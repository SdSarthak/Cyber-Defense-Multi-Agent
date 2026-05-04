const BASE = process.env.REACT_APP_API_URL || "http://localhost:8000";
const WS_BASE = process.env.REACT_APP_WS_URL || "ws://localhost:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`);
  return res.json();
}

export const api = {
  getAgentStatuses: () => request<Record<string, { status: string; task_id?: string }>>("/api/v1/agents/status"),
  getAgentHistory: (name: string, limit = 20) => request<{ history: any[] }>(`/api/v1/agents/${name}/history?limit=${limit}`),
  runAgent: (agent: string, payload: object) => request("/api/v1/agents/run", { method: "POST", body: JSON.stringify({ agent, payload }) }),
  runSupervisor: (payload: object) => request("/api/v1/agents/supervisor/run", { method: "POST", body: JSON.stringify(payload) }),
  getBlackboard: () => request<Record<string, any>>("/api/v1/agents/blackboard"),

  analyzeThreat: (event: object) => request("/api/v1/threats/analyze", { method: "POST", body: JSON.stringify(event) }),
  getRecentThreats: (limit = 50) => request<{ threats: any[] }>(`/api/v1/threats/recent?limit=${limit}`),

  respondToIncident: (incident: object) => request("/api/v1/incidents/respond", { method: "POST", body: JSON.stringify(incident) }),
  getIncident: (id: string) => request(`/api/v1/incidents/${id}`),
  listIncidents: (limit = 20) => request<{ incidents: any[] }>(`/api/v1/incidents/?limit=${limit}`),

  scanVulnerabilities: (cve_ids: string[], asset_ips: string[]) =>
    request("/api/v1/vulnerabilities/scan", { method: "POST", body: JSON.stringify({ cve_ids, asset_ips }) }),
  getCVE: (cve_id: string) => request(`/api/v1/vulnerabilities/cve/${cve_id}`),

  evaluateCompliance: (framework: string, evidence: object = {}) =>
    request("/api/v1/compliance/evaluate", { method: "POST", body: JSON.stringify({ framework, evidence }) }),
  listFrameworks: () => request<{ frameworks: string[] }>("/api/v1/compliance/frameworks"),

  generateReport: (report_type: string, data: object = {}) =>
    request("/api/v1/reports/generate", { method: "POST", body: JSON.stringify({ report_type, data }) }),
  listReports: () => request<{ reports: any[] }>("/api/v1/reports/"),
};

export function createWebSocket(onMessage: (msg: any) => void): WebSocket {
  const ws = new WebSocket(`${WS_BASE}/ws`);
  ws.onmessage = (e) => {
    try { onMessage(JSON.parse(e.data)); } catch {}
  };
  return ws;
}
