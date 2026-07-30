import { authHeader, getToken, logout } from "./auth";

const BASE = process.env.REACT_APP_API_URL || "http://localhost:8000";
const WS_BASE = process.env.REACT_APP_WS_URL || "ws://localhost:8000";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  // `init` is spread first so that the merged headers below always win — the
  // previous order let a caller-supplied `headers` silently drop the auth header.
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...authHeader(),
      ...init?.headers,
    },
  });

  // An expired or revoked token must drop the session, otherwise every polling
  // query in the dashboard keeps hammering the API with a dead credential.
  if (res.status === 401) {
    logout();
    throw new ApiError(401, "Session expired — please sign in again");
  }
  if (!res.ok) {
    throw new ApiError(res.status, `API ${res.status}: ${await res.text()}`);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return res.json();
}

export const api = {
  getAgentStatuses: () =>
    request<Record<string, { status: string; task_id?: string }>>("/api/v1/agents/status"),
  getAgentHistory: (name: string, limit = 20) =>
    request<{ history: any[] }>(`/api/v1/agents/${name}/history?limit=${limit}`),
  runAgent: (agent: string, payload: object) =>
    request("/api/v1/agents/run", { method: "POST", body: JSON.stringify({ agent, payload }) }),
  runSupervisor: (payload: object) =>
    request("/api/v1/agents/supervisor/run", { method: "POST", body: JSON.stringify(payload) }),
  getBlackboard: () => request<Record<string, any>>("/api/v1/agents/blackboard"),

  analyzeThreat: (event: object) =>
    request("/api/v1/threats/analyze", { method: "POST", body: JSON.stringify(event) }),
  getRecentThreats: (limit = 50) =>
    request<{ threats: any[] }>(`/api/v1/threats/recent?limit=${limit}`),
  getThreatStats: (hours = 24) =>
    request<Record<string, any>>(`/api/v1/threats/stats?hours=${hours}`),

  respondToIncident: (incident: object) =>
    request("/api/v1/incidents/respond", { method: "POST", body: JSON.stringify(incident) }),
  getIncident: (id: string) => request(`/api/v1/incidents/${id}`),
  listIncidents: (limit = 20) =>
    request<{ incidents: any[] }>(`/api/v1/incidents/?limit=${limit}`),

  scanVulnerabilities: (cve_ids: string[], asset_ips: string[]) =>
    request("/api/v1/vulnerabilities/scan", {
      method: "POST",
      body: JSON.stringify({ cve_ids, asset_ips }),
    }),
  getCVE: (cve_id: string) => request(`/api/v1/vulnerabilities/cve/${cve_id}`),

  evaluateCompliance: (framework: string, evidence: object = {}) =>
    request("/api/v1/compliance/evaluate", {
      method: "POST",
      body: JSON.stringify({ framework, evidence }),
    }),
  listFrameworks: () => request<{ frameworks: string[] }>("/api/v1/compliance/frameworks"),

  generateReport: (report_type: string, data: object = {}) =>
    request("/api/v1/reports/generate", {
      method: "POST",
      body: JSON.stringify({ report_type, data }),
    }),
  listReports: () => request<{ reports: any[] }>("/api/v1/reports/"),
};

/**
 * Open the telemetry socket, or return null when signed out.
 *
 * The token rides as a query parameter because the browser WebSocket API cannot set
 * an Authorization header on the handshake — the server accepts either form.
 */
export function createWebSocket(onMessage: (msg: any) => void): WebSocket | null {
  const token = getToken();
  if (!token) return null;

  const ws = new WebSocket(`${WS_BASE}/ws?token=${encodeURIComponent(token)}`);
  ws.onmessage = (e) => {
    try {
      onMessage(JSON.parse(e.data));
    } catch {
      /* a non-JSON frame is not actionable for the dashboard */
    }
  };
  return ws;
}
