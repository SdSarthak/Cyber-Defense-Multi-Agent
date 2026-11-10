import { authHeader, getToken, logout } from "./auth";

const BASE = process.env.REACT_APP_API_URL || "http://localhost:8000";
const WS_BASE = process.env.REACT_APP_WS_URL || "ws://localhost:8000";

// ── Response models ─────────────────────────────────────────────────────────

export interface AgentStatusEntry {
  status: string;
  task_id?: string;
  /** Source of truth for the pause toggle — `status` alone cannot say it. */
  paused?: boolean;
}

export type IncidentStatus = "open" | "investigating" | "contained" | "resolved" | "false_positive";

export type ActionStatus =
  | "pending"
  | "pending_approval"
  | "approved"
  | "rejected"
  | "simulated"
  | "completed"
  | "failed";

export interface ContainmentAction {
  action: string;
  automated: boolean;
  status: ActionStatus | string;
  result?: any;
}

/**
 * An incident as listed by the API. PostgreSQL rows carry `id` and the full record;
 * the Redis fallback index carries `incident_id` and a summary only.
 */
export interface Incident {
  id?: string;
  incident_id?: string;
  title?: string;
  description?: string;
  severity?: string;
  status?: string;
  playbook_used?: string;
  playbook?: string;
  priority?: string;
  remediation_steps?: ContainmentAction[];
  affected_assets?: string[];
  timeline?: any[];
  created_at?: string | null;
  resolved_at?: string | null;
}

export interface ActionDecision {
  ok: boolean;
  action?: ContainmentAction;
  error?: string;
}

export type ReportType = "executive" | "threat";

export interface ReportIndexEntry {
  key: string;
  type: string;
  ts: string;
}

export interface GenerateReportResult {
  report?: any;
  report_key?: string | null;
  summary?: string;
}

export interface Vulnerability {
  cve_id: string;
  title?: string;
  cvss_score?: number | null;
  severity?: string | null;
  remediation_status?: string | null;
  asset_ip?: string | null;
  created_at?: string | null;
}

export interface CveRecord {
  cve_id: string;
  description?: string;
  cvss_score?: number | null;
  severity?: string | null;
  vector?: string | null;
  published?: string | null;
  error?: string;
}

export interface LogRecord {
  "@timestamp"?: string;
  source?: string | null;
  host?: string | null;
  service?: string | null;
  message?: string | null;
  is_anomalous?: boolean;
  anomaly?: any;
}

export interface LogSearchParams {
  q?: string;
  anomalousOnly?: boolean;
  limit?: number;
}

export interface LogSearchResult {
  logs: LogRecord[];
  count: number;
  /** "unavailable" when Elasticsearch is disabled or unreachable. */
  source: string;
}

// ── Transport ───────────────────────────────────────────────────────────────

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    /** The server's human-readable reason (FastAPI's `detail`), when it gave one. */
    public detail?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** Pull FastAPI's `detail` out of an error body, falling back to the raw text. */
async function readErrorDetail(res: Response): Promise<string> {
  let text = "";
  try {
    text = await res.text();
  } catch {
    return "";
  }
  try {
    const detail = JSON.parse(text)?.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      // Request validation errors arrive as [{loc, msg, type}, ...].
      const messages = detail.map((d: any) => d?.msg).filter(Boolean);
      if (messages.length) return messages.join("; ");
    }
  } catch {
    /* not JSON — use the text as-is */
  }
  return text;
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
  // Everything else — including 403, which means "signed in, but this role may not
  // do that" — leaves the session alone and reports the server's reason.
  if (!res.ok) {
    const detail = await readErrorDetail(res);
    throw new ApiError(res.status, `API ${res.status}: ${detail}`, detail || undefined);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return res.json();
}

function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** A message fit to show an operator for any error a call can throw. */
export function describeError(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 403) {
      return err.detail ? `Not permitted: ${err.detail}` : "Not permitted for your role";
    }
    return err.detail || err.message;
  }
  if (err instanceof Error) return err.message;
  return String(err ?? "Unknown error");
}

const seg = encodeURIComponent;

// ── Endpoints ───────────────────────────────────────────────────────────────

export const api = {
  getAgentStatuses: () =>
    request<Record<string, AgentStatusEntry>>("/api/v1/agents/status"),
  getAgentHistory: (name: string, limit = 20) =>
    request<{ history: any[] }>(`/api/v1/agents/${seg(name)}/history?limit=${limit}`),
  runAgent: (agent: string, payload: object) =>
    post("/api/v1/agents/run", { agent, payload }),
  runSupervisor: (payload: object) => post("/api/v1/agents/supervisor/run", payload),
  getBlackboard: () => request<Record<string, any>>("/api/v1/agents/blackboard"),

  analyzeThreat: (event: object) => post("/api/v1/threats/analyze", event),
  getRecentThreats: (limit = 50) =>
    request<{ threats: any[] }>(`/api/v1/threats/recent?limit=${limit}`),
  getThreatStats: (hours = 24) =>
    request<Record<string, any>>(`/api/v1/threats/stats?hours=${hours}`),

  respondToIncident: (incident: object) => post<any>("/api/v1/incidents/respond", incident),
  getIncident: (id: string) => request<Incident>(`/api/v1/incidents/${seg(id)}`),
  listIncidents: (limit = 20) =>
    request<{ incidents: Incident[]; count?: number; source?: string }>(
      `/api/v1/incidents/?limit=${limit}`,
    ),
  updateIncident: (id: string, status: IncidentStatus, notes?: string) =>
    post<{ ok: boolean; incident_id: string; status: string; incident?: Incident | null }>(
      `/api/v1/incidents/${seg(id)}/update`,
      notes ? { status, notes } : { status },
    ),
  approveAction: (id: string, index: number) =>
    post<ActionDecision>(`/api/v1/incidents/${seg(id)}/actions/${index}/approve`),
  rejectAction: (id: string, index: number) =>
    post<ActionDecision>(`/api/v1/incidents/${seg(id)}/actions/${index}/reject`),

  scanVulnerabilities: (cve_ids: string[], asset_ips: string[]) =>
    post<any>("/api/v1/vulnerabilities/scan", { cve_ids, asset_ips }),
  listVulnerabilities: (limit = 50) =>
    request<{ vulnerabilities: Vulnerability[]; count: number }>(
      `/api/v1/vulnerabilities/?limit=${limit}`,
    ),
  getCVE: (cve_id: string) => request<CveRecord>(`/api/v1/vulnerabilities/cve/${seg(cve_id)}`),

  evaluateCompliance: (framework: string, evidence: object = {}) =>
    post<any>("/api/v1/compliance/evaluate", { framework, evidence }),
  listFrameworks: () => request<{ frameworks: string[] }>("/api/v1/compliance/frameworks"),

  generateReport: (report_type: ReportType, data: object = {}) =>
    post<GenerateReportResult>("/api/v1/reports/generate", { report_type, data }),
  listReports: (limit = 20) =>
    request<{ reports: ReportIndexEntry[]; count?: number }>(`/api/v1/reports/?limit=${limit}`),
  getReport: (key: string) => request<Record<string, any>>(`/api/v1/reports/${seg(key)}`),

  searchLogs: ({ q = "", anomalousOnly = false, limit = 50 }: LogSearchParams = {}) => {
    const params = new URLSearchParams({
      q,
      anomalous_only: String(anomalousOnly),
      limit: String(limit),
    });
    return request<LogSearchResult>(`/api/v1/logs/search?${params.toString()}`);
  },
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
