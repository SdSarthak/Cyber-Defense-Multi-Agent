import { create } from "zustand";

export type ThreatLevel = "critical" | "high" | "medium" | "low";

export const THREAT_LEVELS: readonly ThreatLevel[] = ["critical", "high", "medium", "low"];

export function isThreatLevel(value: unknown): value is ThreatLevel {
  return typeof value === "string" && (THREAT_LEVELS as readonly string[]).includes(value);
}

/**
 * The agents that make up the mesh. Socket frames also arrive from non-agent
 * publishers ("human" overrides, the "simulation" producer); those must never show
 * up as agents on the status grid.
 */
export const KNOWN_AGENTS = [
  "threat_detection",
  "log_analysis",
  "vulnerability_intel",
  "incident_response",
  "compliance",
  "reporting",
  "supervisor",
] as const;

export type AgentName = (typeof KNOWN_AGENTS)[number];

export function isKnownAgent(value: unknown): value is AgentName {
  return typeof value === "string" && (KNOWN_AGENTS as readonly string[]).includes(value);
}

export type AgentRunStatus = "idle" | "running" | "error" | "disabled";

export interface AgentStatus {
  name: string;
  status: AgentRunStatus;
  task_id?: string;
  /**
   * When the socket reported this status (ms since epoch). The status grid also
   * polls the REST snapshot, and whichever of the two is newer wins.
   */
  updatedAt?: number;
}

export interface Alert {
  id: string;
  channel: string;
  data: any;
  timestamp: string;
}

interface State {
  threatLevel: ThreatLevel;
  agentStatuses: Record<string, AgentStatus>;
  alerts: Alert[];
  incidents: any[];
  recentThreats: any[];
  connected: boolean;

  setThreatLevel: (level: ThreatLevel) => void;
  setAgentStatus: (name: string, status: AgentStatus) => void;
  addAlert: (alert: Alert) => void;
  setIncidents: (incidents: any[]) => void;
  setRecentThreats: (threats: any[]) => void;
  setConnected: (v: boolean) => void;
}

export const useStore = create<State>((set) => ({
  threatLevel: "low",
  agentStatuses: {},
  alerts: [],
  incidents: [],
  recentThreats: [],
  connected: false,

  setThreatLevel: (level) => set({ threatLevel: level }),
  setAgentStatus: (name, status) =>
    set((s) => ({ agentStatuses: { ...s.agentStatuses, [name]: status } })),
  addAlert: (alert) =>
    set((s) => ({ alerts: [alert, ...s.alerts].slice(0, 200) })),
  setIncidents: (incidents) => set({ incidents }),
  setRecentThreats: (recentThreats) => set({ recentThreats }),
  setConnected: (connected) => set({ connected }),
}));
