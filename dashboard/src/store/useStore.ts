import { create } from "zustand";

export type ThreatLevel = "critical" | "high" | "medium" | "low";

export interface AgentStatus {
  name: string;
  status: "idle" | "running" | "error" | "disabled";
  task_id?: string;
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
