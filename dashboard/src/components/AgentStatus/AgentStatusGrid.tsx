import React, { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../services/api";
import { useStore } from "../../store/useStore";

const AGENT_ICONS: Record<string, string> = {
  threat_detection: "🔍",
  log_analysis: "📋",
  vulnerability_intel: "🛡️",
  incident_response: "🚨",
  compliance: "✅",
  reporting: "📊",
  supervisor: "🎯",
};

const STATUS_COLORS: Record<string, string> = {
  idle: "bg-green-500",
  running: "bg-blue-500 animate-pulse",
  error: "bg-red-500",
  disabled: "bg-gray-500",
};

export function AgentStatusGrid() {
  const { agentStatuses } = useStore();
  const { data } = useQuery({
    queryKey: ["agent-statuses"],
    queryFn: api.getAgentStatuses,
    refetchInterval: 5000,
  });

  const statuses = data || agentStatuses;

  return (
    <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
      <h2 className="text-white font-semibold mb-3 text-sm uppercase tracking-wide">Agent Mesh</h2>
      <div className="grid grid-cols-2 gap-2">
        {Object.entries(AGENT_ICONS).map(([name, icon]) => {
          const s = statuses[name] || {};
          const status = (s as any).status || "idle";
          return (
            <div key={name} className="flex items-center gap-2 bg-gray-800 rounded p-2">
              <span className="text-lg">{icon}</span>
              <div className="flex-1 min-w-0">
                <p className="text-white text-xs font-medium truncate">
                  {name.replace(/_/g, " ")}
                </p>
                <p className="text-gray-400 text-xs capitalize">{status}</p>
              </div>
              <div className={`w-2 h-2 rounded-full ${STATUS_COLORS[status] || "bg-gray-500"}`} />
            </div>
          );
        })}
      </div>
    </div>
  );
}
