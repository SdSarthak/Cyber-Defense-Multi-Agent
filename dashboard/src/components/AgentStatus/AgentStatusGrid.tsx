import React, { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../services/api";
import { useStore } from "../../store/useStore";
import type { OverrideResult } from "../../hooks/useWebSocket";

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

// The server records a paused agent as "disabled"; operators call it paused.
const STATUS_LABELS: Record<string, string> = { disabled: "paused" };

interface Props {
  /** Overrides that mutate agent state are admin-only, mirroring the server check. */
  canOverride?: boolean;
  /** Returns false when the socket is not open, so the UI can say so. */
  onOverride?: (command: string, payload: object) => boolean;
  /** The server's reply to the last override, so a refusal is visible. */
  overrideResult?: OverrideResult | null;
}

export function AgentStatusGrid({ canOverride = false, onOverride, overrideResult }: Props) {
  const { agentStatuses } = useStore();
  const queryClient = useQueryClient();
  const [note, setNote] = useState<string | null>(null);

  const { data } = useQuery({
    queryKey: ["agent-statuses"],
    queryFn: api.getAgentStatuses,
    refetchInterval: 5000,
  });

  const statuses = data || agentStatuses;

  function toggle(name: string, paused: boolean) {
    if (!onOverride) return;
    const sent = onOverride(paused ? "resume_agent" : "pause_agent", { agent: name });
    if (!sent) {
      setNote("Not connected — the override was not sent.");
      return;
    }
    setNote(null);
    // The server applies the command and then publishes on agent_events. Re-read the
    // authoritative status shortly after rather than guessing at it locally.
    setTimeout(() => queryClient.invalidateQueries({ queryKey: ["agent-statuses"] }), 500);
  }

  return (
    <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
      <h2 className="text-white font-semibold mb-3 text-sm uppercase tracking-wide">Agent Mesh</h2>
      <div className="grid grid-cols-2 gap-2">
        {Object.entries(AGENT_ICONS).map(([name, icon]) => {
          const s = statuses[name] || {};
          const status = (s as any).status || "idle";
          const paused = status === "disabled";
          return (
            <div key={name} className="flex items-center gap-2 bg-gray-800 rounded p-2">
              <span className="text-lg">{icon}</span>
              <div className="flex-1 min-w-0">
                <p className="text-white text-xs font-medium truncate">
                  {name.replace(/_/g, " ")}
                </p>
                <p className="text-gray-400 text-xs capitalize">
                  {STATUS_LABELS[status] || status}
                </p>
              </div>
              {/* The supervisor owns dispatch; pausing it would strand every task. */}
              {canOverride && name !== "supervisor" && (
                <button
                  onClick={() => toggle(name, paused)}
                  title={paused ? `Resume ${name}` : `Pause ${name}`}
                  className="text-xs text-gray-400 hover:text-white border border-gray-700 hover:border-gray-500 rounded px-1.5 py-0.5 transition-colors"
                >
                  {paused ? "Resume" : "Pause"}
                </button>
              )}
              <div className={`w-2 h-2 rounded-full ${STATUS_COLORS[status] || "bg-gray-500"}`} />
            </div>
          );
        })}
      </div>
      {note && <p className="text-yellow-400 text-xs mt-2">{note}</p>}
      {!note && overrideResult && !overrideResult.ok && (
        <p className="text-red-400 text-xs mt-2">
          {overrideResult.command} refused: {overrideResult.error || "unknown error"}
        </p>
      )}
    </div>
  );
}
