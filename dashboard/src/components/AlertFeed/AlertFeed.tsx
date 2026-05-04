import React from "react";
import { useStore } from "../../store/useStore";
import { formatDistanceToNow } from "date-fns";

const CHANNEL_COLOR: Record<string, string> = {
  escalations: "border-red-500 bg-red-950",
  agent_events: "border-blue-500 bg-blue-950",
  incident_updates: "border-yellow-500 bg-yellow-950",
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-500 text-black",
  low: "bg-green-600 text-white",
};

export function AlertFeed() {
  const { alerts } = useStore();

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-700 flex flex-col h-full">
      <div className="px-4 py-3 border-b border-gray-700">
        <h2 className="text-white font-semibold text-sm uppercase tracking-wide">
          Live Alert Feed
          <span className="ml-2 bg-red-600 text-white text-xs rounded-full px-1.5 py-0.5">
            {alerts.length}
          </span>
        </h2>
      </div>
      <div className="flex-1 overflow-y-auto p-2 space-y-2">
        {alerts.length === 0 && (
          <p className="text-gray-500 text-sm text-center py-8">No alerts yet…</p>
        )}
        {alerts.map((a) => {
          const severity = a.data?.severity;
          const colorClass = CHANNEL_COLOR[a.channel] || "border-gray-600 bg-gray-800";
          return (
            <div key={a.id} className={`rounded border-l-4 px-3 py-2 ${colorClass}`}>
              <div className="flex items-center justify-between gap-2">
                <span className="text-white text-xs font-medium truncate">
                  {a.data?.agent || a.channel}
                  {a.data?.event && <span className="text-gray-400"> › {a.data.event}</span>}
                </span>
                <div className="flex items-center gap-1 shrink-0">
                  {severity && (
                    <span className={`text-xs px-1.5 py-0.5 rounded ${SEVERITY_BADGE[severity] || "bg-gray-600 text-white"}`}>
                      {severity}
                    </span>
                  )}
                  <span className="text-gray-500 text-xs">
                    {formatDistanceToNow(new Date(a.timestamp), { addSuffix: true })}
                  </span>
                </div>
              </div>
              {a.data?.threat_type && (
                <p className="text-gray-300 text-xs mt-1">{a.data.threat_type}</p>
              )}
              {a.data?.result_summary && (
                <p className="text-gray-400 text-xs mt-1 truncate">{a.data.result_summary}</p>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
