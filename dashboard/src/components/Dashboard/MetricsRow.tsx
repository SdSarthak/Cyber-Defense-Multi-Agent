import React from "react";
import { useStore } from "../../store/useStore";

interface MetricCardProps {
  label: string;
  value: string | number;
  sub?: string;
  color?: string;
}

function MetricCard({ label, value, sub, color = "text-white" }: MetricCardProps) {
  return (
    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
      <p className="text-gray-400 text-xs uppercase tracking-wide mb-1">{label}</p>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
      {sub && <p className="text-gray-500 text-xs mt-1">{sub}</p>}
    </div>
  );
}

/** Anything the agents flag as needing immediate attention. */
const URGENT = new Set(["critical", "high"]);

export function MetricsRow() {
  const { alerts, incidents, recentThreats } = useStore();

  const escalations = alerts.filter((a) => a.channel === "escalations").length;

  // Live socket alerts cover this session only; the polled threat list is what
  // survives a reload, so the critical counter reads from both.
  const criticalLive = alerts.filter((a) => a.data?.severity === "critical").length;
  const criticalStored = recentThreats.filter((t: any) => t?.severity === "critical").length;
  const critical = criticalLive + criticalStored;

  const urgentIncidents = incidents.filter(
    (i: any) => URGENT.has(i?.severity) || i?.priority === "p1",
  ).length;

  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
      <MetricCard label="Total Alerts" value={alerts.length} sub="this session" />
      <MetricCard
        label="Escalations"
        value={escalations}
        color={escalations > 0 ? "text-red-400" : "text-white"}
        sub="requiring attention"
      />
      <MetricCard
        label="Critical"
        value={critical}
        color={critical > 0 ? "text-red-500" : "text-green-400"}
        sub="severity events"
      />
      <MetricCard label="Threats" value={recentThreats.length} sub="recorded detections" />
      <MetricCard
        label="Incidents"
        value={incidents.length}
        color={urgentIncidents > 0 ? "text-orange-400" : "text-white"}
        sub={urgentIncidents > 0 ? `${urgentIncidents} high priority` : "tracked incidents"}
      />
    </div>
  );
}
