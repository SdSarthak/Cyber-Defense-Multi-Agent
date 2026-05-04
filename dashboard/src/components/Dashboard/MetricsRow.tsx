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

export function MetricsRow() {
  const { alerts, incidents, recentThreats } = useStore();
  const critical = alerts.filter((a) => a.data?.severity === "critical").length;
  const escalations = alerts.filter((a) => a.channel === "escalations").length;

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      <MetricCard label="Total Alerts" value={alerts.length} sub="last session" />
      <MetricCard label="Escalations" value={escalations} color={escalations > 0 ? "text-red-400" : "text-white"} sub="requiring attention" />
      <MetricCard label="Critical" value={critical} color={critical > 0 ? "text-red-500" : "text-green-400"} sub="severity events" />
      <MetricCard label="Incidents" value={incidents.length} sub="tracked incidents" />
    </div>
  );
}
