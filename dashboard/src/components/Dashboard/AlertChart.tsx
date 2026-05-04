import React, { useMemo } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { useStore } from "../../store/useStore";
import { format } from "date-fns";

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#6b7280",
};

export function AlertChart() {
  const { alerts } = useStore();

  const buckets = useMemo(() => {
    const map: Record<string, Record<string, number>> = {};
    alerts.slice(0, 100).forEach((a) => {
      const minute = format(new Date(a.timestamp), "HH:mm");
      if (!map[minute]) map[minute] = {};
      const sev = a.data?.severity || "info";
      map[minute][sev] = (map[minute][sev] || 0) + 1;
    });
    return Object.entries(map)
      .slice(-15)
      .map(([time, counts]) => ({ time, ...counts }));
  }, [alerts]);

  return (
    <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
      <h2 className="text-white font-semibold text-sm uppercase tracking-wide mb-3">Alert Volume (last 15 min)</h2>
      <ResponsiveContainer width="100%" height={160}>
        <BarChart data={buckets} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
          <XAxis dataKey="time" tick={{ fill: "#9ca3af", fontSize: 10 }} />
          <YAxis tick={{ fill: "#9ca3af", fontSize: 10 }} />
          <Tooltip contentStyle={{ background: "#1f2937", border: "none", color: "#fff" }} />
          {["critical", "high", "medium", "low"].map((sev) => (
            <Bar key={sev} dataKey={sev} stackId="a" fill={SEVERITY_COLOR[sev]} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
