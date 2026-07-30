import React, { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../services/api";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#6b7280",
};

const WINDOWS: { label: string; hours: number }[] = [
  { label: "24h", hours: 24 },
  { label: "7d", hours: 168 },
  { label: "30d", hours: 720 },
];

interface Stats {
  window_hours: number;
  counts: Record<string, number>;
  total: number;
}

/**
 * Severity breakdown of persisted threat detections.
 *
 * The alert chart above only knows about events that arrived over the socket while
 * this tab was open; this panel reads `/threats/stats`, so the operator sees the
 * standing picture immediately after a reload or a shift handover.
 */
export function ThreatSeverityPanel() {
  const [hours, setHours] = useState(24);

  const { data, isLoading, error } = useQuery<Stats>({
    queryKey: ["threat-stats", hours],
    queryFn: () => api.getThreatStats(hours) as Promise<Stats>,
    refetchInterval: 30000,
  });

  const rows = useMemo(() => {
    const counts = data?.counts || {};
    const max = Math.max(1, ...SEVERITY_ORDER.map((s) => counts[s] || 0));
    return SEVERITY_ORDER.map((severity) => ({
      severity,
      count: counts[severity] || 0,
      // Bars are scaled against the busiest severity so a quiet window is still legible.
      pct: ((counts[severity] || 0) / max) * 100,
    }));
  }, [data]);

  return (
    <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-white font-semibold text-sm uppercase tracking-wide">
          Threat Severity
        </h2>
        <div className="flex gap-1">
          {WINDOWS.map((w) => (
            <button
              key={w.hours}
              onClick={() => setHours(w.hours)}
              className={`text-xs rounded px-2 py-1 border transition-colors ${
                hours === w.hours
                  ? "bg-gray-700 border-gray-500 text-white"
                  : "border-gray-700 text-gray-400 hover:text-white"
              }`}
            >
              {w.label}
            </button>
          ))}
        </div>
      </div>

      {error ? (
        <p className="text-red-400 text-xs">Could not load threat statistics.</p>
      ) : isLoading ? (
        <p className="text-gray-500 text-xs">Loading…</p>
      ) : data && data.total === 0 ? (
        <p className="text-gray-500 text-xs">No threats recorded in this window.</p>
      ) : (
        <div className="space-y-2">
          {rows.map(({ severity, count, pct }) => (
            <div key={severity} className="flex items-center gap-2">
              <span className="text-gray-400 text-xs w-16 capitalize">{severity}</span>
              <div className="flex-1 bg-gray-800 rounded h-2 overflow-hidden">
                <div
                  className="h-full rounded"
                  style={{ width: `${pct}%`, backgroundColor: SEVERITY_COLOR[severity] }}
                />
              </div>
              <span className="text-white text-xs w-8 text-right tabular-nums">{count}</span>
            </div>
          ))}
          <p className="text-gray-600 text-xs pt-1">
            {data?.total ?? 0} detections in the last {data?.window_hours ?? hours}h
          </p>
        </div>
      )}
    </div>
  );
}
