import React, { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { api } from "../../services/api";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-green-400",
};

export function IncidentPanel() {
  const [title, setTitle] = useState("");
  const [type, setType] = useState("unknown");
  const [severity, setSeverity] = useState("medium");
  const [result, setResult] = useState<any>(null);

  const { mutate, isPending } = useMutation({
    mutationFn: () => api.respondToIncident({ title, type, severity, description: title }),
    onSuccess: (data) => setResult(data),
  });

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-700 p-4">
      <h2 className="text-white font-semibold text-sm uppercase tracking-wide mb-3">Incident Response</h2>
      <div className="space-y-2 mb-3">
        <input
          className="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white text-sm placeholder-gray-500"
          placeholder="Incident title…"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />
        <div className="flex gap-2">
          <select
            className="flex-1 bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white text-sm"
            value={type}
            onChange={(e) => setType(e.target.value)}
          >
            {["unknown", "brute_force", "ransomware", "data_exfiltration", "c2_beacon", "sql_injection"].map((t) => (
              <option key={t} value={t}>{t.replace(/_/g, " ")}</option>
            ))}
          </select>
          <select
            className="flex-1 bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white text-sm"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
          >
            {["critical", "high", "medium", "low"].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
        <button
          onClick={() => mutate()}
          disabled={isPending || !title}
          className="w-full bg-red-700 hover:bg-red-600 disabled:bg-gray-700 text-white rounded py-2 text-sm font-medium transition-colors"
        >
          {isPending ? "Running Playbook…" : "Execute Response Playbook"}
        </button>
      </div>
      {result && (
        <div className="bg-gray-800 rounded p-3 text-xs space-y-1">
          <p className={`font-semibold ${SEVERITY_COLORS[severity]}`}>
            Playbook: {result.playbook_name} | Priority: {result.response_plan?.priority}
          </p>
          <p className="text-gray-300">{result.summary}</p>
          {result.response_plan?.containment_actions?.slice(0, 3).map((a: any, i: number) => (
            <p key={i} className="text-gray-400">• {a.action} <span className="text-gray-500">({a.status})</span></p>
          ))}
        </div>
      )}
    </div>
  );
}
