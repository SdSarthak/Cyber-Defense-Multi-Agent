import React, { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../../services/api";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";

const FRAMEWORK_COLORS: Record<string, string> = {
  pass: "#22c55e",
  partial: "#eab308",
  fail: "#ef4444",
  na: "#6b7280",
};

export function ComplianceView() {
  const [framework, setFramework] = useState("SOC2");
  const [result, setResult] = useState<any>(null);

  const { data: frameworks } = useQuery({
    queryKey: ["frameworks"],
    queryFn: api.listFrameworks,
  });

  const { mutate, isPending } = useMutation({
    mutationFn: () => api.evaluateCompliance(framework),
    onSuccess: (data) => setResult(data),
  });

  const pieData = result
    ? [
        { name: "Pass", value: result.control_results?.filter((c: any) => c.status === "pass").length || 0 },
        { name: "Partial", value: result.control_results?.filter((c: any) => c.status === "partial").length || 0 },
        { name: "Fail", value: result.control_results?.filter((c: any) => c.status === "fail").length || 0 },
      ]
    : [];

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-700 p-4">
      <h2 className="text-white font-semibold text-sm uppercase tracking-wide mb-3">Compliance Evaluation</h2>
      <div className="flex gap-2 mb-3">
        <select
          className="flex-1 bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white text-sm"
          value={framework}
          onChange={(e) => setFramework(e.target.value)}
        >
          {(frameworks?.frameworks || ["SOC2", "NIST_CSF", "ISO27001"]).map((f: string) => (
            <option key={f} value={f}>{f}</option>
          ))}
        </select>
        <button
          onClick={() => mutate()}
          disabled={isPending}
          className="bg-blue-700 hover:bg-blue-600 disabled:bg-gray-700 text-white rounded px-4 py-2 text-sm font-medium transition-colors"
        >
          {isPending ? "Evaluating…" : "Evaluate"}
        </button>
      </div>

      {result && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-gray-400 text-sm">Overall Score</span>
            <span className={`text-xl font-bold ${result.overall_score >= 70 ? "text-green-400" : result.overall_score >= 40 ? "text-yellow-400" : "text-red-400"}`}>
              {result.overall_score}%
            </span>
          </div>
          <ResponsiveContainer width="100%" height={120}>
            <PieChart>
              <Pie data={pieData} cx="50%" cy="50%" innerRadius={30} outerRadius={50} dataKey="value">
                {pieData.map((entry, i) => (
                  <Cell key={i} fill={Object.values(FRAMEWORK_COLORS)[i]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: "#1f2937", border: "none", color: "#fff" }} />
            </PieChart>
          </ResponsiveContainer>
          {result.failed_controls?.length > 0 && (
            <div>
              <p className="text-red-400 text-xs font-semibold mb-1">Failed Controls</p>
              {result.failed_controls.map((c: string) => (
                <p key={c} className="text-gray-400 text-xs">• {c}</p>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
