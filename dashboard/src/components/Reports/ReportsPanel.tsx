import React, { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, describeError, ReportIndexEntry, ReportType } from "../../services/api";
import { ADMIN_ONLY_TITLE, AdminOnlyHint, CARD, CARD_TITLE, SMALL_BUTTON } from "../common/ui";

const TS_RE = /^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})/;

/** Report index timestamps look like 20260101_120000; show them readably. */
export function formatReportTs(ts: string | undefined | null): string {
  if (!ts) return "";
  const m = TS_RE.exec(ts);
  return m ? `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]} UTC` : ts;
}

function humanize(key: string): string {
  return key.replace(/_/g, " ");
}

/** Metrics the platform could not measure arrive as null — show that, never invent a number. */
export function formatMetric(value: unknown): string {
  if (value === null || value === undefined || value === "") return "n/a";
  if (typeof value === "number") return Number.isInteger(value) ? String(value) : value.toFixed(1);
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function asList(value: unknown): any[] {
  return Array.isArray(value) ? value : [];
}

function ExecutiveReport({ report }: { report: Record<string, any> }) {
  const metrics = report.key_metrics && typeof report.key_metrics === "object" ? report.key_metrics : {};
  const risks = asList(report.top_risks);
  const actions = asList(report.recommended_actions);
  return (
    <div className="space-y-2">
      {report.executive_summary && <p className="text-gray-200">{report.executive_summary}</p>}
      {Object.keys(metrics).length > 0 && (
        <dl className="grid grid-cols-2 gap-x-3 gap-y-1">
          {Object.entries(metrics).map(([k, v]) => (
            <React.Fragment key={k}>
              <dt className="text-gray-500 capitalize truncate">{humanize(k)}</dt>
              <dd className="text-white text-right tabular-nums">{formatMetric(v)}</dd>
            </React.Fragment>
          ))}
        </dl>
      )}
      {risks.length > 0 && (
        <div>
          <p className="text-gray-500 mb-1">Top risks</p>
          {risks.map((r, i) => (
            <p key={i} className="text-gray-300">
              • {typeof r === "string" ? r : r?.risk}
              {r?.impact && <span className="text-gray-500"> — impact {r.impact}</span>}
            </p>
          ))}
        </div>
      )}
      {actions.length > 0 && (
        <div>
          <p className="text-gray-500 mb-1">Recommended actions</p>
          {actions.map((a, i) => (
            <p key={i} className="text-gray-300">
              • {typeof a === "string" ? a : a?.action}
              {a?.priority && <span className="text-gray-500"> ({a.priority})</span>}
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

function ThreatReport({ report }: { report: Record<string, any> }) {
  const iocs = report.iocs && typeof report.iocs === "object" ? report.iocs : {};
  const recs = asList(report.recommendations);
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <p className="text-white font-semibold flex-1">{report.title || "Threat report"}</p>
        {report.tlp && (
          <span className="text-xs px-1.5 py-0.5 rounded bg-gray-700 text-white">TLP:{report.tlp}</span>
        )}
      </div>
      {asList(report.attack_vectors).length > 0 && (
        <p className="text-gray-300">Vectors: {asList(report.attack_vectors).join(", ")}</p>
      )}
      {["ips", "domains", "hashes"].map((kind) => {
        const items = asList(iocs[kind]);
        return items.length > 0 ? (
          <p key={kind} className="text-gray-400 break-all">
            <span className="text-gray-500 uppercase">{kind}:</span> {items.slice(0, 5).join(", ")}
            {items.length > 5 && <span className="text-gray-600"> +{items.length - 5} more</span>}
          </p>
        ) : null;
      })}
      {recs.length > 0 && (
        <div>
          <p className="text-gray-500 mb-1">Recommendations</p>
          {recs.map((r, i) => (
            <p key={i} className="text-gray-300">• {String(r)}</p>
          ))}
        </div>
      )}
    </div>
  );
}

/** Readable rendering of a stored report, whichever type it is. */
export function ReportView({ report }: { report: Record<string, any> | null | undefined }) {
  if (!report || typeof report !== "object") {
    return <p className="text-gray-500">Empty report.</p>;
  }
  if (report.error) {
    return <p className="text-red-400">{String(report.error)}</p>;
  }
  const type =
    report.report_type ?? (report.executive_summary ? "executive" : report.tlp ? "threat" : undefined);

  let body: React.ReactNode;
  if (report.raw_content) {
    // The model's output could not be parsed as JSON; show what it said.
    body = <p className="text-gray-300 whitespace-pre-wrap">{String(report.raw_content).slice(0, 2000)}</p>;
  } else if (type === "executive") {
    body = <ExecutiveReport report={report} />;
  } else if (type === "threat") {
    body = <ThreatReport report={report} />;
  } else {
    body = (
      <pre className="text-gray-400 whitespace-pre-wrap break-all">
        {JSON.stringify(report, null, 2).slice(0, 2000)}
      </pre>
    );
  }
  return (
    <div className="space-y-1">
      {report.generated_at && <p className="text-gray-600">Generated {report.generated_at}</p>}
      {body}
    </div>
  );
}

interface Props {
  /** Generating a report runs the agent mesh and is admin-only on the server. */
  canWrite?: boolean;
}

export function ReportsPanel({ canWrite = false }: Props) {
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<string | null>(null);

  const list = useQuery({
    queryKey: ["reports"],
    queryFn: () => api.listReports(20),
    refetchInterval: 30000,
  });

  const report = useQuery({
    queryKey: ["report", selected],
    queryFn: () => api.getReport(selected as string),
    enabled: Boolean(selected),
  });

  const generate = useMutation({
    mutationFn: (type: ReportType) => api.generateReport(type),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ["reports"] });
      if (res?.report_key) setSelected(res.report_key);
    },
  });

  const reports: ReportIndexEntry[] = list.data?.reports ?? [];

  return (
    <div className={CARD}>
      <div className="flex items-center justify-between mb-3">
        <h2 className={CARD_TITLE}>Reports</h2>
        <div className="flex gap-1">
          {(["executive", "threat"] as ReportType[]).map((type) => (
            <button
              key={type}
              className={SMALL_BUTTON}
              disabled={!canWrite || generate.isPending}
              title={canWrite ? `Generate a ${type} report` : ADMIN_ONLY_TITLE}
              onClick={() => generate.mutate(type)}
            >
              {generate.isPending && generate.variables === type ? "Generating…" : `+ ${type}`}
            </button>
          ))}
        </div>
      </div>
      {!canWrite && <AdminOnlyHint className="mb-2" />}
      {generate.error && <p className="text-red-400 text-xs mb-2">{describeError(generate.error)}</p>}

      {list.error ? (
        <p className="text-red-400 text-xs">{describeError(list.error)}</p>
      ) : list.isLoading ? (
        <p className="text-gray-500 text-xs">Loading…</p>
      ) : reports.length === 0 ? (
        <p className="text-gray-500 text-xs">No reports stored yet.</p>
      ) : (
        <ul className="space-y-1 max-h-40 overflow-y-auto pr-1 mb-2">
          {reports.map((r) => (
            <li key={r.key}>
              <button
                type="button"
                onClick={() => setSelected(r.key === selected ? null : r.key)}
                className={`w-full flex items-center gap-2 rounded px-2 py-1 text-left text-xs ${
                  r.key === selected ? "bg-gray-700" : "bg-gray-800 hover:bg-gray-700"
                }`}
              >
                <span className="text-white capitalize">{r.type}</span>
                <span className="text-gray-500 flex-1 text-right">{formatReportTs(r.ts)}</span>
              </button>
            </li>
          ))}
        </ul>
      )}

      {selected && (
        <div className="bg-gray-800 rounded p-3 text-xs max-h-80 overflow-y-auto">
          {report.isLoading ? (
            <p className="text-gray-500">Loading report…</p>
          ) : report.error ? (
            <p className="text-red-400">{describeError(report.error)}</p>
          ) : (
            <ReportView report={report.data} />
          )}
        </div>
      )}
    </div>
  );
}
