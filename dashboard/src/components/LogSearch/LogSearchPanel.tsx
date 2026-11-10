import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { api, describeError, LogRecord } from "../../services/api";
import { CARD, CARD_TITLE, INPUT, SMALL_BUTTON, SeverityBadge } from "../common/ui";

interface SearchParams {
  q: string;
  anomalousOnly: boolean;
}

function when(ts: string | undefined): string {
  if (!ts) return "";
  const date = new Date(ts);
  return Number.isNaN(date.getTime()) ? ts : formatDistanceToNow(date, { addSuffix: true });
}

function LogRow({ log }: { log: LogRecord }) {
  const anomaly = log.anomaly && typeof log.anomaly === "object" ? log.anomaly : null;
  return (
    <li
      className={`rounded px-2 py-1 border-l-4 ${
        log.is_anomalous ? "border-red-500 bg-red-950/40" : "border-gray-700 bg-gray-800"
      }`}
    >
      <div className="flex items-center gap-2 text-xs">
        <span className="text-white truncate">{log.source || "unknown"}</span>
        {log.host && <span className="text-gray-500 truncate">{log.host}</span>}
        <span className="flex-1" />
        {anomaly && <SeverityBadge severity={anomaly.severity} />}
        <span className="text-gray-500 shrink-0">{when(log["@timestamp"])}</span>
      </div>
      <p className="text-gray-300 text-xs break-all">{String(log.message ?? "").slice(0, 300)}</p>
      {anomaly?.anomaly_type && (
        <p className="text-red-300 text-xs">{String(anomaly.anomaly_type).replace(/_/g, " ")}</p>
      )}
    </li>
  );
}

/** Free-text search over the logs mirrored into Elasticsearch. Read-only. */
export function LogSearchPanel() {
  const [query, setQuery] = useState("");
  const [anomalousOnly, setAnomalousOnly] = useState(false);
  // The submitted search; starts as "everything recent" so the panel is not blank.
  const [params, setParams] = useState<SearchParams>({ q: "", anomalousOnly: false });

  const { data, error, isFetching, refetch } = useQuery({
    queryKey: ["logs", params],
    queryFn: () => api.searchLogs({ q: params.q, anomalousOnly: params.anomalousOnly, limit: 50 }),
  });

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const next = { q: query.trim(), anomalousOnly };
    if (next.q === params.q && next.anomalousOnly === params.anomalousOnly) {
      // Same key — react-query would serve the cached result, so ask again explicitly.
      refetch();
    } else {
      setParams(next);
    }
  }

  const logs: LogRecord[] = data?.logs ?? [];
  const unavailable = data?.source === "unavailable";

  return (
    <div className={CARD}>
      <h2 className={`${CARD_TITLE} mb-3`}>Log Search</h2>
      <form onSubmit={submit} className="space-y-2 mb-3">
        <div className="flex gap-2">
          <input
            className={`flex-1 min-w-0 ${INPUT}`}
            placeholder="Search messages, sources, hosts…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Log search query"
          />
          <button type="submit" className={SMALL_BUTTON} disabled={isFetching}>
            {isFetching ? "Searching…" : "Search"}
          </button>
        </div>
        <label className="flex items-center gap-2 text-gray-400 text-xs">
          <input
            type="checkbox"
            checked={anomalousOnly}
            onChange={(e) => setAnomalousOnly(e.target.checked)}
          />
          Anomalous only
        </label>
      </form>

      {error ? (
        <p className="text-red-400 text-xs">{describeError(error)}</p>
      ) : unavailable ? (
        <p className="text-yellow-400 text-xs">
          Log search is unavailable — Elasticsearch is disabled or unreachable.
        </p>
      ) : !data && isFetching ? (
        <p className="text-gray-500 text-xs">Searching…</p>
      ) : logs.length === 0 ? (
        <p className="text-gray-500 text-xs">No matching logs.</p>
      ) : (
        <>
          <ul className="space-y-1 max-h-80 overflow-y-auto pr-1">
            {logs.map((log, i) => (
              <LogRow key={i} log={log} />
            ))}
          </ul>
          <p className="text-gray-600 text-xs pt-2">{data?.count ?? logs.length} results</p>
        </>
      )}
    </div>
  );
}
