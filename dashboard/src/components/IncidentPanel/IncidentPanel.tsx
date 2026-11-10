import React, { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  api,
  ContainmentAction,
  describeError,
  Incident,
  IncidentStatus,
} from "../../services/api";
import { useStore } from "../../store/useStore";
import {
  ADMIN_ONLY_TITLE,
  AdminOnlyHint,
  CARD,
  CARD_TITLE,
  INPUT,
  SMALL_BUTTON,
  SeverityBadge,
  severityFromPriority,
} from "../common/ui";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-green-400",
};

const INCIDENT_TYPES = ["unknown", "brute_force", "ransomware", "data_exfiltration", "c2_beacon", "sql_injection"];

/** Statuses an incident can be moved to from the list, in the order they are offered. */
const STATUS_TRANSITIONS: { status: IncidentStatus; label: string }[] = [
  { status: "contained", label: "Contain" },
  { status: "resolved", label: "Resolve" },
  { status: "false_positive", label: "False positive" },
];

/** Closed incidents offer a reopen instead of the transitions above. */
const CLOSED = new Set(["resolved", "false_positive"]);

const ACTION_STATUS_STYLE: Record<string, string> = {
  pending: "text-gray-400",
  pending_approval: "text-yellow-400",
  approved: "text-blue-400",
  rejected: "text-gray-500 line-through",
  simulated: "text-purple-400",
  completed: "text-green-400",
  failed: "text-red-400",
};

const ACTION_STATUS_LABEL: Record<string, string> = {
  pending_approval: "awaiting approval",
  // A simulated action never touched a real control — say so rather than "done".
  simulated: "simulated — not executed",
};

/** PostgreSQL rows carry `id`; the Redis fallback index carries `incident_id`. */
export function incidentId(incident: Incident): string | undefined {
  return incident.id ?? incident.incident_id ?? undefined;
}

interface Props {
  /** Write controls are admin-only on the server; mirror that here. */
  canWrite?: boolean;
}

export function IncidentPanel({ canWrite = false }: Props) {
  const incidents = useStore((s) => s.incidents) as Incident[];
  const queryClient = useQueryClient();

  const [title, setTitle] = useState("");
  const [type, setType] = useState("unknown");
  const [severity, setSeverity] = useState("medium");
  const [result, setResult] = useState<any>(null);

  // The list is fed by the polled ["incidents"] query in useSocData; invalidating it
  // re-reads the authoritative state after any change made from this panel.
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["incidents"] });

  const respond = useMutation({
    mutationFn: () => api.respondToIncident({ title, type, severity, description: title }),
    onSuccess: (data) => {
      setResult(data);
      refresh();
    },
  });

  return (
    <div className={CARD}>
      <h2 className={`${CARD_TITLE} mb-3`}>Incident Response</h2>
      <div className="space-y-2 mb-3">
        <input
          className={`w-full ${INPUT}`}
          placeholder="Incident title…"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          disabled={!canWrite}
        />
        <div className="flex gap-2">
          <select
            className={`flex-1 ${INPUT}`}
            value={type}
            onChange={(e) => setType(e.target.value)}
            disabled={!canWrite}
            aria-label="Incident type"
          >
            {INCIDENT_TYPES.map((t) => (
              <option key={t} value={t}>{t.replace(/_/g, " ")}</option>
            ))}
          </select>
          <select
            className={`flex-1 ${INPUT}`}
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            disabled={!canWrite}
            aria-label="Incident severity"
          >
            {["critical", "high", "medium", "low"].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
        <button
          onClick={() => respond.mutate()}
          disabled={!canWrite || respond.isPending || !title}
          title={canWrite ? undefined : ADMIN_ONLY_TITLE}
          className="w-full bg-red-700 hover:bg-red-600 disabled:bg-gray-700 text-white rounded py-2 text-sm font-medium transition-colors"
        >
          {respond.isPending ? "Running Playbook…" : "Execute Response Playbook"}
        </button>
        {!canWrite && <AdminOnlyHint />}
        {respond.error && (
          <p className="text-red-400 text-xs">{describeError(respond.error)}</p>
        )}
      </div>

      {result && (
        <div className="bg-gray-800 rounded p-3 text-xs space-y-1 mb-3">
          <p className={`font-semibold ${SEVERITY_COLORS[severity]}`}>
            Playbook: {result.playbook_name} | Priority: {result.response_plan?.priority}
          </p>
          <p className="text-gray-300">{result.summary}</p>
          {result.response_plan?.containment_actions?.slice(0, 3).map((a: any, i: number) => (
            <p key={i} className="text-gray-400">
              • {a.action}{" "}
              <span className="text-gray-500">({ACTION_STATUS_LABEL[a.status] || a.status})</span>
            </p>
          ))}
        </div>
      )}

      <IncidentList incidents={incidents} canWrite={canWrite} onChanged={refresh} />
    </div>
  );
}

function IncidentList({
  incidents,
  canWrite,
  onChanged,
}: {
  incidents: Incident[];
  canWrite: boolean;
  onChanged: () => void;
}) {
  return (
    <div>
      <p className="text-gray-400 text-xs uppercase tracking-wide mb-2">
        Recent incidents <span className="text-gray-600">({incidents.length})</span>
      </p>
      {incidents.length === 0 ? (
        <p className="text-gray-500 text-xs">No incidents recorded.</p>
      ) : (
        <ul className="space-y-1 max-h-72 overflow-y-auto pr-1">
          {incidents.map((incident, i) => (
            <IncidentRow
              key={incidentId(incident) ?? `row-${i}`}
              incident={incident}
              canWrite={canWrite}
              onChanged={onChanged}
            />
          ))}
        </ul>
      )}
    </div>
  );
}

function IncidentRow({
  incident,
  canWrite,
  onChanged,
}: {
  incident: Incident;
  canWrite: boolean;
  onChanged: () => void;
}) {
  const id = incidentId(incident);
  const [open, setOpen] = useState(false);
  const [note, setNote] = useState("");
  const [message, setMessage] = useState<string | null>(null);

  const setStatus = useMutation({
    mutationFn: (status: IncidentStatus) => api.updateIncident(id as string, status, note.trim() || undefined),
    onSuccess: () => {
      setNote("");
      setMessage(null);
      onChanged();
    },
    onError: (err) => setMessage(describeError(err)),
  });

  const decide = useMutation({
    mutationFn: ({ index, approve }: { index: number; approve: boolean }) =>
      approve ? api.approveAction(id as string, index) : api.rejectAction(id as string, index),
    onSuccess: (res) => {
      setMessage(res && res.ok === false ? res.error || "The server did not apply that decision." : null);
      onChanged();
    },
    onError: (err) => setMessage(describeError(err)),
  });

  const severity = incident.severity ?? severityFromPriority(incident.priority);
  const status = incident.status ?? "";
  const actions: ContainmentAction[] = Array.isArray(incident.remediation_steps)
    ? incident.remediation_steps
    : [];
  const busy = setStatus.isPending || decide.isPending;
  const writeDisabled = !canWrite || !id || busy;
  const writeTitle = canWrite ? undefined : ADMIN_ONLY_TITLE;
  const label = incident.title || incident.playbook_used || incident.playbook || id || "Untitled incident";

  return (
    <li className="bg-gray-800 rounded">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="w-full flex items-center gap-2 px-2 py-1.5 text-left"
      >
        <SeverityBadge severity={severity} />
        <span className="text-white text-xs truncate flex-1">{label}</span>
        <span className="text-gray-400 text-xs shrink-0">{status ? status.replace(/_/g, " ") : "—"}</span>
      </button>

      {open && (
        <div className="px-2 pb-2 space-y-2 text-xs">
          {incident.description && <p className="text-gray-400">{incident.description}</p>}

          <div>
            <p className="text-gray-500 mb-1">Containment actions</p>
            {actions.length === 0 ? (
              <p className="text-gray-600">No containment actions recorded.</p>
            ) : (
              <ul className="space-y-1">
                {actions.map((a, index) => (
                  <li key={index} className="flex items-center gap-2">
                    <span className="text-gray-300 flex-1">
                      {a.action}
                      {a.automated && <span className="text-gray-600"> (automated)</span>}
                    </span>
                    <span className={ACTION_STATUS_STYLE[a.status] || "text-gray-400"}>
                      {ACTION_STATUS_LABEL[a.status] || a.status}
                    </span>
                    {a.status === "pending_approval" && (
                      <>
                        <button
                          className={SMALL_BUTTON}
                          disabled={writeDisabled}
                          title={writeTitle}
                          onClick={() => decide.mutate({ index, approve: true })}
                        >
                          Approve
                        </button>
                        <button
                          className={SMALL_BUTTON}
                          disabled={writeDisabled}
                          title={writeTitle}
                          onClick={() => decide.mutate({ index, approve: false })}
                        >
                          Reject
                        </button>
                      </>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-1">
            <input
              className="flex-1 min-w-0 bg-gray-900 border border-gray-700 rounded px-2 py-1 text-white text-xs placeholder-gray-600"
              placeholder="Note (optional)"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              disabled={!canWrite}
              aria-label="Status note"
            />
            {CLOSED.has(status) ? (
              <button
                className={SMALL_BUTTON}
                disabled={writeDisabled}
                title={writeTitle}
                onClick={() => setStatus.mutate("open")}
              >
                Reopen
              </button>
            ) : (
              STATUS_TRANSITIONS.map(({ status: next, label: text }) => (
                <button
                  key={next}
                  className={SMALL_BUTTON}
                  disabled={writeDisabled || status === next}
                  title={writeTitle}
                  onClick={() => setStatus.mutate(next)}
                >
                  {text}
                </button>
              ))
            )}
          </div>

          {!canWrite && <AdminOnlyHint />}
          {message && <p className="text-red-400">{message}</p>}
        </div>
      )}
    </li>
  );
}
