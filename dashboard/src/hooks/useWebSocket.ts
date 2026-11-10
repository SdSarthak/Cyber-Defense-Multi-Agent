import { useCallback, useEffect, useRef, useState } from "react";
import { createWebSocket } from "../services/api";
import { logout } from "../services/auth";
import {
  AgentName,
  AgentRunStatus,
  isKnownAgent,
  isThreatLevel,
  ThreatLevel,
  useStore,
} from "../store/useStore";

/**
 * The only `agent_events` that describe an agent's run state. Everything else on the
 * channel — routing decisions, report notifications, operator overrides, simulator
 * ticks — is informational, and used to flip the sender to "running" with nothing
 * ever flipping it back.
 */
const STATUS_EVENTS: Record<string, AgentRunStatus> = {
  task_start: "running",
  task_complete: "idle",
  task_error: "error",
};

/** Map an `agent_events` payload to a status change, or null when it is not one. */
export function agentStatusFromEvent(
  data: any,
): { agent: AgentName; status: AgentRunStatus } | null {
  const agent = data?.agent;
  const event = data?.event;
  if (!isKnownAgent(agent) || typeof event !== "string") return null;
  const status = STATUS_EVENTS[event];
  return status ? { agent, status } : null;
}

/**
 * The effective threat level is announced on `agent_events` with event
 * "threat_level". Other frames may carry a `threat_level` field too (an override's
 * echoed payload, an escalation), but those are not the level the board is at.
 */
export function threatLevelFromFrame(msg: any): ThreatLevel | null {
  if (msg?.channel !== "agent_events" || msg.data?.event !== "threat_level") return null;
  const level = String(msg.data?.threat_level ?? "").toLowerCase();
  return isThreatLevel(level) ? level : null;
}

const RECONNECT_DELAY_MS = 3000;
const MAX_RECONNECT_DELAY_MS = 30000;

// RFC 6455 policy violation — what the server sends when the handshake token is
// missing, expired or forged.
export const WS_POLICY_VIOLATION = 1008;

/**
 * Exponential backoff with jitter.
 *
 * A fixed 3s retry turned a server that is down (or a token the server rejects)
 * into an indefinite connection storm: one handshake every three seconds, per open
 * tab, for as long as the page stayed open.
 */
export function reconnectDelay(attempt: number): number {
  const base = Math.min(RECONNECT_DELAY_MS * 2 ** attempt, MAX_RECONNECT_DELAY_MS);
  return Math.round(base / 2 + Math.random() * (base / 2));
}

export interface OverrideResult {
  command: string;
  ok: boolean;
  error?: string;
}

/**
 * Live telemetry socket.
 *
 * Reconnects on drop, but only while the component is mounted — the previous
 * version left a `setTimeout` running after unmount, so every remount stacked
 * another reconnect loop onto the same page.
 */
export function useWebSocket(enabled: boolean = true) {
  const wsRef = useRef<WebSocket | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const closedRef = useRef(false);
  const attemptRef = useRef(0);
  const [lastOverride, setLastOverride] = useState<OverrideResult | null>(null);

  // Selecting actions individually keeps this effect from re-running on every
  // alert that lands in the store.
  const addAlert = useStore((s) => s.addAlert);
  const setAgentStatus = useStore((s) => s.setAgentStatus);
  const setThreatLevel = useStore((s) => s.setThreatLevel);
  const setConnected = useStore((s) => s.setConnected);

  useEffect(() => {
    if (!enabled) return;
    closedRef.current = false;

    function connect() {
      if (closedRef.current) return;

      const ws = createWebSocket((msg) => {
        // An override reply is the answer to a command the operator just issued, so
        // it is surfaced on the control that issued it rather than in the alert feed.
        if (msg?.type === "override_result") {
          setLastOverride({
            command: msg.command,
            ok: Boolean(msg.result?.ok),
            error: msg.result?.error,
          });
          return;
        }

        // The opening frame is a handshake ack; protocol errors are not alerts.
        if (msg?.type === "connected" || msg?.type === "error") {
          return;
        }

        addAlert({
          id:
            typeof crypto !== "undefined" && crypto.randomUUID
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random()}`,
          channel: msg.channel,
          data: msg.data,
          timestamp: new Date().toISOString(),
        });

        if (msg.channel === "agent_events") {
          const update = agentStatusFromEvent(msg.data);
          if (update) {
            setAgentStatus(update.agent, {
              name: update.agent,
              status: update.status,
              task_id:
                update.status === "running" && typeof msg.data?.task_id === "string"
                  ? msg.data.task_id
                  : undefined,
              updatedAt: Date.now(),
            });
          }
        }

        const level = threatLevelFromFrame(msg);
        if (level) {
          setThreatLevel(level);
        }
      });

      // No token: stay disconnected rather than looping on a handshake the server
      // will reject with 1008.
      if (!ws) {
        setConnected(false);
        return;
      }

      ws.onopen = () => {
        attemptRef.current = 0;
        setConnected(true);
      };
      ws.onclose = (event) => {
        setConnected(false);
        if (closedRef.current) return;

        // The server closes with 1008 when it refuses the token. Retrying that is
        // pointless — the credential is dead, so drop the session and let the app
        // render the login screen instead of reconnecting forever.
        if (event?.code === WS_POLICY_VIOLATION) {
          logout();
          return;
        }

        timerRef.current = setTimeout(connect, reconnectDelay(attemptRef.current));
        attemptRef.current += 1;
      };
      wsRef.current = ws;
    }

    connect();

    return () => {
      closedRef.current = true;
      if (timerRef.current) clearTimeout(timerRef.current);
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [enabled, addAlert, setAgentStatus, setThreatLevel, setConnected]);

  const sendOverride = useCallback((command: string, payload: object) => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return false;
    setLastOverride(null);
    ws.send(JSON.stringify({ type: "human_override", command, payload }));
    return true;
  }, []);

  return { sendOverride, lastOverride };
}
