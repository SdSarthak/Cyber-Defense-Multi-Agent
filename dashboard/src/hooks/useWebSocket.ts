import { useCallback, useEffect, useRef } from "react";
import { createWebSocket } from "../services/api";
import { useStore } from "../store/useStore";

const RECONNECT_DELAY_MS = 3000;

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
        // The server's opening frame is a handshake ack, and override replies are
        // request/response — neither belongs in the alert feed.
        if (msg?.type === "connected" || msg?.type === "override_result" || msg?.type === "error") {
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

        if (msg.channel === "agent_events" && msg.data?.agent && msg.data?.event) {
          setAgentStatus(msg.data.agent, {
            name: msg.data.agent,
            status: msg.data.event === "task_complete" ? "idle" : "running",
          });
        }
        if (msg.data?.threat_level) {
          setThreatLevel(msg.data.threat_level);
        }
      });

      // No token: stay disconnected rather than looping on a handshake the server
      // will reject with 1008.
      if (!ws) {
        setConnected(false);
        return;
      }

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (closedRef.current) return;
        timerRef.current = setTimeout(connect, RECONNECT_DELAY_MS);
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
    ws.send(JSON.stringify({ type: "human_override", command, payload }));
    return true;
  }, []);

  return { sendOverride };
}
