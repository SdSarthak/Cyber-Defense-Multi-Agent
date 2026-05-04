import { useEffect, useRef } from "react";
import { createWebSocket } from "../services/api";
import { useStore } from "../store/useStore";

export function useWebSocket() {
  const wsRef = useRef<WebSocket | null>(null);
  const { addAlert, setAgentStatus, setThreatLevel, setConnected } = useStore();

  useEffect(() => {
    function connect() {
      const ws = createWebSocket((msg) => {
        const alert = { id: crypto.randomUUID(), channel: msg.channel, data: msg.data, timestamp: new Date().toISOString() };
        addAlert(alert);

        if (msg.channel === "agent_events" && msg.data?.agent && msg.data?.event) {
          setAgentStatus(msg.data.agent, { name: msg.data.agent, status: msg.data.event === "task_complete" ? "idle" : "running" });
        }
        if (msg.data?.threat_level) {
          setThreatLevel(msg.data.threat_level);
        }
      });

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        setTimeout(connect, 3000);
      };
      wsRef.current = ws;
    }
    connect();
    return () => wsRef.current?.close();
  }, []);

  function sendOverride(command: string, payload: object) {
    wsRef.current?.send(JSON.stringify({ type: "human_override", command, payload }));
  }

  return { sendOverride };
}
