import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../services/api";
import { useStore } from "../store/useStore";

const POLL_MS = 15000;

/**
 * Poll the REST snapshot endpoints into the shared store.
 *
 * The WebSocket only carries events that happen *while* the dashboard is open, so
 * without this the incident and threat counters started at zero on every reload and
 * the store's `setIncidents` / `setRecentThreats` actions were never called at all.
 */
export function useSocData() {
  const setIncidents = useStore((s) => s.setIncidents);
  const setRecentThreats = useStore((s) => s.setRecentThreats);

  const incidents = useQuery({
    queryKey: ["incidents"],
    queryFn: () => api.listIncidents(50),
    refetchInterval: POLL_MS,
  });

  const threats = useQuery({
    queryKey: ["recent-threats"],
    queryFn: () => api.getRecentThreats(50),
    refetchInterval: POLL_MS,
  });

  useEffect(() => {
    if (incidents.data?.incidents) setIncidents(incidents.data.incidents);
  }, [incidents.data, setIncidents]);

  useEffect(() => {
    if (threats.data?.threats) setRecentThreats(threats.data.threats);
  }, [threats.data, setRecentThreats]);

  return {
    loading: incidents.isLoading || threats.isLoading,
    error: incidents.error || threats.error,
  };
}
