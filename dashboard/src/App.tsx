import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useWebSocket } from "./hooks/useWebSocket";
import { useSocData } from "./hooks/useSocData";
import { useSession } from "./hooks/useSession";
import { logout } from "./services/auth";
import { LoginScreen } from "./components/Login/LoginScreen";
import { ThreatLevelBanner } from "./components/Dashboard/ThreatLevelBanner";
import { MetricsRow } from "./components/Dashboard/MetricsRow";
import { AlertChart } from "./components/Dashboard/AlertChart";
import { ThreatSeverityPanel } from "./components/Dashboard/ThreatSeverityPanel";
import { AgentStatusGrid } from "./components/AgentStatus/AgentStatusGrid";
import { AlertFeed } from "./components/AlertFeed/AlertFeed";
import { IncidentPanel } from "./components/IncidentPanel/IncidentPanel";
import { ComplianceView } from "./components/ComplianceView/ComplianceView";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // A 401 has already cleared the session and swapped in the login screen;
      // retrying it would just burn requests.
      retry: (failureCount, error: any) => error?.status !== 401 && failureCount < 1,
      refetchOnWindowFocus: false,
    },
  },
});

function SOCDashboard({ username, role }: { username: string; role: string }) {
  const { sendOverride, lastOverride } = useWebSocket();
  useSocData();

  function signOut() {
    // Drop cached responses too, so the next operator never sees stale data.
    queryClient.clear();
    logout();
  }

  return (
    <div className="min-h-screen bg-gray-950 text-white p-4 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Cyber Defense SOC</h1>
          <p className="text-gray-500 text-xs">AI-Powered Multi-Agent Security Operations</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-gray-600 text-xs">{new Date().toLocaleString()}</span>
          <span className="text-gray-400 text-xs">
            {username} <span className="text-gray-600">({role})</span>
          </span>
          <button
            onClick={signOut}
            className="text-xs text-gray-400 hover:text-white border border-gray-700 hover:border-gray-500 rounded px-2 py-1 transition-colors"
          >
            Sign out
          </button>
        </div>
      </div>

      {/* Threat Level */}
      <ThreatLevelBanner />

      {/* Metrics */}
      <MetricsRow />

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left: Alert Feed */}
        <div className="lg:col-span-1 h-96">
          <AlertFeed />
        </div>

        {/* Center: Charts + Agent Grid */}
        <div className="lg:col-span-1 space-y-4">
          <AlertChart />
          <ThreatSeverityPanel />
          <AgentStatusGrid
            canOverride={role === "admin"}
            onOverride={sendOverride}
            overrideResult={lastOverride}
          />
        </div>

        {/* Right: Incident + Compliance */}
        <div className="lg:col-span-1 space-y-4">
          <IncidentPanel />
          <ComplianceView />
        </div>
      </div>
    </div>
  );
}

function Root() {
  const session = useSession();
  if (!session) return <LoginScreen />;
  // Keying on the username tears down every socket and query on operator change.
  return <SOCDashboard key={session.username} username={session.username} role={session.role} />;
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Root />
    </QueryClientProvider>
  );
}
