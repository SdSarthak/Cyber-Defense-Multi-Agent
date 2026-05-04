import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useWebSocket } from "./hooks/useWebSocket";
import { ThreatLevelBanner } from "./components/Dashboard/ThreatLevelBanner";
import { MetricsRow } from "./components/Dashboard/MetricsRow";
import { AlertChart } from "./components/Dashboard/AlertChart";
import { AgentStatusGrid } from "./components/AgentStatus/AgentStatusGrid";
import { AlertFeed } from "./components/AlertFeed/AlertFeed";
import { IncidentPanel } from "./components/IncidentPanel/IncidentPanel";
import { ComplianceView } from "./components/ComplianceView/ComplianceView";

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 1 } } });

function SOCDashboard() {
  useWebSocket();

  return (
    <div className="min-h-screen bg-gray-950 text-white p-4 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Cyber Defense SOC</h1>
          <p className="text-gray-500 text-xs">AI-Powered Multi-Agent Security Operations</p>
        </div>
        <span className="text-gray-600 text-xs">{new Date().toLocaleString()}</span>
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
          <AgentStatusGrid />
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

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <SOCDashboard />
    </QueryClientProvider>
  );
}
