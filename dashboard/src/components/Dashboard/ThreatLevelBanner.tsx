import React from "react";
import { useStore } from "../../store/useStore";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../services/api";

const LEVEL_CONFIG = {
  critical: { bg: "bg-red-700", text: "CRITICAL", label: "Immediate response required" },
  high:     { bg: "bg-orange-600", text: "HIGH", label: "Active threat detected" },
  medium:   { bg: "bg-yellow-500", text: "MEDIUM", label: "Elevated threat activity" },
  low:      { bg: "bg-green-700", text: "LOW", label: "Normal operations" },
};

export function ThreatLevelBanner() {
  const { threatLevel, connected } = useStore();
  const { data: bb } = useQuery({ queryKey: ["blackboard"], queryFn: api.getBlackboard, refetchInterval: 10000 });
  const level = (bb?.threat_level || threatLevel) as keyof typeof LEVEL_CONFIG;
  const config = LEVEL_CONFIG[level] || LEVEL_CONFIG.low;

  return (
    <div className={`${config.bg} rounded-lg px-4 py-3 flex items-center justify-between`}>
      <div>
        <span className="text-white font-bold text-lg">{config.text}</span>
        <span className="text-white/80 ml-3 text-sm">{config.label}</span>
      </div>
      <div className="flex items-center gap-2">
        <div className={`w-2 h-2 rounded-full ${connected ? "bg-green-400 animate-pulse" : "bg-gray-400"}`} />
        <span className="text-white/70 text-xs">{connected ? "Live" : "Disconnected"}</span>
      </div>
    </div>
  );
}
