import React from "react";

/** Tooltip on a control an analyst can see but not use. */
export const ADMIN_ONLY_TITLE = "Admin only — your role has read-only access";

/**
 * Shown next to write controls for a read-only role. The server refuses these calls
 * with 403 for anyone but an admin, so the UI says so up front instead of letting the
 * operator click into an error.
 */
export function AdminOnlyHint({ className = "" }: { className?: string }) {
  return (
    <p className={`text-gray-500 text-xs ${className}`} role="note">
      Admin only — analysts have read-only access.
    </p>
  );
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-500 text-black",
  low: "bg-green-600 text-white",
  info: "bg-gray-600 text-white",
};

const PRIORITY_SEVERITY: Record<string, string> = {
  p1: "critical",
  p2: "high",
  p3: "medium",
  p4: "low",
};

/** Redis-only incident rows carry a priority (p1–p4) instead of a severity. */
export function severityFromPriority(priority?: string | null): string | undefined {
  return priority ? PRIORITY_SEVERITY[String(priority).toLowerCase()] : undefined;
}

export function SeverityBadge({ severity }: { severity?: string | null }) {
  if (!severity) return null;
  const key = String(severity).toLowerCase();
  return (
    <span className={`text-xs px-1.5 py-0.5 rounded ${SEVERITY_BADGE[key] || "bg-gray-600 text-white"}`}>
      {key}
    </span>
  );
}

export const CARD = "bg-gray-900 rounded-lg border border-gray-700 p-4";
export const CARD_TITLE = "text-white font-semibold text-sm uppercase tracking-wide";
export const INPUT =
  "bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white text-sm placeholder-gray-500";
export const SMALL_BUTTON =
  "text-xs text-gray-300 hover:text-white border border-gray-700 hover:border-gray-500 rounded px-2 py-1 transition-colors disabled:opacity-40 disabled:hover:text-gray-300 disabled:hover:border-gray-700 disabled:cursor-not-allowed";
