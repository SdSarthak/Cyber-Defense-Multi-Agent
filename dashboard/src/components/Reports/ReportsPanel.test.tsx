import React from "react";
import { render, screen } from "@testing-library/react";

import { formatMetric, formatReportTs, ReportView } from "./ReportsPanel";

describe("ReportView", () => {
  it("renders an executive report and shows unmeasured metrics as n/a", () => {
    render(
      <ReportView
        report={{
          report_type: "executive",
          executive_summary: "Posture is stable.",
          key_metrics: { total_incidents: 3, mean_time_to_detect_hours: null },
          top_risks: [{ risk: "Exposed SSH", impact: "high" }],
          recommended_actions: [{ action: "Enforce MFA", priority: "high" }],
        }}
      />
    );

    expect(screen.getByText("Posture is stable.")).toBeTruthy();
    expect(screen.getByText("3")).toBeTruthy();
    expect(screen.getByText("n/a")).toBeTruthy();
    expect(screen.getByText(/Exposed SSH/)).toBeTruthy();
    expect(screen.getByText(/Enforce MFA/)).toBeTruthy();
  });

  it("renders a threat report with its TLP and IOCs", () => {
    render(
      <ReportView
        report={{
          report_type: "threat",
          title: "SSH campaign",
          tlp: "AMBER",
          iocs: { ips: ["185.220.101.45"], domains: [], hashes: [] },
          recommendations: ["Block the range"],
        }}
      />
    );

    expect(screen.getByText("SSH campaign")).toBeTruthy();
    expect(screen.getByText("TLP:AMBER")).toBeTruthy();
    expect(screen.getByText(/185\.220\.101\.45/)).toBeTruthy();
    expect(screen.getByText(/Block the range/)).toBeTruthy();
  });

  it("shows the model's raw text when its output could not be parsed", () => {
    render(<ReportView report={{ report_type: "executive", raw_content: "Unstructured answer" }} />);
    expect(screen.getByText("Unstructured answer")).toBeTruthy();
  });
});

describe("formatting", () => {
  it("formats index timestamps", () => {
    expect(formatReportTs("20260101_120501")).toBe("2026-01-01 12:05 UTC");
    expect(formatReportTs("20260101_120501_ab12")).toBe("2026-01-01 12:05 UTC");
    expect(formatReportTs("yesterday")).toBe("yesterday");
  });

  it("never invents a number for a missing metric", () => {
    expect(formatMetric(null)).toBe("n/a");
    expect(formatMetric(undefined)).toBe("n/a");
    expect(formatMetric(2.345)).toBe("2.3");
    expect(formatMetric(7)).toBe("7");
  });
});
