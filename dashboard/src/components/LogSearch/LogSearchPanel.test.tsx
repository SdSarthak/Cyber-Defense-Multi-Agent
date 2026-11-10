import React from "react";
import { fireEvent, screen, waitFor } from "@testing-library/react";

import { api } from "../../services/api";
import { renderWithClient } from "../../test-utils";
import { LogSearchPanel } from "./LogSearchPanel";

jest.mock("../../services/api", () => ({
  ...jest.requireActual("../../services/api"),
  api: { searchLogs: jest.fn() },
}));

const mockSearch = api.searchLogs as jest.Mock;

it("says so when Elasticsearch is unavailable", async () => {
  mockSearch.mockResolvedValue({ logs: [], count: 0, source: "unavailable" });
  renderWithClient(<LogSearchPanel />);
  expect(await screen.findByText(/Log search is unavailable/)).toBeTruthy();
});

it("lists results and flags anomalous entries", async () => {
  mockSearch.mockResolvedValue({
    logs: [
      {
        "@timestamp": new Date().toISOString(),
        source: "sshd",
        message: "Failed password for root from 185.220.101.45",
        is_anomalous: true,
        anomaly: { anomaly_type: "brute_force", severity: "high" },
      },
    ],
    count: 1,
    source: "elasticsearch",
  });
  renderWithClient(<LogSearchPanel />);

  expect(await screen.findByText(/Failed password for root/)).toBeTruthy();
  expect(screen.getByText("brute force")).toBeTruthy();
  expect(screen.getByText("1 results")).toBeTruthy();
});

it("sends the query and the anomalous-only filter", async () => {
  mockSearch.mockResolvedValue({ logs: [], count: 0, source: "elasticsearch" });
  renderWithClient(<LogSearchPanel />);
  // Let the initial "recent logs" load settle so the Search button is idle again.
  await screen.findByText("No matching logs.");
  expect(mockSearch).toHaveBeenCalledTimes(1);

  fireEvent.change(screen.getByLabelText("Log search query"), { target: { value: "union select" } });
  fireEvent.click(screen.getByLabelText("Anomalous only"));
  fireEvent.click(screen.getByRole("button", { name: "Search" }));

  await waitFor(() =>
    expect(mockSearch).toHaveBeenLastCalledWith({ q: "union select", anomalousOnly: true, limit: 50 })
  );
});
