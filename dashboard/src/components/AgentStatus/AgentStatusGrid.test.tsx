import React from "react";
import { fireEvent, screen, waitFor } from "@testing-library/react";

import { api } from "../../services/api";
import { useStore } from "../../store/useStore";
import { renderWithClient } from "../../test-utils";
import { AgentStatusGrid, resolveAgentView } from "./AgentStatusGrid";

jest.mock("../../services/api", () => ({
  ...jest.requireActual("../../services/api"),
  api: { getAgentStatuses: jest.fn() },
}));

const mockStatuses = api.getAgentStatuses as jest.Mock;

beforeEach(() => {
  useStore.setState({ agentStatuses: {} });
});

describe("resolveAgentView", () => {
  it("reads paused from the flag, not from a disabled status", () => {
    expect(resolveAgentView({ status: "idle", paused: true }, undefined, 0)).toEqual({
      status: "idle",
      paused: true,
    });
    // A pause that expired server-side must not keep reading as paused.
    expect(resolveAgentView({ status: "disabled", paused: false }, undefined, 0).paused).toBe(false);
  });

  it("prefers a socket status that arrived after the last poll", () => {
    const polled = { status: "idle", paused: false };
    expect(resolveAgentView(polled, { name: "x", status: "running", updatedAt: 2000 }, 1000).status).toBe("running");
    expect(resolveAgentView(polled, { name: "x", status: "running", updatedAt: 500 }, 1000).status).toBe("idle");
  });

  it("falls back to the socket, then idle, before the first poll lands", () => {
    expect(resolveAgentView(undefined, { name: "x", status: "error" }, 0).status).toBe("error");
    expect(resolveAgentView(undefined, undefined, 0)).toEqual({ status: "idle", paused: false });
  });
});

describe("AgentStatusGrid", () => {
  it("labels a paused agent and offers an admin Resume", async () => {
    mockStatuses.mockResolvedValue({
      threat_detection: { status: "idle", paused: true },
      log_analysis: { status: "running", paused: false },
    });
    const onOverride = jest.fn().mockReturnValue(true);

    renderWithClient(<AgentStatusGrid canOverride onOverride={onOverride} />);

    const resume = await screen.findByTitle("Resume threat_detection");
    expect(screen.getByText("paused")).toBeTruthy();
    expect(screen.getByTitle("Pause log_analysis")).toBeTruthy();

    fireEvent.click(resume);
    expect(onOverride).toHaveBeenCalledWith("resume_agent", { agent: "threat_detection" });
  });

  it("offers Pause, not Resume, when the status is stale but the pause is gone", async () => {
    mockStatuses.mockResolvedValue({ compliance: { status: "disabled", paused: false } });

    renderWithClient(<AgentStatusGrid canOverride onOverride={jest.fn()} />);

    expect(await screen.findByTitle("Pause compliance")).toBeTruthy();
    expect(screen.queryByTitle("Resume compliance")).toBeNull();
  });

  it("shows no pause controls to an analyst", async () => {
    mockStatuses.mockResolvedValue({ threat_detection: { status: "idle", paused: true } });

    renderWithClient(<AgentStatusGrid canOverride={false} />);

    await waitFor(() => expect(screen.getByText("paused")).toBeTruthy());
    expect(screen.queryAllByTitle(/^(Pause|Resume) /)).toHaveLength(0);
  });
});
