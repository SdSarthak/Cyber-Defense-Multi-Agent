import React from "react";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";

import { api } from "../../services/api";
import { useStore } from "../../store/useStore";
import { renderWithClient } from "../../test-utils";
import { IncidentPanel, incidentId } from "./IncidentPanel";

jest.mock("../../services/api", () => ({
  ...jest.requireActual("../../services/api"),
  api: {
    respondToIncident: jest.fn(),
    updateIncident: jest.fn(),
    approveAction: jest.fn(),
    rejectAction: jest.fn(),
  },
}));

const mockApi = api as jest.Mocked<typeof api>;

const PG_INCIDENT = {
  id: "inc-1",
  title: "SSH brute force",
  severity: "high",
  status: "investigating",
  remediation_steps: [
    { action: "Block source IP", automated: true, status: "pending_approval" },
    { action: "Reset credentials", automated: false, status: "pending" },
    { action: "Isolate host", automated: true, status: "simulated" },
  ],
};

const REDIS_INCIDENT = { incident_id: "r-1", title: "Redis-only incident", priority: "p1" };

function expand(title: RegExp) {
  fireEvent.click(screen.getByRole("button", { name: title }));
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole("button", { name }) as HTMLButtonElement;
}

beforeEach(() => {
  useStore.setState({ incidents: [PG_INCIDENT, REDIS_INCIDENT] });
});

it("uses id for PostgreSQL rows and incident_id for Redis rows", () => {
  expect(incidentId(PG_INCIDENT)).toBe("inc-1");
  expect(incidentId(REDIS_INCIDENT)).toBe("r-1");
});

describe("as an admin", () => {
  it("approves a containment action awaiting approval by its index", async () => {
    mockApi.approveAction.mockResolvedValue({ ok: true });
    renderWithClient(<IncidentPanel canWrite />);

    expand(/SSH brute force/);
    fireEvent.click(button("Approve"));

    await waitFor(() => expect(mockApi.approveAction).toHaveBeenCalledWith("inc-1", 0));
  });

  it("rejects a containment action", async () => {
    mockApi.rejectAction.mockResolvedValue({ ok: true });
    renderWithClient(<IncidentPanel canWrite />);

    expand(/SSH brute force/);
    fireEvent.click(button("Reject"));

    await waitFor(() => expect(mockApi.rejectAction).toHaveBeenCalledWith("inc-1", 0));
  });

  it("moves an incident to resolved, carrying the note", async () => {
    mockApi.updateIncident.mockResolvedValue({ ok: true, incident_id: "inc-1", status: "resolved" });
    renderWithClient(<IncidentPanel canWrite />);

    expand(/SSH brute force/);
    fireEvent.change(screen.getByLabelText("Status note"), { target: { value: "host reimaged" } });
    fireEvent.click(button("Resolve"));

    await waitFor(() =>
      expect(mockApi.updateIncident).toHaveBeenCalledWith("inc-1", "resolved", "host reimaged")
    );
  });

  it("shows the server's refusal instead of failing silently", async () => {
    mockApi.approveAction.mockResolvedValue({ ok: false, error: "Action is no longer pending" });
    renderWithClient(<IncidentPanel canWrite />);

    expand(/SSH brute force/);
    fireEvent.click(button("Approve"));

    expect(await screen.findByText("Action is no longer pending")).toBeTruthy();
  });

  it("labels simulated actions as not executed", () => {
    renderWithClient(<IncidentPanel canWrite />);
    expand(/SSH brute force/);
    expect(screen.getByText("simulated — not executed")).toBeTruthy();
  });

  it("handles a Redis-only row with no recorded actions", () => {
    renderWithClient(<IncidentPanel canWrite />);
    expand(/Redis-only incident/);
    expect(screen.getByText("No containment actions recorded.")).toBeTruthy();
    // Severity is derived from the p1 priority.
    const row = screen.getByRole("button", { name: /Redis-only incident/ });
    expect(within(row).getByText("critical")).toBeTruthy();
  });
});

describe("as an analyst", () => {
  it("disables the playbook trigger and says why", () => {
    renderWithClient(<IncidentPanel canWrite={false} />);

    expect(button("Execute Response Playbook").disabled).toBe(true);
    expect(screen.getAllByRole("note").length).toBeGreaterThan(0);
  });

  it("disables approvals and status changes", () => {
    renderWithClient(<IncidentPanel canWrite={false} />);
    expand(/SSH brute force/);

    for (const name of ["Approve", "Reject", "Contain", "Resolve", "False positive"]) {
      expect(button(name).disabled).toBe(true);
    }
    fireEvent.click(button("Approve"));
    expect(mockApi.approveAction).not.toHaveBeenCalled();
  });
});
