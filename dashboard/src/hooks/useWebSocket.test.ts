/**
 * Telemetry socket lifecycle.
 *
 * The reconnect loop is the part of the dashboard that can hurt the server: it runs
 * in every open tab, for as long as the page is open, with no user involvement.
 */
import { act, renderHook } from "@testing-library/react";

import { createWebSocket } from "../services/api";
import { logout } from "../services/auth";
import { useStore } from "../store/useStore";
import {
  agentStatusFromEvent,
  reconnectDelay,
  threatLevelFromFrame,
  useWebSocket,
  WS_POLICY_VIOLATION,
} from "./useWebSocket";

jest.mock("../services/api", () => ({ createWebSocket: jest.fn() }));
jest.mock("../services/auth", () => ({ logout: jest.fn() }));

const mockCreate = createWebSocket as jest.MockedFunction<typeof createWebSocket>;
const mockLogout = logout as jest.MockedFunction<typeof logout>;

interface FakeSocket {
  onopen?: () => void;
  onclose?: (event: { code: number }) => void;
  close: jest.Mock;
  send: jest.Mock;
  readyState: number;
}

let sockets: FakeSocket[] = [];
let handlers: Array<(msg: any) => void> = [];

function makeSocket(): FakeSocket {
  return { close: jest.fn(), send: jest.fn(), readyState: 1 };
}

beforeEach(() => {
  jest.useFakeTimers();
  sockets = [];
  handlers = [];
  // The store is a module singleton; start every test from a blank board.
  useStore.setState({ agentStatuses: {}, threatLevel: "low", alerts: [] });
  mockCreate.mockReset();
  mockLogout.mockReset();
  mockCreate.mockImplementation((onMessage: (msg: any) => void) => {
    handlers.push(onMessage);
    const socket = makeSocket();
    sockets.push(socket);
    return socket as unknown as WebSocket;
  });
});

afterEach(() => {
  jest.useRealTimers();
});

describe("reconnectDelay", () => {
  it("grows with each consecutive failure", () => {
    jest.spyOn(Math, "random").mockReturnValue(0.5);
    expect(reconnectDelay(0)).toBe(2250);
    expect(reconnectDelay(1)).toBe(4500);
    expect(reconnectDelay(2)).toBe(9000);
  });

  it("never exceeds the 30 second ceiling", () => {
    jest.spyOn(Math, "random").mockReturnValue(1);
    for (let attempt = 0; attempt < 20; attempt += 1) {
      expect(reconnectDelay(attempt)).toBeLessThanOrEqual(30000);
    }
  });

  it("always waits at least half the nominal delay", () => {
    jest.spyOn(Math, "random").mockReturnValue(0);
    expect(reconnectDelay(0)).toBe(1500);
  });
});

describe("agentStatusFromEvent", () => {
  it.each([
    ["task_start", "running"],
    ["task_complete", "idle"],
    ["task_error", "error"],
  ])("maps %s to %s", (event, status) => {
    expect(agentStatusFromEvent({ agent: "compliance", event })).toEqual({
      agent: "compliance",
      status,
    });
  });

  it.each([
    [{ agent: "compliance", event: "report_ready" }],
    [{ agent: "unknown_agent", event: "task_start" }],
    [{ agent: "compliance" }],
    [{ event: "task_start" }],
    [null],
    [undefined],
  ])("returns null for %j", (data) => {
    expect(agentStatusFromEvent(data)).toBeNull();
  });
});

describe("threatLevelFromFrame", () => {
  it("reads the level off an agent_events threat_level frame", () => {
    expect(
      threatLevelFromFrame({ channel: "agent_events", data: { event: "threat_level", threat_level: "medium" } })
    ).toBe("medium");
  });

  it("rejects other channels, other events and unknown levels", () => {
    expect(threatLevelFromFrame({ channel: "escalations", data: { event: "threat_level", threat_level: "high" } })).toBeNull();
    expect(threatLevelFromFrame({ channel: "agent_events", data: { event: "override", threat_level: "high" } })).toBeNull();
    expect(threatLevelFromFrame({ channel: "agent_events", data: { event: "threat_level", threat_level: "severe" } })).toBeNull();
    expect(threatLevelFromFrame(null)).toBeNull();
  });
});

describe("reconnect behaviour", () => {
  it("opens exactly one socket on mount", () => {
    renderHook(() => useWebSocket());
    expect(mockCreate).toHaveBeenCalledTimes(1);
  });

  it("reconnects after an unexpected drop", () => {
    renderHook(() => useWebSocket());
    act(() => sockets[0].onclose?.({ code: 1006 }));
    expect(mockCreate).toHaveBeenCalledTimes(1);

    act(() => {
      jest.advanceTimersByTime(31000);
    });
    expect(mockCreate).toHaveBeenCalledTimes(2);
  });

  it("backs off further on each successive failure", () => {
    jest.spyOn(Math, "random").mockReturnValue(0);
    renderHook(() => useWebSocket());

    act(() => sockets[0].onclose?.({ code: 1006 }));
    act(() => {
      jest.advanceTimersByTime(1500);
    });
    expect(mockCreate).toHaveBeenCalledTimes(2);

    act(() => sockets[1].onclose?.({ code: 1006 }));
    // The second wait is longer than the first: 1500ms is no longer enough.
    act(() => {
      jest.advanceTimersByTime(1500);
    });
    expect(mockCreate).toHaveBeenCalledTimes(2);

    act(() => {
      jest.advanceTimersByTime(1500);
    });
    expect(mockCreate).toHaveBeenCalledTimes(3);
  });

  it("resets the backoff once a connection succeeds", () => {
    jest.spyOn(Math, "random").mockReturnValue(0);
    renderHook(() => useWebSocket());

    act(() => sockets[0].onclose?.({ code: 1006 }));
    act(() => {
      jest.advanceTimersByTime(1500);
    });
    act(() => sockets[1].onopen?.());
    act(() => sockets[1].onclose?.({ code: 1006 }));

    // Back to the first-attempt delay rather than continuing to grow.
    act(() => {
      jest.advanceTimersByTime(1500);
    });
    expect(mockCreate).toHaveBeenCalledTimes(3);
  });

  it("stops retrying and drops the session when the server refuses the token", () => {
    renderHook(() => useWebSocket());
    act(() => sockets[0].onclose?.({ code: WS_POLICY_VIOLATION }));

    expect(mockLogout).toHaveBeenCalledTimes(1);
    act(() => {
      jest.advanceTimersByTime(120000);
    });
    expect(mockCreate).toHaveBeenCalledTimes(1);
  });

  it("does not reconnect after unmount", () => {
    const { unmount } = renderHook(() => useWebSocket());
    act(() => sockets[0].onclose?.({ code: 1006 }));
    unmount();

    act(() => {
      jest.advanceTimersByTime(120000);
    });
    expect(mockCreate).toHaveBeenCalledTimes(1);
    expect(sockets[0].close).toHaveBeenCalled();
  });

  it("stays disconnected when there is no token to hand the server", () => {
    mockCreate.mockReturnValue(null);
    renderHook(() => useWebSocket());

    act(() => {
      jest.advanceTimersByTime(120000);
    });
    expect(mockCreate).toHaveBeenCalledTimes(1);
    expect(useStore.getState().connected).toBe(false);
  });

  it("opens nothing at all when disabled", () => {
    renderHook(() => useWebSocket(false));
    expect(mockCreate).not.toHaveBeenCalled();
  });
});

describe("message routing", () => {
  it("surfaces an override reply instead of filing it as an alert", () => {
    const before = useStore.getState().alerts.length;
    const { result } = renderHook(() => useWebSocket());

    act(() =>
      handlers[0]({
        type: "override_result",
        command: "pause_agent",
        result: { ok: false, error: "Role 'analyst' may not run pause_agent" },
      })
    );

    expect(result.current.lastOverride).toEqual({
      command: "pause_agent",
      ok: false,
      error: "Role 'analyst' may not run pause_agent",
    });
    expect(useStore.getState().alerts.length).toBe(before);
  });

  it("ignores the handshake ack and protocol errors", () => {
    const before = useStore.getState().alerts.length;
    renderHook(() => useWebSocket());

    act(() => handlers[0]({ type: "connected", user: "admin" }));
    act(() => handlers[0]({ type: "error", error: "Malformed JSON" }));

    expect(useStore.getState().alerts.length).toBe(before);
  });

  it("records a broadcast event as an alert", () => {
    renderHook(() => useWebSocket());

    act(() =>
      handlers[0]({
        channel: "agent_events",
        data: { agent: "threat_detection", event: "task_complete" },
      })
    );

    expect(useStore.getState().alerts[0].channel).toBe("agent_events");
  });

  it("walks an agent through running, error and idle on task events", () => {
    renderHook(() => useWebSocket());
    const status = () => useStore.getState().agentStatuses.threat_detection;

    act(() =>
      handlers[0]({
        channel: "agent_events",
        data: { agent: "threat_detection", event: "task_start", task_id: "t-1" },
      })
    );
    expect(status().status).toBe("running");
    expect(status().task_id).toBe("t-1");
    expect(status().updatedAt).toEqual(expect.any(Number));

    act(() =>
      handlers[0]({ channel: "agent_events", data: { agent: "threat_detection", event: "task_error" } })
    );
    expect(status().status).toBe("error");

    act(() =>
      handlers[0]({ channel: "agent_events", data: { agent: "threat_detection", event: "task_complete" } })
    );
    expect(status().status).toBe("idle");
    expect(status().task_id).toBeUndefined();
  });

  it("does not treat informational events as status changes", () => {
    renderHook(() => useWebSocket());

    // Each of these used to flip its sender to "running" with nothing to flip it back.
    for (const data of [
      { agent: "supervisor", event: "routing_decision" },
      { agent: "supervisor", event: "escalation_received" },
      { agent: "supervisor", event: "escalation_handled" },
      { agent: "reporting", event: "report_ready" },
      { agent: "human", event: "override" },
      { agent: "simulation", event: "logs_ready" },
    ]) {
      act(() => handlers[0]({ channel: "agent_events", data }));
    }

    expect(useStore.getState().agentStatuses).toEqual({});
  });

  it("ignores status events from publishers that are not agents", () => {
    renderHook(() => useWebSocket());

    act(() => handlers[0]({ channel: "agent_events", data: { agent: "human", event: "task_start" } }));
    act(() =>
      handlers[0]({ channel: "agent_events", data: { agent: "simulation", event: "task_complete" } })
    );

    expect(useStore.getState().agentStatuses).toEqual({});
  });

  it("only status-maps frames on the agent_events channel", () => {
    renderHook(() => useWebSocket());

    act(() =>
      handlers[0]({ channel: "escalations", data: { agent: "log_analysis", event: "task_start" } })
    );

    expect(useStore.getState().agentStatuses).toEqual({});
  });

  it("takes the threat level only from threat_level frames", () => {
    renderHook(() => useWebSocket());

    // A threat_level riding on some other event is not the board's effective level.
    act(() =>
      handlers[0]({
        channel: "agent_events",
        data: { agent: "threat_detection", event: "task_complete", threat_level: "critical" },
      })
    );
    act(() =>
      handlers[0]({ channel: "escalations", data: { event: "threat_level", threat_level: "critical" } })
    );
    expect(useStore.getState().threatLevel).toBe("low");

    act(() =>
      handlers[0]({
        channel: "agent_events",
        data: { agent: "supervisor", event: "threat_level", threat_level: "HIGH" },
      })
    );
    expect(useStore.getState().threatLevel).toBe("high");
  });

  it("ignores a threat_level frame carrying an unknown level", () => {
    renderHook(() => useWebSocket());

    act(() =>
      handlers[0]({
        channel: "agent_events",
        data: { agent: "supervisor", event: "threat_level", threat_level: "bananas" },
      })
    );

    expect(useStore.getState().threatLevel).toBe("low");
  });

  it("refuses to send an override over a socket that is not open", () => {
    const { result } = renderHook(() => useWebSocket());
    sockets[0].readyState = 3; // CLOSED

    let sent: boolean | undefined;
    act(() => {
      sent = result.current.sendOverride("pause_agent", { agent: "threat_detection" });
    });

    expect(sent).toBe(false);
    expect(sockets[0].send).not.toHaveBeenCalled();
  });

  it("sends a well-formed override over an open socket", () => {
    const { result } = renderHook(() => useWebSocket());

    let sent: boolean | undefined;
    act(() => {
      sent = result.current.sendOverride("pause_agent", { agent: "threat_detection" });
    });

    expect(sent).toBe(true);
    expect(JSON.parse(sockets[0].send.mock.calls[0][0])).toEqual({
      type: "human_override",
      command: "pause_agent",
      payload: { agent: "threat_detection" },
    });
  });
});
