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
import { reconnectDelay, useWebSocket, WS_POLICY_VIOLATION } from "./useWebSocket";

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

  it("records a broadcast event as an alert and updates agent status", () => {
    renderHook(() => useWebSocket());

    act(() =>
      handlers[0]({
        channel: "agent_events",
        data: { agent: "threat_detection", event: "task_complete", threat_level: "critical" },
      })
    );

    const state = useStore.getState();
    expect(state.alerts[0].channel).toBe("agent_events");
    expect(state.agentStatuses.threat_detection.status).toBe("idle");
    expect(state.threatLevel).toBe("critical");
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
