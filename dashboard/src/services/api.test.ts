/**
 * REST client error handling and request shapes.
 *
 * Non-GET routes are admin-only, so an analyst's dashboard will see 403s. A 403 means
 * "signed in, not allowed" — it must surface the server's reason and must NOT drop
 * the session the way a 401 does, or one stray click would log an analyst out.
 */
import { api, ApiError, describeError } from "./api";
import { authHeader, logout } from "./auth";

jest.mock("./auth", () => ({
  authHeader: jest.fn(),
  getToken: jest.fn(),
  logout: jest.fn(),
}));

const mockLogout = logout as jest.MockedFunction<typeof logout>;
const mockAuthHeader = authHeader as jest.MockedFunction<typeof authHeader>;

let fetchMock: jest.Mock;

function respond(status: number, body: unknown) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  fetchMock = jest.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    text: async () => text,
    json: async () => (typeof body === "string" ? JSON.parse(body) : body),
  });
  global.fetch = fetchMock as unknown as typeof fetch;
}

function lastCall(): { url: string; init: RequestInit } {
  const [url, init] = fetchMock.mock.calls[fetchMock.mock.calls.length - 1];
  return { url, init };
}

beforeEach(() => {
  mockLogout.mockReset();
  mockAuthHeader.mockReturnValue({ Authorization: "Bearer test-token" });
});

describe("error handling", () => {
  it("throws ApiError(403) with the server's reason and keeps the session", async () => {
    respond(403, { detail: "Role 'analyst' may not perform this action" });

    const err = await api.updateIncident("inc-1", "resolved").catch((e) => e);

    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(403);
    expect(err.detail).toBe("Role 'analyst' may not perform this action");
    expect(mockLogout).not.toHaveBeenCalled();
    expect(describeError(err)).toBe("Not permitted: Role 'analyst' may not perform this action");
  });

  it("still drops the session on a 401", async () => {
    respond(401, { detail: "Invalid or expired token" });

    const err = await api.listIncidents().catch((e) => e);

    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(401);
    expect(mockLogout).toHaveBeenCalledTimes(1);
  });

  it("flattens request-validation errors into one readable message", async () => {
    respond(422, {
      detail: [
        { loc: ["query", "limit"], msg: "Input should be less than or equal to 200", type: "less_than_equal" },
        { loc: ["query", "q"], msg: "String too long", type: "string_too_long" },
      ],
    });

    const err = await api.searchLogs({ q: "x" }).catch((e) => e);

    expect(err.status).toBe(422);
    expect(err.detail).toBe("Input should be less than or equal to 200; String too long");
    expect(mockLogout).not.toHaveBeenCalled();
  });

  it("falls back to the raw body when the error is not JSON", async () => {
    respond(502, "Bad Gateway");

    const err = await api.listReports().catch((e) => e);

    expect(err.status).toBe(502);
    expect(describeError(err)).toBe("Bad Gateway");
  });

  it("sends the bearer token on every call", async () => {
    respond(200, { reports: [], count: 0 });

    await api.listReports();

    expect((lastCall().init.headers as Record<string, string>).Authorization).toBe("Bearer test-token");
  });
});

describe("request shapes", () => {
  it("posts an incident status change with its note", async () => {
    respond(200, { ok: true });

    await api.updateIncident("inc 1", "contained", "isolated host");

    const { url, init } = lastCall();
    expect(url).toMatch(/\/api\/v1\/incidents\/inc%201\/update$/);
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ status: "contained", notes: "isolated host" });
  });

  it("omits an empty note", async () => {
    respond(200, { ok: true });

    await api.updateIncident("inc-1", "resolved");

    expect(JSON.parse(lastCall().init.body as string)).toEqual({ status: "resolved" });
  });

  it.each([
    ["approveAction", "approve"],
    ["rejectAction", "reject"],
  ] as const)("%s posts to the action's %s route", async (fn, verb) => {
    respond(200, { ok: true, action: { action: "Block IP", automated: true, status: "approved" } });

    const res = await api[fn]("inc-1", 2);

    const { url, init } = lastCall();
    expect(url).toMatch(new RegExp(`/api/v1/incidents/inc-1/actions/2/${verb}$`));
    expect(init.method).toBe("POST");
    expect(res.ok).toBe(true);
  });

  it("builds the log search query string", async () => {
    respond(200, { logs: [], count: 0, source: "elasticsearch" });

    await api.searchLogs({ q: "failed password", anomalousOnly: true, limit: 25 });

    const url = new URL(lastCall().url);
    expect(url.pathname).toBe("/api/v1/logs/search");
    expect(url.searchParams.get("q")).toBe("failed password");
    expect(url.searchParams.get("anomalous_only")).toBe("true");
    expect(url.searchParams.get("limit")).toBe("25");
  });

  it("encodes a report key into the path", async () => {
    respond(200, { executive_summary: "ok" });

    await api.getReport("report:executive:20260101_000000:ab12");

    expect(lastCall().url).toMatch(/\/api\/v1\/reports\/report%3Aexecutive%3A20260101_000000%3Aab12$/);
  });

  it("asks for a bounded vulnerability list", async () => {
    respond(200, { vulnerabilities: [], count: 0 });

    await api.listVulnerabilities(50);

    expect(lastCall().url).toMatch(/\/api\/v1\/vulnerabilities\/\?limit=50$/);
  });
});
