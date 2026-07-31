/**
 * Session handling tests.
 *
 * The expiry maths and the shape-checking around the login response decide whether
 * the dashboard renders the app or the login screen. Getting either wrong is
 * invisible until the operator is staring at a dashboard that silently 401s on
 * every request.
 */
import {
  authHeader,
  clearSession,
  getSession,
  getToken,
  isAuthenticated,
  login,
  logout,
  onSessionChange,
} from "./auth";

const TOKEN_KEY = "cds.token";
const EXPIRY_KEY = "cds.token_expires_at";
const ROLE_KEY = "cds.role";
const USER_KEY = "cds.user";

function storeSession(token: string, msFromNow: number, role = "admin") {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(EXPIRY_KEY, String(Date.now() + msFromNow));
  localStorage.setItem(ROLE_KEY, role);
  localStorage.setItem(USER_KEY, "admin");
}

function mockLoginResponse(body: unknown, status = 200) {
  global.fetch = jest.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  }) as unknown as typeof fetch;
}

beforeEach(() => {
  localStorage.clear();
  jest.restoreAllMocks();
});

describe("token expiry", () => {
  it("returns a token that is comfortably in date", () => {
    storeSession("jwt-abc", 60_000);
    expect(getToken()).toBe("jwt-abc");
    expect(isAuthenticated()).toBe(true);
  });

  it("discards a token that has already expired", () => {
    storeSession("jwt-abc", -1000);
    expect(getToken()).toBeNull();
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });

  it("treats the final five seconds as already expired", () => {
    // The request would land after expiry, so spending it is a guaranteed 401.
    storeSession("jwt-abc", 4_000);
    expect(getToken()).toBeNull();
  });

  it("keeps a token with more than five seconds left", () => {
    storeSession("jwt-abc", 6_000);
    expect(getToken()).toBe("jwt-abc");
  });

  it("treats a token with no recorded expiry as dead", () => {
    // Not a token this app stored. It used to be treated as never expiring.
    localStorage.setItem(TOKEN_KEY, "orphan-token");
    expect(getToken()).toBeNull();
  });

  it("treats an unparseable expiry as dead", () => {
    localStorage.setItem(TOKEN_KEY, "jwt-abc");
    localStorage.setItem(EXPIRY_KEY, "tomorrow-ish");
    expect(getToken()).toBeNull();
  });

  it("clears every session key when a token expires", () => {
    storeSession("jwt-abc", -1);
    getToken();
    [TOKEN_KEY, EXPIRY_KEY, ROLE_KEY, USER_KEY].forEach((key) =>
      expect(localStorage.getItem(key)).toBeNull()
    );
  });
});

describe("session shape", () => {
  it("exposes the stored role and username", () => {
    storeSession("jwt-abc", 60_000, "analyst");
    expect(getSession()).toEqual({ token: "jwt-abc", role: "analyst", username: "admin" });
  });

  it("defaults an absent role to analyst rather than admin", () => {
    localStorage.setItem(TOKEN_KEY, "jwt-abc");
    localStorage.setItem(EXPIRY_KEY, String(Date.now() + 60_000));
    expect(getSession()?.role).toBe("analyst");
  });

  it("returns no session at all when signed out", () => {
    expect(getSession()).toBeNull();
    expect(authHeader()).toEqual({});
  });

  it("builds a bearer header from a live token", () => {
    storeSession("jwt-abc", 60_000);
    expect(authHeader()).toEqual({ Authorization: "Bearer jwt-abc" });
  });
});

describe("login", () => {
  it("stores the session and notifies subscribers", async () => {
    mockLoginResponse({ access_token: "jwt-new", expires_in: 3600, role: "admin" });
    const seen: unknown[] = [];
    const unsubscribe = onSessionChange((s) => seen.push(s));

    const session = await login("admin", "admin123");

    expect(session).toEqual({ token: "jwt-new", role: "admin", username: "admin" });
    expect(localStorage.getItem(TOKEN_KEY)).toBe("jwt-new");
    expect(seen).toHaveLength(1);
    unsubscribe();
  });

  it("records the expiry the server asked for", async () => {
    mockLoginResponse({ access_token: "jwt-new", expires_in: 60, role: "admin" });
    const before = Date.now();
    await login("admin", "admin123");
    const expiresAt = Number(localStorage.getItem(EXPIRY_KEY));
    expect(expiresAt).toBeGreaterThanOrEqual(before + 60_000);
    expect(expiresAt).toBeLessThan(before + 61_000);
  });

  it("reports bad credentials distinctly from other failures", async () => {
    mockLoginResponse({ detail: "Invalid credentials" }, 401);
    await expect(login("admin", "nope")).rejects.toThrow("Invalid username or password");
  });

  it("surfaces a server error with its status", async () => {
    mockLoginResponse({}, 503);
    await expect(login("admin", "admin123")).rejects.toThrow("503");
  });

  it("rejects a response with no access_token instead of storing 'undefined'", async () => {
    mockLoginResponse({ expires_in: 3600, role: "admin" });
    await expect(login("admin", "admin123")).rejects.toThrow("did not return a token");
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });

  it("rejects a token that is already expired on arrival", async () => {
    mockLoginResponse({ access_token: "jwt-new", expires_in: 0, role: "admin" });
    await expect(login("admin", "admin123")).rejects.toThrow("expired token");
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });

  it("rejects a non-JSON body", async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => {
        throw new SyntaxError("Unexpected token < in JSON");
      },
    }) as unknown as typeof fetch;
    await expect(login("admin", "admin123")).rejects.toThrow("did not return a token");
  });

  it("falls back to the analyst role when the server omits one", async () => {
    mockLoginResponse({ access_token: "jwt-new", expires_in: 3600 });
    const session = await login("admin", "admin123");
    expect(session.role).toBe("analyst");
  });
});

describe("logout", () => {
  it("clears storage and notifies subscribers with null", () => {
    storeSession("jwt-abc", 60_000);
    const seen: unknown[] = [];
    const unsubscribe = onSessionChange((s) => seen.push(s));

    logout();

    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
    expect(seen).toEqual([null]);
    unsubscribe();
  });

  it("stops notifying after unsubscribe", () => {
    const seen: unknown[] = [];
    const unsubscribe = onSessionChange((s) => seen.push(s));
    unsubscribe();
    logout();
    expect(seen).toEqual([]);
  });

  it("is safe to call when already signed out", () => {
    expect(() => clearSession()).not.toThrow();
    expect(getSession()).toBeNull();
  });
});
