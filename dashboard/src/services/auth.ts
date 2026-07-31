/**
 * Bearer-token session handling.
 *
 * Every `/api/v1/*` route behind AuthMiddleware needs a JWT, and so does the `/ws`
 * socket. The token lives in localStorage so a page reload does not force a new
 * login, and the expiry is tracked locally so an obviously-dead token is discarded
 * before it produces a wave of 401s.
 */
const TOKEN_KEY = "cds.token";
const EXPIRY_KEY = "cds.token_expires_at";
const ROLE_KEY = "cds.role";
const USER_KEY = "cds.user";

const BASE = process.env.REACT_APP_API_URL || "http://localhost:8000";

export interface Session {
  token: string;
  role: string;
  username: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  role: string;
}

type Listener = (session: Session | null) => void;

const listeners = new Set<Listener>();

function emit(session: Session | null) {
  listeners.forEach((fn) => fn(session));
}

/** Subscribe to login/logout. Returns an unsubscribe function. */
export function onSessionChange(fn: Listener): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

function isExpired(): boolean {
  const raw = localStorage.getItem(EXPIRY_KEY);
  // A token with no recorded expiry is not a token this app stored — treat it as
  // dead rather than as one that never expires, which is what a missing key used
  // to mean.
  if (!raw) return true;
  const expiresAt = Number(raw);
  if (!Number.isFinite(expiresAt)) return true;
  // Treat a token in its last 5 seconds as already gone; the request would land
  // after expiry anyway.
  return Date.now() >= expiresAt - 5000;
}

export function getToken(): string | null {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return null;
  if (isExpired()) {
    clearSession();
    return null;
  }
  return token;
}

export function getSession(): Session | null {
  const token = getToken();
  if (!token) return null;
  return {
    token,
    role: localStorage.getItem(ROLE_KEY) || "analyst",
    username: localStorage.getItem(USER_KEY) || "",
  };
}

export function isAuthenticated(): boolean {
  return getToken() !== null;
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(EXPIRY_KEY);
  localStorage.removeItem(ROLE_KEY);
  localStorage.removeItem(USER_KEY);
}

export function logout() {
  clearSession();
  emit(null);
}

export async function login(username: string, password: string): Promise<Session> {
  const res = await fetch(`${BASE}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });

  if (res.status === 401) {
    throw new Error("Invalid username or password");
  }
  if (!res.ok) {
    throw new Error(`Login failed (${res.status})`);
  }

  let body: LoginResponse;
  try {
    body = await res.json();
  } catch {
    throw new Error("Login failed: the server did not return a token");
  }

  // Without this check a response missing `access_token` stored the literal string
  // "undefined", so the app looked signed in while every request 401'd.
  if (!body || typeof body.access_token !== "string" || !body.access_token) {
    throw new Error("Login failed: the server did not return a token");
  }

  const ttlSeconds = Number(body.expires_in);
  const validTtl = Number.isFinite(ttlSeconds) && ttlSeconds > 0 ? ttlSeconds : 0;
  if (!validTtl) {
    // An already-expired token would bounce straight back to this screen.
    throw new Error("Login failed: the server issued an expired token");
  }

  const role = typeof body.role === "string" && body.role ? body.role : "analyst";
  localStorage.setItem(TOKEN_KEY, body.access_token);
  localStorage.setItem(EXPIRY_KEY, String(Date.now() + validTtl * 1000));
  localStorage.setItem(ROLE_KEY, role);
  localStorage.setItem(USER_KEY, username);

  const session = { token: body.access_token, role, username };
  emit(session);
  return session;
}

/** Auth header for fetch, or an empty object when signed out. */
export function authHeader(): Record<string, string> {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}
