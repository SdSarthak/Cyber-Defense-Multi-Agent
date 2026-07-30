import React, { useState } from "react";
import { login } from "../../services/auth";

export function LoginScreen() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      // `login` broadcasts the new session, which re-renders App into the dashboard.
      await login(username, password);
    } catch (err: any) {
      setError(err?.message || "Login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
      <form
        onSubmit={submit}
        className="w-full max-w-sm bg-gray-900 border border-gray-700 rounded-lg p-6 space-y-4"
      >
        <div>
          <h1 className="text-white text-xl font-bold tracking-tight">Cyber Defense SOC</h1>
          <p className="text-gray-500 text-xs mt-1">Sign in to the agent mesh</p>
        </div>

        <div className="space-y-2">
          <label className="block">
            <span className="text-gray-400 text-xs uppercase tracking-wide">Username</span>
            <input
              className="mt-1 w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white text-sm"
              value={username}
              autoComplete="username"
              onChange={(e) => setUsername(e.target.value)}
            />
          </label>
          <label className="block">
            <span className="text-gray-400 text-xs uppercase tracking-wide">Password</span>
            <input
              className="mt-1 w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white text-sm"
              type="password"
              value={password}
              autoComplete="current-password"
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
        </div>

        {error && (
          <p className="text-red-400 text-xs bg-red-950 border border-red-800 rounded px-3 py-2">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={busy || !username || !password}
          className="w-full bg-blue-700 hover:bg-blue-600 disabled:bg-gray-700 text-white rounded py-2 text-sm font-medium transition-colors"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>

        <p className="text-gray-600 text-xs text-center">
          Demo credentials are configured via <code>ADMIN_USERNAME</code> /{" "}
          <code>ADMIN_PASSWORD</code> in the API environment.
        </p>
      </form>
    </div>
  );
}
