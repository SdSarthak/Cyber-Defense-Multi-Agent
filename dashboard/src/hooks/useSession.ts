import { useEffect, useState } from "react";
import { getSession, onSessionChange, Session } from "../services/auth";

/**
 * Current session, kept in sync with `services/auth`.
 *
 * A 401 anywhere in the app calls `logout()`, which fires the same subscription —
 * so an expired token bounces the operator back to the login screen without any
 * component needing to know about it.
 */
export function useSession(): Session | null {
  const [session, setSession] = useState<Session | null>(() => getSession());

  useEffect(() => onSessionChange(setSession), []);

  return session;
}
