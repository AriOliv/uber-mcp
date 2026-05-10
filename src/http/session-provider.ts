/**
 * SessionTokenProvider — looks up cookie-based UberCredentials by userSub from the
 * UserTokenStore. There is no programmatic refresh: when the cookie session
 * expires (24h), the user must re-login via /login/start. The background loop
 * just prunes expired entries.
 */

import type { TokenProvider } from "../index.js";
import type { UserTokenStore, UberCredentials } from "./store.js";

export class SessionTokenProvider implements TokenProvider {
  constructor(
    private readonly userSub: string,
    private readonly store: UserTokenStore
  ) {}

  async getValidToken(): Promise<{
    token: string | null;
    accountId: string;
    error?: string;
    credentials?: UberCredentials;
  }> {
    const creds = this.store.get(this.userSub);
    if (!creds) {
      return {
        token: null,
        accountId: this.userSub,
        error: "No Uber session found. Re-authenticate via the OAuth login page (/login/start).",
      };
    }
    const now = Math.floor(Date.now() / 1000);
    if (creds.expiresAt <= now) {
      this.store.delete(this.userSub);
      return {
        token: null,
        accountId: this.userSub,
        error: "Uber session expired. Re-authenticate via /login/start.",
      };
    }
    return {
      token: "cookie",
      accountId: creds.userSub,
      credentials: creds,
    };
  }
}

export function startTokenRefreshLoop(store: UserTokenStore, intervalMs = 60_000): () => void {
  const timer = setInterval(() => {
    const now = Math.floor(Date.now() / 1000);
    for (const userSub of store.allIds()) {
      const creds = store.get(userSub);
      if (!creds) continue;
      if (creds.expiresAt <= now) {
        store.delete(userSub);
      }
    }
  }, intervalMs);
  timer.unref?.();
  return () => clearInterval(timer);
}
