import { randomBytes, randomUUID } from "crypto";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";

function randomId(bytes = 16): string {
  return randomBytes(bytes).toString("hex");
}

export class InMemoryClientsStore implements OAuthRegisteredClientsStore {
  private clients = new Map<string, OAuthClientInformationFull>();

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.clients.get(clientId);
  }

  async registerClient(
    client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">
  ): Promise<OAuthClientInformationFull> {
    const full: OAuthClientInformationFull = {
      ...client,
      client_id: `uber_${randomId(12)}`,
      client_id_issued_at: Math.floor(Date.now() / 1000),
    };
    this.clients.set(full.client_id, full);
    return full;
  }
}

export type PendingAuthFlow = {
  flowId: string;
  clientId: string;
  redirectUri: string;
  state?: string;
  scopes: string[];
  codeChallenge: string;
  resource?: string;
  createdAt: number;
  expiresAt: number;
  browserSessionId?: string;
};

export class PendingAuthStore {
  private flows = new Map<string, PendingAuthFlow>();

  create(
    partial: Omit<PendingAuthFlow, "flowId" | "createdAt" | "expiresAt">,
    ttlSec = 600
  ): PendingAuthFlow {
    const now = Math.floor(Date.now() / 1000);
    const flow: PendingAuthFlow = {
      ...partial,
      flowId: randomId(16),
      createdAt: now,
      expiresAt: now + ttlSec,
    };
    this.flows.set(flow.flowId, flow);
    return flow;
  }

  get(flowId: string): PendingAuthFlow | undefined {
    const f = this.flows.get(flowId);
    if (!f) return undefined;
    if (f.expiresAt < Math.floor(Date.now() / 1000)) {
      this.flows.delete(flowId);
      return undefined;
    }
    return f;
  }

  update(flowId: string, patch: Partial<PendingAuthFlow>): void {
    const f = this.flows.get(flowId);
    if (!f) return;
    this.flows.set(flowId, { ...f, ...patch });
  }

  delete(flowId: string): void {
    this.flows.delete(flowId);
  }
}

export type AuthCode = {
  code: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource?: string;
  userSub: string;
  expiresAt: number;
};

export class AuthCodeStore {
  private codes = new Map<string, AuthCode>();

  create(partial: Omit<AuthCode, "code" | "expiresAt">, ttlSec = 60): AuthCode {
    const ac: AuthCode = {
      ...partial,
      code: randomId(24),
      expiresAt: Math.floor(Date.now() / 1000) + ttlSec,
    };
    this.codes.set(ac.code, ac);
    return ac;
  }

  peek(code: string): AuthCode | undefined {
    const ac = this.codes.get(code);
    if (!ac) return undefined;
    if (ac.expiresAt < Math.floor(Date.now() / 1000)) {
      this.codes.delete(code);
      return undefined;
    }
    return ac;
  }

  take(code: string): AuthCode | undefined {
    const ac = this.peek(code);
    if (!ac) return undefined;
    this.codes.delete(code);
    return ac;
  }
}

export type RefreshRecord = {
  refreshToken: string;
  clientId: string;
  userSub: string;
  resource?: string;
  scopes: string[];
  expiresAt: number;
};

export class RefreshTokenStore {
  private tokens = new Map<string, RefreshRecord>();

  create(
    partial: Omit<RefreshRecord, "refreshToken" | "expiresAt">,
    ttlSec = 60 * 60 * 24 * 30
  ): RefreshRecord {
    const r: RefreshRecord = {
      ...partial,
      refreshToken: randomId(32),
      expiresAt: Math.floor(Date.now() / 1000) + ttlSec,
    };
    this.tokens.set(r.refreshToken, r);
    return r;
  }

  take(token: string): RefreshRecord | undefined {
    const r = this.tokens.get(token);
    if (!r) return undefined;
    this.tokens.delete(token);
    if (r.expiresAt < Math.floor(Date.now() / 1000)) return undefined;
    return r;
  }
}

/* -------------------- Uber session credentials store --------------------- */

export type UberCookie = {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: number;
  httpOnly: boolean;
  secure: boolean;
  sameSite?: "Strict" | "Lax" | "None";
};

export type UberCredentials = {
  cookies: UberCookie[];
  cookieHeader: string;
  cityId: number;
  sessionType: "desktop_session" | "mobile_session";
  userSub: string;
  userAgent: string;
  capturedAt: number;
  expiresAt: number;
};

export class UserTokenStore {
  private byId = new Map<string, UberCredentials>();

  set(userSub: string, creds: UberCredentials): void {
    this.byId.set(userSub, creds);
  }

  get(userSub: string): UberCredentials | undefined {
    return this.byId.get(userSub);
  }

  has(userSub: string): boolean {
    return this.byId.has(userSub);
  }

  delete(userSub: string): void {
    this.byId.delete(userSub);
  }

  allIds(): string[] {
    return Array.from(this.byId.keys());
  }
}

/* --------------------- Browser session capacity store -------------------- */

export type BrowserSessionHandle<S = unknown> = {
  sessionId: string;
  flowId: string;
  session: S;
  createdAt: number;
  lastActivityAt: number;
};

export class BrowserSessionStore<S = unknown> {
  private sessions = new Map<string, BrowserSessionHandle<S>>();

  constructor(private readonly maxSessions: number) {}

  size(): number {
    return this.sessions.size;
  }

  canCreate(): boolean {
    return this.sessions.size < this.maxSessions;
  }

  newSessionId(): string {
    return randomUUID();
  }

  put(handle: BrowserSessionHandle<S>): void {
    this.sessions.set(handle.sessionId, handle);
  }

  get(sessionId: string): BrowserSessionHandle<S> | undefined {
    return this.sessions.get(sessionId);
  }

  touch(sessionId: string): void {
    const h = this.sessions.get(sessionId);
    if (h) h.lastActivityAt = Date.now();
  }

  delete(sessionId: string): BrowserSessionHandle<S> | undefined {
    const h = this.sessions.get(sessionId);
    if (h) this.sessions.delete(sessionId);
    return h;
  }

  staleIds(cutoffMs: number): string[] {
    const ids: string[] = [];
    for (const [id, h] of this.sessions) {
      if (h.lastActivityAt < cutoffMs) ids.push(id);
    }
    return ids;
  }
}
