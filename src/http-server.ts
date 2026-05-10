#!/usr/bin/env node

import dotenv from "dotenv";
dotenv.config();

import http from "http";
import express from "express";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolRequest,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";

import { toolDefinitions, executeTool } from "./index.js";
import { UberOAuthProvider } from "./http/provider.js";
import { createLoginRouter } from "./http/login-router.js";
import { createRemoteBrowserRouter } from "./http/remote-browser-router.js";
import { SessionTokenProvider, startTokenRefreshLoop } from "./http/session-provider.js";
import type { RemoteBrowserSession } from "./http/remote-browser.js";

const PORT = Number(process.env.PORT ?? 3000);
const PUBLIC_URL = (process.env.PUBLIC_URL ?? `http://localhost:${PORT}`).replace(
  /\/$/,
  ""
);
const JWT_SECRET_STR = process.env.MCP_JWT_SECRET;
const MAX_BROWSER_SESSIONS = Number(process.env.MAX_BROWSER_SESSIONS ?? 3);
const BROWSER_HEADLESS = process.env.BROWSER_HEADLESS !== "false";

if (!JWT_SECRET_STR || JWT_SECRET_STR.length < 32) {
  console.error("MCP_JWT_SECRET is required and must be at least 32 characters. Aborting.");
  process.exit(1);
}
const JWT_SECRET = new TextEncoder().encode(JWT_SECRET_STR);

const issuerUrl = new URL(PUBLIC_URL);
const resourceUrl = new URL("/mcp", PUBLIC_URL);

const provider = new UberOAuthProvider({
  issuerUrl,
  resourceUrl,
  loginPath: "/login",
  jwtSecret: JWT_SECRET,
  maxBrowserSessions: MAX_BROWSER_SESSIONS,
});

const toolMap = new Map(toolDefinitions.map((t) => [t.name, t]));

const app = express();

app.use(express.json({ limit: "4mb" }));
app.use(express.urlencoded({ extended: false }));

app.use((req, _res, next) => {
  const sessionId = req.header("mcp-session-id");
  const hasAuth = !!req.header("authorization");
  const bodyMethod = (req.body as { method?: string } | undefined)?.method;
  console.log(
    `[http] ${req.method} ${req.path}${bodyMethod ? ` rpc=${bodyMethod}` : ""}${
      sessionId ? ` session=${sessionId.slice(0, 8)}` : ""
    }${hasAuth ? " auth=yes" : " auth=no"}`
  );
  next();
});

app.use(
  mcpAuthRouter({
    provider,
    issuerUrl,
    baseUrl: new URL(PUBLIC_URL),
    resourceServerUrl: resourceUrl,
    scopesSupported: ["mcp:tools"],
    resourceName: "Uber MCP",
  })
);

app.use(createLoginRouter(provider));

const httpServer = http.createServer(app);

app.use(
  createRemoteBrowserRouter({
    provider,
    httpServer,
    publicUrl: PUBLIC_URL,
    headless: BROWSER_HEADLESS,
    maxBrowserSessions: MAX_BROWSER_SESSIONS,
  })
);

app.get("/healthz", (_req, res) => {
  res.json({
    ok: true,
    tools: toolDefinitions.length,
    publicUrl: PUBLIC_URL,
    browserSessions: provider.browserSessions.size(),
    maxBrowserSessions: MAX_BROWSER_SESSIONS,
    activeUsers: provider.userTokens.allIds().length,
  });
});

// Dev-only debug endpoint: lists user IDs (no cookies).
if (process.env.NODE_ENV !== "production") {
  app.get("/debug/users", (_req, res) => {
    const ids = provider.userTokens.allIds();
    res.json({
      count: ids.length,
      ids,
      sessions: ids.map((sub) => {
        const c = provider.userTokens.get(sub);
        return c
          ? {
              sub,
              cityId: c.cityId,
              cookieCount: c.cookies.length,
              expiresAt: c.expiresAt,
              expiresIn: c.expiresAt - Math.floor(Date.now() / 1000),
            }
          : null;
      }),
    });
  });
}

/* ----------------------------- MCP endpoint -------------------------- */

const resourceMetadataUrl = `${PUBLIC_URL}/.well-known/oauth-protected-resource${resourceUrl.pathname}`;
const bearerGuard = requireBearerAuth({
  verifier: provider,
  requiredScopes: [],
  resourceMetadataUrl,
});

function makeMcpServer(userSub: string): McpServer {
  const sessionProvider = new SessionTokenProvider(userSub, provider.userTokens);

  const mcp = new McpServer(
    { name: "@aol/uber-mcp", version: "0.1.0" },
    { capabilities: { tools: {} } }
  );

  const low = mcp.server;

  low.setRequestHandler(ListToolsRequestSchema, async () => {
    const tools: Tool[] = toolDefinitions.map((def) => ({
      name: def.name,
      description: def.description,
      inputSchema: { type: "object" as const, ...def.inputSchema },
    }));
    return { tools };
  });

  low.setRequestHandler(CallToolRequestSchema, async (req: CallToolRequest) => {
    const def = toolMap.get(req.params.name);
    if (!def) {
      const r: CallToolResult = {
        content: [{ type: "text", text: `Unknown tool: ${req.params.name}` }],
        isError: true,
      };
      return r;
    }
    const args = (req.params.arguments as Record<string, unknown>) ?? {};
    console.log(`[mcp] tools/call name=${req.params.name}`);
    return executeTool(def, args, sessionProvider);
  });

  return mcp;
}

app.all("/mcp", bearerGuard, async (req, res) => {
  const auth = req.auth;
  const userSub = auth?.extra?.userSub as string | undefined;
  if (!userSub) {
    res.status(401).json({ error: "invalid_token", error_description: "missing sub" });
    return;
  }

  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => {
    transport.close().catch(() => {});
  });
  const server = makeMcpServer(userSub);
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

/* ----------------------- Background cleanup loop --------------------- */

startTokenRefreshLoop(provider.userTokens, 60_000);

/* -------------------------------- Listen ----------------------------- */

httpServer.listen(PORT, () => {
  console.log(`Uber MCP remote listening on :${PORT}`);
  console.log(`  Public URL:          ${PUBLIC_URL}`);
  console.log(`  Resource (MCP):      ${resourceUrl.href}`);
  console.log(`  Authorization:       ${issuerUrl.href}`);
  console.log(`  Tools:               ${toolDefinitions.length}`);
  console.log(`  Max browser sess:    ${MAX_BROWSER_SESSIONS}`);
  console.log(`  Browser headless:    ${BROWSER_HEADLESS}`);
});

function shutdown(signal: string) {
  console.log(`[uber-mcp] ${signal} — shutting down active browser sessions…`);
  const ids = (provider.browserSessions as unknown as { sessions?: Map<string, { session: RemoteBrowserSession }> }).sessions;
  if (ids) {
    for (const [, h] of ids) {
      h.session.close().catch(() => {});
    }
  }
  httpServer.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
