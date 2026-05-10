/**
 * /login — minimal entry shell. The actual login UX lives at /login/start
 * (remote-browser-router.ts) which streams a server-side Chromium canvas.
 *
 * This file just renders the "start" button page and provides /login/preview
 * (dev-only convenience to skip the OAuth flow).
 */

import { Router } from "express";
import type { UberOAuthProvider } from "./provider.js";

export function createLoginRouter(provider: UberOAuthProvider): Router {
  const router = Router();

  // Dev-only: synthesize a flow and jump straight to /login/start.
  if (process.env.NODE_ENV !== "production") {
    router.get("/login/preview", (_req, res) => {
      const flow = provider.pending.create({
        clientId: "preview",
        redirectUri: "http://localhost:0/preview",
        scopes: [],
        codeChallenge: "preview",
      });
      res.redirect(`/login/start?authFlow=${flow.flowId}`);
    });
  }

  router.get("/login", (req, res) => {
    const authFlow = typeof req.query.authFlow === "string" ? req.query.authFlow : "";
    const flow = authFlow ? provider.pending.get(authFlow) : undefined;
    if (!flow) {
      res.status(400).type("html").send(page(
        `<h1>Link expired</h1><p>Restart the OAuth flow from your MCP client.</p>`
      ));
      return;
    }

    const startUrl = `/login/start?authFlow=${encodeURIComponent(flow.flowId)}`;
    res.type("html").send(page(`
      <div class="brand">
        <svg viewBox="0 0 32 32" width="40" height="40" fill="#fff"><rect width="32" height="32" rx="6" fill="#000"/><text x="16" y="22" text-anchor="middle" font-family="Helvetica,Arial,sans-serif" font-weight="900" font-size="14" fill="#fff">Uber</text></svg>
      </div>
      <h1>Sign in to Uber</h1>
      <p>You'll be connected to Uber's official login screen, streamed from this MCP server. Your password is never sent to us — only to <code>auth.uber.com</code>. After login, we capture your session cookies so the MCP can call Uber's APIs on your behalf.</p>
      <a class="btn" href="${escapeHtml(startUrl)}">Continue</a>
      <p class="footer">Powered by a server-side Chromium. No browser extension or copy-paste needed.</p>
    `));
  });

  return router;
}

const STYLE = `
  * { box-sizing: border-box; }
  html, body { margin: 0; height: 100%; }
  body { background: #000; color: #fff;
         font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
         display: grid; place-items: center; padding: 32px 20px; }
  .card { width: 100%; max-width: 420px; background: #0a0a0a; border: 1px solid #222;
          border-radius: 14px; padding: 36px 32px; }
  .brand { margin-bottom: 24px; display: flex; align-items: center; }
  h1 { margin: 0 0 12px; font-size: 22px; font-weight: 700; letter-spacing: -0.01em; }
  p { margin: 0 0 22px; color: #aaa; line-height: 1.55; font-size: 14px; }
  p code { background: #1a1a1a; padding: 1px 5px; border-radius: 3px; color: #ddd;
           font-family: ui-monospace, monospace; font-size: 12px; }
  .btn { display: block; width: 100%; padding: 14px 18px; text-align: center;
         font-weight: 600; font-size: 14px; background: #fff; color: #000;
         border-radius: 8px; text-decoration: none; transition: background 0.15s; }
  .btn:hover { background: #e5e5e5; }
  .footer { margin-top: 22px; font-size: 12px; color: #555; text-align: center; }
`;

function page(body: string): string {
  return `<!doctype html><html><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Sign in to Uber</title>
<style>${STYLE}</style>
</head><body><div class="card">${body}</div></body></html>`;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
