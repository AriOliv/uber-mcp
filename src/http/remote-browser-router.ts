/**
 * Remote-browser login router.
 *
 *   GET  /login/start     — creates a Chromium session, returns HTML+JS canvas client.
 *   WS   /login/ws/:sid   — bidirectional: server sends frame events, receives input.
 */

import { Router } from "express";
import type { Request, Response } from "express";
import type { IncomingMessage, Server as HttpServer } from "http";
import type { Socket } from "net";
import { WebSocketServer, type WebSocket } from "ws";

import type { UberOAuthProvider } from "./provider.js";
import {
  RemoteBrowserSession,
  type DoneEvent,
  type FrameEvent,
  type InputMessage,
} from "./remote-browser.js";

const SESSION_TTL_MS = 10 * 60 * 1000; // 10min

export type RemoteBrowserRouterDeps = {
  provider: UberOAuthProvider;
  httpServer: HttpServer;
  publicUrl: string;
  headless?: boolean;
  maxBrowserSessions: number;
};

export function createRemoteBrowserRouter(deps: RemoteBrowserRouterDeps): Router {
  const { provider, httpServer, publicUrl, headless } = deps;
  const router = Router();

  router.get("/login/start", async (req: Request, res: Response) => {
    const authFlow = typeof req.query.authFlow === "string" ? req.query.authFlow : "";
    const flow = authFlow ? provider.pending.get(authFlow) : undefined;
    if (!flow) {
      res.status(400).type("html").send(errorPage("Login link expired or invalid. Restart the OAuth flow from your client."));
      return;
    }

    if (!provider.browserSessions.canCreate()) {
      res.status(503).type("html").send(
        errorPage(
          `Server is at capacity (${provider.browserSessions.size()}/${deps.maxBrowserSessions} active login sessions). Try again in a minute.`
        )
      );
      return;
    }

    const sessionId = provider.browserSessions.newSessionId();
    const session = new RemoteBrowserSession({ headless: headless !== false });

    provider.browserSessions.put({
      sessionId,
      flowId: flow.flowId,
      session,
      createdAt: Date.now(),
      lastActivityAt: Date.now(),
    });
    provider.pending.update(flow.flowId, { browserSessionId: sessionId });

    try {
      await session.start();
    } catch (err) {
      provider.browserSessions.delete(sessionId);
      await session.close().catch(() => {});
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[remote-browser-router] failed to start session: ${msg}`);
      res.status(500).type("html").send(errorPage(`Failed to start browser: ${msg}`));
      return;
    }

    const wsUrl = buildWsUrl(publicUrl, sessionId);
    res.type("html").send(canvasPage({ sessionId, wsUrl, flowId: flow.flowId }));
  });

  const wss = new WebSocketServer({ noServer: true });

  httpServer.on("upgrade", (req: IncomingMessage, socket: Socket, head: Buffer) => {
    const url = new URL(req.url ?? "", "http://x");
    const m = url.pathname.match(/^\/login\/ws\/([\w-]+)$/);
    if (!m) return;
    const sessionId = m[1];
    const handle = provider.browserSessions.get(sessionId);
    if (!handle) {
      socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      attachWebSocket(ws, sessionId, provider);
    });
  });

  const cleanupTimer = setInterval(() => {
    const cutoff = Date.now() - SESSION_TTL_MS;
    for (const id of provider.browserSessions.staleIds(cutoff)) {
      const handle = provider.browserSessions.delete(id);
      if (handle) {
        const s = handle.session as RemoteBrowserSession;
        s.close().catch(() => {});
        console.log(`[remote-browser-router] cleaned up stale session ${id}`);
      }
    }
  }, 60_000);
  cleanupTimer.unref?.();

  return router;
}

function attachWebSocket(ws: WebSocket, sessionId: string, provider: UberOAuthProvider): void {
  const handle = provider.browserSessions.get(sessionId);
  if (!handle) {
    ws.close(1011, "session-not-found");
    return;
  }
  const session = handle.session as RemoteBrowserSession;
  const flow = provider.pending.get(handle.flowId);

  const safeSend = (obj: unknown) => {
    if (ws.readyState !== ws.OPEN) return;
    try {
      ws.send(JSON.stringify(obj));
    } catch {
      /* noop */
    }
  };

  const onFrame = (frame: FrameEvent) => {
    provider.browserSessions.touch(sessionId);
    safeSend({ type: "frame", data: frame.data, width: frame.width, height: frame.height });
  };

  const onNavigated = (url: string) => {
    safeSend({ type: "navigated", url });
  };

  const onDone = (evt: DoneEvent) => {
    if (!flow) {
      safeSend({ type: "error", message: "auth flow expired during login" });
      ws.close();
      return;
    }
    provider.userTokens.set(evt.credentials.userSub, evt.credentials);
    const ac = provider.codes.create({
      clientId: flow.clientId,
      redirectUri: flow.redirectUri,
      codeChallenge: flow.codeChallenge,
      scopes: flow.scopes,
      resource: flow.resource,
      userSub: evt.credentials.userSub,
    });
    provider.pending.delete(flow.flowId);

    const redirectUrl = new URL(flow.redirectUri);
    redirectUrl.searchParams.set("code", ac.code);
    if (flow.state) redirectUrl.searchParams.set("state", flow.state);

    safeSend({ type: "done", redirect: redirectUrl.toString() });
    setTimeout(() => {
      ws.close(1000, "done");
      provider.browserSessions.delete(sessionId);
      session.close().catch(() => {});
    }, 250);
  };

  const onError = (err: { message: string }) => {
    safeSend({ type: "error", message: err.message });
  };

  session.on("frame", onFrame);
  session.on("navigated", onNavigated);
  session.on("done", onDone);
  session.on("error", onError);

  ws.on("message", async (raw) => {
    provider.browserSessions.touch(sessionId);
    try {
      const text = typeof raw === "string" ? raw : raw.toString("utf8");
      const msg = JSON.parse(text) as InputMessage;
      await session.dispatchInput(msg);
    } catch (err) {
      const m = err instanceof Error ? err.message : String(err);
      safeSend({ type: "error", message: `bad input: ${m}` });
    }
  });

  ws.on("close", () => {
    session.off("frame", onFrame);
    session.off("navigated", onNavigated);
    session.off("done", onDone);
    session.off("error", onError);
  });
}

function buildWsUrl(publicUrl: string, sessionId: string): string {
  const u = new URL(publicUrl);
  const proto = u.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${u.host}/login/ws/${sessionId}`;
}

/* ----------------------------- HTML pages ----------------------------- */

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function errorPage(message: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"/><title>Uber MCP — error</title>
    <style>
      body { font-family: system-ui, -apple-system, sans-serif; background: #000; color: #fff;
             display: grid; place-items: center; height: 100vh; margin: 0; }
      .card { max-width: 480px; padding: 32px; background: #111; border-radius: 8px; }
      h1 { margin: 0 0 12px; font-size: 18px; }
      p { margin: 0; color: #aaa; line-height: 1.5; }
    </style></head><body><div class="card">
      <h1>Login error</h1><p>${escapeHtml(message)}</p>
    </div></body></html>`;
}

function canvasPage(opts: { sessionId: string; wsUrl: string; flowId: string }): string {
  return `<!doctype html><html><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no"/>
<title>Sign in to Uber</title>
<style>
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; height: 100%; background: #000; color: #fff;
               font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
               overflow: hidden; }
  #frame { display: grid; place-items: center; width: 100%; height: 100%; }
  #canvas { background: #fff; box-shadow: 0 4px 24px rgba(0,0,0,0.5);
            cursor: default; image-rendering: -webkit-optimize-contrast; }
  #status { position: fixed; top: 12px; left: 12px; padding: 6px 10px;
            background: rgba(0,0,0,0.7); border-radius: 4px; font-size: 12px;
            color: #aaa; pointer-events: none; opacity: 0; transition: opacity 0.2s; }
  #status.show { opacity: 1; }
  #overlay { position: fixed; inset: 0; display: grid; place-items: center;
             background: rgba(0,0,0,0.85); color: #fff; z-index: 10;
             font-size: 16px; transition: opacity 0.3s; }
  #overlay.hide { opacity: 0; pointer-events: none; }
  .spinner { width: 32px; height: 32px; border: 3px solid #444; border-top-color: #fff;
             border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto 16px; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .text-c { text-align: center; }
</style>
</head><body>
<div id="frame"><canvas id="canvas" tabindex="0" width="1280" height="800"></canvas></div>
<div id="status"></div>
<div id="overlay"><div class="text-c">
  <div class="spinner"></div>
  <div>Connecting to Uber…</div>
</div></div>
<script>
(function() {
  const SESSION_ID = ${JSON.stringify(opts.sessionId)};
  const WS_URL = ${JSON.stringify(opts.wsUrl)};
  const canvas = document.getElementById("canvas");
  const ctx = canvas.getContext("2d");
  const overlay = document.getElementById("overlay");
  const statusEl = document.getElementById("status");
  let ws = null;
  let serverWidth = 1280;
  let serverHeight = 800;

  function setStatus(msg, ms = 1500) {
    statusEl.textContent = msg;
    statusEl.classList.add("show");
    if (ms > 0) setTimeout(() => statusEl.classList.remove("show"), ms);
  }

  function fitCanvas() {
    const margin = 24;
    const availW = window.innerWidth - margin;
    const availH = window.innerHeight - margin;
    const aspect = serverWidth / serverHeight;
    let w = availW, h = availW / aspect;
    if (h > availH) { h = availH; w = availH * aspect; }
    canvas.style.width = Math.floor(w) + "px";
    canvas.style.height = Math.floor(h) + "px";
  }

  function send(obj) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      try { ws.send(JSON.stringify(obj)); } catch (e) {}
    }
  }

  function canvasCoords(e) {
    const r = canvas.getBoundingClientRect();
    const x = ((e.clientX - r.left) / r.width) * canvas.width;
    const y = ((e.clientY - r.top) / r.height) * canvas.height;
    return { x: Math.round(x), y: Math.round(y) };
  }

  function modBits(e) {
    return (e.altKey ? 1 : 0) | (e.ctrlKey ? 2 : 0) | (e.metaKey ? 4 : 0) | (e.shiftKey ? 8 : 0);
  }

  function buttonName(b) {
    return b === 0 ? "left" : b === 1 ? "middle" : b === 2 ? "right" : "left";
  }

  function isPrintable(key) {
    return key.length === 1 && !key.match(/[\\u0000-\\u001f]/);
  }

  function drawFrame(b64, w, h) {
    if (w !== serverWidth || h !== serverHeight) {
      serverWidth = w; serverHeight = h;
      canvas.width = w; canvas.height = h;
      fitCanvas();
    }
    const img = new Image();
    img.onload = () => { ctx.drawImage(img, 0, 0); };
    img.src = "data:image/jpeg;base64," + b64;
  }

  function connect() {
    ws = new WebSocket(WS_URL);
    ws.onopen = () => {
      overlay.classList.add("hide");
      setStatus("Connected", 1000);
      send({ type: "resize", width: 1280, height: 800 });
      canvas.focus();
    };
    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch (e) { return; }
      if (msg.type === "frame") {
        drawFrame(msg.data, msg.width, msg.height);
      } else if (msg.type === "navigated") {
        setStatus(msg.url, 2000);
      } else if (msg.type === "done") {
        overlay.classList.remove("hide");
        overlay.querySelector("div").innerHTML =
          '<div class="spinner"></div><div>Login complete. Redirecting…</div>';
        if (msg.redirect) {
          setTimeout(() => { window.location.href = msg.redirect; }, 400);
        }
      } else if (msg.type === "error") {
        overlay.classList.remove("hide");
        overlay.querySelector("div").innerHTML =
          '<div style="color:#ff6b6b;font-weight:600;margin-bottom:8px">Login error</div><div style="color:#aaa">' +
          (msg.message || "unknown") + '</div>';
      }
    };
    ws.onclose = () => { setStatus("Disconnected", 0); };
    ws.onerror = () => { setStatus("Connection error", 0); };
  }

  canvas.addEventListener("mousemove", (e) => {
    const p = canvasCoords(e);
    send({ type: "mouse", action: "move", x: p.x, y: p.y, modifiers: modBits(e) });
  });
  canvas.addEventListener("mousedown", (e) => {
    e.preventDefault();
    const p = canvasCoords(e);
    send({ type: "mouse", action: "down", x: p.x, y: p.y,
           button: buttonName(e.button), modifiers: modBits(e), clickCount: 1 });
    canvas.focus();
  });
  canvas.addEventListener("mouseup", (e) => {
    e.preventDefault();
    const p = canvasCoords(e);
    send({ type: "mouse", action: "up", x: p.x, y: p.y,
           button: buttonName(e.button), modifiers: modBits(e), clickCount: 1 });
  });
  canvas.addEventListener("contextmenu", (e) => e.preventDefault());
  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const p = canvasCoords(e);
    send({ type: "wheel", x: p.x, y: p.y, deltaX: e.deltaX, deltaY: e.deltaY });
  }, { passive: false });

  canvas.addEventListener("keydown", (e) => {
    e.preventDefault();
    const text = isPrintable(e.key) ? e.key : "";
    if (text) {
      send({ type: "key", action: "press", key: e.key, code: e.code, text, modifiers: modBits(e) });
    } else {
      send({ type: "key", action: "down", key: e.key, code: e.code, modifiers: modBits(e) });
    }
  });
  canvas.addEventListener("keyup", (e) => {
    e.preventDefault();
    if (isPrintable(e.key)) return;
    send({ type: "key", action: "up", key: e.key, code: e.code, modifiers: modBits(e) });
  });

  window.addEventListener("resize", fitCanvas);
  fitCanvas();
  connect();
})();
</script>
</body></html>`;
}
