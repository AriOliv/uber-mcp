/**
 * RemoteBrowserSession — wraps a Playwright Chromium that drives
 * https://auth.uber.com/v2/. The server attaches via CDP to stream JPEG frames
 * (Page.startScreencast), forwards user input (Input.dispatchMouseEvent /
 * Input.dispatchKeyEvent), watches for the post-login redirect, and captures
 * cookies for later API calls.
 *
 * One Chromium process per session. Use BrowserSessionStore to enforce a cap.
 */

import { EventEmitter } from "events";
import type { Browser, BrowserContext, CDPSession, Page, Cookie } from "playwright";
import { chromium as chromiumExtra } from "playwright-extra";
import StealthPlugin from "puppeteer-extra-plugin-stealth";

import type { UberCookie, UberCredentials } from "./store.js";

chromiumExtra.use(StealthPlugin());

const UBER_USER_AGENT =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36";

const AUTH_START_URL =
  "https://auth.uber.com/v2/?next_url=" +
  encodeURIComponent("https://m.uber.com/go/home");

/** URLs that signal a successful login (post-redirect chain settled). */
const POST_LOGIN_URL_RE =
  /^https:\/\/m\.uber\.com\/go\/(home|login-redirect|drop|product-selection)/;

export type FrameEvent = {
  data: string; // base64 JPEG
  width: number;
  height: number;
};

export type DoneEvent = {
  credentials: UberCredentials;
};

export type RemoteBrowserOptions = {
  headless?: boolean;
  viewport?: { width: number; height: number };
  initialUrl?: string;
};

/** Strongly-typed input messages from the WebSocket client. */
export type InputMessage =
  | {
      type: "mouse";
      action: "move" | "down" | "up" | "click";
      x: number;
      y: number;
      button?: "left" | "middle" | "right";
      modifiers?: number;
      clickCount?: number;
    }
  | {
      type: "key";
      action: "down" | "up" | "press";
      key: string;
      code?: string;
      text?: string;
      modifiers?: number;
    }
  | { type: "wheel"; x: number; y: number; deltaX: number; deltaY: number }
  | { type: "resize"; width: number; height: number };

export class RemoteBrowserSession extends EventEmitter {
  private browser: Browser | null = null;
  private context: BrowserContext | null = null;
  private page: Page | null = null;
  private cdp: CDPSession | null = null;
  private viewport = { width: 1280, height: 800 };
  private closed = false;
  private completed = false;

  constructor(private readonly opts: RemoteBrowserOptions = {}) {
    super();
    if (opts.viewport) this.viewport = opts.viewport;
  }

  /** Launch Chromium, navigate to auth.uber.com, attach CDP, start screencast. */
  async start(): Promise<void> {
    if (this.browser) return;

    const headless = this.opts.headless !== false;
    this.browser = await chromiumExtra.launch({
      headless,
      args: [
        "--disable-blink-features=AutomationControlled",
        "--no-sandbox",
        "--disable-dev-shm-usage",
      ],
    });

    this.context = await this.browser.newContext({
      userAgent: UBER_USER_AGENT,
      viewport: this.viewport,
      locale: "en-US",
      deviceScaleFactor: 1,
      isMobile: false,
      hasTouch: false,
      acceptDownloads: false,
    });

    this.page = await this.context.newPage();

    // Watch URL changes to detect successful login
    this.page.on("framenavigated", (frame) => {
      if (frame !== this.page?.mainFrame()) return;
      const url = frame.url();
      this.emit("navigated", url);
      if (POST_LOGIN_URL_RE.test(url) && !this.completed) {
        this.completed = true;
        void this.captureAndFinish().catch((err) => this.emitError(err));
      }
    });

    // Attach CDP session for screencast + input dispatch
    this.cdp = await this.context.newCDPSession(this.page);

    this.cdp.on("Page.screencastFrame", async (event: { data: string; sessionId: number; metadata: { deviceWidth?: number; deviceHeight?: number } }) => {
      try {
        await this.cdp?.send("Page.screencastFrameAck", { sessionId: event.sessionId });
      } catch {
        // CDP may have closed
      }
      const frame: FrameEvent = {
        data: event.data,
        width: event.metadata?.deviceWidth ?? this.viewport.width,
        height: event.metadata?.deviceHeight ?? this.viewport.height,
      };
      this.emit("frame", frame);
    });

    await this.cdp.send("Page.enable");
    await this.cdp.send("Page.startScreencast", {
      format: "jpeg",
      quality: 70,
      maxWidth: this.viewport.width,
      maxHeight: this.viewport.height,
      everyNthFrame: 1,
    });

    const startUrl = this.opts.initialUrl ?? AUTH_START_URL;
    await this.page.goto(startUrl, { waitUntil: "domcontentloaded", timeout: 30_000 });
  }

  /** Forward an input event from the WebSocket client to Chromium via CDP. */
  async dispatchInput(msg: InputMessage): Promise<void> {
    if (!this.cdp || !this.page) return;
    try {
      switch (msg.type) {
        case "mouse": {
          const cdpType =
            msg.action === "move"
              ? "mouseMoved"
              : msg.action === "down"
                ? "mousePressed"
                : msg.action === "up"
                  ? "mouseReleased"
                  : "mousePressed";
          if (msg.action === "click") {
            await this.cdp.send("Input.dispatchMouseEvent", {
              type: "mousePressed",
              x: msg.x,
              y: msg.y,
              button: msg.button ?? "left",
              modifiers: msg.modifiers ?? 0,
              clickCount: msg.clickCount ?? 1,
            });
            await this.cdp.send("Input.dispatchMouseEvent", {
              type: "mouseReleased",
              x: msg.x,
              y: msg.y,
              button: msg.button ?? "left",
              modifiers: msg.modifiers ?? 0,
              clickCount: msg.clickCount ?? 1,
            });
          } else {
            await this.cdp.send("Input.dispatchMouseEvent", {
              type: cdpType,
              x: msg.x,
              y: msg.y,
              button: msg.button ?? "left",
              modifiers: msg.modifiers ?? 0,
              clickCount: msg.clickCount ?? 1,
            });
          }
          break;
        }
        case "wheel": {
          await this.cdp.send("Input.dispatchMouseEvent", {
            type: "mouseWheel",
            x: msg.x,
            y: msg.y,
            deltaX: msg.deltaX,
            deltaY: msg.deltaY,
            modifiers: 0,
          });
          break;
        }
        case "key": {
          const cdpType =
            msg.action === "down"
              ? "keyDown"
              : msg.action === "up"
                ? "keyUp"
                : "char";
          if (msg.action === "press") {
            if (msg.text && msg.text.length > 0 && msg.key.length === 1) {
              await this.cdp.send("Input.dispatchKeyEvent", {
                type: "char",
                text: msg.text,
                modifiers: msg.modifiers ?? 0,
              });
            } else {
              await this.cdp.send("Input.dispatchKeyEvent", {
                type: "keyDown",
                key: msg.key,
                code: msg.code,
                modifiers: msg.modifiers ?? 0,
              });
              await this.cdp.send("Input.dispatchKeyEvent", {
                type: "keyUp",
                key: msg.key,
                code: msg.code,
                modifiers: msg.modifiers ?? 0,
              });
            }
          } else {
            await this.cdp.send("Input.dispatchKeyEvent", {
              type: cdpType,
              key: msg.key,
              code: msg.code,
              text: msg.text,
              modifiers: msg.modifiers ?? 0,
            });
          }
          break;
        }
        case "resize": {
          this.viewport = { width: msg.width, height: msg.height };
          await this.page.setViewportSize(this.viewport);
          try {
            await this.cdp.send("Page.stopScreencast");
            await this.cdp.send("Page.startScreencast", {
              format: "jpeg",
              quality: 70,
              maxWidth: this.viewport.width,
              maxHeight: this.viewport.height,
              everyNthFrame: 1,
            });
          } catch {
            // ignore
          }
          break;
        }
      }
    } catch (err) {
      console.warn(
        `[remote-browser] dispatchInput error: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  async captureNow(): Promise<UberCredentials | null> {
    if (this.completed) return null;
    this.completed = true;
    return await this.captureCookies();
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    try { await this.cdp?.send("Page.stopScreencast").catch(() => {}); } catch { /* noop */ }
    try { await this.cdp?.detach().catch(() => {}); } catch { /* noop */ }
    try { await this.context?.close().catch(() => {}); } catch { /* noop */ }
    try { await this.browser?.close().catch(() => {}); } catch { /* noop */ }
    this.cdp = null;
    this.context = null;
    this.page = null;
    this.browser = null;
  }

  /* ---------------------------- internals --------------------------- */

  private async captureAndFinish(): Promise<void> {
    // Allow the m.uber.com redirect chain to settle.
    await new Promise((r) => setTimeout(r, 1500));
    // Visit other Uber subdomains so their domain-specific session cookies get set.
    // Without this, riders.uber.com and www.uber.com return 404 (their cookies are only
    // established when you navigate to those domains at least once after login).
    await this.warmupSubdomains();
    try {
      const creds = await this.captureCookies();
      if (creds) {
        const done: DoneEvent = { credentials: creds };
        this.emit("done", done);
      } else {
        this.emitError(new Error("post-login cookie capture returned no credentials"));
      }
    } catch (err) {
      this.emitError(err);
    }
  }

  private async warmupSubdomains(): Promise<void> {
    if (!this.context) return;
    const urls = [
      "https://riders.uber.com/",
      "https://www.uber.com/",
      "https://payments.uber.com/",
    ];
    let warmPage: Page | null = null;
    try {
      warmPage = await this.context.newPage();
      for (const url of urls) {
        try {
          await warmPage.goto(url, { waitUntil: "domcontentloaded", timeout: 12_000 });
          // Brief pause for auth redirect chains (payments redirects to auth then back).
          await new Promise((r) => setTimeout(r, 800));
        } catch {
          // Non-fatal — continue with next domain.
        }
      }
    } catch {
      // Non-fatal — proceed with whatever cookies were captured.
    } finally {
      await warmPage?.close().catch(() => {});
    }
  }

  private async captureCookies(): Promise<UberCredentials | null> {
    if (!this.context) return null;
    const raw: Cookie[] = await this.context.cookies();
    const cookies: UberCookie[] = raw.map((c) => ({
      name: c.name,
      value: c.value,
      domain: c.domain,
      path: c.path,
      expires: typeof c.expires === "number" ? c.expires : -1,
      httpOnly: !!c.httpOnly,
      secure: !!c.secure,
      sameSite:
        c.sameSite === "Strict" || c.sameSite === "Lax" || c.sameSite === "None"
          ? c.sameSite
          : undefined,
    }));

    // Build Cookie header for the most-used domain (m.uber.com). The dispatcher
    // can rebuild for other domains using the cookies array.
    const cookieHeader = buildCookieHeader(cookies, "m.uber.com");

    // Decode jwt-session payload (no signature verification — we just read sub/exp)
    const jwtCookie = cookies.find((c) => c.name === "jwt-session");
    const jwtClaims = jwtCookie ? decodeJwtPayload(jwtCookie.value) : {};
    const sub =
      typeof jwtClaims.sub === "string" && jwtClaims.sub
        ? jwtClaims.sub
        : `uber_${cookies.find((c) => c.name === "marketing_vistor_id")?.value ?? Math.random().toString(36).slice(2)}`;
    const jwtExp =
      typeof jwtClaims.exp === "number" ? jwtClaims.exp : Math.floor(Date.now() / 1000) + 86400;

    // Try to extract cityId from the page (if available). Defaults to São Paulo.
    let cityId = 458;
    try {
      const cityFromBody = await this.page?.evaluate(() => {
        const meta = document.querySelector(
          'meta[name="x-uber-rv-initial-load-city-id"]'
        );
        const v = meta?.getAttribute("content");
        if (v && /^\d+$/.test(v)) return Number(v);
        return null;
      });
      if (typeof cityFromBody === "number") cityId = cityFromBody;
    } catch {
      /* ignore */
    }

    const credentials: UberCredentials = {
      cookies,
      cookieHeader,
      cityId,
      sessionType: "desktop_session",
      userSub: sub,
      userAgent: UBER_USER_AGENT,
      capturedAt: Math.floor(Date.now() / 1000),
      expiresAt: Math.min(jwtExp, Math.floor(Date.now() / 1000) + 86400),
    };

    return credentials;
  }

  private emitError(err: unknown): void {
    const msg = err instanceof Error ? err.message : String(err);
    this.emit("error", { message: msg });
  }
}

/** Build a Cookie header value from cookies whose domain matches the host. */
export function buildCookieHeader(cookies: UberCookie[], host: string): string {
  return cookies
    .filter((c) => domainMatches(c.domain, host))
    .map((c) => `${c.name}=${c.value}`)
    .join("; ");
}

function domainMatches(cookieDomain: string, host: string): boolean {
  const d = cookieDomain.startsWith(".") ? cookieDomain.slice(1) : cookieDomain;
  return host === d || host.endsWith("." + d);
}

function decodeJwtPayload(jwt: string): { sub?: string; exp?: number; [k: string]: unknown } {
  try {
    const part = jwt.split(".")[1];
    if (!part) return {};
    const json = Buffer.from(part, "base64url").toString("utf8");
    return JSON.parse(json);
  } catch {
    return {};
  }
}
