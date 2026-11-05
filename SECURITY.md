# Security Policy

## Reporting a vulnerability

Please **do not open a public issue**. Report privately via GitHub's
[private vulnerability reporting](https://github.com/AriOliv/uber-mcp/security/advisories/new)
for this repository. Include a description, reproduction steps and affected
version. We aim to acknowledge reports within 72 hours and to ship a fix or
mitigation for confirmed issues promptly, crediting reporters who wish it.

Only the latest release on `main` is supported.

## Threat model

This server holds a user's Uber **session cookies** and acts on their behalf.
Treat the process, its `.env` and its logs as highly sensitive. It is
unofficial and not affiliated with Uber.

## Protections

**Tool execution**
- Every client-supplied argument set is validated against the tool's declared
  JSON schema (`src/security.ts`): types, enums, required fields, unknown
  properties, string length, array size, nesting depth, control characters and
  `__proto__`/`constructor`/`prototype` keys are rejected before any request.
- URL path parameters are percent-encoded (no path traversal / request
  smuggling to other endpoints). Requests only go to a fixed allowlist of
  Uber hosts; the host can never be influenced by tool arguments.
- GraphQL operations come from hardcoded queries; clients only supply variables.

**Authentication / tokens**
- OAuth 2.1 with PKCE; authorization codes are single-use (60 s), refresh
  tokens are rotated on use, access tokens are HS256 JWTs (1 h) verified with a
  pinned algorithm, `typ`, issuer, audience and required `sub`/`exp` claims.
- `MCP_JWT_SECRET` (≥ 32 chars) is mandatory; the server refuses to start without it.
- Uber cookies are kept in memory only, never written to disk, never returned
  by tools, and are pruned on expiry (24 h). Cookies are sent only to the
  matching Uber host.
- The login WebSocket rejects connections whose `Origin` differs from `PUBLIC_URL`.

**Leak prevention**
- Upstream error text and internal errors are passed through `redact()`
  (bearer/JWT tokens, cookies, passwords, e-mails, phone numbers) and truncated
  before reaching logs or tool results. Logs never contain request bodies,
  cookies or tokens.
- `/healthz` returns liveness only. `/debug/users` exists only when
  `NODE_ENV !== "production"` and only answers on loopback.

**HTTP hardening**
- `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`,
  `Cross-Origin-*`, `Permissions-Policy`, `Cache-Control: no-store`, HSTS (when
  `PUBLIC_URL` is https) and a CSP on `/login*`; `X-Powered-By` disabled.
- Body size limits (1 MB JSON, 100 KB form). `X-Forwarded-*` is ignored unless
  `TRUST_PROXY` is set.

**Dependencies**
- `npm audit --omit=dev` runs in CI (`--audit-level=high`) and the project
  currently reports 0 known vulnerabilities (`qs` is pinned via `overrides`).

## Operator recommendations

- Run behind a TLS-terminating reverse proxy, set `PUBLIC_URL` to the https URL
  and `NODE_ENV=production`.
- Add rate limiting at the proxy; keep `MAX_BROWSER_SESSIONS` low.
- Rotate `MCP_JWT_SECRET` if exposed (invalidates all tokens).
- Never commit `.env` or share `UBER_COOKIE_HEADER`.
