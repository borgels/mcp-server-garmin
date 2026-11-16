# Changelog

## 0.2.0

### Changes

- HTTP: the server refuses to start on a non-loopback bind (default `0.0.0.0`)
  without `MCP_HTTP_TOKEN`, unless `MCP_HTTP_ALLOW_UNAUTHENTICATED=true`; the
  escape hatch never applies with `GARMIN_TRUST_FORWARDED_USER=true`.
- HTTP: `MCP_HTTP_TOKEN` must be at least 32 printable ASCII characters.
- HTTP: failed `/mcp` authentications are limited per client address (429 with
  `Retry-After`); valid tokens are never throttled. New `MCP_AUTH_FAILURE_LIMIT`
  (default 20, `0` disables) and `MCP_AUTH_FAILURE_WINDOW_MS` (default 60000).
- HTTP: 401 responses carry `WWW-Authenticate: Bearer`.
- `PORT`, the limits above and `MCP_HTTP_ALLOW_UNAUTHENTICATED` are validated at
  startup; invalid values stop the server with a clear message.
- The MCP server reports the package version.
- Dependencies: in-range lock refresh (`fastmcp` 4.2.0, `authlib`, `certifi`,
  `dnspython`, `joserfc`, `opentelemetry-api`) so `pip-audit` reports no known
  vulnerabilities. CI runs `pip-audit`, uses pinned actions and builds the image
  on pull requests; images are published only after tests pass, with SBOM and
  provenance. Grouped Dependabot updates, `.dockerignore`, `.gitattributes`.

### Upgrade notes

- A deployment on the default `0.0.0.0` bind must set `MCP_HTTP_TOKEN` (it
  already must with `GARMIN_TRUST_FORWARDED_USER=true`) of at least 32
  characters. A shorter token now stops the server.
- Invalid values for the variables above now stop the server at startup.
- Unchanged: `/garmin/enroll` and `/healthz` remain reachable without the
  bearer; existing variable names are unchanged.

### Also in this release

- Security: refuse to start when `GARMIN_TRUST_FORWARDED_USER=true` and `MCP_HTTP_TOKEN` is
  unset; the `/mcp` bearer is now compared in constant time.
- Security: the enrollment page shows the gateway identity the link is bound to and requires
  an explicit, browser-bound confirmation before accepting credentials.
- Security: HTML-escape error text on the enrollment page; pending MFA hand-offs expire after
  10 minutes.
- Dependencies pinned to exact versions with hashes (`requirements.lock`), used by the
  Dockerfile and CI.

## 0.1.0

Initial release (unofficial Garmin Connect API via python-garminconnect).

- Per-user login: each user links their OWN Garmin account through a browser
  enrollment form (email/password/MFA entered in the browser, NOT in Claude).
  Only the resulting OAuth token blob is stored — never the password — encrypted
  (AES-256-GCM), keyed by the gateway-verified identity (X-MCP-User). Fail-closed.
- Login is done once per user and cached; per-account 429 sets a ~24h backoff.
- Tools: daily summary, heart rate, sleep, HRV, stress, body composition,
  activities, training readiness; log_weight (write, gated). connect/status/disconnect.
