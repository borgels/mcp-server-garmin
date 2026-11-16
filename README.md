# mcp-server-garmin

MCP server for **Garmin Connect** (personal health/fitness data) with per-user login and encrypted, per-user token storage.

This is an independent, unofficial project. It is not developed, endorsed or supported by Garmin.

> **Unofficial API.** Garmin has no obtainable official API for individual developers, so this uses `python-garminconnect` against Garmin's private endpoints. This may violate Garmin's Terms of Service and can break when Garmin changes their auth. Login is rate-limited per account (24–48h blocks) — the server logs in once per user and rides the token.

## Isolation

Behind an authenticating gateway that forwards the signed-in user as `X-MCP-User`, every tool is bound to that user. Tokens are AES-256-GCM encrypted per user; a user only ever reaches their own data, and the server fails closed without a verified identity. Passwords are **never stored** — only the resulting OAuth tokens. Users enroll via `garmin_connect`, which returns a single-use browser form where they enter their Garmin credentials (kept out of Claude entirely).

## Security configuration

- `MCP_HTTP_TOKEN` — shared bearer the gateway must send on `/mcp` (`Authorization: Bearer <token>`), compared in constant time. It is **required** when `GARMIN_TRUST_FORWARDED_USER=true`: the server refuses to start without it, because otherwise anyone who can reach the port could claim any `X-MCP-User`. Keep `/mcp` reachable only from the gateway.
- The server **refuses to start** on a non-loopback bind (the default is `MCP_HTTP_HOST=0.0.0.0`) without `MCP_HTTP_TOKEN`, unless `MCP_HTTP_ALLOW_UNAUTHENTICATED=true` (never together with `GARMIN_TRUST_FORWARDED_USER=true`). The token must be at least 32 printable ASCII characters (e.g. `openssl rand -hex 32`).
- Failed `/mcp` authentications are limited per client address: after `MCP_AUTH_FAILURE_LIMIT` (default 20, `0` disables) failures within `MCP_AUTH_FAILURE_WINDOW_MS` (default 60000) further failures get 429 with `Retry-After`. A valid token is never throttled. 401 responses carry `WWW-Authenticate: Bearer`.
- `PORT` and the limits above are validated at startup; invalid values stop the server with a clear message.
- `/garmin/enroll` and `/healthz` need no bearer.
- The enrollment page shows which gateway identity the link is bound to and requires an explicit confirmation, bound to the confirming browser (HttpOnly cookie), before it accepts Garmin credentials. Links are single-use and expire after 10 minutes.

## Security model

- Each user links their own Garmin account; tools only use the tokens stored for the identity in `X-MCP-User`. That header is only trusted with `GARMIN_TRUST_FORWARDED_USER=true`, and only behind `MCP_HTTP_TOKEN`; without it every tool refuses.
- User authentication and authorization belong in an identity-aware gateway in front of this server: it signs the user in, sets `X-MCP-User` and holds the bearer token. This server does not authenticate end users itself.
- Tool access is not data access: whoever can call `/mcp` with the bearer and a given `X-MCP-User` value acts as that user against Garmin.
- The HTTP server does not terminate TLS. Put it behind a TLS-terminating proxy or keep it on a private network.

## Tools

`garmin_connect` / `garmin_status` / `garmin_disconnect`; `garmin_daily_summary`, `garmin_get_heart_rates`, `garmin_get_sleep`, `garmin_get_hrv`, `garmin_get_stress`, `garmin_get_body_composition`, `garmin_get_activities`, `garmin_get_training_readiness`; `garmin_log_weight` (write, `GARMIN_ENABLE_WRITES=true`).

## Run

```bash
pip install --require-hashes -r requirements.lock
python -m app.server   # /mcp + /garmin/enroll on :3000
PYTHONPATH=. pytest tests/
```

Dependencies are pinned with hashes in `requirements.lock`. CI runs `pip-audit` against the lock on pull requests and as part of every publish (including the weekly rebuild): a newly published advisory for a pinned package blocks image publishing until the lock is refreshed. To update them, edit `pyproject.toml` and regenerate:

```bash
uv pip compile pyproject.toml --generate-hashes --universal --python-version 3.12 -o requirements.lock
```

Docker images: `ghcr.io/borgels/mcp-server-garmin`.
