# mcp-server-garmin

MCP server for **Garmin Connect** (personal health/fitness data) with per-user login and encrypted, per-user token storage.

> **Unofficial API.** Garmin has no obtainable official API for individual developers, so this uses `python-garminconnect` against Garmin's private endpoints. This may violate Garmin's Terms of Service and can break when Garmin changes their auth. Login is rate-limited per account (24–48h blocks) — the server logs in once per user and rides the token.

## Isolation

Behind an authenticating gateway that forwards the signed-in user as `X-MCP-User`, every tool is bound to that user. Tokens are AES-256-GCM encrypted per user; a user only ever reaches their own data, and the server fails closed without a verified identity. Passwords are **never stored** — only the resulting OAuth tokens. Users enroll via `garmin_connect`, which returns a single-use browser form where they enter their Garmin credentials (kept out of Claude entirely).

## Security configuration

- `MCP_HTTP_TOKEN` — shared bearer the gateway must send on `/mcp` (`Authorization: Bearer <token>`), compared in constant time. It is **required** when `GARMIN_TRUST_FORWARDED_USER=true`: the server refuses to start without it, because otherwise anyone who can reach the port could claim any `X-MCP-User`. Keep `/mcp` reachable only from the gateway.
- The enrollment page shows which gateway identity the link is bound to and requires an explicit confirmation before it accepts Garmin credentials. Links are single-use and expire after 10 minutes.

## Tools

`garmin_connect` / `garmin_status` / `garmin_disconnect`; `garmin_daily_summary`, `garmin_get_heart_rates`, `garmin_get_sleep`, `garmin_get_hrv`, `garmin_get_stress`, `garmin_get_body_composition`, `garmin_get_activities`, `garmin_get_training_readiness`; `garmin_log_weight` (write, `GARMIN_ENABLE_WRITES=true`).

## Run

```bash
pip install --require-hashes -r requirements.lock
python -m app.server   # /mcp + /garmin/enroll on :3000
PYTHONPATH=. pytest tests/
```

Dependencies are pinned with hashes in `requirements.lock`. To update them, edit `pyproject.toml` and regenerate:

```bash
uv pip compile pyproject.toml --generate-hashes --universal --python-version 3.12 -o requirements.lock
```

Docker images: `ghcr.io/borgels/mcp-server-garmin`.
