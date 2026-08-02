# mcp-server-garmin

MCP server for **Garmin Connect** (personal health/fitness data) with per-user login and encrypted, per-user token storage.

> **Unofficial API.** Garmin has no obtainable official API for individual developers, so this uses `python-garminconnect` against Garmin's private endpoints. This may violate Garmin's Terms of Service and can break when Garmin changes their auth. Login is rate-limited per account (24–48h blocks) — the server logs in once per user and rides the token.

## Isolation

Behind an authenticating gateway that forwards the signed-in user as `X-MCP-User`, every tool is bound to that user. Tokens are AES-256-GCM encrypted per user; a user only ever reaches their own data, and the server fails closed without a verified identity. Passwords are **never stored** — only the resulting OAuth tokens. Users enroll via `garmin_connect`, which returns a single-use browser form where they enter their Garmin credentials (kept out of Claude entirely).

## Tools

`garmin_connect` / `garmin_status` / `garmin_disconnect`; `garmin_daily_summary`, `garmin_get_heart_rates`, `garmin_get_sleep`, `garmin_get_hrv`, `garmin_get_stress`, `garmin_get_body_composition`, `garmin_get_activities`, `garmin_get_training_readiness`; `garmin_log_weight` (write, `GARMIN_ENABLE_WRITES=true`).

## Run

```bash
pip install .
python -m app.server   # /mcp + /garmin/enroll on :3000
PYTHONPATH=. pytest tests/
```

Docker images: `ghcr.io/borgels/mcp-server-garmin`.
