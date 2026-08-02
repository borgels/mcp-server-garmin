# Changelog

## 0.1.0

Initial release (unofficial Garmin Connect API via python-garminconnect).

- Per-user login: each user links their OWN Garmin account through a browser
  enrollment form (email/password/MFA entered in the browser, NOT in Claude).
  Only the resulting OAuth token blob is stored — never the password — encrypted
  (AES-256-GCM), keyed by the gateway-verified identity (X-MCP-User). Fail-closed.
- Login is done once per user and cached; per-account 429 sets a ~24h backoff.
- Tools: daily summary, heart rate, sleep, HRV, stress, body composition,
  activities, training readiness; log_weight (write, gated). connect/status/disconnect.
