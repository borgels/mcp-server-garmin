# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately to <security@borgels.com>.

Do not include API keys, access tokens, personal data or other secrets in
public GitHub issues. Include a concise description, the affected version,
reproduction steps and the impact where possible.

## Supported versions

Security fixes are made on the `main` branch and in the latest published
release.

## Credential handling

Garmin passwords are entered in the single-use enrollment form and are never
stored; only the resulting tokens are kept, encrypted per user. Server secrets
(`MCP_HTTP_TOKEN`, `GARMIN_ENCRYPTION_KEY`) are read from the server
environment only. If you
believe tokens or secrets were exposed, rotate `MCP_HTTP_TOKEN` and
`GARMIN_ENCRYPTION_KEY`, and have affected users disconnect and reconnect their Garmin
account.
