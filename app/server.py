"""Garmin Connect MCP server — per-user login, encrypted token storage.

Each user links their OWN Garmin account via a browser enrollment form (email +
password + MFA entered in the browser, NOT in Claude). Only the resulting OAuth
tokens are stored (encrypted, per-user, keyed by the gateway-verified identity);
the password is never persisted. A user can only ever reach their own data.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import math
import os
import sys
import time
from html import escape
from typing import Any

from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers
from starlette.responses import HTMLResponse, PlainTextResponse

from . import __version__
from .store import TokenStore
from . import garmin_client as gc

mcp = FastMCP("garmin", version=__version__)
store = TokenStore()
_clients: dict[str, Any] = {}  # in-memory Garmin client cache per user
# state -> (monotonic expiry, client_state); transient MFA hand-off, dropped after MFA_PENDING_TTL_S
_mfa_pending: dict[str, tuple[float, Any]] = {}
MFA_PENDING_TTL_S = 10 * 60


# --- identity & isolation -------------------------------------------------

def _trust_forwarded() -> bool:
    return os.environ.get("GARMIN_TRUST_FORWARDED_USER") == "true"


def _writes_enabled() -> bool:
    return os.environ.get("GARMIN_ENABLE_WRITES") == "true"


def current_user() -> str:
    """The gateway-verified user for this request, or fail closed."""
    if not _trust_forwarded():
        raise RuntimeError("This connector requires the gateway (GARMIN_TRUST_FORWARDED_USER not set).")
    headers = get_http_headers() or {}
    user = (headers.get("x-mcp-user") or "").strip()
    if not user:
        raise RuntimeError(
            "No verified user identity (X-MCP-User). This connector only works behind a gateway that "
            "forwards the signed-in user; each user sees only their own Garmin data."
        )
    return user


def _get_client(user: str) -> Any:
    key = TokenStore.user_key(user)
    if key in _clients:
        return _clients[key]
    blob = None
    rec = store.get_record(user)
    if rec:
        blob = rec.get("blob") or None
    if not blob:
        raise RuntimeError("NOT_ENROLLED: run garmin_connect and complete the browser login first.")
    client = gc.make_client(blob)
    _clients[key] = client
    return client


def _call(user: str, fn_name: str, *args: Any) -> Any:
    client = _get_client(user)
    try:
        return getattr(client, fn_name)(*args)
    except Exception as exc:  # noqa: BLE001
        if gc.is_rate_limit_error(exc):
            store.set_rate_limited(user, int(time.time()) + 24 * 3600)
            raise RuntimeError("Garmin rate-limited this account (429). Backing off ~24h; do not retry.") from exc
        if gc.is_auth_error(exc):
            # The stored session is dead. Drop the cached client so a re-enroll
            # takes effect immediately, and say plainly what to do — we cannot
            # re-login automatically because the password is never stored.
            _clients.pop(TokenStore.user_key(user), None)
            raise RuntimeError(
                "GARMIN_SESSION_EXPIRED: your stored Garmin session is no longer valid "
                "(Garmin returned 401). This happens when the token ages out, you change "
                "your Garmin password, or Garmin invalidates the session. Run garmin_connect "
                "and sign in again — no data is lost, and this is not a problem with your watch."
            ) from exc
        raise


def _today() -> str:
    # Date is provided by callers; default handled per-tool to avoid banned Date in tests.
    return time.strftime("%Y-%m-%d", time.gmtime())


# --- enrollment tools -----------------------------------------------------

@mcp.tool
def garmin_search_capabilities(query: str = "") -> dict:
    """List the Garmin tools available (discovery; no Garmin call)."""
    tools = [
        "garmin_connect", "garmin_status", "garmin_disconnect",
        "garmin_daily_summary", "garmin_get_heart_rates", "garmin_get_sleep",
        "garmin_get_hrv", "garmin_get_stress", "garmin_get_body_composition",
        "garmin_get_activities", "garmin_get_training_readiness", "garmin_log_weight",
    ]
    q = query.lower().strip()
    return {"tools": [t for t in tools if not q or q in t]}


@mcp.tool
def garmin_connect() -> dict:
    """Start linking YOUR Garmin account. Returns a one-time enrollment link to open
    in your browser, where you enter your Garmin email/password (and MFA if enabled)
    directly — never in Claude. Only the resulting tokens are stored, not the password."""
    user = current_user()
    state = store.create_state(user)
    base = os.environ.get("GARMIN_PUBLIC_BASE_URL", "https://garmin.me.mcp.example.com")
    return {
        "alreadyConnected": bool(store.get_record(user)),
        "enrollmentUrl": f"{base}/garmin/enroll?state={state}",
        "instructions": "Open enrollmentUrl in your browser and sign in with YOUR Garmin account. "
        "Single-use, expires in 10 minutes. Note: this uses Garmin's unofficial API.",
    }


@mcp.tool
def garmin_status() -> dict:
    """Whether your Garmin account is linked, and any rate-limit backoff."""
    user = current_user()
    rec = store.get_record(user)
    if not rec:
        return {"connected": False, "hint": "Run garmin_connect to link your account."}
    return {
        "connected": True,
        "connectedAt": rec.get("connected_at"),
        "rateLimitedUntil": rec.get("meta", {}).get("rate_limited_until", 0),
    }


@mcp.tool
def garmin_disconnect() -> dict:
    """Remove your stored Garmin tokens from this server."""
    user = current_user()
    _clients.pop(TokenStore.user_key(user), None)
    return {"disconnected": store.delete(user)}


# --- data tools -----------------------------------------------------------

@mcp.tool
def garmin_daily_summary(date: str) -> dict:
    """Daily wellness summary (steps, calories, floors, Body Battery, intensity) for YYYY-MM-DD."""
    return _call(current_user(), "get_stats", date)


@mcp.tool
def garmin_get_heart_rates(date: str) -> dict:
    """All-day + resting heart rate for YYYY-MM-DD."""
    return _call(current_user(), "get_heart_rates", date)


@mcp.tool
def garmin_get_sleep(date: str) -> dict:
    """Sleep stages, score and duration for YYYY-MM-DD."""
    return _call(current_user(), "get_sleep_data", date)


@mcp.tool
def garmin_get_hrv(date: str) -> dict:
    """Overnight HRV status for YYYY-MM-DD."""
    return _call(current_user(), "get_hrv_data", date)


@mcp.tool
def garmin_get_stress(date: str) -> dict:
    """All-day stress for YYYY-MM-DD."""
    return _call(current_user(), "get_stress_data", date)


@mcp.tool
def garmin_get_body_composition(start_date: str, end_date: str) -> dict:
    """Weight and body composition between two YYYY-MM-DD dates."""
    return _call(current_user(), "get_body_composition", start_date, end_date)


@mcp.tool
def garmin_get_activities(start: int = 0, limit: int = 20) -> list:
    """Recent activities (workouts) — paginated by start/limit."""
    return _call(current_user(), "get_activities", start, limit)


@mcp.tool
def garmin_get_training_readiness(date: str) -> dict:
    """Training readiness for YYYY-MM-DD."""
    return _call(current_user(), "get_training_readiness", date)


@mcp.tool
def garmin_log_weight(weight_kg: float) -> dict:
    """Log a weigh-in (kg) to Garmin. Requires write access on this instance."""
    if not _writes_enabled():
        raise RuntimeError("Write access is disabled (GARMIN_ENABLE_WRITES != true).")
    return {"result": _call(current_user(), "add_weigh_in", weight_kg, "kg")}


# --- enrollment web routes (reached directly, NOT via the gateway) --------

def _page(title: str, body_html: str, ok: bool = True) -> HTMLResponse:
    html = (
        f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{escape(title)}</title><body style='font-family:system-ui;max-width:26rem;margin:3rem auto;padding:0 1rem'>"
        f"<h1>{'✅' if ok else '⚠️'} {escape(title)}</h1>{body_html}</body>"
    )
    return HTMLResponse(html, status_code=200 if ok else 400, headers={
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
    })


def _identity_banner(user: str) -> str:
    return (
        "<p style='padding:.75rem;border:2px solid #b60;background:#fff4e5;font-size:1.1rem'>"
        f"You are linking this Garmin account to <b>{escape(user)}</b>.</p>"
    )


def _confirm_form(state: str, user: str, error: str = "") -> str:
    err = f"<p style='color:#b00'>{escape(error)}</p>" if error else ""
    return (
        f"{err}{_identity_banner(user)}"
        "<p>Only continue if this is <b>your</b> identity and you started this link yourself "
        "from your own Claude session. If not, close this page.</p>"
        f"<form method=post><input type=hidden name=state value='{escape(state)}'>"
        "<input type=hidden name=step value=confirm>"
        "<label><input type=checkbox name=confirm_identity value=yes required> "
        f"Yes, link my Garmin account to {escape(user)}</label>"
        "<br><button style='margin-top:1rem;padding:.6rem 1rem'>Continue</button></form>"
    )


def _form(state: str, user: str, mfa: bool = False, error: str = "") -> str:
    err = f"<p style='color:#b00'>{escape(error)}</p>" if error else ""
    banner = _identity_banner(user)
    if mfa:
        return (
            f"{err}{banner}<form method=post><input type=hidden name=state value='{escape(state)}'>"
            "<p>Enter the Garmin verification code sent to you:</p>"
            "<input name=mfa placeholder='2FA code' style='padding:.5rem;width:100%'>"
            "<button style='margin-top:1rem;padding:.6rem 1rem'>Verify</button></form>"
        )
    return (
        f"{err}{banner}<p>Sign in with <b>your own</b> Garmin Connect account. Your password is used once to obtain a "
        "token and is <b>not stored</b>.</p><form method=post>"
        f"<input type=hidden name=state value='{escape(state)}'>"
        "<input name=email placeholder='Garmin email' style='padding:.5rem;width:100%;margin-bottom:.5rem'>"
        "<input name=password type=password placeholder='Garmin password' style='padding:.5rem;width:100%'>"
        "<button style='margin-top:1rem;padding:.6rem 1rem'>Connect</button></form>"
    )


def _mfa_gc() -> None:
    now = time.monotonic()
    for key in [k for k, (exp, _) in _mfa_pending.items() if exp <= now]:
        _mfa_pending.pop(key, None)


def _mfa_put(state: str, client_state: Any) -> None:
    _mfa_gc()
    _mfa_pending[state] = (time.monotonic() + MFA_PENDING_TTL_S, client_state)


def _mfa_pop(state: str) -> Any:
    _mfa_gc()
    entry = _mfa_pending.pop(state, None)
    return entry[1] if entry else None


_EXPIRED = "<p>Run garmin_connect again in Claude.</p>"
# Cookie binding the browser that confirmed the identity to the credential submission.
ENROLL_COOKIE = "garmin_enroll"


@mcp.custom_route("/garmin/enroll", methods=["GET", "POST"])
async def enroll(request):  # noqa: ANN001
    if request.method == "GET":
        state = request.query_params.get("state", "")
        user = store.peek_state(state)
        if not user:
            return _page("Link expired", _EXPIRED, ok=False)
        # Step 1: show which identity the link is bound to and require an explicit
        # confirmation before any Garmin credentials are accepted.
        return _page("Connect Garmin", _confirm_form(state, user))

    form = await request.form()
    state = str(form.get("state", ""))
    user = store.peek_state(state)
    if not user:
        return _page("Link expired", _EXPIRED, ok=False)

    if form.get("step") == "confirm":
        if form.get("confirm_identity") != "yes":
            return _page("Confirm the account", _confirm_form(state, user, error="Please tick the box to confirm."), ok=False)
        nonce = store.confirm_state(state)
        if not nonce:
            return _page("Link expired", _EXPIRED, ok=False)
        resp = _page("Connect Garmin", _form(state, user))
        resp.set_cookie(
            ENROLL_COOKIE, nonce, max_age=10 * 60, path="/garmin", httponly=True, samesite="strict",
            secure=os.environ.get("GARMIN_PUBLIC_BASE_URL", "https://").startswith("https:"),
        )
        return resp

    if not store.state_confirmed(state, request.cookies.get(ENROLL_COOKIE)):
        return _page("Confirm the account", _confirm_form(state, user, error="Please confirm the account in this browser first."), ok=False)

    try:
        if form.get("mfa"):
            client_state = _mfa_pop(state)
            if client_state is None:
                return _page("Session lost", "<p>Please restart via garmin_connect.</p>", ok=False)
            blob = gc.resume_login(client_state, str(form["mfa"]).strip())
        else:
            try:
                blob = gc.begin_login(str(form.get("email", "")).strip(), str(form.get("password", "")))
            except gc.MfaRequired as m:
                _mfa_put(state, m.client_state)
                return _page("Two-factor code", _form(state, user, mfa=True))
        store.set_token_blob(user, blob)
        store.consume_state(state)
        _clients.pop(TokenStore.user_key(user), None)
        return _page("Garmin connected", "<p>Your Garmin account is linked. Close this tab and return to Claude.</p>")
    except Exception as exc:  # noqa: BLE001
        return _page("Connection failed", _form(state, user, error=str(exc)[:200]), ok=False)


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request):  # noqa: ANN001
    return PlainTextResponse("ok")


def _bearer_ok(authorization: bytes, token: str) -> bool:
    """Constant-time check of an Authorization header against the expected bearer."""
    expected = hashlib.sha256(f"Bearer {token}".encode()).digest()
    supplied = hashlib.sha256(authorization).digest()
    return hmac.compare_digest(expected, supplied)


# --- startup configuration ---------------------------------------------------

MIN_TOKEN_LENGTH = 32
DEFAULT_AUTH_FAILURE_LIMIT = 20
DEFAULT_AUTH_FAILURE_WINDOW_MS = 60_000
_TRUE = {"true", "1", "yes", "on"}
_FALSE = {"false", "0", "no", "off"}


def _env_int(env: Any, name: str, default: int, lo: int, hi: int) -> int:
    raw = (env.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw, 10)
    except ValueError:
        value = None
    if value is None or not lo <= value <= hi:
        raise SystemExit(f"Refusing to start: {name} must be an integer between {lo} and {hi}; got {raw[:40]!r}.")
    return value


def _env_bool(env: Any, name: str) -> bool:
    raw = (env.get(name) or "").strip().lower()
    if not raw:
        return False
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    raise SystemExit(f'Refusing to start: {name} must be "true" or "false"; got {raw[:40]!r}.')


def _is_loopback(host: str) -> bool:
    h = host.strip().lower().strip("[]").rstrip(".")
    if h in ("localhost", "::1"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def check_startup_config(env: Any = None) -> dict[str, Any]:
    """Validate the HTTP configuration and refuse to start in an unsafe one.

    - With GARMIN_TRUST_FORWARDED_USER=true every tool trusts the X-MCP-User
      header, so /mcp must only be reachable by the gateway: MCP_HTTP_TOKEN is
      required (MCP_HTTP_ALLOW_UNAUTHENTICATED does not override this).
    - A non-loopback bind without MCP_HTTP_TOKEN is refused unless
      MCP_HTTP_ALLOW_UNAUTHENTICATED=true.
    - MCP_HTTP_TOKEN must be at least 32 printable ASCII characters.
    - PORT and the auth-failure limits must be valid integers.

    Returns the validated settings."""
    env = os.environ if env is None else env
    token = (env.get("MCP_HTTP_TOKEN") or "").strip()
    trust = env.get("GARMIN_TRUST_FORWARDED_USER") == "true"
    host = (env.get("MCP_HTTP_HOST") or "").strip() or "0.0.0.0"
    settings = {
        "host": host,
        "port": _env_int(env, "PORT", 3000, 1, 65_535),
        "auth_failure_limit": _env_int(env, "MCP_AUTH_FAILURE_LIMIT", DEFAULT_AUTH_FAILURE_LIMIT, 0, 1_000_000),
        "auth_failure_window_ms": _env_int(
            env, "MCP_AUTH_FAILURE_WINDOW_MS", DEFAULT_AUTH_FAILURE_WINDOW_MS, 1, 86_400_000
        ),
    }
    allow_unauthenticated = _env_bool(env, "MCP_HTTP_ALLOW_UNAUTHENTICATED")

    if token and len(token) < MIN_TOKEN_LENGTH:
        raise SystemExit(
            f"Refusing to start: MCP_HTTP_TOKEN must be at least {MIN_TOKEN_LENGTH} characters long "
            "(for example: openssl rand -hex 32)."
        )
    if token and not all(0x21 <= ord(ch) <= 0x7E for ch in token):
        raise SystemExit("Refusing to start: MCP_HTTP_TOKEN must only contain printable ASCII characters without whitespace.")
    if trust and not token:
        raise SystemExit(
            "Refusing to start: GARMIN_TRUST_FORWARDED_USER=true requires MCP_HTTP_TOKEN "
            "(the shared bearer the gateway sends on /mcp). Without it, anyone who can reach "
            "this port could act as any user. Set MCP_HTTP_TOKEN to a long random secret."
        )
    if not token and not allow_unauthenticated and not _is_loopback(host):
        raise SystemExit(
            f"Refusing to start: listening on {host} (MCP_HTTP_HOST, default 0.0.0.0) without MCP_HTTP_TOKEN. "
            "Set MCP_HTTP_TOKEN, set MCP_HTTP_HOST=127.0.0.1, or set MCP_HTTP_ALLOW_UNAUTHENTICATED=true "
            "if access is restricted by other means."
        )
    return settings


class _AuthFailureLimiter:
    """Fixed-window count of failed /mcp authentications per client address.
    Memory is bounded; expired entries are swept and, if still full, the oldest
    entry is evicted."""

    def __init__(self, limit: int, window_s: float, max_entries: int = 10_000) -> None:
        self.limit = limit
        self.window_s = window_s
        self.max_entries = max_entries
        self._entries: dict[str, list[float]] = {}  # key -> [count, reset_at]

    def retry_after(self, key: str, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        entry = self._entries.get(key)
        if not entry:
            return 0
        if entry[1] <= now:
            del self._entries[key]
            return 0
        return max(1, math.ceil(entry[1] - now)) if entry[0] >= self.limit else 0

    def record_failure(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        entry = self._entries.get(key)
        if entry and entry[1] > now:
            entry[0] += 1
            return entry[0] == self.limit
        self._entries.pop(key, None)
        if len(self._entries) >= self.max_entries:
            for k in [k for k, e in self._entries.items() if e[1] <= now]:
                del self._entries[k]
            if len(self._entries) >= self.max_entries:
                del self._entries[next(iter(self._entries))]
        self._entries[key] = [1, now + self.window_s]
        return self.limit == 1


class _InternalAuth:
    """Require the gateway's shared bearer on /mcp (the enrollment routes and
    /healthz stay open — they're reached directly and self-secured by state).
    Failed authentications are limited per client address; a valid token is
    never throttled."""

    def __init__(
        self,
        app: Any,
        auth_failure_limit: int = DEFAULT_AUTH_FAILURE_LIMIT,
        auth_failure_window_ms: int = DEFAULT_AUTH_FAILURE_WINDOW_MS,
    ) -> None:
        self.app = app
        self.limiter = (
            _AuthFailureLimiter(auth_failure_limit, auth_failure_window_ms / 1000) if auth_failure_limit > 0 else None
        )

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        path = scope.get("path") or ""
        if scope.get("type") == "http" and (path == "/mcp" or path.startswith("/mcp/")):
            token = (os.environ.get("MCP_HTTP_TOKEN") or "").strip()
            if token or _trust_forwarded():
                headers = dict(scope.get("headers") or [])
                # Fail closed: a trusted X-MCP-User without a configured token is never accepted.
                if not token or not _bearer_ok(headers.get(b"authorization", b""), token):
                    client = scope.get("client") or ("unknown", 0)
                    remote = str(client[0])
                    if self.limiter:
                        retry_after = self.limiter.retry_after(remote)
                        if retry_after > 0:
                            await _plain(send, 429, b"Too many failed authentication attempts",
                                         [(b"retry-after", str(retry_after).encode())])
                            return
                        if self.limiter.record_failure(remote):
                            print(f"[http] {remote} reached {self.limiter.limit} failed authentication attempts; "
                                  "further failures get 429", file=sys.stderr)
                    await _plain(send, 401, b"Unauthorized", [(b"www-authenticate", b"Bearer")])
                    return
        await self.app(scope, receive, send)


async def _plain(send: Any, status: int, body: bytes, extra_headers: list[tuple[bytes, bytes]]) -> None:
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"text/plain"), *extra_headers]})
    await send({"type": "http.response.body", "body": body})


def build_app(env: Any = None, settings: dict[str, Any] | None = None) -> Any:
    """Build the ASGI app; validates the configuration unless already-validated settings are passed."""
    settings = check_startup_config(env) if settings is None else settings
    return _InternalAuth(
        mcp.http_app(path="/mcp"),
        auth_failure_limit=settings["auth_failure_limit"],
        auth_failure_window_ms=settings["auth_failure_window_ms"],
    )


if __name__ == "__main__":
    import uvicorn

    try:
        settings = check_startup_config()
    except SystemExit as exc:
        reason = str(exc).removeprefix("Refusing to start: ")
        print(f"Garmin MCP HTTP server not started: {reason}", file=sys.stderr)
        raise SystemExit(1) from None
    app = build_app(settings=settings)
    uvicorn.run(app, host=settings["host"], port=settings["port"])
