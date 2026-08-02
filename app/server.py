"""Garmin Connect MCP server — per-user login, encrypted token storage.

Each user links their OWN Garmin account via a browser enrollment form (email +
password + MFA entered in the browser, NOT in Claude). Only the resulting OAuth
tokens are stored (encrypted, per-user, keyed by the gateway-verified identity);
the password is never persisted. A user can only ever reach their own data.
"""
from __future__ import annotations

import os
import time
from typing import Any

from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers
from starlette.responses import HTMLResponse, PlainTextResponse

from .store import TokenStore
from . import garmin_client as gc

mcp = FastMCP("garmin")
store = TokenStore()
_clients: dict[str, Any] = {}  # in-memory Garmin client cache per user
_mfa_pending: dict[str, Any] = {}  # state -> garth client_state (transient)


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
    base = os.environ.get("GARMIN_PUBLIC_BASE_URL", "https://garmin.me.mcp.borgels.com")
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
        f"<title>{title}</title><body style='font-family:system-ui;max-width:26rem;margin:3rem auto;padding:0 1rem'>"
        f"<h1>{'✅' if ok else '⚠️'} {title}</h1>{body_html}</body>"
    )
    return HTMLResponse(html, status_code=200 if ok else 400)


def _form(state: str, mfa: bool = False, error: str = "") -> str:
    err = f"<p style='color:#b00'>{error}</p>" if error else ""
    if mfa:
        return (
            f"{err}<form method=post><input type=hidden name=state value='{state}'>"
            "<p>Enter the Garmin verification code sent to you:</p>"
            "<input name=mfa placeholder='2FA code' style='padding:.5rem;width:100%'>"
            "<button style='margin-top:1rem;padding:.6rem 1rem'>Verify</button></form>"
        )
    return (
        f"{err}<p>Sign in with <b>your own</b> Garmin Connect account. Your password is used once to obtain a "
        "token and is <b>not stored</b>.</p><form method=post>"
        f"<input type=hidden name=state value='{state}'>"
        "<input name=email placeholder='Garmin email' style='padding:.5rem;width:100%;margin-bottom:.5rem'>"
        "<input name=password type=password placeholder='Garmin password' style='padding:.5rem;width:100%'>"
        "<button style='margin-top:1rem;padding:.6rem 1rem'>Connect</button></form>"
    )


@mcp.custom_route("/garmin/enroll", methods=["GET", "POST"])
async def enroll(request):  # noqa: ANN001
    if request.method == "GET":
        state = request.query_params.get("state", "")
        if not store.peek_state(state):
            return _page("Link expired", "<p>Run garmin_connect again in Claude.</p>", ok=False)
        return _page("Connect Garmin", _form(state))

    form = await request.form()
    state = form.get("state", "")
    user = store.peek_state(state)
    if not user:
        return _page("Link expired", "<p>Run garmin_connect again in Claude.</p>", ok=False)
    try:
        if form.get("mfa"):
            client_state = _mfa_pending.pop(state, None)
            if client_state is None:
                return _page("Session lost", "<p>Please restart via garmin_connect.</p>", ok=False)
            blob = gc.resume_login(client_state, form["mfa"].strip())
        else:
            try:
                blob = gc.begin_login(form["email"].strip(), form["password"])
            except gc.MfaRequired as m:
                _mfa_pending[state] = m.client_state
                return _page("Two-factor code", _form(state, mfa=True))
        store.set_token_blob(user, blob)
        store.consume_state(state)
        _clients.pop(TokenStore.user_key(user), None)
        return _page("Garmin connected", "<p>Your Garmin account is linked. Close this tab and return to Claude.</p>")
    except Exception as exc:  # noqa: BLE001
        return _page("Connection failed", _form(state, error=str(exc)[:200]), ok=False)


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request):  # noqa: ANN001
    return PlainTextResponse("ok")


if __name__ == "__main__":
    mcp.run(
        transport="http",
        host=os.environ.get("MCP_HTTP_HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "3000")),
        path="/mcp",
    )
