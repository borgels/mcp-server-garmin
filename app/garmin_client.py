"""Garmin login + data access, built on python-garminconnect (>=0.3.8).

IMPORTANT (unofficial API): login is the ONLY rate-limit-dangerous operation and
Garmin blocks per-account (24-48h) on repeated logins. So we log in ONCE per
user, persist the resulting OAuth token blob (never the password), and ride it.
python-garminconnect handles lazy OAuth2 refresh from the ~1yr OAuth1 token.

garminconnect 0.3.x dropped garth: auth is native (curl_cffi) and MFA state is
held on the live client instance. So the MFA flow keeps the SAME Garmin object
between the two enrollment POSTs and resumes on it; `resume_login`'s first arg
is vestigial (the library reads the pending state from the client itself).
"""
from __future__ import annotations

from typing import Any

# garminconnect is imported lazily inside functions so tests that only exercise
# the token store don't need the heavy auth stack installed.


class MfaRequired(Exception):
    """Raised when Garmin needs a 2FA code; carries the live client to resume on.

    `client_state` is the in-progress `Garmin` instance (name kept for the
    enrollment route). It MUST be reused for resume_login — the MFA state lives
    on it, not in a serializable blob.
    """

    def __init__(self, client_state: Any) -> None:
        super().__init__("Garmin requires a 2FA/MFA code.")
        self.client_state = client_state


def begin_login(email: str, password: str) -> str:
    """Attempt login. Returns a token blob on success, or raises MfaRequired."""
    from garminconnect import Garmin

    g = Garmin(email, password, return_on_mfa=True)
    status, _ = g.login()
    if status == "needs_mfa":
        raise MfaRequired(g)
    return _capture(g)


def resume_login(client_state: Any, mfa_code: str) -> str:
    """Complete MFA on the same client instance and return the token blob."""
    client_state.resume_login(None, mfa_code)
    return _capture(client_state)


def _capture(g: Any) -> str:
    """Serialize the authenticated session to an opaque token string (>512 chars)."""
    return g.client.dumps()


def make_client(token_blob: str) -> Any:
    """Restore an authenticated python-garminconnect client from a stored blob.

    login() loads the token string directly (len>512 → treated as token data,
    not a path) and refreshes the OAuth2 token lazily — no password needed.
    """
    from garminconnect import Garmin

    g = Garmin()
    g.login(tokenstore=token_blob)
    return g


def is_rate_limit_error(exc: Exception) -> bool:
    text = f"{type(exc).__name__}: {exc}".lower()
    return "429" in text or "too many requests" in text or "rate limit" in text
