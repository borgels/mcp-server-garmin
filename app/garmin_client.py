"""Garmin login + data access, built on python-garminconnect / garth.

IMPORTANT (unofficial API): login is the ONLY rate-limit-dangerous operation and
Garmin blocks per-account (24-48h) on repeated logins. So we log in ONCE per
user, persist the resulting OAuth token blob (never the password), and ride it.
python-garminconnect handles lazy OAuth2 refresh from the ~1yr OAuth1 token.
"""
from __future__ import annotations

import base64
import io
import tempfile
from pathlib import Path
from typing import Any

# Imported lazily inside functions so tests that only exercise the store don't
# require the heavy garminconnect/garth stack.


def _dump_token_dir(dir_path: str) -> str:
    """Serialize garth's token dir (oauth1 + oauth2 json) into one base64 blob."""
    import json

    files = {}
    for name in ("oauth1_token.json", "oauth2_token.json"):
        p = Path(dir_path) / name
        if p.exists():
            files[name] = p.read_text()
    return base64.b64encode(json.dumps(files).encode()).decode()


def _restore_token_dir(blob: str) -> str:
    import json

    files = json.loads(base64.b64decode(blob).decode())
    d = tempfile.mkdtemp(prefix="garth-")
    for name, content in files.items():
        (Path(d) / name).write_text(content)
    return d


class MfaRequired(Exception):
    """Raised when Garmin needs a 2FA code; carries a resumable client state."""

    def __init__(self, client_state: Any) -> None:
        super().__init__("Garmin requires a 2FA/MFA code.")
        self.client_state = client_state


def begin_login(email: str, password: str) -> str:
    """Attempt login. Returns a token blob on success, or raises MfaRequired."""
    import garth

    result1, result2 = garth.login(email, password, return_on_mfa=True)
    if result1 == "needs_mfa":
        raise MfaRequired(result2)
    return _capture(garth)


def resume_login(client_state: Any, mfa_code: str) -> str:
    import garth

    garth.resume_login(client_state, mfa_code)
    return _capture(garth)


def _capture(garth_mod: Any) -> str:
    d = tempfile.mkdtemp(prefix="garth-out-")
    garth_mod.save(d)
    return _dump_token_dir(d)


def make_client(token_blob: str) -> Any:
    """Restore an authenticated python-garminconnect client from a stored blob."""
    from garminconnect import Garmin

    d = _restore_token_dir(token_blob)
    g = Garmin()
    g.login(d)  # resumes from token dir; refreshes OAuth2 lazily, no password
    return g


def is_rate_limit_error(exc: Exception) -> bool:
    text = f"{type(exc).__name__}: {exc}".lower()
    return "429" in text or "too many requests" in text or "rate limit" in text
