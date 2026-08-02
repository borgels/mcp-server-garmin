"""Per-user encrypted token store + one-time enrollment-state store (Garmin).

Each user's Garmin OAuth token blob is encrypted at rest (AES-256-GCM) with a
key derived from GARMIN_ENCRYPTION_KEY and keyed by the gateway-verified user
identity, so a user can only ever reach their own row. Passwords are NEVER
stored — only the resulting OAuth tokens. Persisted to a JSON file on a volume.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

STATE_TTL_S = 10 * 60


class TokenStore:
    def __init__(self, path: str | None = None, encryption_key: str | None = None) -> None:
        self.path = Path(path or os.environ.get("GARMIN_STORE_PATH", "/data/store.json"))
        secret = encryption_key or os.environ.get("GARMIN_ENCRYPTION_KEY", "")
        if len(secret) < 16:
            raise ValueError("Missing/weak GARMIN_ENCRYPTION_KEY (min 16 chars) — required to encrypt tokens at rest.")
        self._key = hashlib.sha256(secret.encode()).digest()
        self._tokens: dict[str, dict[str, str]] = {}
        self._states: dict[str, dict[str, Any]] = {}
        self._load()

    @staticmethod
    def user_key(identity: str) -> str:
        return identity.strip().lower()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text())
            self._tokens = raw.get("tokens", {})
            self._states = raw.get("states", {})
        except Exception:
            self._tokens, self._states = {}, {}

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(f".{secrets.token_hex(6)}.tmp")
        tmp.write_text(json.dumps({"tokens": self._tokens, "states": self._states}))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)  # atomic

    def _encrypt(self, plaintext: str) -> dict[str, str]:
        iv = secrets.token_bytes(12)
        ct = AESGCM(self._key).encrypt(iv, plaintext.encode(), None)
        return {"iv": base64.b64encode(iv).decode(), "data": base64.b64encode(ct).decode()}

    def _decrypt(self, enc: dict[str, str]) -> str:
        iv = base64.b64decode(enc["iv"])
        ct = base64.b64decode(enc["data"])
        return AESGCM(self._key).decrypt(iv, ct, None).decode()

    # --- tokens (the Garmin oauth blob, as an opaque string) ---

    def get_token_blob(self, user: str) -> str | None:
        enc = self._tokens.get(self.user_key(user))
        return self._decrypt(enc) if enc else None

    def set_token_blob(self, user: str, blob: str, meta: dict[str, Any] | None = None) -> None:
        payload = json.dumps({"blob": blob, "meta": meta or {}, "connected_at": int(time.time())})
        self._tokens[self.user_key(user)] = self._encrypt(payload)
        self._persist()

    def get_record(self, user: str) -> dict[str, Any] | None:
        raw = self.get_token_blob(user)
        return json.loads(raw) if raw else None

    def delete(self, user: str) -> bool:
        key = self.user_key(user)
        if key not in self._tokens:
            return False
        del self._tokens[key]
        self._persist()
        return True

    # --- rate-limit backoff bookkeeping (per-account 429) ---

    def set_rate_limited(self, user: str, until_epoch: int) -> None:
        rec = self.get_record(user) or {"blob": "", "meta": {}}
        rec["meta"]["rate_limited_until"] = until_epoch
        self._tokens[self.user_key(user)] = self._encrypt(json.dumps(rec))
        self._persist()

    def rate_limited_until(self, user: str) -> int:
        rec = self.get_record(user)
        return int(rec.get("meta", {}).get("rate_limited_until", 0)) if rec else 0

    # --- one-time enrollment state (binds the enroll form to a user) ---

    def create_state(self, user: str) -> str:
        self._gc_states()
        state = secrets.token_urlsafe(24)
        self._states[state] = {"user": self.user_key(user), "created_at": int(time.time())}
        self._persist()
        return state

    def peek_state(self, state: str) -> str | None:
        """Return the bound user without consuming (form GET shows the page)."""
        self._gc_states()
        entry = self._states.get(state)
        if not entry:
            return None
        if int(time.time()) - entry["created_at"] > STATE_TTL_S:
            return None
        return entry["user"]

    def consume_state(self, state: str) -> str | None:
        user = self.peek_state(state)
        if state in self._states:
            del self._states[state]
            self._persist()
        return user

    def _gc_states(self) -> None:
        now = int(time.time())
        stale = [s for s, e in self._states.items() if now - e["created_at"] > STATE_TTL_S]
        for s in stale:
            del self._states[s]
        if stale:
            self._persist()
