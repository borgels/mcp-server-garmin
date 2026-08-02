import json
import time

import pytest

from app.store import TokenStore


def make(tmp_path):
    return TokenStore(path=str(tmp_path / "store.json"), encryption_key="test-encryption-key-1234567890")


def test_encrypts_at_rest_and_roundtrips_case_insensitive(tmp_path):
    s = make(tmp_path)
    s.set_token_blob("ABO@borgels.com", "SECRET-BLOB-XYZ", {"foo": "bar"})
    rec = s.get_record("abo@borgels.com")
    assert rec["blob"] == "SECRET-BLOB-XYZ"
    raw = (tmp_path / "store.json").read_text()
    assert "SECRET-BLOB-XYZ" not in raw  # encrypted at rest
    assert "iv" in raw


def test_weak_key_rejected(tmp_path):
    with pytest.raises(ValueError):
        TokenStore(path=str(tmp_path / "s.json"), encryption_key="short")


def test_state_single_use_and_bound(tmp_path):
    s = make(tmp_path)
    st = s.create_state("me@x.dk")
    assert s.peek_state(st) == "me@x.dk"
    assert s.consume_state(st) == "me@x.dk"
    assert s.consume_state(st) is None  # consumed
    assert s.consume_state("bogus") is None


def test_persists_across_instances(tmp_path):
    make(tmp_path).set_token_blob("u@x.dk", "BLOB")
    assert make(tmp_path).get_record("u@x.dk")["blob"] == "BLOB"


def test_rate_limit_bookkeeping(tmp_path):
    s = make(tmp_path)
    s.set_token_blob("u@x.dk", "B")
    s.set_rate_limited("u@x.dk", int(time.time()) + 100)
    assert s.rate_limited_until("u@x.dk") > time.time()


def test_delete(tmp_path):
    s = make(tmp_path)
    s.set_token_blob("u@x.dk", "B")
    assert s.delete("u@x.dk") is True
    assert s.get_record("u@x.dk") is None
    assert s.delete("u@x.dk") is False
