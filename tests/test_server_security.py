"""Security regression tests for the HTTP surface (auth on /mcp, enrollment page)."""
import os
import tempfile

import pytest

os.environ.setdefault("GARMIN_ENCRYPTION_KEY", "test-encryption-key-1234567890")
os.environ.setdefault("GARMIN_STORE_PATH", os.path.join(tempfile.mkdtemp(), "store.json"))

from starlette.applications import Starlette  # noqa: E402
from starlette.responses import PlainTextResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from app import garmin_client as gc  # noqa: E402
from app import server  # noqa: E402


# --- /mcp bearer --------------------------------------------------------------

def test_refuses_to_start_when_trusting_forwarded_user_without_token():
    with pytest.raises(SystemExit) as exc:
        server.check_startup_config({"GARMIN_TRUST_FORWARDED_USER": "true", "MCP_HTTP_TOKEN": ""})
    assert "MCP_HTTP_TOKEN" in str(exc.value)
    with pytest.raises(SystemExit):
        server.check_startup_config({"GARMIN_TRUST_FORWARDED_USER": "true", "MCP_HTTP_TOKEN": "   "})


TOKEN = "a" * 64


def test_starts_with_token_or_without_trust():
    server.check_startup_config({"GARMIN_TRUST_FORWARDED_USER": "true", "MCP_HTTP_TOKEN": TOKEN})
    server.check_startup_config({"MCP_HTTP_HOST": "127.0.0.1"})
    settings = server.check_startup_config({"MCP_HTTP_TOKEN": f" {TOKEN}\n", "PORT": "8080"})
    assert settings["host"] == "0.0.0.0" and settings["port"] == 8080


def test_refuses_non_loopback_bind_without_token_unless_explicitly_allowed():
    with pytest.raises(SystemExit) as exc:
        server.check_startup_config({})
    assert "MCP_HTTP_TOKEN" in str(exc.value)
    with pytest.raises(SystemExit):
        server.check_startup_config({"MCP_HTTP_HOST": "10.0.0.5"})
    server.check_startup_config({"MCP_HTTP_ALLOW_UNAUTHENTICATED": "true"})
    for host in ("127.0.0.1", "localhost", "::1", "[::1]"):
        server.check_startup_config({"MCP_HTTP_HOST": host})
    # The escape hatch never allows a trusted X-MCP-User without a token.
    with pytest.raises(SystemExit):
        server.check_startup_config({"MCP_HTTP_ALLOW_UNAUTHENTICATED": "true", "GARMIN_TRUST_FORWARDED_USER": "true"})


def test_rejects_weak_tokens_and_invalid_numbers():
    with pytest.raises(SystemExit, match="at least 32"):
        server.check_startup_config({"MCP_HTTP_TOKEN": "s3cret-token"})
    with pytest.raises(SystemExit, match="printable ASCII"):
        server.check_startup_config({"MCP_HTTP_TOKEN": TOKEN + " x"})
    for name, value in (("PORT", "abc"), ("PORT", "0"), ("PORT", "70000"), ("MCP_AUTH_FAILURE_LIMIT", "-1"),
                        ("MCP_AUTH_FAILURE_WINDOW_MS", "1m"), ("MCP_HTTP_ALLOW_UNAUTHENTICATED", "maybe")):
        with pytest.raises(SystemExit, match=name):
            server.check_startup_config({"MCP_HTTP_TOKEN": TOKEN, name: value})


def test_version_matches_pyproject():
    import pathlib
    import tomllib

    from app import __version__

    pyproject = tomllib.loads((pathlib.Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
    assert __version__ == pyproject["project"]["version"]


def test_bearer_compare():
    assert server._bearer_ok(b"Bearer s3cret", "s3cret")
    assert not server._bearer_ok(b"Bearer s3cre", "s3cret")
    assert not server._bearer_ok(b"", "s3cret")
    assert not server._bearer_ok(b"s3cret", "s3cret")


def _wrapped_client(**limits):
    async def ok(request):
        return PlainTextResponse("inner")

    inner = Starlette(routes=[Route("/mcp", ok, methods=["GET", "POST"]), Route("/healthz", ok)])
    return TestClient(server._InternalAuth(inner, **limits))


def test_mcp_requires_bearer_when_token_set(monkeypatch):
    monkeypatch.setenv("MCP_HTTP_TOKEN", "s3cret")
    monkeypatch.setenv("GARMIN_TRUST_FORWARDED_USER", "true")
    c = _wrapped_client()
    assert c.get("/mcp", headers={"x-mcp-user": "victim@example.com"}).status_code == 401
    wrong = c.get("/mcp", headers={"authorization": "Bearer wrong"})
    assert wrong.status_code == 401
    assert wrong.headers["www-authenticate"] == "Bearer"
    assert c.get("/mcp", headers={"authorization": "Bearer s3cret"}).status_code == 200
    assert c.get("/healthz").status_code == 200


def test_mcp_fails_closed_when_trusting_forwarded_user_without_token(monkeypatch):
    monkeypatch.delenv("MCP_HTTP_TOKEN", raising=False)
    monkeypatch.setenv("GARMIN_TRUST_FORWARDED_USER", "true")
    c = _wrapped_client()
    assert c.get("/mcp", headers={"x-mcp-user": "victim@example.com"}).status_code == 401


def test_failed_auth_is_throttled_but_valid_token_is_not(monkeypatch):
    monkeypatch.setenv("MCP_HTTP_TOKEN", TOKEN)
    c = _wrapped_client(auth_failure_limit=3)
    bad = {"authorization": "Bearer nope"}
    good = {"authorization": f"Bearer {TOKEN}"}
    for _ in range(3):
        assert c.get("/mcp", headers=bad).status_code == 401
    blocked = c.get("/mcp", headers=bad)
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) > 0
    assert c.get("/mcp", headers=good).status_code == 200
    assert c.get("/healthz").status_code == 200


def test_auth_failure_limit_zero_disables_throttling(monkeypatch):
    monkeypatch.setenv("MCP_HTTP_TOKEN", TOKEN)
    c = _wrapped_client(auth_failure_limit=0)
    for _ in range(30):
        assert c.get("/mcp", headers={"authorization": "Bearer nope"}).status_code == 401


def test_limiter_memory_is_bounded_and_window_expires():
    limiter = server._AuthFailureLimiter(2, 60, max_entries=100)
    for i in range(1000):
        limiter.record_failure(f"k{i}", now=0)
    assert len(limiter._entries) <= 100
    limiter.record_failure("a", now=0)
    limiter.record_failure("a", now=0)
    assert limiter.retry_after("a", now=1) == 59
    assert limiter.retry_after("a", now=61) == 0


# --- enrollment page ----------------------------------------------------------

@pytest.fixture
def enroll_client():
    return TestClient(server.mcp.http_app(path="/mcp"), base_url="https://testserver")


def test_enroll_shows_identity_and_requires_confirmation(enroll_client, monkeypatch):
    calls = []
    monkeypatch.setattr(gc, "begin_login", lambda e, p: calls.append(e) or "BLOB")
    state = server.store.create_state("<b>owner</b>@example.com")

    page = enroll_client.get(f"/garmin/enroll?state={state}").text
    assert "You are linking this Garmin account to" in page
    assert "&lt;b&gt;owner&lt;/b&gt;@example.com" in page  # escaped
    assert "<b>owner</b>" not in page
    assert "name=confirm_identity" in page
    assert "name=password" not in page  # no credential form before confirmation

    # Credentials posted without confirming are refused.
    r = enroll_client.post("/garmin/enroll", data={"state": state, "email": "a@b.c", "password": "pw"})
    assert r.status_code == 400
    assert calls == []
    assert server.store.get_record("<b>owner</b>@example.com") is None

    # Confirm step without the checkbox is refused.
    r = enroll_client.post("/garmin/enroll", data={"state": state, "step": "confirm"})
    assert r.status_code == 400
    assert not server.store.state_confirmed(state, "anything")

    # Confirming in another client (no shared cookie) does not unlock credentials here.
    other = TestClient(server.mcp.http_app(path="/mcp"), base_url="https://testserver")
    r = other.post("/garmin/enroll", data={"state": state, "step": "confirm", "confirm_identity": "yes"})
    assert r.status_code == 200 and "name=password" in r.text
    enroll_client.cookies.clear()
    r = enroll_client.post("/garmin/enroll", data={"state": state, "email": "a@b.c", "password": "pw"})
    assert r.status_code == 400 and calls == []

    r = enroll_client.post("/garmin/enroll", data={"state": state, "step": "confirm", "confirm_identity": "yes"})
    assert r.status_code == 200 and "name=password" in r.text
    set_cookie = r.headers["set-cookie"]
    assert "garmin_enroll=" in set_cookie and "HttpOnly" in set_cookie and "Secure" in set_cookie
    assert r.headers["x-frame-options"] == "DENY"

    r = enroll_client.post("/garmin/enroll", data={"state": state, "email": "a@b.c", "password": "pw"})
    assert r.status_code == 200 and calls == ["a@b.c"]
    assert server.store.get_record("<b>owner</b>@example.com")["blob"] == "BLOB"
    assert server.store.peek_state(state) is None  # single use


def test_enroll_error_message_is_escaped(enroll_client, monkeypatch):
    def boom(e, p):
        raise RuntimeError("<script>alert(1)</script>")

    monkeypatch.setattr(gc, "begin_login", boom)
    state = server.store.create_state("u@example.com")
    r = enroll_client.post("/garmin/enroll", data={"state": state, "step": "confirm", "confirm_identity": "yes"})
    assert r.status_code == 200
    r = enroll_client.post("/garmin/enroll", data={"state": state, "email": "a@b.c", "password": "pw"})
    assert r.status_code == 400
    assert "<script>" not in r.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text


def test_mfa_pending_expires(monkeypatch):
    server._mfa_pending.clear()
    now = [1000.0]
    monkeypatch.setattr(server.time, "monotonic", lambda: now[0])
    server._mfa_put("s1", "CLIENT-STATE")
    now[0] += server.MFA_PENDING_TTL_S - 1
    server._mfa_put("s2", "OTHER")
    assert server._mfa_pop("s2") == "OTHER"
    now[0] += 2  # s1 is now past its TTL
    assert server._mfa_pop("s1") is None
    server._mfa_put("s3", "X")
    now[0] += server.MFA_PENDING_TTL_S + 1
    server._mfa_put("s4", "Y")  # any access garbage-collects stale entries
    assert "s3" not in server._mfa_pending
