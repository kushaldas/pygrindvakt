"""Error model: machine ``code``, ``upstream_*`` attributes, ``__cause__`` chaining."""

from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pygrindvakt
import pytest
from pygrindvakt import (
    AuthnError,
    GrindvaktError,
    InternalError,
    OAuthError,
    federation,
    metadata,
    request,
    rp,
)
from pygrindvakt.http import ReqwestClient

EXPECTED_CLASS_CODES = {
    "GrindvaktError": "internal",
    "BadRequestError": "bad_request",
    "AuthnError": "authn",
    "StateError": "state",
    "ConfigError": "config",
    "CryptoError": "crypto",
    "AttributeMappingError": "attribute",
    "JoseError": "jose",
    "UnknownKeyError": "unknown_kid",
    "JsonError": "json",
    "InternalError": "internal",
    "NoBoundEndpointError": "no_bound_endpoint",
    "UnknownModuleError": "unknown_module",
    "DpopError": "dpop",
    "DpopInvalidError": "invalid_dpop_proof",
    "DpopReplayError": "dpop_replay",
    "DpopNonceRequiredError": "use_dpop_nonce",
    "DpopServerError": "dpop_server",
}

UPSTREAM_ATTRS = (
    "upstream_status",
    "upstream_error",
    "upstream_error_description",
    "upstream_body",
)

PROV = rp.ProviderInfo("http://127.0.0.1:1", "http://127.0.0.1:1/a", "http://127.0.0.1:1/token")
RPC = rp.RpClient("demo", "https://rp.example.com/cb", client_secret="s")
VERIFIER = "v" * 48


@pytest.mark.parametrize("name,code", sorted(EXPECTED_CLASS_CODES.items()))
def test_class_level_code(name, code):
    cls = getattr(pygrindvakt, name)
    assert cls.code == code
    inst = cls("boom")
    assert inst.code == code
    assert str(inst) == "boom"
    for attr in UPSTREAM_ATTRS:
        assert getattr(inst, attr) is None


def test_oauth_error_code_is_instance_level():
    e = OAuthError("invalid_grant", "nope")
    assert e.code == "invalid_grant"
    assert e.upstream_status is None


def test_instance_code_override_does_not_leak_to_class():
    e = InternalError("x")
    e.code = "transport"
    assert InternalError("y").code == "internal"
    assert InternalError.code == "internal"


# --- upstream errors -------------------------------------------------------------


class FakeTokenClient:
    def __init__(self, status, body, ctype="application/json"):
        self.reply = (status, body, ctype)

    def get(self, url):
        return self.reply

    def post_form(self, url, form, headers):
        return self.reply


def test_exchange_code_400_exposes_upstream_details():
    body = b'{"error":"invalid_grant","error_description":"code expired for s3cret"}'
    with pytest.raises(AuthnError) as ei:
        rp.exchange_code(FakeTokenClient(400, body), PROV, RPC, "code", VERIFIER)
    e = ei.value
    assert str(e) == "authentication error: token endpoint returned 400"
    assert "s3cret" not in str(e)
    assert e.code == "invalid_grant"
    assert e.upstream_status == 400
    assert e.upstream_error == "invalid_grant"
    assert e.upstream_error_description == "code expired for s3cret"
    assert e.upstream_body is not None and "invalid_grant" in e.upstream_body


def test_upstream_body_is_escaped():
    body = b"bad \x1b[31mred\x1b[0m\nline2\rline3"
    with pytest.raises(AuthnError) as ei:
        rp.exchange_code(FakeTokenClient(400, body, "text/plain"), PROV, RPC, "code", VERIFIER)
    e = ei.value
    assert e.upstream_status == 400
    assert e.upstream_body is not None
    assert "\x1b" not in e.upstream_body
    assert "\n" not in e.upstream_body
    assert "\r" not in e.upstream_body
    assert "\x1b" not in str(e)
    # No OAuth error code in the body: the class default applies.
    assert e.upstream_error is None
    assert e.code == "authn"


def test_non_auth_upstream_error_code_is_always_upstream_http():
    body = b'{"error":"invalid_client","error_description":"d"}'
    with pytest.raises(InternalError) as ei:
        rp.fetch_jwks(FakeTokenClient(500, body), "http://127.0.0.1:1/jwks", "http://127.0.0.1:1")
    e = ei.value
    assert e.code == "upstream_http"
    assert e.upstream_error == "invalid_client"
    assert e.upstream_status == 500


def test_non_auth_upstream_failure_is_internal_with_attributes():
    with pytest.raises(InternalError) as ei:
        rp.fetch_jwks(
            FakeTokenClient(500, b"oops"),
            "http://127.0.0.1:1/jwks",
            "http://127.0.0.1:1",
        )
    e = ei.value
    assert e.upstream_status == 500
    assert e.code == "upstream_http"


# --- __cause__ chaining ----------------------------------------------------------


class RaisingClient:
    def __init__(self, exc):
        self.exc = exc

    def get(self, url):
        raise self.exc

    def post_form(self, url, form, headers):
        raise self.exc


def test_python_client_exception_is_chained(unraisable):
    boom = ValueError("boom")
    with pytest.raises(InternalError) as ei:
        rp.exchange_code(RaisingClient(boom), PROV, RPC, "code", VERIFIER)
    unraisable.expect(ValueError, "boom", count=1, adapter=RaisingClient)
    assert ei.value.__cause__ is boom
    assert ei.value.code == "transport"
    assert ei.value.upstream_status is None


def test_python_client_get_exception_is_chained(unraisable):
    boom = RuntimeError("get failed")
    with pytest.raises(InternalError) as ei:
        rp.discover(RaisingClient(boom), "http://127.0.0.1:1")
    unraisable.expect(RuntimeError, "get failed", count=1, adapter=RaisingClient)
    assert ei.value.__cause__ is boom
    assert ei.value.code == "transport"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_reqwest_connect_failure_chains_connection_error():
    port = free_port()  # closed again: nothing listens
    client = ReqwestClient(connect_timeout=2, read_timeout=2, request_timeout=5)
    with pytest.raises(InternalError) as ei:
        client.get(f"http://127.0.0.1:{port}/")
    assert isinstance(ei.value.__cause__, ConnectionError)
    assert ei.value.code == "transport"
    with pytest.raises(InternalError) as ei:
        client.post_form(f"http://127.0.0.1:{port}/", [("a", "b")])
    assert isinstance(ei.value.__cause__, ConnectionError)


def test_reqwest_connect_failure_through_rp_function():
    port = free_port()
    client = ReqwestClient(connect_timeout=2, read_timeout=2, request_timeout=5)
    with pytest.raises(InternalError) as ei:
        rp.discover(client, f"http://127.0.0.1:{port}")
    assert isinstance(ei.value.__cause__, ConnectionError)
    assert ei.value.code == "transport"


class _Handler(BaseHTTPRequestHandler):
    # Paths where the client is expected to hang up early: /slow (client times
    # out while we sleep) and /big (client aborts the body at its size cap).
    # A disconnect anywhere else is a real error and must stay visible.
    _CLIENT_ABORTS = frozenset({"/slow", "/big"})

    def do_GET(self):
        try:
            self._respond()
        except (BrokenPipeError, ConnectionResetError):
            if self.path not in self._CLIENT_ABORTS:
                raise

    def _respond(self):
        if self.path == "/slow":
            time.sleep(3)
        elif self.path == "/big":
            data = b"x" * 5000
            self.send_response(200)
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(200)
        self.send_header("content-length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def test_reqwest_timeout_chains_timeout_error(server):
    client = ReqwestClient(connect_timeout=1, read_timeout=1, request_timeout=1)
    with pytest.raises(InternalError) as ei:
        client.get(f"{server}/slow")
    assert isinstance(ei.value.__cause__, TimeoutError)
    assert ei.value.code == "transport"


def test_reqwest_response_too_large(server):
    client = ReqwestClient(max_response_bytes=100)
    with pytest.raises(InternalError) as ei:
        client.get(f"{server}/big")
    assert ei.value.code == "response_too_large"
    assert ei.value.__cause__ is None


def test_success_after_failure_has_no_stale_cause(server):
    client = ReqwestClient(connect_timeout=1, read_timeout=1, request_timeout=1)
    with pytest.raises(InternalError):
        client.get(f"http://127.0.0.1:{free_port()}/")
    status, body, _ = client.get(f"{server}/")
    assert (status, body) == (200, b"ok")


def test_plain_internal_error_without_transport_failure_has_no_cause():
    # A bad return shape from the adapter is still a transport-level failure
    # raised by the adapter; but a plain Internal error elsewhere is not.
    with pytest.raises(GrindvaktError) as ei:
        rp.ProviderInfo("not a url", "x", "y")
    assert ei.value.__cause__ is None


def test_no_cross_call_leakage_between_threads(server):
    closed = free_port()
    results: dict[int, BaseException | None] = {}

    def fail(i):
        c = ReqwestClient(connect_timeout=2, read_timeout=2, request_timeout=5)
        try:
            c.get(f"http://127.0.0.1:{closed}/")
        except InternalError as e:
            results[i] = e

    def succeed(i):
        # Shares the process-wide default client; must never see another
        # thread's failure.
        try:
            for _ in range(5):
                rp.fetch_jwks(None, f"{server}/", server)
        except GrindvaktError as e:
            results[i] = e

    ths = [threading.Thread(target=fail, args=(i,)) for i in range(4)]
    ths += [threading.Thread(target=succeed, args=(10 + i,)) for i in range(4)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    for i in range(4):
        assert isinstance(results[i].__cause__, ConnectionError)
    for i in range(10, 14):
        # fetch_jwks of "ok" fails at JWKS parsing, never with a transport cause.
        assert results[i].__cause__ is None
        assert results[i].code != "transport"


def test_nested_calls_keep_their_own_causes(unraisable):
    inner_boom = KeyError("inner")
    outer_boom = ValueError("outer")

    class Outer:
        def get(self, url):
            # A nested pygrindvakt call with its own failing client.
            with pytest.raises(InternalError) as ei:
                rp.discover(RaisingClient(inner_boom), "http://127.0.0.1:1")
            assert ei.value.__cause__ is inner_boom
            raise outer_boom

        def post_form(self, url, form, headers):
            raise outer_boom

    with pytest.raises(InternalError) as ei:
        rp.discover(Outer(), "http://127.0.0.1:1")
    assert ei.value.__cause__ is outer_boom
    assert sorted(type(r.exc_value).__name__ for r in unraisable) == ["KeyError", "ValueError"]


def test_tolerated_earlier_failure_is_not_blamed_for_a_later_error(unraisable):
    """A failed fetch in a multi-fetch flow must only be attributed to the error
    that fetch produced. Trust-anchor resolution tolerates per-anchor failures
    and raises the last error; one anchor's client raises, the other answers
    500, so whichever error is raised must be self-consistent. (A stale-slot
    ``Internal`` error unrelated to a fetch is not producible through the
    public API; the attribution check compares the emitted message.)"""
    boom = ValueError("first anchor down")

    class Mixed:
        def get(self, url):
            if "ta1" in url:
                raise boom
            return (500, b"nope", "text/plain")

        def post_form(self, url, form, headers):
            return (500, b"", None)

    anchors = {"https://ta1.example": {"keys": []}, "https://ta2.example": {"keys": []}}
    with pytest.raises(GrindvaktError) as ei:
        federation.resolve_via_trust_anchors(Mixed(), "https://sub.example", anchors)
    e = ei.value
    if e.code == "transport":
        assert e.__cause__ is boom
    else:
        assert e.__cause__ is None
        assert e.upstream_status == 500
    unraisable.expect(ValueError, "first anchor down", count=1, adapter=Mixed)


# --- error layout: BadRequestError is a ValueError ---------------------------------


def test_bad_request_mro():
    assert pygrindvakt.BadRequestError.__mro__[:4] == (
        pygrindvakt.BadRequestError,
        GrindvaktError,
        ValueError,
        Exception,
    )
    assert pygrindvakt.BadRequestError.__module__ == "pygrindvakt"
    assert pygrindvakt.BadRequestError.status_hint == 400


def test_value_error_catches_config_faults():
    with pytest.raises(ValueError) as ei:
        rp.RpClient("demo", "https://rp.example.com/cb", auth_method="x")
    assert isinstance(ei.value, pygrindvakt.ConfigError)
    assert isinstance(ei.value, GrindvaktError)
    assert ei.value.code == "config"

    with pytest.raises(ValueError) as ei2:
        rp.JwksCache(None, "https://x/jwks", "https://x").verify_id_token("t", "c", "n", ["NOPE"])
    assert isinstance(ei2.value, pygrindvakt.ConfigError)


def test_config_error_mro_and_defaults():
    cls = pygrindvakt.ConfigError
    assert cls.__mro__[:4] == (cls, GrindvaktError, ValueError, Exception)
    assert cls.__module__ == "pygrindvakt"
    assert cls.status_hint == 500
    assert cls.code == "config"
    e = cls("boom")
    assert e.auth_failure is False
    assert e.retryable is False
    assert e.log_summary == "ConfigError(code='config', status_hint=500): boom"


def _cfg_jwks_cache(**kw):
    return lambda: rp.JwksCache(None, "https://x/jwks", "https://x", **kw)


CONFIG_FAULTS = {
    "unknown auth_method": lambda: rp.RpClient("d", "https://rp.example.com/cb", auth_method="x"),
    "secret missing": lambda: rp.RpClient("d", "https://rp.example.com/cb", auth_method="client_secret_post"),
    "empty secret": lambda: rp.RpClient("d", "https://rp.example.com/cb", client_secret=""),
    "bad algorithm": lambda: rp.JwksCache(None, "https://x/jwks", "https://x").verify_id_token("t", "c", "n", ["NOPE"]),
    "negative ttl": _cfg_jwks_cache(default_ttl=-1),
    "min above max": _cfg_jwks_cache(min_ttl=10, max_ttl=5),
    "bad fetch_timeout": _cfg_jwks_cache(fetch_timeout=0.0),
    "metadata base": lambda: metadata.ProviderMetadata("https://op.example.com", "http://evil.example"),
}


@pytest.mark.parametrize("name", sorted(CONFIG_FAULTS))
def test_config_faults_are_config_error_not_bad_request(name):
    with pytest.raises(pygrindvakt.ConfigError) as ei:
        CONFIG_FAULTS[name]()
    e = ei.value
    assert isinstance(e, ValueError)
    assert isinstance(e, GrindvaktError)
    assert not isinstance(e, pygrindvakt.BadRequestError)
    assert e.status_hint == 500
    assert e.code == "config"


def test_negative_seconds_is_config_error():
    with pytest.raises(pygrindvakt.ConfigError):
        rp.JwksCache(None, "https://x/jwks", "https://x", default_ttl=-1)


def test_request_input_faults_stay_bad_request():
    client = rp.RpClient("demo", "https://rp.example.com/cb", client_secret="s")
    with pytest.raises(pygrindvakt.BadRequestError) as ei:
        rp.authorization_url(PROV, client, "s", "n", redirect_uri="https://evil.example/cb")
    assert not isinstance(ei.value, pygrindvakt.ConfigError)
    assert ei.value.status_hint == 400


def test_bad_request_clause_must_precede_value_error_and_grindvakt_error():
    """BadRequestError is a ValueError and a GrindvaktError: only the first matching clause runs."""
    client = rp.RpClient("demo", "https://rp.example.com/cb", client_secret="s")

    def classify(call):
        try:
            call()
        except pygrindvakt.BadRequestError:
            return "bad-request"
        except pygrindvakt.ConfigError:
            return "config"
        except GrindvaktError:
            return "grindvakt"
        except ValueError:
            return "value-error"
        return "no-error"

    bad_request = lambda: rp.authorization_url(PROV, client, "s", "n", redirect_uri="https://evil.example/cb")  # noqa: E731
    config_fault = lambda: rp.RpClient("c", "https://x/cb", auth_method="x")  # noqa: E731
    assert classify(bad_request) == "bad-request"
    # A config fault is not a BadRequestError, so it reaches its own clause.
    assert classify(config_fault) == "config"


def test_handler_separates_config_fault_from_login_failure():
    """``except ConfigError: raise`` first keeps a deployment fault out of the login-failed page."""

    def handler(call):
        try:
            return call()
        except pygrindvakt.ConfigError:
            raise
        except GrindvaktError:
            return "login-failed"

    # A real login failure: the token endpoint rejects the code.
    body = b'{"error":"invalid_grant"}'
    login = lambda: rp.exchange_code(FakeTokenClient(400, body), PROV, RPC, "code", VERIFIER)  # noqa: E731
    assert handler(login) == "login-failed"

    # A configuration fault propagates (to a 500 / alert), never to the user as a login error.
    with pytest.raises(pygrindvakt.ConfigError):
        handler(CONFIG_FAULTS["unknown auth_method"])


def test_bad_request_pickle_and_repr():
    import pickle

    e = pygrindvakt.BadRequestError("boom")
    e2 = pickle.loads(pickle.dumps(e))
    assert type(e2) is pygrindvakt.BadRequestError
    assert str(e2) == "boom"
    assert repr(e) == "BadRequestError('boom')"


# --- auth_failure / retryable / log_summary --------------------------------------


def test_defaults():
    assert GrindvaktError.auth_failure is False
    assert GrindvaktError.retryable is False
    assert AuthnError.auth_failure is True
    assert InternalError("x").auth_failure is False
    assert OAuthError("invalid_request").retryable is False


def test_token_endpoint_400_is_auth_failure_not_retryable():
    with pytest.raises(AuthnError) as ei:
        rp.exchange_code(FakeTokenClient(400, b"{}"), PROV, RPC, "code", VERIFIER)
    assert ei.value.auth_failure is True
    assert ei.value.retryable is False


@pytest.mark.parametrize("status", [500, 502, 503, 504, 429])
def test_token_endpoint_retryable_statuses(status):
    with pytest.raises(AuthnError) as ei:
        rp.exchange_code(FakeTokenClient(status, b"down", "text/plain"), PROV, RPC, "code", VERIFIER)
    assert ei.value.retryable is True


@pytest.mark.parametrize("status", [400, 401, 404])
def test_token_endpoint_non_retryable_statuses(status):
    with pytest.raises(AuthnError) as ei:
        rp.exchange_code(FakeTokenClient(status, b"no", "text/plain"), PROV, RPC, "code", VERIFIER)
    assert ei.value.retryable is False


def test_token_endpoint_200_oauth_error_body_not_retryable():
    body = b'{"error":"temporarily_unavailable"}'
    with pytest.raises(AuthnError) as ei:
        rp.exchange_code(FakeTokenClient(200, body), PROV, RPC, "code", VERIFIER)
    assert ei.value.retryable is False


def test_upstream_error_code_cannot_spoof_retryable():
    body = b'{"error":"transport"}'
    with pytest.raises(AuthnError) as ei:
        rp.exchange_code(FakeTokenClient(400, body), PROV, RPC, "code", VERIFIER)
    assert ei.value.retryable is False


def test_jwks_500_is_not_auth_failure_and_retryable():
    with pytest.raises(InternalError) as ei:
        rp.fetch_jwks(FakeTokenClient(500, b"oops"), "http://127.0.0.1:1/jwks", "http://127.0.0.1:1")
    assert ei.value.auth_failure is False
    assert ei.value.retryable is True


def test_jwks_404_is_not_retryable():
    with pytest.raises(InternalError) as ei:
        rp.fetch_jwks(FakeTokenClient(404, b"no"), "http://127.0.0.1:1/jwks", "http://127.0.0.1:1")
    assert ei.value.auth_failure is False
    assert ei.value.retryable is False


def test_transport_is_retryable(unraisable):
    with pytest.raises(InternalError) as ei:
        rp.fetch_jwks(RaisingClient(OSError("down")), "http://127.0.0.1:1/jwks", "http://127.0.0.1:1")
    assert ei.value.code == "transport"
    assert ei.value.retryable is True
    unraisable.expect(OSError, "down", count=1, adapter=RaisingClient)


def test_transport_error_is_typed_with_chained_cause(unraisable):
    cause = OSError("down")
    with pytest.raises(InternalError) as ei:
        rp.exchange_code(RaisingClient(cause), PROV, RPC, "code", VERIFIER)
    assert type(ei.value) is InternalError
    assert ei.value.code == "transport"
    assert ei.value.auth_failure is False
    assert ei.value.__cause__ is not None
    assert not getattr(ei.value, "__notes__", None)
    unraisable.expect(OSError, "down", count=1, adapter=RaisingClient)


@pytest.mark.parametrize("spoof", ["transport", "jwks_fetch_timeout", "discovery_backoff", "discovery_fetch_timeout"])
def test_upstream_error_string_cannot_spoof_retryable(spoof):
    body = f'{{"error":"{spoof}"}}'.encode()
    for status in (400, 401):
        with pytest.raises(AuthnError) as ei:
            rp.exchange_code(FakeTokenClient(status, body), PROV, RPC, "code", VERIFIER)
        assert ei.value.auth_failure is True
        assert ei.value.code == spoof
        assert ei.value.retryable is False


@pytest.mark.parametrize("spoof", ["transport", "jwks_fetch_timeout", "discovery_backoff", "discovery_fetch_timeout"])
def test_upstream_error_string_with_5xx_is_retryable_by_status(spoof):
    body = f'{{"error":"{spoof}"}}'.encode()
    with pytest.raises(AuthnError) as ei:
        rp.exchange_code(FakeTokenClient(503, body), PROV, RPC, "code", VERIFIER)
    assert ei.value.code == spoof
    assert ei.value.retryable is True


def test_binding_raised_transport_in_exchange_code_is_retryable(unraisable):
    with pytest.raises(InternalError) as ei:
        rp.exchange_code(RaisingClient(OSError("down")), PROV, RPC, "code", VERIFIER)
    assert ei.value.code == "transport"
    assert ei.value.retryable is True
    unraisable.expect(OSError, "down", count=1, adapter=RaisingClient)


def test_userinfo_upstream_error_string_cannot_spoof_retryable():
    body = b'{"error":"transport"}'
    with pytest.raises(AuthnError) as ei:
        rp.fetch_userinfo(FakeTokenClient(401, body), "http://127.0.0.1:1/ui", "tok", "sub", "http://127.0.0.1:1")
    assert ei.value.auth_failure is True
    assert ei.value.code == "transport"
    assert ei.value.retryable is False


def _login_failed_status(e: GrindvaktError) -> int:
    """Mirror of the status mapping in examples/flask-rp/app.py and the RP guide."""
    if e.retryable:
        return 503
    return 401 if e.auth_failure else 400


def test_login_failed_status_mapping():
    with pytest.raises(GrindvaktError) as ei:
        rp.exchange_code(FakeTokenClient(503, b"down", "text/plain"), PROV, RPC, "code", VERIFIER)
    assert _login_failed_status(ei.value) == 503

    body = b'{"error":"invalid_grant","error_description":"expired"}'
    with pytest.raises(GrindvaktError) as ei:
        rp.exchange_code(FakeTokenClient(400, body), PROV, RPC, "code", VERIFIER)
    assert ei.value.auth_failure is True
    assert _login_failed_status(ei.value) == 401

    with pytest.raises(GrindvaktError) as ei:
        rp.fetch_jwks(FakeTokenClient(404, b"no"), "http://127.0.0.1:1/jwks", "http://127.0.0.1:1")
    assert not ei.value.auth_failure and not ei.value.retryable
    assert _login_failed_status(ei.value) == 400


def test_log_summary_format_and_excludes_body():
    body = b'{"error":"invalid_grant","error_description":"code expired for s3cret"}'
    with pytest.raises(AuthnError) as ei:
        rp.exchange_code(FakeTokenClient(400, body), PROV, RPC, "code", VERIFIER)
    e = ei.value
    summary = e.log_summary
    assert summary == (
        "AuthnError(code='invalid_grant', status_hint=401): authentication error: token endpoint returned 400"
    )
    assert "s3cret" not in summary
    assert e.upstream_body is not None and e.upstream_body not in summary


def test_log_summary_plain_exception():
    assert InternalError("x").log_summary == "InternalError(code='internal', status_hint=500): x"
    assert pygrindvakt.BadRequestError("y").log_summary == "BadRequestError(code='bad_request', status_hint=400): y"


def test_log_summary_escapes_and_caps_message():
    e = InternalError("line1\nline2\r\x1b[31m " + "x" * 1000)
    summary = e.log_summary
    assert "\n" not in summary and "\r" not in summary and "\x1b" not in summary
    assert "line1\\nline2\\r\\u{001b}" in summary
    assert summary.endswith("...")
    prefix = "InternalError(code='internal', status_hint=500): "
    assert len(summary) - len(prefix) <= 512


# Mirrors grindvakt::error::is_invisible_format (inclusive ranges).
INVISIBLE_RANGES = [
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x0600, 0x0605),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200D),
    (0x200E, 0x200F),
    (0x2028, 0x2029),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2065, 0x2065),
    (0x2066, 0x2069),
    (0x206A, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
]


def _invisible_samples():
    for lo, hi in INVISIBLE_RANGES:
        yield from sorted({lo, hi, (lo + hi) // 2, min(lo + 1, hi), max(hi - 1, lo)})


@pytest.mark.parametrize("cp", list(_invisible_samples()), ids=lambda cp: f"U+{cp:04X}")
def test_log_summary_escapes_every_invisible_range(cp):
    summary = InternalError(f"a{chr(cp)}b").log_summary
    assert chr(cp) not in summary
    assert f"a\\u{{{cp:04x}}}b" in summary


def _tag_char_error() -> OAuthError:
    req = request.AuthorizationRequest.from_params(
        [
            ("client_id", "demo"),
            ("response_type", "code"),
            ("redirect_uri", "https://rp.example/cb"),
            ("scope", "openid"),
            ("response_mode", "\U000e0041smuggled\U000e0042"),
        ]
    )
    with pytest.raises(OAuthError) as exc:
        req.validate_response_mode()
    return exc.value


def test_log_summary_escapes_tag_chars_in_oauth_error_description():
    e = _tag_char_error()
    assert e.description is not None and "\U000e0041" in e.description
    assert "\U000e0041" not in e.log_summary
    assert "\U000e0042" not in e.log_summary
    # str(e) is already escaped, so log_summary escapes its backslashes again.
    assert "u{e0041}smuggled" in e.log_summary and "u{e0042}" in e.log_summary
    assert "\U000e0041" not in str(e)


def test_oauth_error_str_escapes_but_description_and_wire_unchanged():
    raw = "bad\n\x1b[31m\u202e\u200b\U000e0041 \\ end"
    e = OAuthError("invalid_request", raw)
    assert e.description == raw
    text = str(e)
    assert text == "invalid_request: bad\\n\\u{001b}[31m\\u{202e}\\u{200b}\\u{e0041} \\\\ end"
    resp = e.to_response()
    assert resp.status == 400
    assert resp.body == OAuthError("invalid_request", raw).to_response().body
    assert resp.body == pygrindvakt._native.oauth_error_response("invalid_request", raw, None).body
    assert "\x1b" not in resp.body.decode() and "\u202e" not in resp.body.decode()


def test_oauth_error_str_caps_description():
    text = str(OAuthError("invalid_request", "x" * 2000))
    assert text.endswith("...")
    assert len(text) - len("invalid_request: ") <= 512
    assert str(OAuthError("invalid_request")) == "invalid_request"


def test_log_summary_escapes_and_caps_code():
    e = InternalError("x")
    e.code = "a\nb" + "c" * 200
    summary = e.log_summary
    assert "\n" not in summary
    assert "code='a\\nb" in summary
    code_part = summary.split("code=", 1)[1].split(", status_hint", 1)[0]
    assert len(code_part) <= 64 + 2


@pytest.mark.parametrize("ch", ["'", "\\", "\n"])
def test_log_summary_code_bound_holds_for_escaped_characters(ch):
    e = InternalError("x")
    e.code = ch * 64
    code_part = e.log_summary.split("code=", 1)[1].split(", status_hint", 1)[0]
    # Surrounding quotes are not part of the 64-character bound.
    assert len(code_part) <= 64 + 2
    # Every quote inside the field is escaped, so none can close it early.
    inner = code_part[1:-1]
    assert "'" not in inner.replace("\\'", "").replace("\\\\", "")


def test_log_summary_robust_to_bad_code_and_hint():
    e = InternalError("x")
    e.code = 123
    assert e.log_summary == "InternalError(code=None, status_hint=500): x"
    del e.__dict__["code"]
    e.code = None
    e.status_hint = None
    assert e.log_summary == "InternalError(code=None, status_hint=None): x"
    e2 = InternalError("y")
    e2.status_hint = "nope"
    assert e2.log_summary == "InternalError(code='internal', status_hint=None): y"


def test_bad_request_instance_has_code_and_status_hint():
    e = pygrindvakt.BadRequestError()
    assert e.code == "bad_request"
    assert e.status_hint == 400
    assert isinstance(e, ValueError)


@pytest.mark.parametrize(
    ("cls", "expected"),
    [
        (pygrindvakt.AuthnError, True),
        (pygrindvakt.UnknownKeyError, False),
        (pygrindvakt.DpopReplayError, False),
        (pygrindvakt.DpopInvalidError, False),
        (pygrindvakt.DpopNonceRequiredError, False),
        (pygrindvakt.DpopServerError, False),
        (pygrindvakt.BadRequestError, False),
        (pygrindvakt.ConfigError, False),
    ],
)
def test_auth_failure_class_layout(cls, expected):
    # Pins the documented layout: auth_failure is the core's narrow
    # "authentication step" flag, not a general "authentication failed" one.
    assert cls.auth_failure is expected


OAUTH_CODES = [
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "unsupported_response_type",
    "invalid_scope",
    "access_denied",
    "login_required",
    "server_error",
    "temporarily_unavailable",
    "invalid_dpop_proof",
]


@pytest.mark.parametrize("code", OAUTH_CODES)
def test_oauth_error_accepts_every_core_code(code):
    resp = OAuthError(code).to_response()
    assert resp.status in (400, 401, 500, 503)
    assert code.encode() in resp.body


@pytest.mark.parametrize("code", ["INVALID_REQUEST", "invalid_request ", "consent_required", ""])
def test_oauth_error_rejects_unknown_code(code):
    with pytest.raises(ValueError, match="unknown OAuth error code"):
        OAuthError(code).to_response()
