"""Framework-agnostic request/response types and the built-in HTTP client."""

import os
import signal
import sys
import time

import pytest
from exotic_cases import (
    ACCEPT_CASES,
    BAD_FLOATS,
    BIG_INT_CASES,
    CYCLIC_BUILDERS,
    REJECT_CASES,
    RESERVED_KEY_CASES,
    TOKEN_LOOP_BUILDERS,
    nested,
    wrap_in_lists,
)
from pygrindvakt import BadRequestError, http


def test_request_data_normalization():
    """Path loses its leading slash, method is upper-cased, header names lower-cased."""
    r = http.HttpRequestData(
        path="/OIDC/token",
        method="post",
        uri="https://op/OIDC/token?x=1",
        query={"x": "1"},
        form={"grant_type": "code"},
        body=b"grant_type=code",
        headers={"Authorization": "Bearer t", "Content-Type": "x"},
        cookies={"s": "v"},
    )
    assert r.path == "OIDC/token" and r.method == "POST"
    assert r.headers == {"authorization": "Bearer t", "content-type": "x"}
    assert r.authorization() == "Bearer t" and r.bearer_token() == "t"
    assert r.param("x") == "1" and r.param("grant_type") == "code" and r.param("nope") is None
    assert r.body == b"grant_type=code" and r.cookies == {"s": "v"}
    r.headers = {"X-A": "b"}
    assert r.headers == {"x-a": "b"} and r.bearer_token() is None
    assert "HttpRequestData" in repr(r)


def test_request_data_defaults():
    r = http.HttpRequestData()
    assert r.method == "GET" and r.query == {} and r.body == b""


def test_request_data_preserves_duplicate_parameter_pairs():
    """Adapters retain multiplicity until an OAuth parser can reject it."""
    r = http.HttpRequestData(
        query=[("client_id", "first"), ("client_id", "second")],
        form=[("grant_type", "authorization_code"), ("grant_type", "refresh_token")],
    )
    assert r.query_pairs == [("client_id", "first"), ("client_id", "second")]
    assert r.form_pairs == [
        ("grant_type", "authorization_code"),
        ("grant_type", "refresh_token"),
    ]


def test_response_builders():
    r = http.Response.redirect("https://x")
    assert r.status == 302 and r.header("Location") == "https://x"
    r = http.Response.json({"a": [1, 2]}, status=201)
    assert r.status == 201 and r.body == b'{"a":[1,2]}' and r.header("content-type") == "application/json"
    r = http.Response.html("<p>hi</p>")
    assert r.text() == "<p>hi</p>" and "text/html" in r.header("content-type")
    r = http.Response.text_response(404, "nope").with_header("x-a", "1").with_header("x-a", "2")
    assert r.status == 404 and [v for k, v in r.headers if k == "x-a"] == ["1", "2"]
    r2 = http.Response(200, [("a", "b")], b"body")
    r2.status = 500
    r2.body = b"x"
    assert r2.status == 500 and r2.body == b"x" and r2.headers == [("a", "b")]


def test_fetch_response():
    f = http.HttpFetchResponse(200, b'{"k": 1}', "application/json")
    assert f.json() == {"k": 1} and f.text() == '{"k": 1}' and f.status == 200


def test_reqwest_client_validation():
    with pytest.raises(ValueError):
        http.ReqwestClient(connect_timeout=0)
    with pytest.raises(ValueError):
        http.ReqwestClient(max_response_bytes=0)
    c = http.ReqwestClient(request_timeout=5)
    assert "request_timeout=5" in repr(c)


def test_reqwest_client_against_local_server():
    """The built-in client talks to a real local HTTP server, never follows
    redirects, and enforces the response-size cap."""
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/redir":
                self.send_response(302)
                self.send_header("Location", "/ok")
                self.end_headers()
                return
            if self.path == "/big":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"x" * 5000)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"echo:" + body + b"|" + self.headers.get("X-Test", "").encode())

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        c = __import__("pygrindvakt").http.ReqwestClient(max_response_bytes=1000)
        st, body, ct = c.get(f"{base}/ok")
        assert (st, body, ct) == (200, b'{"ok": true}', "application/json")
        st, body, ct = c.get(f"{base}/redir")
        assert st == 302  # not followed
        st, body, ct = c.post_form(f"{base}/p", [("a", "b c")], [("X-Test", "hdr")])
        assert body == b"echo:a=b+c|hdr"
        from pygrindvakt import InternalError

        with pytest.raises(InternalError, match="byte limit"):
            c.get(f"{base}/big")
    finally:
        _stop(srv)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="fork test is Linux-only")
@pytest.mark.filterwarnings("ignore:.*fork.*:DeprecationWarning")
def test_reqwest_client_usable_after_fork():
    """A client used (and its pool warmed) before ``fork`` keeps working in the
    child: the PID-keyed pool is rebuilt lazily and the runtime is per process.

    The fork is quiescent (no other thread is inside a pygrindvakt call). Fork
    while another thread holds an internal lock is documented as unsupported,
    so it is deliberately not tested."""
    import http.server as hs
    import threading

    class H(hs.BaseHTTPRequestHandler):
        # HTTP/1.1 + Content-Length => keep-alive, so the parent really leaves a
        # live pooled connection behind at fork time.
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "4")
            self.end_headers()
            self.wfile.write(b"pong")

    srv = hs.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_port}/"
    try:
        c = http.ReqwestClient()
        assert c.get(url)[:2] == (200, b"pong")  # warm the pool in the parent
        pid = os.fork()
        if pid == 0:  # child
            code = 1
            try:
                ok = c.get(url)[:2] == (200, b"pong")
                ok = ok and c.post_form(url, [("a", "b")])[0] in (200, 501)
                code = 0 if ok else 2
            finally:
                os._exit(code)
        # A stale lock or runtime in the child hangs forever: poll with a
        # deadline, then kill and reap so the test fails instead of the job.
        deadline = time.monotonic() + 30
        while True:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                break
            if time.monotonic() > deadline:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                pytest.fail("forked child hung (30 s)")
            time.sleep(0.05)
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, status
        assert c.get(url)[:2] == (200, b"pong")  # parent unaffected
    finally:
        _stop(srv)


def _recording_servers():
    """Two local servers on different ports. A redirects (status taken from the
    path, e.g. /307) to B; B records every request it receives."""
    import http.server as hs
    import threading

    received = []

    class B(hs.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _record(self):
            n = int(self.headers.get("Content-Length", 0))
            received.append((self.command, self.headers.get("Authorization"), self.rfile.read(n)))
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"b")

        do_GET = do_POST = _record

    b = hs.ThreadingHTTPServer(("127.0.0.1", 0), B)

    class A(hs.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _redirect(self):
            n = int(self.headers.get("Content-Length", 0))
            self.rfile.read(n)
            self.send_response(int(self.path.strip("/")))
            self.send_header("Location", f"http://127.0.0.1:{b.server_port}/steal")
            self.end_headers()

        do_GET = do_POST = _redirect

    a = hs.ThreadingHTTPServer(("127.0.0.1", 0), A)
    for s in (a, b):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    return a, b, received


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_credentials_never_forwarded_on_cross_origin_redirect(status):
    a, b, received = _recording_servers()
    try:
        c = http.ReqwestClient()
        base = f"http://127.0.0.1:{a.server_port}/{status}"
        st, _, _ = c.get(base, [("Authorization", "Bearer secret-token")])
        assert st == status
        st, _, _ = c.post_form(base, [("client_secret", "hunter2")], [("Authorization", "Basic abc")])
        assert st == status
        st, _, _ = c.get(base)
        assert st == status
        assert received == []  # B was never contacted
    finally:
        _stop(a)
        _stop(b)


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_post_json_never_follows_redirect(status):
    """Separate from the test above so post_json alone is what a redirect mutation fails."""
    a, b, received = _recording_servers()
    try:
        c = http.ReqwestClient()
        base = f"http://127.0.0.1:{a.server_port}/{status}"
        st, _, _ = c.post_json(base, {"token": "secret"}, [("Authorization", "Bearer secret-token")])
        assert st == status
        assert received == []
    finally:
        _stop(a)
        _stop(b)


def test_reqwest_get_sends_headers():
    import http.server as hs
    import threading

    seen = {}

    class H(hs.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            seen["auth"] = self.headers.get("Authorization")
            seen["x"] = self.headers.get_all("X-Multi")
            self.send_response(200)
            self.end_headers()

    srv = hs.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        c = http.ReqwestClient()
        url = f"http://127.0.0.1:{srv.server_port}/"
        assert (
            c.get(
                url,
                headers=[
                    ("Authorization", "Bearer t"),
                    ("X-Multi", "1"),
                    ("X-Multi", "2"),
                ],
            )[0]
            == 200
        )
        assert seen == {"auth": "Bearer t", "x": ["1", "2"]}
        assert c.get(url, None)[0] == 200 and seen["auth"] is None
    finally:
        _stop(srv)


@pytest.mark.parametrize(
    "headers",
    [
        [("bad name", "v")],
        [("", "v")],
        [("X-Ok", "line\nbreak")],
        [("X-Ok", "café\x00")],
    ],
)
def test_reqwest_get_invalid_header_is_bad_request(headers):
    from pygrindvakt import BadRequestError

    with pytest.raises(BadRequestError):
        http.ReqwestClient().get("http://127.0.0.1:9/", headers)


# --- supports_get_with_headers -----------------------------------------------------------


class _GetPost:
    def get(self, url):
        raise AssertionError("no request may be made")

    def post_form(self, url, form, headers):
        raise AssertionError("no request may be made")


class _GetHeaders(_GetPost):
    def get(self, url, headers=None):
        raise AssertionError("no request may be made")


class _GetKwargs(_GetPost):
    def get(self, url, **kwargs):
        raise AssertionError("no request may be made")


class _GetWithHeaders(_GetPost):
    def get_with_headers(self, url, headers):
        raise AssertionError("no request may be made")


class _PositionalOnly(_GetPost):
    def get(self, url, headers=None, /):
        raise AssertionError("no request may be made")


class _NoPost:
    def get(self, url, headers=None):
        raise AssertionError("no request may be made")


class _Exploding:
    @property
    def get(self):
        raise RuntimeError("boom")

    post_form = None


@pytest.mark.parametrize(
    ("client", "expected"),
    [
        (None, True),
        (http.ReqwestClient(), True),
        (_GetPost(), False),
        (_GetHeaders(), True),
        (_GetKwargs(), True),
        (_GetWithHeaders(), True),
        (_PositionalOnly(), False),
        (_NoPost(), False),
        (_Exploding(), False),
        (object(), False),
        ("https://example.com", False),
        (42, False),
        (print, False),
    ],
)
def test_supports_get_with_headers(client, expected):
    assert http.supports_get_with_headers(client) is expected


@pytest.mark.parametrize(
    "location",
    [
        "/a\rb",
        "/a\nb",
        "/a\tb",
        "/a b",
        "/a\x00b",
        "/a\u202eb",
        "/a\u200bb",
        "https://rp.example/cb\r\nSet-Cookie: x=1",
        "/x\\@evil.example",
        "https://evil.example\\@op.example.com/cb",
    ],
)
def test_response_redirect_rejects_unsafe_chars(location):
    with pytest.raises(BadRequestError):
        http.Response.redirect(location)


@pytest.mark.parametrize(
    "location", ["https://rp.example/cb\u202e\u200b", "a b\u200fc", "/x\\@evil.example", "/a\u200bb"]
)
@pytest.mark.parametrize("name", ["location", "Location", "LOCATION"])
def test_location_gate_applies_to_generic_header_apis(name, location):
    with pytest.raises(BadRequestError):
        http.Response(302, [(name, location)])
    with pytest.raises(BadRequestError):
        http.Response(302).with_header(name, location)
    r = http.Response(302, [("location", "/ok")])
    with pytest.raises(BadRequestError):
        r.headers = [(name, location)]
    assert r.headers == [("location", "/ok")]


def test_location_gate_does_not_touch_other_headers():
    r = http.Response(200).with_header("x-note", "a b\u200f\\c")
    assert r.header("x-note") == "a b\u200f\\c"


@pytest.mark.parametrize("location", ["/login", "https://rp.example/cb?x=1#frag", "relative/path?q=1"])
def test_response_redirect_accepts_clean_targets(location):
    r = http.Response.redirect(location)
    assert r.status == 302 and r.header("location") == location


@pytest.mark.parametrize("name", ["", "a b", "x:y", "x\r\n", "é"])
def test_response_with_header_rejects_bad_name(name):
    with pytest.raises(BadRequestError):
        http.Response(200).with_header(name, "v")


@pytest.mark.parametrize("value", ["a\rb", "a\nb", "a\x00b", "a\x0bb", "a\x7fb", "a\r\nSet-Cookie: x=1"])
def test_response_with_header_rejects_bad_value(value):
    with pytest.raises(BadRequestError):
        http.Response(200).with_header("x-a", value)


def test_response_with_header_accepts_normal_values():
    r = http.Response(200).with_header("X-Tok_en.1", "a\tb c; d=e").with_header("x-empty", "")
    assert r.headers == [("X-Tok_en.1", "a\tb c; d=e"), ("x-empty", "")]


def test_response_constructor_validates_headers():
    r = http.Response(200, [("x-a", "a\tb"), ("set-cookie", "k=v")])
    assert r.headers == [("x-a", "a\tb"), ("set-cookie", "k=v")]
    assert http.Response(204).headers == []
    for bad in ([("", "v")], [("a b", "v")], [("x:y", "v")], [("x-a", "v\r\nx: y")], [("x-a", "v\x00")]):
        with pytest.raises(BadRequestError):
            http.Response(200, bad)
    with pytest.raises(BadRequestError):
        http.Response(302, [("x-ok", "v"), ("location", "/a\r\nSet-Cookie: x=1")])


def test_response_headers_setter_validates_each_pair():
    r = http.Response(200)
    r.headers = [("x-a", "a\tb"), ("set-cookie", "k=v")]
    assert r.headers == [("x-a", "a\tb"), ("set-cookie", "k=v")]
    for bad in ([("", "v")], [("a b", "v")], [("x:y", "v")], [("x-a", "v\r\nx: y")], [("x-a", "v\x00")]):
        with pytest.raises(BadRequestError):
            r.headers = bad
    # a rejected assignment leaves the previous headers untouched
    assert r.headers == [("x-a", "a\tb"), ("set-cookie", "k=v")]
    with pytest.raises(BadRequestError):
        r.headers = [("x-ok", "v"), ("x-bad", "v\n")]
    assert r.headers == [("x-a", "a\tb"), ("set-cookie", "k=v")]


# --- ReqwestClient.post_json -------------------------------------------------------------


def _json_server(big: bool = False):
    """Local server recording each POST (path, body, headers); /big answers with 5000 bytes."""
    import http.server as hs
    import threading

    seen: list[dict] = []

    class H(hs.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            seen.append(
                {
                    "path": self.path,
                    "body": self.rfile.read(n),
                    "content_type": self.headers.get_all("Content-Type"),
                    "auth": self.headers.get("Authorization"),
                    "multi": self.headers.get_all("X-Multi"),
                }
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"x" * 5000 if self.path == "/big" else b'{"ok":true}')

    srv = hs.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}", seen


def _stop(srv):
    """Stop the server and close its listening socket (no ResourceWarning later)."""
    srv.shutdown()
    srv.server_close()


def test_post_json_against_local_server():
    srv, base, seen = _json_server()
    try:
        c = http.ReqwestClient()
        body = {"b": 1, "a": [True, None, 1.5], "big": 2**70, "neg": -(2**64)}
        st, out, ct = c.post_json(
            f"{base}/p",
            body,
            [("Authorization", "Bearer t"), ("X-Multi", "1"), ("X-Multi", "2")],
        )
        assert (st, out, ct) == (200, b'{"ok":true}', "application/json")
        assert seen[-1]["body"] == (
            b'{"b":1,"a":[true,null,1.5],"big":1180591620717411303424,"neg":-18446744073709551616}'
        )
        assert seen[-1]["content_type"] == ["application/json"]
        assert seen[-1]["auth"] == "Bearer t" and seen[-1]["multi"] == ["1", "2"]

        assert c.post_json(f"{base}/p", {"a": 1})[0] == 200  # headers omitted
        assert seen[-1]["auth"] is None and seen[-1]["body"] == b'{"a":1}'
        assert c.post_json(f"{base}/p", {"a": 1}, None)[0] == 200

        c.post_json(f"{base}/p", (1, "x", None))
        assert seen[-1]["body"] == b'[1,"x",null]'
        c.post_json(f"{base}/p", "str")
        assert seen[-1]["body"] == b'"str"'
        c.post_json(f"{base}/p", 7)
        assert seen[-1]["body"] == b"7"
        c.post_json(f"{base}/p", None)
        assert seen[-1]["body"] == b"null"
    finally:
        _stop(srv)


@pytest.mark.parametrize(
    ("supplied", "kept"),
    [
        (None, "application/json"),
        ("application/json; charset=utf-8", "application/json; charset=utf-8"),
        ("Application/JSON", "Application/JSON"),
        ("application/merge-patch+json", "application/merge-patch+json"),
        ("application/vnd.api+JSON;x=y", "application/vnd.api+JSON;x=y"),
    ],
)
def test_post_json_content_type_policy_kept(supplied, kept):
    srv, base, seen = _json_server()
    try:
        headers = [("content-type", supplied)] if supplied else [("X-Other", "1")]
        assert http.ReqwestClient().post_json(f"{base}/p", {"a": 1}, headers)[0] == 200
        assert seen[-1]["content_type"] == [kept]  # exactly one header
    finally:
        _stop(srv)


@pytest.mark.parametrize(
    "headers",
    [
        [("Content-Type", "text/plain")],
        [("Content-Type", "application/x-www-form-urlencoded")],
        [("Content-Type", "application/jsonx")],
        [("Content-Type", "application/+json")],
        [("Content-Type", "text/json")],
        [("Content-Type", "application/json"), ("content-type", "application/json")],
    ],
)
def test_post_json_content_type_policy_rejected(headers):
    srv, base, seen = _json_server()
    try:
        with pytest.raises(BadRequestError):
            http.ReqwestClient().post_json(f"{base}/p", {"a": 1}, headers)
        assert seen == []  # never contacted
    finally:
        _stop(srv)


@pytest.mark.parametrize(
    "name",
    [
        "Content-Length",
        "content-length",
        "Transfer-Encoding",
        "Host",
        "Connection",
        "Expect",
        "Content-Encoding",
    ],
)
def test_post_json_client_owned_headers_rejected(name):
    srv, base, seen = _json_server()
    try:
        with pytest.raises(BadRequestError, match="set by the client"):
            http.ReqwestClient().post_json(f"{base}/p", {"a": 1}, [(name, "0")])
        assert seen == []  # never contacted
    finally:
        _stop(srv)


@pytest.mark.parametrize(
    "name",
    ["Content-Length", "Transfer-Encoding", "Host", "Connection", "Expect", "Content-Encoding"],
)
@pytest.mark.parametrize("method", ["get", "post_form", "post_json"])
def test_client_owned_headers_rejected_on_every_request_type(method, name):
    # Port 9 is never reached: a guard that did not fire would surface as a
    # connection failure (InternalError), not BadRequestError.
    c = http.ReqwestClient(connect_timeout=1, request_timeout=2)
    url = "http://127.0.0.1:9/"
    headers = [("Authorization", "Bearer t"), (name, "0")]
    with pytest.raises(BadRequestError, match="set by the client"):
        if method == "get":
            c.get(url, headers)
        elif method == "post_form":
            c.post_form(url, [("code", "secret")], headers)
        else:
            c.post_json(url, {"a": 1}, headers)


def test_post_form_still_sends_caller_headers():
    srv, base, seen = _json_server()
    try:
        # Legitimate headers still pass through post_form; the body is intact.
        st, _, _ = http.ReqwestClient().post_form(
            f"{base}/p", [("a", "1")], [("Authorization", "Bearer t"), ("X-Multi", "v")]
        )
        assert st == 200
        assert seen[0]["body"] == b"a=1"
        assert seen[0]["auth"] == "Bearer t"
        assert seen[0]["multi"] == ["v"]
        assert seen[0]["content_type"] == ["application/x-www-form-urlencoded"]
    finally:
        _stop(srv)


@pytest.mark.parametrize(
    ("body", "exc", "match"),
    [
        ({"a": [1.0, {"b": float("nan")}]}, ValueError, "non-finite"),
        ([float("inf")], ValueError, "non-finite"),
        (object(), TypeError, None),
        ({1: "x"}, TypeError, None),
        (b"bytes", TypeError, "byte array"),
        ({"a": b"bytes"}, TypeError, "byte array"),
    ],
)
def test_post_json_bad_body_never_sent(body, exc, match):
    srv, base, seen = _json_server()
    try:
        with pytest.raises(exc, match=match):
            http.ReqwestClient().post_json(f"{base}/p", body)
        assert seen == []
    finally:
        _stop(srv)


def test_post_json_too_deep_never_sent():
    srv, base, seen = _json_server()
    try:
        deep: list = []
        for _ in range(200):
            deep = [deep]
        with pytest.raises(ValueError, match="nested too deeply"):
            http.ReqwestClient().post_json(f"{base}/p", deep)
        assert seen == []
    finally:
        _stop(srv)


@pytest.mark.parametrize("bad", BAD_FLOATS)
@pytest.mark.parametrize("case", REJECT_CASES, ids=[c.id for c in REJECT_CASES])
def test_post_json_non_finite_in_exotic_container_never_sent(case, bad):
    srv, base, seen = _json_server()
    try:
        for body in ({"s": case.build(bad)}, [[case.build(bad)]]):
            with pytest.raises(ValueError, match="non-finite"):
                http.ReqwestClient().post_json(f"{base}/p", body)
        assert seen == []
    finally:
        _stop(srv)


@pytest.mark.parametrize("case", ACCEPT_CASES, ids=[c.id for c in ACCEPT_CASES])
def test_post_json_exotic_container_sent_exactly(case):
    import json

    srv, base, seen = _json_server()
    try:
        assert http.ReqwestClient().post_json(f"{base}/p", {"s": case.build()})[0] == 200
        assert json.loads(seen[-1]["body"]) == {"s": case.expected}
    finally:
        _stop(srv)


@pytest.mark.parametrize("case", RESERVED_KEY_CASES, ids=[c.id for c in RESERVED_KEY_CASES])
def test_post_json_reserved_number_key_never_sent(case):
    srv, base, seen = _json_server()
    try:
        for body in ({"s": case.value}, [[case.value]], case.value):
            with pytest.raises(ValueError, match="reserved"):
                http.ReqwestClient().post_json(f"{base}/p", body)
        assert seen == []
    finally:
        _stop(srv)


@pytest.mark.parametrize(("n", "digits"), BIG_INT_CASES)
def test_post_json_big_int_exact_digits(n, digits):
    srv, base, seen = _json_server()
    try:
        assert http.ReqwestClient().post_json(f"{base}/p", {"s": n})[0] == 200
        assert seen[-1]["body"] == f'{{"s":{digits}}}'.encode()
    finally:
        _stop(srv)


def test_post_json_depth_limit():
    srv, base, seen = _json_server()
    try:
        assert http.ReqwestClient().post_json(f"{base}/p", nested(127))[0] == 200
        with pytest.raises(ValueError, match="nested too deeply"):
            http.ReqwestClient().post_json(f"{base}/p", nested(128))
        with pytest.raises(ValueError, match="nested too deeply"):
            http.ReqwestClient().post_json(f"{base}/p", nested(10_000))
        assert len(seen) == 1
    finally:
        _stop(srv)


def test_post_json_self_referential_list_never_sent():
    srv, base, seen = _json_server()
    try:
        loop: list = []
        loop.append(loop)
        with pytest.raises(ValueError, match="nested too deeply"):
            http.ReqwestClient().post_json(f"{base}/p", loop)
        assert seen == []
    finally:
        _stop(srv)


@pytest.mark.parametrize("name", sorted(TOKEN_LOOP_BUILDERS))
def test_post_json_cyclic_or_chained_token_map_never_sent(name):
    srv, base, seen = _json_server()
    try:
        with pytest.raises(ValueError, match="reserved"):
            http.ReqwestClient().post_json(f"{base}/p", TOKEN_LOOP_BUILDERS[name]())
        assert seen == []
    finally:
        _stop(srv)


@pytest.mark.parametrize("leaf", [1, 2**128, -(2**200)])
def test_post_json_big_int_counts_like_any_scalar_at_the_depth_limit(leaf):
    # post_json has no claims dict: 127 lists is the deepest accepted nesting.
    srv, base, seen = _json_server()
    try:
        c = http.ReqwestClient()
        assert c.post_json(f"{base}/p", wrap_in_lists(leaf, 127))[0] == 200
        assert seen[0]["body"] == (b"[" * 127) + str(leaf).encode() + (b"]" * 127)
        with pytest.raises(ValueError, match="nested too deeply"):
            c.post_json(f"{base}/p", wrap_in_lists(leaf, 128))
        assert len(seen) == 1
    finally:
        _stop(srv)


@pytest.mark.parametrize("name", sorted(CYCLIC_BUILDERS))
def test_post_json_cyclic_or_deep_non_list_container_never_sent(name):
    srv, base, seen = _json_server()
    try:
        with pytest.raises(ValueError, match="nested too deeply"):
            http.ReqwestClient().post_json(f"{base}/p", CYCLIC_BUILDERS[name]())
        assert seen == []
    finally:
        _stop(srv)


def test_post_json_response_size_cap():
    from pygrindvakt import InternalError

    srv, base, seen = _json_server()
    try:
        c = http.ReqwestClient(max_response_bytes=1000)
        with pytest.raises(InternalError, match="byte limit") as ei:
            c.post_json(f"{base}/big", {"a": 1})
        assert ei.value.code == "response_too_large"
        assert len(seen) == 1
    finally:
        _stop(srv)


@pytest.mark.parametrize("method", ["get", "post_json"])
@pytest.mark.parametrize(
    "headers",
    [[("bad name", "v")], [("", "v")], [("X-Ok", "line\nbreak")], [("X-Ok", "café\x00")]],
)
def test_reqwest_invalid_header_is_bad_request_get_and_post_json(method, headers):
    c = http.ReqwestClient()
    with pytest.raises(BadRequestError):
        if method == "get":
            c.get("http://127.0.0.1:9/", headers)
        else:
            c.post_json("http://127.0.0.1:9/", {"a": 1}, headers)


def test_post_json_connect_failure_chains_connection_error():
    import socket

    from pygrindvakt import InternalError

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    c = http.ReqwestClient(connect_timeout=2, read_timeout=2, request_timeout=5)
    with pytest.raises(InternalError) as ei:
        c.post_json(f"http://127.0.0.1:{port}/", {"a": 1})
    assert ei.value.code == "transport"
    assert isinstance(ei.value.__cause__, ConnectionError)


def test_optional_post_json_does_not_change_required_protocol():
    """post_json is optional: the required members stay get + post_form.

    No public function calls ``HttpClient::post_json`` yet (grindvakt 0.12.0 only
    adds the trait method), so the adapter's post_json path (Python object
    hand-off, ConfigError for a client lacking it) cannot be driven from Python.
    """

    class Minimal:
        def get(self, url):
            return 200, b"{}", "application/json"

        def post_form(self, url, form, headers):
            return 200, b"{}", "application/json"

    class WithPostJson(Minimal):
        def post_json(self, url, body, headers):
            return 200, b"{}", "application/json"

    assert http.supports_get_with_headers(Minimal()) is False
    assert http.supports_get_with_headers(WithPostJson()) is False
    assert http.supports_get_with_headers(http.ReqwestClient()) is True
