"""Type stubs for ``pygrindvakt.http`` - framework-agnostic request / response
types, the outbound ``HttpClient`` protocol, and the built-in reqwest client.

SECURITY: an injected ``HttpClientProtocol`` implementation is responsible for
timeouts, for *not* following redirects (a 307/308 would re-send token-endpoint
form bodies and Bearer tokens cross-origin), and for bounding response sizes.
The built-in ``ReqwestClient`` never follows redirects (for any request type)
and does all three.

Request headers on GET (needed by ``rp.fetch_userinfo(method="GET")``) are
optional. Whether an injected client supports them is decided once, when the
client is first used: it does if its ``get`` accepts a ``headers`` parameter
passable by keyword (positional-only and ``*headers`` do not count; a ``**kwargs`` parameter also counts) or it has a callable
``get_with_headers(url, headers)`` (preferred when present). pygrindvakt never
calls ``get`` and falls back on ``TypeError``. A client without support raises
``ConfigError`` only when a GET with headers is requested. See
``HttpClientWithHeadersProtocol``.

A JSON POST (``ReqwestClient.post_json``) is optional for an injected client: it
may provide ``post_json(url, body, headers)``, where ``body`` is a
JSON-compatible Python object. A client without it raises ``ConfigError`` only
when a JSON POST is requested. See ``HttpClientPostJsonProtocol``.

NAME SHADOWING: ``from pygrindvakt import http`` rebinds the name ``http`` in
the importing module and shadows the standard-library ``http`` package there
(``http.HTTPStatus``, ``http.client``, ``http.server`` ...). Prefer
``from pygrindvakt import http as gv_http`` or ``import pygrindvakt.http``.

THREADING: see ``ReqwestClient`` for the thread-safety and fork semantics of
the built-in client. A Python ``HttpClientProtocol`` implementation runs on the
calling thread while it holds the GIL, so one shared across threads must be
thread-safe itself.
"""

from typing import Any, Protocol, TypeAlias, TypeGuard

class HttpClientProtocol(Protocol):
    """Outbound HTTP client protocol accepted wherever ``http=`` is taken.

    Either method may return an ``HttpFetchResponse`` or the
    ``(status, body, content_type[, headers])`` tuple, where ``headers`` is a
    list of response ``(name, value)`` pairs (names are lower-cased, order and
    repeats kept). Return them when you can: without response headers
    ``rp.JwksCache`` cannot see ``Cache-Control`` and warns. Exceptions are logged via
    ``sys.unraisablehook`` and reported as ``InternalError``.

    The implementation runs on the thread driving the pygrindvakt call, holding
    the GIL. An instance shared across threads must be thread-safe itself.
    Calling back into pygrindvakt from inside a method is supported; each such
    nested call runs on a helper thread.
    """

    def get(self, url: str) -> _FetchResult: ...
    def post_form(
        self,
        url: str,
        form: list[tuple[str, str]],
        headers: list[tuple[str, str]],
    ) -> _FetchResult: ...

class HttpClientWithHeadersProtocol(HttpClientProtocol, Protocol):
    """An ``HttpClientProtocol`` whose ``get`` also accepts request headers.

    Stub-only. Needed for ``rp.fetch_userinfo(method="GET")``. A client may
    instead provide ``get_with_headers(url, headers)``; if present it is
    preferred. The client must not follow redirects, or must strip
    ``Authorization`` on a cross-origin redirect: the headers carry the access
    token.
    """

    def get(self, url: str, headers: list[tuple[str, str]] | None = None) -> _FetchResult: ...

class HttpClientGetWithHeadersProtocol(HttpClientProtocol, Protocol):
    """An ``HttpClientProtocol`` that also provides
    ``get_with_headers(url, headers)``.

    Stub-only. The alternative to ``HttpClientWithHeadersProtocol`` for
    clients whose ``get`` takes no ``headers``; preferred over ``get`` at
    runtime when present.
    """

    def get_with_headers(self, url: str, headers: list[tuple[str, str]]) -> _FetchResult: ...

class HttpClientPostJsonProtocol(HttpClientProtocol, Protocol):
    """An ``HttpClientProtocol`` that also provides ``post_json(url, body, headers)``.

    Stub-only. ``post_json`` is optional: the required members stay ``get`` and
    ``post_form``. ``body`` is a JSON-compatible Python object (dict, list,
    str, int, float, bool or None); the method returns the same result as
    ``post_form``. It must set ``Content-Type: application/json`` and must not
    follow cross-origin redirects (including 307 / 308).
    """

    def post_json(
        self,
        url: str,
        body: Any,
        headers: list[tuple[str, str]],
    ) -> _FetchResult: ...

class HttpRequestData:
    """A parsed inbound HTTP request, normalized for grindvakt.

    Build one from your framework's request object. ``headers`` keys are
    lower-cased; ``form`` is the parsed ``application/x-www-form-urlencoded``
    body.

    For authorization-response (protocol) parameters build ``query`` / ``form``
    from a list of ``(str, str)`` pairs (``request.args.items(multi=True)``): a
    mapping discards duplicate names, and ``rp.parse_authorization_response``
    raises ``TypeError`` for a non-empty channel built from, or last assigned,
    a mapping. Assigning pairs to the ``query`` / ``form`` setters is accepted
    and keeps duplicates in ``query_pairs`` / ``form_pairs``.
    """

    def __init__(
        self,
        path: str = ...,
        method: str = ...,
        uri: str = ...,
        query: dict[str, str] | list[tuple[str, str]] | None = ...,
        form: dict[str, str] | list[tuple[str, str]] | None = ...,
        body: bytes | None = ...,
        headers: dict[str, str] | None = ...,
        cookies: dict[str, str] | None = ...,
    ) -> None: ...
    @property
    def path(self) -> str: ...
    @path.setter
    def path(self, value: str) -> None: ...
    @property
    def method(self) -> str: ...
    @method.setter
    def method(self, value: str) -> None: ...
    @property
    def uri(self) -> str: ...
    @uri.setter
    def uri(self, value: str) -> None: ...
    @property
    def query(self) -> dict[str, str]: ...
    @query.setter
    def query(self, value: dict[str, str] | list[tuple[str, str]]) -> None: ...
    @property
    def query_pairs(self) -> list[tuple[str, str]]: ...
    @property
    def form(self) -> dict[str, str]: ...
    @form.setter
    def form(self, value: dict[str, str] | list[tuple[str, str]]) -> None: ...
    @property
    def form_pairs(self) -> list[tuple[str, str]]: ...
    @property
    def body(self) -> bytes: ...
    @body.setter
    def body(self, value: bytes) -> None: ...
    @property
    def headers(self) -> dict[str, str]: ...
    @headers.setter
    def headers(self, value: dict[str, str]) -> None: ...
    @property
    def cookies(self) -> dict[str, str]: ...
    @cookies.setter
    def cookies(self, value: dict[str, str]) -> None: ...
    def param(self, key: str) -> str | None:
        """Look up a parameter from the query string first, then the form body."""
    def authorization(self) -> str | None:
        """The value of the ``Authorization`` header, if present."""
    def bearer_token(self) -> str | None:
        """Extract a Bearer token from the Authorization header."""
    def __repr__(self) -> str: ...

class Response:
    """A framework-agnostic HTTP response produced by grindvakt.

    ``headers`` is a list of ``(name, value)`` pairs (multi-valued headers such
    as ``set-cookie`` are supported); ``body`` is ``bytes``. The constructor
    and assigning ``headers`` validate each pair like ``with_header``.

    Raises:
        BadRequestError: from the constructor, the ``headers`` setter,
            ``with_header`` and ``redirect`` on an unsafe name, value or
            location.
    """

    def __init__(
        self,
        status: int,
        headers: list[tuple[str, str]] | None = ...,
        body: bytes | None = ...,
    ) -> None: ...
    @property
    def status(self) -> int: ...
    @status.setter
    def status(self, value: int) -> None: ...
    @property
    def headers(self) -> list[tuple[str, str]]: ...
    @headers.setter
    def headers(self, value: list[tuple[str, str]]) -> None: ...
    @property
    def body(self) -> bytes: ...
    @body.setter
    def body(self, value: bytes) -> None: ...
    def text(self) -> str:
        """Body decoded as UTF-8 (lossy)."""
    def header(self, name: str) -> str | None:
        """First value of header ``name`` (case-insensitive), if any."""
    def with_header(self, name: str, value: str) -> Response:
        """Return a copy with an extra header appended.

        Raises ``BadRequestError`` if ``name`` is empty or not an RFC 9110
        token, or ``value`` holds a C0 control (HTAB excepted), DEL or NUL. A
        ``location`` header must also pass the ``redirect`` check.
        """
    def with_body(self, body: bytes) -> Response:
        """Return a copy with the body replaced."""
    @staticmethod
    def redirect(location: str) -> Response:
        """302 redirect to ``location``.

        Raises ``BadRequestError`` if ``location`` contains whitespace,
        control, bidi or invisible formatting characters or a backslash. No
        scheme or host policy is applied; relative targets and fragments are
        allowed. A ``location`` header set through the constructor,
        ``with_header`` or the ``headers`` setter gets the same check.
        """
    @staticmethod
    def html(body: str) -> Response:
        """A ``text/html`` response."""
    @staticmethod
    def json(value: Any, status: int = ...) -> Response:
        """An ``application/json`` response from any JSON-serializable value."""
    @staticmethod
    def text_response(status: int, body: str) -> Response:
        """A plain-text response."""
    def __repr__(self) -> str: ...

class HttpFetchResponse:
    """The result of an outbound fetch made through an ``HttpClient``."""

    def __init__(
        self,
        status: int,
        body: bytes,
        content_type: str | None = ...,
        headers: list[tuple[str, str]] | None = ...,
    ) -> None: ...
    @property
    def headers(self) -> list[tuple[str, str]]:
        """Response ``(name, value)`` pairs, names lower-cased; empty if none."""
    @property
    def status(self) -> int: ...
    @property
    def body(self) -> bytes: ...
    @property
    def content_type(self) -> str | None: ...
    def text(self) -> str: ...
    def json(self) -> Any:
        """Parse the body as JSON into native Python objects."""
    def __repr__(self) -> str: ...

class ReqwestClient:
    """The built-in outbound HTTP client (reqwest + rustls).

    Never follows redirects, enforces connect/read/total timeouts and a
    streaming response-size cap. Also exposes ``get`` / ``post_form`` / ``post_json`` so it
    satisfies the Python ``HttpClientProtocol`` itself.

    Thread safety: instances are frozen and share their state behind an
    ``Arc``, so one instance may be used from many threads. The GIL is released
    during I/O, so concurrent calls run in parallel. ``http=None`` selects a
    process-wide default instance with the same properties.

    Fork safety: the connection pool is keyed by PID and rebuilt lazily in a
    child after ``fork``; inherited connections are never reused and the tokio
    runtime is rebuilt per process (ADR 0001). Forking while another thread has a
    request in flight is not supported. Fork only while no other
    thread is inside a pygrindvakt call: an internal lock held by another
    thread at fork time stays locked in the child and can deadlock it. A
    ``ReqwestClient`` may be created before ``fork``; a ``RedisStore`` must be
    created after.
    """

    def __init__(
        self,
        connect_timeout: int = ...,
        read_timeout: int = ...,
        request_timeout: int = ...,
        max_response_bytes: int = ...,
        user_agent: str | None = ...,
    ) -> None: ...
    def get(self, url: str, headers: list[tuple[str, str]] | None = ...) -> tuple[int, bytes, str | None]:
        """Issue a GET, optionally with request headers.

        Returns ``(status, body, content_type)``. Redirects are never followed,
        so the headers are only sent to ``url``. An invalid header name or
        value raises ``BadRequestError``.
        """
    def post_form(
        self,
        url: str,
        form: list[tuple[str, str]],
        headers: list[tuple[str, str]] | None = ...,
    ) -> tuple[int, bytes, str | None]:
        """Issue a form-encoded POST. Returns ``(status, body, content_type)``."""
    def post_json(
        self,
        url: str,
        body: Any,
        headers: list[tuple[str, str]] | None = ...,
    ) -> tuple[int, bytes, str | None]:
        """Send a JSON body with a POST. Returns ``(status, body, content_type)``.

        Lets you call a JSON API without another HTTP library, using this
        client's timeouts, response-size cap and TLS settings. ``body`` in the
        result is the raw response bytes: decode it yourself (``json.loads``).

        ``body`` is any JSON-compatible value (sets, deques and other
        sequence-like objects serialize as arrays), serialized compactly with
        dict order kept and integers exact. NaN / infinity and nesting deeper than
        127 levels raise ``ValueError``; a value that is not JSON-compatible raises
        ``TypeError``. Nothing is sent in those cases.

        ``Content-Type: application/json`` is set unless ``headers`` supplies
        one whose media type is ``application/json`` or ``application/*+json``
        (parameters and case ignored), which is kept; any other Content-Type
        raises ``BadRequestError``. Redirects are never followed (including 307
        / 308), so the headers are only sent to ``url``. An invalid header name
        or value raises ``BadRequestError``, as does supplying ``Content-Length``,
        ``Transfer-Encoding``, ``Host``, ``Connection``, ``Expect`` or
        ``Content-Encoding`` (the client frames and addresses the request
        itself; ``get`` and ``post_form`` refuse them too).
        """
    def __repr__(self) -> str: ...

# Stub-only aliases (underscore-prefixed so they are not expected at runtime).
# What a client method may return: the ``(status, body, content_type)`` tuple,
# the same with an optional 4th ``headers`` element (response ``(name, value)``
# pairs), or an ``HttpFetchResponse`` (see ``extract_fetch`` in
# ``src/http.rs``). Report headers if you can: ``rp.JwksCache`` needs
# ``Cache-Control`` / ``Age`` to honour the OP's cache lifetime.
_FetchResult: TypeAlias = (
    tuple[int, bytes, str | None] | tuple[int, bytes, str | None, list[tuple[str, str]] | None] | HttpFetchResponse
)
# What every networked function accepts as ``http``: any protocol client, the
# built-in ``ReqwestClient``, or ``None`` for the process-wide default client.
_HttpArg: TypeAlias = HttpClientProtocol | ReqwestClient | None  # noqa: PYI047 (imported by other stubs)
# What a networked function accepts as ``http`` when it sends request headers on
# GET (``rp.fetch_userinfo(method="GET")``).
_HttpHeadersArg: TypeAlias = HttpClientWithHeadersProtocol | HttpClientGetWithHeadersProtocol | ReqwestClient | None

def supports_get_with_headers(client: object | None) -> TypeGuard[_HttpHeadersArg]:
    """Whether ``client`` can send request headers on GET, without any request.

    ``None`` and ``ReqwestClient`` are ``True``; any other object only if it
    has callable ``get`` and ``post_form`` and a ``get_with_headers`` or a
    ``get`` accepting ``headers`` by keyword. Never raises; an unsupported
    shape is ``False``. Narrows the type for ``rp.fetch_userinfo(method="GET")``.

    .. versionadded:: 0.3.0
    """
