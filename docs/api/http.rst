pygrindvakt.http
================

.. py:module:: pygrindvakt.http

Framework-agnostic request and response types, the outbound ``HttpClient``
protocol, and the built-in reqwest client.

.. warning::

   **Import name.** ``from pygrindvakt import http`` rebinds the name ``http``
   in your module and shadows the standard-library :mod:`http` package there
   (``http.HTTPStatus``, ``http.client``, ``http.server``, ...). Prefer
   ``from pygrindvakt import http as gv_http`` or ``import pygrindvakt.http``.

:class:`HttpRequestData` is what a web-framework adapter builds from the
incoming request (see :doc:`../guides/op_flask`); :class:`Response` is what
the application turns back into its framework's response type. Neither
depends on any framework.

Outbound HTTP (RP discovery, code exchange, federation fetches) goes through an
object satisfying the :class:`HttpClientProtocol`: either the built-in
:class:`ReqwestClient` or any Python object with ``get`` and ``post_form``
methods. A ``post_json`` method is optional (see below).

.. warning::

   An injected HTTP client is responsible for enforcing timeouts, for **not**
   following redirects (a 307 / 308 would re-send token-endpoint form bodies,
   including the ``client_secret`` and authorization code, cross-origin), and
   for bounding response sizes. The built-in client does all three.

Redirects and credentials
~~~~~~~~~~~~~~~~~~~~~~~~~

grindvakt validates the URLs it requests but cannot validate where a server
redirects to, so the client must not leak credentials:

* ``post_form`` carries ``client_secret``, authorization codes, PKCE verifiers
  and ``Authorization`` headers. It must not follow cross-origin redirects at
  all, including ``307`` / ``308``.
* ``post_json`` carries a JSON body and any headers you pass (for example
  ``Authorization``). It must not follow cross-origin redirects at all,
  including ``307`` / ``308``.
* GET with headers carries ``Authorization: Bearer``. It must not follow
  redirects, or must strip ``Authorization`` on a cross-origin redirect.

The built-in :class:`ReqwestClient` never follows redirects for any request
(``GET``, ``GET`` with headers, form ``POST``, JSON ``POST``); a ``3xx`` is returned as an ordinary
response and callers treat it as a failure. An injected client is responsible
for the same policy.

Request headers on GET
~~~~~~~~~~~~~~~~~~~~~~

``rp.fetch_userinfo(method="GET")`` sends the access token as a header, so the
client must accept request headers on GET. This is decided **once**, when the
client is first used, not by calling and catching ``TypeError``. A Python client
supports headers if either

* it has a callable ``get_with_headers(url, headers)`` (preferred when
  present), or
* its ``get`` accepts a ``headers`` parameter that can be passed by keyword (positional-only or ``*headers`` does not count; a ``**kwargs`` parameter also
  counts), and is called as ``get(url, headers=[(name, value), ...])``.

``headers`` is a list of ``(name, value)`` pairs. A client that supports
neither raises :class:`~pygrindvakt.ConfigError` when a GET with headers is
requested; plain ``get`` and ``post_form`` are unaffected. The type-checking
protocols for such a client are :class:`HttpClientWithHeadersProtocol` and
:class:`HttpClientGetWithHeadersProtocol` (both stub-only).

.. py:function:: supports_get_with_headers(client: object | None) -> TypeGuard[HttpClientWithHeadersProtocol | HttpClientGetWithHeadersProtocol | ReqwestClient | None]

   Whether ``client`` can send request headers on GET, using the same test as
   the networked functions but **without performing any request**. ``None``
   (the built-in client) and a :class:`ReqwestClient` are ``True``. Any other
   object is ``True`` only if it has callable ``get`` and ``post_form`` and
   either a callable ``get_with_headers`` or a ``get`` that accepts ``headers``
   by keyword (or ``**kwargs``). It never raises: an object of any other shape,
   or one whose attributes raise, gives ``False``.

   Call it at startup to fail early instead of on the first
   ``rp.fetch_userinfo(method="GET")``. The ``TypeGuard`` return type narrows
   the argument for the type checker, so no ``cast`` to
   :class:`HttpClientWithHeadersProtocol` is needed:

   .. code-block:: python

      from pygrindvakt import http, rp

      if not http.supports_get_with_headers(my_client):
          raise SystemExit("my_client cannot send headers on GET; use method=\"POST\"")
      rp.fetch_userinfo(my_client, info.userinfo_endpoint, token, sub, info.issuer, method="GET")

   .. versionadded:: 0.3.0

Inbound request
---------------

.. py:class:: HttpRequestData(path: str = "", method: str = "GET", uri: str = "", query: dict[str, str] | None = None, form: dict[str, str] | None = None, body: bytes | None = None, headers: dict[str, str] | None = None, cookies: dict[str, str] | None = None)

   A parsed inbound HTTP request, normalized for grindvakt. Build one from
   your framework's request object.

   Normalization happens in the constructor and the setters: ``path`` loses
   its leading slash, ``method`` is upper-cased, and header names are
   lower-cased. ``form`` is the parsed ``application/x-www-form-urlencoded``
   body; ``body`` is the raw bytes. Every attribute is readable and writable.

   ``query`` and ``form`` accept a ``dict`` (or any mapping) or a list of
   ``(str, str)`` pairs, in the constructor and the setters. For
   authorization-response parameters build them from pairs
   (``request.args.items(multi=True)``): a mapping, for example
   ``request.args.to_dict()``, keeps one value per name. The instance
   remembers whether each channel was last set from a mapping, and
   :func:`pygrindvakt.rp.parse_authorization_response` raises
   :class:`TypeError` when the channel it reads is non-empty and was set from a
   mapping. The ``query`` / ``form`` getters and :meth:`param` are unchanged.

   .. py:attribute:: path
      :type: str
   .. py:attribute:: method
      :type: str
   .. py:attribute:: uri
      :type: str
   .. py:attribute:: query
      :type: dict[str, str]
   .. py:attribute:: form
      :type: dict[str, str]
   .. py:attribute:: body
      :type: bytes
   .. py:attribute:: headers
      :type: dict[str, str]

      Header names are lower-cased on assignment.

   .. py:attribute:: cookies
      :type: dict[str, str]

   .. py:method:: param(key: str) -> str | None

      Look up a parameter from the query string first, then the form body.

   .. py:method:: authorization() -> str | None

      The value of the ``Authorization`` header, if present.

   .. py:method:: bearer_token() -> str | None

      Extract a Bearer token from the ``Authorization`` header, or ``None``
      when the header is absent or not a Bearer credential.

   Example, adapting a Flask request:

   .. code-block:: python

      import flask
      from pygrindvakt.http import HttpRequestData

      def request_data() -> HttpRequestData:
          r = flask.request
          return HttpRequestData(
              path=r.path.lstrip("/"),
              method=r.method,
              uri=r.url,
              query=list(r.args.items(multi=True)),
              form=list(r.form.items(multi=True)),
              body=r.get_data(),
              headers={k.lower(): v for k, v in r.headers.items()},
              cookies=r.cookies.to_dict(),
          )

Outbound response
-----------------

.. py:class:: Response(status: int, headers: list[tuple[str, str]] | None = None, body: bytes | None = None)

   A framework-agnostic HTTP response produced by grindvakt.

   ``headers`` is a list of ``(name, value)`` pairs, so multi-valued headers
   such as ``set-cookie`` are supported; ``body`` is ``bytes``. All three are
   readable and writable. The constructor and assigning ``headers`` apply the
   same checks as :meth:`with_header` to every pair and raise
   :class:`pygrindvakt.BadRequestError` on the first bad one (an assignment
   leaves the old value in place).

   .. versionchanged:: 0.4.0
      Header names, header values and redirect locations are validated
      (header-injection hardening); see :meth:`with_header` and
      :meth:`redirect`. Previously any string was accepted.

   .. py:attribute:: status
      :type: int
   .. py:attribute:: headers
      :type: list[tuple[str, str]]
   .. py:attribute:: body
      :type: bytes

   .. py:method:: text() -> str

      Body decoded as UTF-8 (lossy).

   .. py:method:: header(name: str) -> str | None

      First value of header ``name`` (case-insensitive), if any.

   .. py:method:: with_header(name: str, value: str) -> Response

      Return a copy with an extra header appended. Raises
      :class:`pygrindvakt.BadRequestError` if ``name`` is empty or not an
      RFC 9110 token, or ``value`` contains a C0 control character (a
      horizontal tab is allowed), DEL or NUL. A ``location`` header (any
      case) must also pass the :meth:`redirect` check on its value.

      .. versionchanged:: 0.4.0
         Validates ``name`` and ``value``.

   .. py:method:: with_body(body: bytes) -> Response

      Return a copy with the body replaced.

   .. py:staticmethod:: redirect(location: str) -> Response

      A ``302`` redirect to ``location``. Raises
      :class:`pygrindvakt.BadRequestError` if ``location`` contains
      whitespace, control, bidi or invisible formatting characters or a
      backslash (the ``url`` crate and browsers read ``\\`` as ``/``). No
      scheme or host policy is applied: relative targets (``/login``) and
      fragments are accepted. The same check applies to a ``location`` header
      set through the constructor, ``with_header`` or the ``headers`` setter.

      .. versionchanged:: 0.4.0
         Rejects unsafe characters in ``location``.

   .. py:staticmethod:: html(body: str) -> Response

      A ``text/html`` response.

   .. py:staticmethod:: json(value: Any, status: int = 200) -> Response

      An ``application/json`` response from any JSON-serializable value.

   .. py:staticmethod:: text_response(status: int, body: str) -> Response

      A plain-text response.

   Example, converting to a framework response:

   .. code-block:: python

      from flask import Response as FlaskResponse
      from django.http import HttpResponse

      def to_flask(r):
          return FlaskResponse(r.body, status=r.status, headers=list(r.headers))

      def to_django(r):
          out = HttpResponse(r.body, status=r.status)
          del out["Content-Type"]          # keep only what pygrindvakt set
          for name, value in r.headers:
              out[name] = value
          return out

Outbound HTTP client protocol
-----------------------------

.. py:class:: HttpClientProtocol

   The duck-typed protocol accepted wherever an ``http`` argument is taken
   (every networked function in :mod:`pygrindvakt.rp`,
   :mod:`pygrindvakt.federation` and :mod:`pygrindvakt.discovery`). It is a
   :class:`typing.Protocol` in the stubs; at runtime any object with the two
   methods is accepted, and the methods are checked for existence when the
   object is first passed (``TypeError`` otherwise).

   Both methods may return either a ``(status, body, content_type)`` tuple, a
   ``(status, body, content_type, headers)`` tuple, or an
   :class:`HttpFetchResponse`. ``headers`` is an optional list of response
   ``(name, value)`` string pairs (or ``None``); names are lower-cased, order
   and repeated headers are kept, and a wrongly shaped value is reported like
   any other bad return (:class:`pygrindvakt.InternalError`). Report headers
   whenever the underlying library exposes them: :class:`pygrindvakt.rp.JwksCache`
   reads ``Cache-Control`` and ``Age`` from them, and without any it warns
   and falls back to ``default_ttl``. ``body`` must be ``bytes`` (not
   ``bytearray`` or ``memoryview``). An exception raised by either method is
   logged through ``sys.unraisablehook`` and reported to the caller as
   :class:`pygrindvakt.InternalError`.

   .. py:method:: get(url: str) -> tuple[int, bytes, str | None]

      Issue a GET and return ``(status, body, content_type)``. Optionally
      also ``get(url, headers=...)`` or ``get_with_headers(url, headers)``;
      see *Request headers on GET* above.

   .. py:method:: post_form(url: str, form: list[tuple[str, str]], headers: list[tuple[str, str]]) -> tuple[int, bytes, str | None]

      Issue an ``application/x-www-form-urlencoded`` POST with the extra
      request ``headers`` (for example ``Authorization`` for
      ``client_secret_basic``) and return ``(status, body, content_type)``.
      ``form`` may be empty: :func:`pygrindvakt.rp.fetch_userinfo` sends the
      bearer token this way by default (``method="POST"``).

   .. py:method:: post_json(url: str, body: Any, headers: list[tuple[str, str]]) -> tuple[int, bytes, str | None]

      **Optional.** Issue a POST with a JSON body and return
      ``(status, body, content_type)``, like ``post_form``. ``body`` is passed
      as a JSON-compatible Python object (dict, list, str, int, float, bool or
      ``None``). The method should set ``Content-Type: application/json``
      and must not follow cross-origin redirects. It is looked up when a JSON
      POST is requested; a client without it raises
      :class:`pygrindvakt.ConfigError` for that call only. The required
      members stay ``get`` and ``post_form``. The type-checking protocol is
      :class:`HttpClientPostJsonProtocol` (stub-only).

      .. versionadded:: 0.5.0

   The implementation runs on the thread that is driving the pygrindvakt
   call, holding the GIL (so a client shared across threads must be
   thread-safe itself). It may call back into pygrindvakt, which is how a
   test's fake client drives an in-process
   :class:`pygrindvakt.provider.Provider`; the nested call runs on a helper
   thread and costs one thread spawn.

   Example, an ``httpx``-backed client with a private CA:

   .. code-block:: python

      import httpx

      class HttpxClient:
          def __init__(self, ca_file: str):
              self._c = httpx.Client(
                  verify=ca_file,
                  timeout=httpx.Timeout(10.0, connect=5.0),
                  follow_redirects=False,           # never follow redirects
              )

          def get(self, url):
              r = self._c.get(url)
              return r.status_code, r.content, r.headers.get("content-type")

          def post_form(self, url, form, headers):
              r = self._c.post(url, data=dict(form), headers=dict(headers))
              return r.status_code, r.content, r.headers.get("content-type")

      md = rp.discover(HttpxClient("/etc/ssl/private-ca.pem"), "https://op.example.com")

.. py:class:: HttpClientPostJsonProtocol

   The :class:`HttpClientProtocol` variant that also provides the optional
   ``post_json(url, body, headers)``. **Stub-only**, like
   :class:`HttpClientWithHeadersProtocol`: it is not importable at runtime.

   .. versionadded:: 0.5.0

.. py:class:: HttpClientWithHeadersProtocol

   The :class:`HttpClientProtocol` variant whose ``get`` also takes request
   headers: ``get(url, headers: list[tuple[str, str]] | None = None)``. Needed
   to type-check a client passed to
   :func:`pygrindvakt.rp.fetch_userinfo(method="GET") <pygrindvakt.rp.fetch_userinfo>`.

   **Stub-only:** it exists in ``http.pyi`` for static checkers and is not
   importable at runtime; any object with the right methods is accepted. A
   client may instead provide ``get_with_headers(url, headers)``, which is
   preferred when present. Either way the client must not follow redirects, or
   must strip ``Authorization`` on a cross-origin redirect: those headers carry
   the access token.

   .. versionadded:: 0.2.0

.. py:class:: HttpClientGetWithHeadersProtocol

   The :class:`HttpClientProtocol` variant that provides
   ``get_with_headers(url, headers)`` instead of a ``headers`` parameter on
   ``get``. The runtime prefers this method when both forms exist.

   **Stub-only**, as for :class:`HttpClientWithHeadersProtocol`.

   .. versionadded:: 0.2.0

.. py:class:: HttpFetchResponse(status: int, body: bytes, content_type: str | None = None, headers: list[tuple[str, str]] | None = None)

   The result of an outbound fetch made through an ``HttpClient``. A Python
   client may return one of these instead of the tuple.

   .. py:attribute:: status
      :type: int
   .. py:attribute:: body
      :type: bytes
   .. py:attribute:: content_type
      :type: str | None
   .. py:attribute:: headers
      :type: list[tuple[str, str]]

      Read-only response ``(name, value)`` pairs; names are lower-cased,
      order and repeats kept. Empty when none were given.

      .. versionadded:: 0.2.0

   .. py:method:: text() -> str

      Body decoded as UTF-8 (lossy).

   .. py:method:: json() -> Any

      Parse the body as JSON into native Python objects.

Built-in client
---------------

.. _reqwest-client-fork:

.. py:class:: ReqwestClient(connect_timeout: int = 10, read_timeout: int = 15, request_timeout: int = 30, max_response_bytes: int = 8388608, user_agent: str | None = None)

   The built-in outbound HTTP client (reqwest + rustls; no OpenSSL).

   It never follows redirects, enforces connect / read / total timeouts (in
   seconds) and a streaming response-size cap (8 MiB by default; the cap is
   checked before every chunk is appended, so an untrusted ``Content-Length``
   cannot bypass it). Every limit must be greater than zero, otherwise the
   constructor raises ``ValueError``. The default ``user_agent`` is
   ``pygrindvakt/<version>``.

   .. rubric:: Threads and fork

   *Threads.* Instances are immutable and share their state, so one
   ``ReqwestClient`` can safely be used from many threads. The GIL is released
   during I/O, so concurrent calls run in parallel. ``http=None`` selects a
   process-wide default instance with the same properties.

   *Fork.* The connection pool is keyed by process id and rebuilt lazily in a
   child after ``fork``; connections inherited from the parent are never
   reused, and the tokio runtime is rebuilt per process (see
   `ADR 0001 <https://github.com/kushaldas/pygrindvakt/blob/main/docs/adr/0001-sync-api-over-embedded-tokio-runtime.md>`_).
   A client created in a gunicorn master therefore keeps working in the
   workers, provided the fork is quiescent (see below).

   .. warning::

      Fork only while no other thread is inside a pygrindvakt call (for
      example in a gunicorn master before it starts any thread that calls
      pygrindvakt). A ``post_fork`` hook does not help: it runs in the child,
      after the fork has already happened. The pool and runtime are guarded by internal locks. If
      another thread holds one at the moment of ``fork``, the child inherits
      it locked with no owner and can block forever, before the process id
      check runs. Forking concurrently with active calls is not supported.

   A ``ReqwestClient`` may be created
   before ``fork``; a :class:`~pygrindvakt.provider.RedisStore` must be created
   after it (see :doc:`../guides/stores`).

   *Python clients.* A Python :class:`HttpClientProtocol` implementation runs
   on the calling thread while it holds the GIL, so an instance shared across
   threads must be thread-safe itself. A re-entrant call back into pygrindvakt
   from inside it costs a helper thread.

   It also exposes ``get`` / ``post_form`` / ``post_json`` so it satisfies the Python
   :class:`HttpClientProtocol` itself, which makes it usable from your own
   code for fetches that need the same hardening.

   .. py:method:: get(url: str, headers: list[tuple[str, str]] | None = None) -> tuple[int, bytes, str | None]

      Issue a GET, optionally with request ``headers`` as ``(name, value)``
      pairs. Returns ``(status, body, content_type)``. A ``3xx`` comes
      back as-is (not followed), so the headers are never forwarded to a
      redirect target. An invalid header name or value raises
      :class:`pygrindvakt.BadRequestError`, as does supplying
      ``Content-Length``, ``Transfer-Encoding``, ``Host``, ``Connection``,
      ``Expect`` or ``Content-Encoding`` (see below). Raises
      :class:`pygrindvakt.InternalError` on connection failure or when the body
      exceeds ``max_response_bytes``.

      .. versionchanged:: 0.2.0
         Added the ``headers`` parameter and the recording of response headers
         on the internal fetch response.

      .. versionchanged:: 0.5.0
         Refuses client-owned headers.

   .. py:method:: post_form(url: str, form: list[tuple[str, str]], headers: list[tuple[str, str]] | None = None) -> tuple[int, bytes, str | None]

      Issue a form-encoded POST. Returns ``(status, body, content_type)``. An
      invalid header name or value raises :class:`pygrindvakt.BadRequestError`,
      as does supplying a client-owned header (see below).

      .. versionchanged:: 0.5.0
         Refuses client-owned headers.

   **Client-owned headers.** ``get``, ``post_form`` and ``post_json`` frame and
   address the request themselves, so they refuse a caller-supplied
   ``Content-Length``, ``Transfer-Encoding``, ``Host``, ``Connection``,
   ``Expect`` or ``Content-Encoding`` with :class:`pygrindvakt.BadRequestError`
   before anything is sent. Otherwise a ``Content-Length: 0`` would silently
   drop a request body (for example a token request's ``client_secret`` and
   authorization code), and ``Host`` would address the request at a different
   virtual host than the one connected to. Strip these when forwarding headers
   from an inbound request.

   .. py:method:: post_json(url: str, body: Any, headers: list[tuple[str, str]] | None = None) -> tuple[int, bytes, str | None]

      Send a JSON body with a POST and return ``(status, body, content_type)``.
      This lets you call a JSON API without adding or configuring another HTTP
      library: the request uses this client's timeouts, response-size cap and
      TLS settings, like every other pygrindvakt request. ``body`` in the
      result is the raw response bytes, so decode it yourself (for example
      with ``json.loads``).

      .. code-block:: python

         import json
         from pygrindvakt import http

         client = http.ReqwestClient(request_timeout=5)
         status, body, content_type = client.post_json(
             "https://api.example.com/v1/evaluate",
             {"subject": "alice", "action": "read"},
             [("Authorization", "Bearer <token>")],
         )
         if status == 200:
             result = json.loads(body)

      ``body`` is any JSON-compatible Python value (dict, list, tuple, str,
      int, float, bool, ``None``). Sets, frozensets, deques and other
      sequence-like objects serialize as arrays and mapping-like objects as
      objects. It is serialized compactly, dict order is
      kept and integers are exact (beyond 64 bits too). ``NaN`` / infinity and
      nesting deeper than 127 levels raise :class:`ValueError`; a value that is not
      JSON-compatible raises :class:`TypeError`. Nothing is sent in those
      cases.

      **Content-Type.** ``application/json`` is set by default. If ``headers``
      supplies a ``Content-Type`` whose media type (parameters ignored,
      case-insensitive) is ``application/json`` or ``application/*+json``, it
      is kept as given (for example ``application/json; charset=utf-8`` or
      ``application/merge-patch+json``). Any other ``Content-Type`` raises
      :class:`pygrindvakt.BadRequestError`. Exactly one ``Content-Type``
      header is sent.

      Redirects are never followed (including ``307`` / ``308``), so
      ``headers`` such as ``Authorization`` are only sent to ``url``. An
      invalid header name or value raises :class:`pygrindvakt.BadRequestError`,
      as does supplying a client-owned header such as ``Content-Length`` or
      ``Host`` (see above).
      A redirect (``3xx``) or an error status is returned as an ordinary
      status for you to check. Raises :class:`pygrindvakt.InternalError` on
      connection failure or when the response body exceeds
      ``max_response_bytes``.

      .. versionadded:: 0.5.0

   Passing ``None`` as the ``http`` argument of any networked function
   selects a process-wide default ``ReqwestClient`` with the default limits.

   .. code-block:: python

      from pygrindvakt import http, rp

      client = http.ReqwestClient(request_timeout=5, max_response_bytes=256 * 1024)
      md = rp.discover(client, "https://op.example.com")
      status, body, content_type = client.get("https://op.example.com/jwks")
