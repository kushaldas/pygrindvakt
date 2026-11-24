Exceptions
==========

.. py:module:: pygrindvakt
   :no-index:

All errors raised by pygrindvakt derive from a single base class,
:class:`GrindvaktError`, so you can catch one base type or a specific subtype.
Every class carries a ``status_hint`` class attribute: the HTTP status that
conventionally accompanies the failure. It is a hint for your own error
handling, not something the binding sends anywhere.

The hierarchy mirrors grindvakt's ``Error`` and ``DpopError`` enums:

.. code-block:: text

   GrindvaktError(Exception)            status_hint
   ├── BadRequestError                  400  (also a ValueError)
   ├── AuthnError                       401
   ├── StateError                       500
   ├── ConfigError                      500  (also a ValueError)
   ├── CryptoError                      500
   ├── AttributeMappingError            500
   ├── JoseError                        500
   │   └── UnknownKeyError              401
   ├── JsonError                        500
   ├── InternalError                    500
   ├── NoBoundEndpointError             404
   ├── UnknownModuleError               404
   ├── OAuthError                       (per code: 400 / 401 / 500 / 503)
   └── DpopError                        400
       ├── DpopInvalidError             400
       ├── DpopReplayError              400
       ├── DpopNonceRequiredError       400
       └── DpopServerError              500

.. danger::

   Only :meth:`OAuthError.to_response` and :meth:`OAuthError.to_redirect`
   produce output that is safe to send to a client. The message of every
   other exception (``str(exc)``) is an operator-facing diagnostic: it may
   name internal hosts, quote upstream error bodies, or describe which
   cryptographic check failed. Log it; never put it in an HTTP response.

.. important::

   A :class:`ConfigError` is a deployment fault, not a failed login or a bad
   request from the user. Do not turn it into a user-visible 4xx or 503 and do
   not show it as "login failed": log it with
   :attr:`~GrindvaktError.log_summary` and re-raise (a 500 and an alert), so a
   broken configuration cannot hide among ordinary failures. Catch
   :class:`ConfigError` before :class:`GrindvaktError`.

.. versionchanged:: 0.3.0

   ``str(OAuthError)`` now escapes control, bidi, invisible-format and tag
   characters (and backslash) in the description and caps it at 512
   characters. This is a behaviour change: the result used to be the raw
   ``"{code}: {description}"``. ``OAuthError.description`` is unchanged: it is
   the raw, untrusted value, so escape it yourself before logging it directly.
   The wire output of :meth:`OAuthError.to_response` and
   :meth:`OAuthError.to_redirect` is unchanged.

Argument validation
-------------------

:class:`BadRequestError` and :class:`ConfigError` both derive from
:class:`GrindvaktError` and the built-in ``ValueError`` (MRO: the class,
``GrindvaktError``, ``ValueError``, ``Exception``). Existing
``except ValueError`` handlers keep working, and ``except GrindvaktError``
catches both.

The rule: a fault in *configuration or wiring*, fixed by changing the
integrator's code or settings, is a :class:`ConfigError` (``status_hint``
500). A malformed value that arrived with a *request* is a
:class:`BadRequestError` (``status_hint`` 400). Configuration faults are
log-only: they are never a client error.

* :class:`ConfigError`: an unknown ``auth_method`` or an inconsistent
  ``client_secret`` / ``signing_key`` combination, an unknown JWS algorithm
  name, a negative ``seconds`` value or a ``leeway`` outside 0 to 300,
  :class:`~pygrindvakt.rp.JwksCache` numeric arguments (``min_ttl`` above
  ``max_ttl``, a bad ``fetch_timeout``), an issuer mismatch between a cache
  and its caller, invalid :class:`~pygrindvakt.rp.ProviderInfo` /
  :class:`~pygrindvakt.rp.RpClient` URLs, :class:`~pygrindvakt.metadata.ProviderMetadata`
  URL and extra-field validation, and invalid ``fetch_userinfo`` options.
* :class:`BadRequestError`: values that may come from a request, such as a
  ``redirect_uri`` override that is not registered, a
  ``post_logout_redirect_uri`` that is not registered, reserved or empty
  ``end_session_url`` parameters, plus the malformed-request reports of
  grindvakt itself (and the standalone validators in
  :mod:`pygrindvakt.discovery` and :mod:`pygrindvakt.federation`).

.. versionchanged:: 0.3.0
   :class:`ConfigError` is also a ``ValueError`` (it was a plain
   :class:`GrindvaktError` subclass), and configuration faults in
   :mod:`pygrindvakt.rp` and :class:`pygrindvakt.metadata.ProviderMetadata`
   raise it instead of :class:`BadRequestError` or a plain ``ValueError``.
   :class:`BadRequestError` is also a ``ValueError``. These sites still raise a
   plain ``ValueError`` and are follow-up work: ``ProviderMetadata.from_dict`` /
   ``from_json`` parse failures, the ``extra`` and ``extra_params`` arguments of
   :mod:`pygrindvakt.rp`, OAuth error-code parsing and
   ``oauth_error_redirect``, and the ``client``, ``tokens``, ``dpop``,
   ``provider``, ``request`` and ``http`` modules. Until those modules migrate,
   ``except ValueError`` is the catch-all for argument errors;
   ``except BadRequestError`` and ``except ConfigError`` only cover
   :mod:`pygrindvakt.rp` and :class:`~pygrindvakt.metadata.ProviderMetadata`.

Base class
----------

.. py:exception:: GrindvaktError

   Base class for every pygrindvakt error.

   .. py:attribute:: code
      :type: str

      A short machine-readable identifier. Every class has a class-level
      default (see :ref:`error-codes`); an instance may override it with a
      more precise value. :attr:`OAuthError.code` has the same meaning.

   .. py:attribute:: status_hint
      :type: int

      The HTTP status conventionally paired with this error class. ``500``
      on the base class; each subclass overrides it as listed above.

   .. py:attribute:: upstream_status
      :type: int | None

      HTTP status of the upstream response that caused this error, else
      ``None``.

   .. py:attribute:: upstream_error
      :type: str | None

      The upstream's OAuth ``error`` code (capped at 64 characters), else
      ``None``.

   .. py:attribute:: upstream_error_description
      :type: str | None

      The upstream's ``error_description``, else ``None``.

   .. py:attribute:: upstream_body
      :type: str | None

      The upstream response body, else ``None``. Control and bidirectional
      characters are escaped and the length is capped.

   .. py:attribute:: auth_failure
      :type: bool

      ``True`` when the failure happened in an authentication step: every
      :class:`AuthnError`, and an upstream token or UserInfo request that was
      rejected. ``False`` for metadata fetches (discovery, JWKS, federation)
      and all other errors. It tells apart a rejected token or UserInfo
      exchange from an unreachable or misbehaving metadata endpoint, and
      nothing more.

      It is **not** a general "authentication failed" flag. It is ``False``
      on :class:`UnknownKeyError` (unknown ``kid`` on a signed JWT), on every
      :class:`DpopError` subclass (including :class:`DpopReplayError`, a
      replay is an attack signal) and on :class:`BadRequestError`. Branch on
      the class for those: do not rely on ``auth_failure`` alone to decide on
      session teardown, alerting or rate-limiting.

      .. versionadded:: 0.3.0

   .. py:attribute:: retryable
      :type: bool

      ``True`` when retrying the same call later may succeed: the upstream
      answered with HTTP status 500 or above or 429, or ``code`` is
      ``transport``, ``jwks_fetch_timeout``, ``discovery_backoff`` or
      ``discovery_fetch_timeout`` (except that ``discovery_backoff`` takes the
      ``retryable`` of the failure it is chained to, see below). This is
      defined by pygrindvakt, not by grindvakt. ``False`` otherwise,
      including for a 4xx answer from the upstream and for every error
      raised for invalid arguments. It says nothing about idempotency or
      backoff; apply your own. In particular it does not make an RP callback
      safe to replay: the pending session is gone and the authorization code
      may be consumed, so start a new login instead (see :doc:`guides/rp`).

      .. versionadded:: 0.3.0

   .. py:attribute:: log_summary
      :type: str

      A one-line description for logs, formatted as
      ``"{ClassName}(code={code!r}, status_hint={n}): {str(exc)}"``. It is
      safe to *log*, not safe to send to clients. ``code`` can be controlled
      by the upstream, but it is escaped and at most 64 characters, and
      ``str(exc)`` is escaped, length-capped and never embeds an upstream
      body. Only :attr:`upstream_error_description` and
      :attr:`upstream_body` are unsafe to log.

      .. versionadded:: 0.3.0

   .. danger::

      ``upstream_error_description`` and ``upstream_body`` are free text from
      the upstream and may echo secrets (credentials, codes, tokens) or
      personal data. Escaping makes them safe to *print*, not safe to
      *disclose*: never log them verbatim and never return them to end users.
      ``upstream_status`` and ``upstream_error`` are not redacted.

   The ``upstream_*`` attributes are ``None`` unless the error was raised
   because an upstream endpoint (token, UserInfo, JWKS, discovery, federation)
   answered with a failure. ``str(exc)`` stays generic and does not contain
   the body, for example ``authentication error: token endpoint returned 400``.

.. _error-codes:

Error codes
-----------

``exc.code`` is the class default unless noted. These values are stable:

.. list-table::
   :header-rows: 1

   * - Class
     - Default ``code``
   * - ``GrindvaktError`` / ``InternalError``
     - ``internal``
   * - ``BadRequestError``
     - ``bad_request``
   * - ``AuthnError``
     - ``authn``
   * - ``StateError``
     - ``state``
   * - ``ConfigError``
     - ``config``
   * - ``CryptoError``
     - ``crypto``
   * - ``AttributeMappingError``
     - ``attribute``
   * - ``JoseError``
     - ``jose``
   * - ``UnknownKeyError``
     - ``unknown_kid``
   * - ``JsonError``
     - ``json``
   * - ``NoBoundEndpointError``
     - ``no_bound_endpoint``
   * - ``UnknownModuleError``
     - ``unknown_module``
   * - ``DpopError``
     - ``dpop``
   * - ``DpopInvalidError``
     - ``invalid_dpop_proof``
   * - ``DpopReplayError``
     - ``dpop_replay``
   * - ``DpopNonceRequiredError``
     - ``use_dpop_nonce``
   * - ``DpopServerError``
     - ``dpop_server``
   * - ``OAuthError``
     - the OAuth error string given at construction

Instance-level overrides:

* A failed token or UserInfo request (``AuthnError``) carries the upstream's
  OAuth ``error`` value when it sent one, for example ``invalid_client`` or
  ``invalid_grant`` (also available as ``upstream_error``). Without one the
  class default ``authn`` applies. Code values from the upstream are
  arbitrary strings; compare against known values, do not assume a closed set.
  This ``code`` is **controlled by the upstream server** (escaped, at most 64
  characters). Branching on ``exc.code == "invalid_grant"`` is fine, but never
  put it into a log line, redirect, template or query string without the same
  care you would give any other untrusted input, and do not treat an unknown
  value as trustworthy. Because of this, never use ``code`` to decide whether
  to retry: use ``retryable``, which is not derived from upstream text (an
  upstream sending ``error=transport`` does not make the failure retryable).
* ``unmet_authentication_requirements`` (``AuthnError``): the provider could
  not meet a requested authentication requirement (core's
  ``UnmetAuthenticationRequirements``). Core 0.13 itself never raises it; an
  application frontend does. It is an authentication failure
  (``auth_failure`` is ``True``, ``status_hint`` is 401) and is not retryable.
* ``userinfo_unverifiable`` (``AuthnError``): :func:`pygrindvakt.rp.fetch_userinfo`
  received a signed (``application/jwt``) UserInfo response but was not given
  everything needed to verify it (``jwks``, ``client_id``,
  ``allowed_algorithms``, ``trust``); it refuses rather than trusting it.
* ``userinfo_encrypted`` (``AuthnError``): the UserInfo response is an
  encrypted JWT (JWE), which is not supported.
* ``transport`` (``InternalError``): an outbound request failed before a
  response was obtained (connection refused, timeout, a Python ``HttpClient``
  that raised). The original failure is chained as ``__cause__``.
  ``retryable`` is ``True``.
* ``response_too_large`` (``InternalError``): an outbound response exceeded the
  client's size cap.
* ``jwks_fetch_timeout`` (``InternalError``): a :class:`pygrindvakt.rp.JwksCache`
  call waited longer than ``fetch_timeout`` seconds for another thread's
  in-flight JWKS fetch. The fetching thread is not interrupted and the cache
  stays usable. ``retryable`` is ``True``.
* ``discovery_fetch_timeout`` (``InternalError``): a
  :class:`pygrindvakt.rp.DiscoveryCache` call waited longer than
  ``fetch_timeout`` seconds for another thread's in-flight discovery fetch.
  The fetching thread is not interrupted and its result is cached.
  ``retryable`` is ``True``.
* ``discovery_backoff`` (``InternalError``): a
  :class:`pygrindvakt.rp.DiscoveryCache` call made no request because the
  last discovery fetch failed less than ``failure_backoff`` seconds ago and no
  stale document may be served (``stale_on_error=False``, none cached, or it
  is older than ``max_stale``). The original failure is chained as
  ``__cause__`` (a copy without traceback, so it holds no frames).
  ``retryable`` is the ``retryable`` of that cause: ``True`` after a
  transport error, an upstream 5xx or 429, ``False`` after a permanent
  failure such as an issuer mismatch or a malformed document.
* ``shared_secret_algorithm`` (``ConfigError``): ``HS256``, ``HS384`` or
  ``HS512`` in ``allowed_algorithms`` together with a
  :class:`pygrindvakt.rp.JwksCache`. A published JWK Set never carries the
  key for MAC-signed ID tokens (OIDC Core section 10.1: it derives from the
  ``client_secret``). Raised before any fetch; there is no override. Verify
  with :func:`pygrindvakt.rp.verify_id_token` and a key set built from the
  ``client_secret`` instead.
* ``weak_shared_secret`` (``ConfigError``): an ``HS*`` token is verified
  against a caller-built key set whose ``oct`` key is shorter than the hash
  output (32, 48 or 64 bytes for ``HS256``, ``HS384``, ``HS512``; RFC 7518
  section 3.2), or whose ``k`` is not strict unpadded base64url. Only the key
  the token selects is checked (its ``kid``, or the only key of a one-key
  set): a weak key elsewhere in the set does not raise, but one selected by
  its ``kid`` does, so keep weak keys out of verifier sets. Raised by
  :mod:`pygrindvakt.rp` verification and, since 0.3.0, also by
  :func:`pygrindvakt.jwt.verify_with_jwks` and
  :func:`pygrindvakt.jwt.verify_with_jwk`. The message never contains the
  key.
* ``symmetric_algorithm`` (``AuthnError``): a federation document passed to
  :func:`pygrindvakt.federation.verify`, ``verify_typed``,
  ``verify_self_signed`` or ``verify_trust_marks`` has a header ``alg`` of ``HS256``, ``HS384``,
  ``HS512`` or ``none``. Entity statements are signed with asymmetric keys.
* ``trust_mark_missing`` (``AuthnError``):
  :func:`pygrindvakt.federation.verify_trust_marks` found no entry of the
  required type.
* ``trust_mark_invalid`` (``AuthnError``): entries of the required type
  exist but none verified (bad signature, ``typ``, ``sub``, ``iss``, lifetime,
  type mismatch, ``delegation``, or no ``exp`` with ``require_exp``).
* ``upstream_http`` (``InternalError``): a discovery, JWKS or federation
  fetch got a failing status. Always this value for such non-auth failures,
  even if the upstream sent an OAuth ``error`` (that stays in
  ``upstream_error``). ``retryable`` is ``True`` for an upstream status of
  500 or above or 429.

.. note::

   ``status_hint`` is a class attribute. For a metadata fetch failure the
   core library suggests 502 (an upstream fault), while the binding keeps
   these on :class:`InternalError`, whose ``status_hint`` is 500. Use
   ``upstream_status`` and ``retryable`` for decisions about the upstream.

.. versionchanged:: 0.3.0
   The stable codes ``jwks_fetch_timeout`` and ``discovery_backoff`` are
   listed above together with the ``retryable`` attribute.
.. versionadded:: 0.3.0
   The codes ``discovery_fetch_timeout`` (and, raised by
   :class:`pygrindvakt.rp.DiscoveryCache`, ``discovery_backoff``).
.. versionadded:: 0.3.0
   The codes ``shared_secret_algorithm``, ``weak_shared_secret`` and
   ``symmetric_algorithm``.
.. versionadded:: 0.7.0
   The codes ``trust_mark_missing`` and ``trust_mark_invalid``.

Transport causes
----------------

When an outbound fetch fails, the raised ``InternalError`` has ``code ==
"transport"`` and the underlying exception as ``__cause__``:

* the exception raised by your Python ``HttpClient`` (the very same object);
* for the built-in ``ReqwestClient``: ``TimeoutError`` for connect, read or
  total timeouts, ``ConnectionError`` for connection failures and ``OSError``
  for other transport or body-read failures. ``response_too_large`` has no
  cause.

The cause is captured per call, so concurrent and nested calls never see each
other's failures, and it is attached only to the error that the failed fetch
itself produced (a tolerated earlier failure is not blamed for an unrelated
error).

grindvakt errors
----------------

One subclass per ``grindvakt::Error`` variant.

.. py:exception:: BadRequestError

   The request was malformed (``status_hint`` 400); also a ``ValueError``.
   Raised, for example, by
   the federation and discovery parsers on an invalid entity identifier or a
   malformed policy, by :meth:`pygrindvakt.federation.EntityStatement.jwks`
   when the statement carries no keys, and by the :mod:`pygrindvakt.rp`
   checks on values that may come from a request (an unregistered
   ``redirect_uri`` or ``post_logout_redirect_uri``, reserved ``extra``
   parameters). It is not used for configuration faults: see
   :class:`ConfigError`.

.. py:exception:: AuthnError

   Authentication failed somewhere in the flow (``status_hint`` 401). This is
   what the Relying Party functions raise when an upstream token endpoint or
   userinfo endpoint rejects the request, when an id_token fails
   verification, when :func:`pygrindvakt.rp.verify_id_token` is called
   without an expected nonce, and when a federation trust chain does not
   validate.

.. py:exception:: StateError

   Flow state could not be sealed or unsealed (``status_hint`` 500).

.. py:exception:: ConfigError

   Configuration is invalid (``status_hint`` 500); also a ``ValueError``.
   Raised, for instance, when :class:`pygrindvakt.provider.RedisStore` cannot
   parse its URL, for an unknown ``auth_method`` or JWS algorithm name, invalid
   :class:`~pygrindvakt.rp.JwksCache` arguments, or an invalid
   :class:`~pygrindvakt.metadata.ProviderMetadata` URL. It is never a client
   error: log ``exc.log_summary`` and re-raise instead of answering the user
   with a 4xx or 503 (catch it before :class:`GrindvaktError`).

   .. versionchanged:: 0.3.0
      Also derives from ``ValueError``.

.. py:exception:: CryptoError

   Cryptographic or key-material failure (``status_hint`` 500): an unknown
   algorithm name, a PKCS#11 key that cannot be loaded, and similar.

.. py:exception:: AttributeMappingError

   Attribute mapping failure (``status_hint`` 500).

.. py:exception:: JoseError

   JOSE (JWS / JWE / JWK) error (``status_hint`` 500): a malformed JWK, a JWKS
   that does not deserialize, a JWK generation failure.

.. py:exception:: UnknownKeyError

   Subclass of :class:`JoseError` (``status_hint`` 401, ``code``
   ``unknown_kid``). Raised by :class:`pygrindvakt.rp.JwksCache` (and by
   :func:`pygrindvakt.rp.verify_id_token` / :func:`pygrindvakt.rp.fetch_userinfo`
   given a cache) when a token's ``kid`` names no key in the issuer's JWK Set
   even after the one rate-limited refresh. It is raised before the signature
   is checked and is the "reject, do not retry" signal for key-rotation
   handling. Because it derives from :class:`JoseError`, not
   :class:`AuthnError`, catch it explicitly if you treat both as a failed
   login.

.. py:exception:: JsonError

   JSON serialization or deserialization error (``status_hint`` 500).

.. py:exception:: InternalError

   Any other internal error (``status_hint`` 500). Outbound HTTP failures
   surface here: connection errors from the built-in client, a response that
   exceeds the size cap, a non-2xx status where one was required, and any
   exception raised by a Python ``HttpClient`` implementation.

.. py:exception:: NoBoundEndpointError

   No endpoint bound to the path (``status_hint`` 404).

.. py:exception:: UnknownModuleError

   Unknown module (``status_hint`` 404).

OAuthError
----------

.. py:exception:: OAuthError(code: str, description: str | None = None, state: str | None = None)

   An OAuth 2.0 / OpenID Connect protocol error (RFC 6749 section 5.2). This
   is the only exception that carries structured, client-facing data, and the
   only one with rendering methods.

   Raised by every :class:`pygrindvakt.provider.Provider` endpoint method and
   by :meth:`pygrindvakt.request.AuthorizationRequest.from_params`.
   Applications may also raise it themselves to translate their own
   authentication failures into a protocol response, for example
   ``OAuthError("access_denied", "wrong password", state)`` when a login form
   is submitted with bad credentials.

   ``code`` must be one of the recognised OAuth error strings:
   ``invalid_request``, ``invalid_client``, ``invalid_grant``,
   ``unauthorized_client``, ``unsupported_grant_type``,
   ``unsupported_response_type``, ``invalid_scope``, ``access_denied``,
   ``login_required``, ``server_error``, ``temporarily_unavailable`` or
   ``invalid_dpop_proof``. An unknown code raises ``ValueError`` at
   construction time, so a typo fails where it is written, not when the
   error is rendered.

   .. py:attribute:: code
      :type: str

      The OAuth error string, e.g. ``"invalid_request"``.

   .. py:attribute:: description
      :type: str | None

      Optional human-readable ``error_description``.

   .. py:attribute:: state
      :type: str | None

      The client's ``state`` value to echo back, if known.

   .. py:property:: http_status
      :type: int

      The HTTP status conventionally returned with this error code: ``400``
      for most codes, ``401`` for ``invalid_client``, ``500`` for
      ``server_error``, ``503`` for ``temporarily_unavailable``.

   .. py:property:: status_hint
      :type: int

      Alias of :attr:`http_status`, kept for parity with the other
      :class:`GrindvaktError` subclasses.

   .. py:method:: with_state(state: str | None) -> OAuthError

      Return a copy carrying ``state`` (the client's value to echo back).

   .. py:method:: to_response() -> pygrindvakt.http.Response

      Render as a direct JSON error response for the token and userinfo
      endpoints, and for authorization-endpoint failures that happen
      **before** the ``redirect_uri`` was validated.

      The result has the correct status, an ``application/json`` body of the
      form ``{"error": ..., "error_description": ...}``, a
      ``cache-control: no-store`` header and, for ``invalid_client``, a
      ``www-authenticate`` header. This output is safe to send to clients.

   .. py:method:: to_redirect(redirect_uri: str, response_mode: str) -> pygrindvakt.http.Response

      Render as a ``302`` redirect back to the client with ``error``,
      ``error_description`` and ``state`` in the query string, or in the URL
      fragment when ``response_mode="fragment"``. Pass the same mode selected
      for the successful authorization response. The mode is mandatory so an
      implicit or hybrid error cannot accidentally fall back to query mode.

      Only call this with a ``redirect_uri`` that has already been validated
      against the registered client, i.e. after
      :meth:`pygrindvakt.provider.Provider.validate_authorization_request`
      succeeded for that request. Redirecting to an unvalidated URI turns
      your OP into an open redirector.

      As a header-injection guard the base ``redirect_uri`` is syntax-checked
      before the response is built. :class:`BadRequestError` is raised if it
      contains whitespace, control, bidi or invisible formatting characters or
      userinfo, is unparsable, or has a fragment; the message never echoes the
      value. This does **not** check that the URI is registered or that its
      scheme is acceptable: exact-match it against the client's registered
      URIs first.

      .. versionchanged:: 0.3.0
         Raises :class:`BadRequestError` for an invalid base ``redirect_uri``.

DPoP errors
-----------

Raised by :func:`pygrindvakt.dpop.validate_proof` and
:func:`pygrindvakt.dpop.validate_resource_proof`. They mirror grindvakt's
``DpopError`` enum and are distinct from :class:`OAuthError` because RFC 9449
gives them their own response shapes; :doc:`guides/dpop` shows how to render
each one.

.. py:exception:: DpopError

   Base class for DPoP proof validation errors (``status_hint`` 400).

.. py:exception:: DpopInvalidError

   The DPoP proof is malformed or fails validation (``status_hint`` 400): a
   bad signature, wrong ``typ``, ``htm`` / ``htu`` mismatch, a stale ``iat``,
   or an ``ath`` that does not match the presented access token. Respond
   with ``invalid_dpop_proof``.

.. py:exception:: DpopReplayError

   The proof's ``jti`` was already seen within its lifetime (``status_hint``
   400). Respond with ``invalid_dpop_proof``.

.. py:exception:: DpopNonceRequiredError

   A server nonce is required but the proof carried none, or carried a stale
   or forged one (``status_hint`` 400). Challenge the client: respond with
   the ``use_dpop_nonce`` error and a fresh
   :func:`pygrindvakt.dpop.issue_nonce` value in a ``DPoP-Nonce`` header.

.. py:exception:: DpopServerError

   The replay store failed, so the proof could not be evaluated
   (``status_hint`` 500). Raised when a Python ``ReplayStore`` raises; the
   original exception has been logged through ``sys.unraisablehook``.

Example
-------

.. code-block:: python

   import logging

   import pygrindvakt
   from pygrindvakt import OAuthError

   log = logging.getLogger(__name__)

   try:
       tr = op.handle_token_request(form_pairs, TOKEN_URL, auth_header=auth)
       resp = tr.to_response()
   except OAuthError as e:
       resp = e.to_response()                 # client-safe: status, JSON body, no-store
   except pygrindvakt.GrindvaktError as e:
       log.exception("token endpoint failed")  # str(e) is for logs only
       resp = OAuthError("server_error").to_response()
