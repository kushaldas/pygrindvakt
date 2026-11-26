pygrindvakt.rp
==============

.. py:module:: pygrindvakt.rp

The Relying Party (client) side of OIDC / OAuth 2.0: discovery, the
authorization URL, code exchange, id_token verification, userinfo, and
``private_key_jwt`` client assertions. :doc:`../guides/rp` shows the full
flow.

Outbound HTTP goes through the ``http`` argument of the networked functions:
``None`` for the built-in client, a :class:`pygrindvakt.http.ReqwestClient`,
or any object implementing :class:`pygrindvakt.http.HttpClientProtocol`.
Networked calls block the calling thread with the GIL released.

.. note:: Nonce policy

   :func:`verify_id_token` refuses to run without an expected nonce unless
   ``unsafe_skip_nonce_check=True`` is passed explicitly. This Python API
   guard makes an intentional nonce-free flow visible in code review.

Provider and client
-------------------

.. py:class:: ProviderInfo(issuer: str, authorization_endpoint: str, token_endpoint: str, userinfo_endpoint: str | None = None, jwks_uri: str | None = None, *, end_session_endpoint: str | None = None, allow_cross_origin_end_session: bool = False)

   The minimal upstream-provider information the RP needs. Immutable. Build
   one by hand for a statically configured provider, or with
   :meth:`from_metadata` from a discovered document.

   Construction validates the issuer and every endpoint as absolute HTTPS
   URLs. Plain HTTP is allowed only when the issuer itself is a loopback HTTP
   development origin, and then only for loopback endpoint hosts. URL
   credentials and fragments are rejected before any credentials can be sent.

   ``end_session_endpoint`` additionally must have the **same origin as the
   issuer** (scheme, host compared case-insensitively after IDNA
   normalisation, and effective port; an explicit default port equals the
   implicit one), because :func:`end_session_url` sends ``id_token_hint`` (the
   full ID token) to that endpoint's host. A cross-origin endpoint raises
   :class:`pygrindvakt.ConfigError` unless
   ``allow_cross_origin_end_session=True`` is passed, for OPs that legitimately
   log out on another origin; the scheme, userinfo and fragment checks still
   apply then. No other endpoint is origin-checked.

   .. py:staticmethod:: from_metadata(metadata: ProviderMetadata, *, allow_cross_origin_end_session: bool = False) -> ProviderInfo

      Build from a :class:`pygrindvakt.metadata.ProviderMetadata` (as
      returned by :func:`discover`); the userinfo endpoint is ``None``
      if the provider does not advertise one. An advertised
      ``end_session_endpoint`` is carried over if it is safe (https, no userinfo
      or fragment) and has the same origin as the issuer, or
      ``allow_cross_origin_end_session=True`` is passed. Otherwise it is dropped
      (``None``) so login never depends on logout; :func:`end_session_url`
      then raises :class:`pygrindvakt.ConfigError`. (The direct constructor is
      strict and raises.)

      A dropped ``end_session_endpoint`` also emits a :class:`UserWarning`
      (it is never silent). That includes a non-string advertised value
      (number, object, list, ...), reported as "non-string value (<type>)".
      :func:`end_session_url` words its :class:`pygrindvakt.ConfigError` from
      the outcome recorded here: not advertised, rejected (cross-origin or
      unsafe) or advertised with a non-string value. The returned object keeps the discovery document
      as :attr:`metadata`, so a caller can tell "no endpoint" from "rejected
      endpoint":

      .. code-block:: python

         info = rp.ProviderInfo.from_metadata(md)
         advertised = info.metadata.end_session_endpoint
         if info.end_session_endpoint is None and advertised is not None:
             log.warning("OP logout endpoint %r was rejected", advertised)

      .. versionchanged:: 0.3.0
         Keeps the source document as :attr:`metadata`.

   .. py:property:: issuer
      :type: str
   .. py:property:: authorization_endpoint
      :type: str
   .. py:property:: token_endpoint
      :type: str
   .. py:property:: userinfo_endpoint
      :type: str | None
   .. py:property:: jwks_uri
      :type: str | None
   .. py:property:: end_session_endpoint
      :type: str | None

      OIDC RP-Initiated Logout endpoint, or ``None``. Validated like the
      other endpoints at construction and bound to the issuer's origin
      (see above). Used by :func:`end_session_url`.

   .. py:property:: metadata
      :type: ProviderMetadata | None

      The :class:`pygrindvakt.metadata.ProviderMetadata` this value was built
      from: set by :meth:`from_metadata`, so
      ``ProviderInfo.from_metadata(discover(...))`` has it; ``None`` for a
      hand-built ``ProviderInfo``. Each
      access returns a copy. It is not part of ``repr()``.

      .. warning::

         EVERY endpoint on ``info.metadata`` (``userinfo_endpoint``,
         ``token_endpoint``, ``authorization_endpoint``, ``jwks_uri``,
         ``end_session_endpoint`` ...) is UNVALIDATED data from the OP
         (ADR 0004 section 3 exempts discovery). Never send credentials or
         tokens to them. Use the validated properties on the
         :class:`ProviderInfo` itself (``info.userinfo_endpoint``,
         ``info.token_endpoint`` ...). The raw ``end_session_endpoint`` is
         kept only so you can diagnose a rejection; never redirect to it.

      Equality, hashing and copying of ``ProviderInfo`` are
      unchanged (it defines no ``__eq__``/``__hash__``, so instances compare
      by identity).

      .. versionadded:: 0.3.0

.. py:class:: RpClient(client_id: str, redirect_uri: str, *, scope: str = "openid profile email", client_secret: str | None = None, auth_method: str | None = None, signing_key: SigningKey | None = None, post_logout_redirect_uris: list[str] | None = None, redirect_uris: list[str] | None = None, allow_unregistered_redirect_uri: bool = False)

   RP client configuration: ``client_id``, the ``redirect_uri`` registered
   at the OP, the requested ``scope``, and how the client authenticates to
   the upstream token endpoint. Immutable.

   ``auth_method`` is one of ``"none"``, ``"client_secret_basic"``,
   ``"client_secret_post"`` or ``"private_key_jwt"``. When omitted it
   defaults to ``client_secret_basic`` if ``client_secret`` is given, else
   ``none``. Inconsistent combinations raise :class:`~pygrindvakt.ConfigError` (also a ``ValueError``) rather than
   being ignored: a secret method without ``client_secret``,
   ``private_key_jwt`` without ``signing_key``, an empty secret, or a secret
   or key that the chosen method would not use.

   ``post_logout_redirect_uris`` registers the post-logout redirect URIs this
   client may use with :func:`end_session_url`. Each is validated like a
   redirect URI (absolute, no fragment) at construction.

   ``redirect_uris`` registers alternative login redirect URIs accepted as
   the per-call ``redirect_uri=`` override of :func:`authorization_url`,
   :func:`signed_request_object`, :func:`begin` and :func:`exchange_code`.
   An override is accepted only if it exactly equals ``redirect_uri`` or one
   entry (plain string comparison, no normalisation); otherwise
   :class:`~pygrindvakt.BadRequestError`. Entries are validated at
   construction (absolute, no fragment) and must not be plain ``http`` to a
   non-loopback host; ``https``, loopback ``http`` and custom/private-use
   schemes (native apps) are allowed. "Loopback" means exactly ``localhost``,
   ``127.0.0.0/8`` or ``::1``. The configured ``redirect_uri`` itself is not
   transport-checked.

   ``allow_unregistered_redirect_uri=True`` skips the registration check
   (the override must still be valid and not plain ``http`` to a non-loopback
   host). Use it only for RFC 7591 dynamic registrations, never with a value
   derived from request data.

   .. versionadded:: 0.2.0
      The ``post_logout_redirect_uris``, ``redirect_uris`` and
      ``allow_unregistered_redirect_uri`` parameters (and their read-only
      properties). Before 0.2.0 any syntactically valid per-call
      ``redirect_uri`` override was accepted.

   .. warning::

      ``client_secret`` is a credential. Load it from a secret store or an
      environment variable rather than embedding it in source; it is held in
      memory as a Python ``str`` for the lifetime of the object and cannot
      be zeroized. It is never included in ``repr()``.

   .. py:property:: client_id
      :type: str
   .. py:property:: redirect_uri
      :type: str
   .. py:property:: scope
      :type: str
   .. py:property:: post_logout_redirect_uris
      :type: tuple[str, ...]

      The registered post-logout redirect URIs (empty if none).
   .. py:property:: redirect_uris
      :type: tuple[str, ...]

      The registered alternative login redirect URIs (empty if none).
   .. py:property:: allow_unregistered_redirect_uri
      :type: bool
   .. py:property:: auth_method
      :type: str

      The resolved token-endpoint authentication method as a string.

   .. code-block:: python

      from pygrindvakt import keys, rp

      confidential = rp.RpClient("demo", "https://rp.example.com/cb", client_secret=os.environ["OIDC_SECRET"])
      public = rp.RpClient("spa", "https://rp.example.com/cb", scope="openid")
      rp_key = keys.signing_key_from_pem(open("rp-key.pem", "rb").read(), kid="rp-1")
      jwt_auth = rp.RpClient("jwt-rp", "https://rp.example.com/cb",
                             auth_method="private_key_jwt", signing_key=rp_key)

.. py:class:: TokenSet

   The result of a successful code exchange. ``access_token``, ``id_token``,
   ``token_type``, ``refresh_token``, ``expires_in`` and ``scope`` are pulled
   out of the response; :attr:`raw` is the full JSON body.
   ``repr()`` never shows the token values.

   .. py:property:: access_token
      :type: str
   .. py:property:: id_token
      :type: str
   .. py:property:: token_type
      :type: str
   .. py:property:: refresh_token
      :type: str | None

      ``raw["refresh_token"]`` if it is a string, else ``None``. A long-lived
      credential: store it encrypted and never log it. ``repr()`` shows only
      ``refresh_token=<set>`` or ``None``.

      .. versionadded:: 0.3.0
   .. py:property:: expires_in
      :type: int | None

      ``raw["expires_in"]`` in seconds: a non-negative JSON integer (an
      integral float is accepted) or a digits-only string, at most 10 years
      (315360000 seconds). ``None`` means "absent or not acceptable"
      (negative, non-integer, garbage, longer than 10 years), NEVER "no
      expiry": apply your own default lifetime when it is ``None`` and do not
      treat ``None`` as unbounded.

      .. versionadded:: 0.3.0
   .. py:property:: scope
      :type: str | None

      ``raw["scope"]`` if it is a string, else ``None``. The granted scope,
      which the OP may have narrowed.

      .. versionadded:: 0.3.0
   .. py:property:: raw
      :type: dict[str, Any]

      The complete token-endpoint response as a dict.

Starting the flow
-----------------

.. py:function:: authorization_url(provider: ProviderInfo, client: RpClient, state: str, nonce: str, code_challenge: str | None = None, extra: dict[str, str] | list[tuple[str, str]] | None = None, *, redirect_uri: str | None = None) -> str

   Build the authorization request URL to redirect the user to, with
   ``response_type=code``, the client's id, redirect URI and scope,
   ``state``, ``nonce`` and, when ``code_challenge`` is given,
   ``code_challenge_method=S256``. An authorization endpoint that already
   has a query string is extended with ``&``.

   ``state`` and ``nonce`` must be fresh random values bound to the user's
   session (:func:`pygrindvakt.util.random_token`); ``code_challenge`` is the
   PKCE ``S256`` challenge (:func:`pygrindvakt.pkce.s256_challenge`).
   ``extra`` adds further query parameters, as a dict or as a list of
   ``(name, value)`` pairs when a name must repeat; anything else raises
   ``ValueError``. Library-controlled parameter names and ambiguous duplicate
   extension names are rejected; repeatable ``resource`` remains supported.

   ``redirect_uri`` overrides the client's configured value for this call
   only. It must be an absolute URL without a fragment, else
   :class:`pygrindvakt.BadRequestError` is raised, and the same value must
   be passed to :func:`exchange_code`; keep it in the session.

.. py:function:: begin(provider: ProviderInfo, client: RpClient, *, extra: dict[str, str] | list[tuple[str, str]] | None = None, redirect_uri: str | None = None, pkce: bool = True, request_object_key: SigningKey | None = None) -> BeginResult

   Start an authorization-code flow: generate a fresh ``state`` and
   ``nonce`` (32 random bytes each, base64url) and a PKCE verifier (48
   random bytes, 64 characters), and return a :class:`BeginResult`
   ``(url, state, nonce, code_verifier)``. The challenge is ``S256``. Store
   ``state``, ``nonce`` and ``code_verifier`` (and ``redirect_uri`` if
   overridden) in the user's session.

   ``pkce=False`` omits PKCE and returns ``None`` as the code verifier; it is
   refused with :class:`pygrindvakt.ConfigError` for public clients
   (``auth_method="none"``). With ``request_object_key`` a signed request
   object (see :func:`signed_request_object`) is added as the ``request``
   parameter. ``extra`` and ``redirect_uri`` behave as in
   :func:`authorization_url`.

.. py:class:: BeginResult

   The return type of :func:`begin`: a :func:`collections.namedtuple`
   subclass with the fields ``url: str``, ``state: str``, ``nonce: str`` and
   ``code_verifier: str | None`` (the name matches the ``code_verifier``
   parameter of :func:`exchange_code`). It is a real :class:`tuple`: unpacking
   (``url, state, nonce, verifier = rp.begin(...)``), indexing, ``==`` and
   ``isinstance(x, tuple)`` all keep working, and ``_fields`` / ``_replace``
   are available.

   ``state``, ``nonce`` and ``code_verifier`` are secrets, so ``repr()``
   redacts them, and the query of ``url`` (which carries ``state`` and
   ``nonce``) is replaced by ``?…``::

      BeginResult(url='https://op.example.com/authorization?…', state=<redacted>, nonce=<redacted>, code_verifier=<redacted>)

   A ``code_verifier`` of ``None`` (``pkce=False``) is shown as ``None``.

   .. versionadded:: 0.3.0

.. py:function:: signed_request_object(provider: ProviderInfo, client: RpClient, key: SigningKey, state: str, nonce: str, code_challenge: str | None = None, *, redirect_uri: str | None = None, claims: dict[str, Any] | None = None, prompt: str | None = None, ui_locales: str | None = None, acr_values: str | None = None, max_age: int | None = None, sign_request: dict[str, Any] | None = None) -> str

   Build a signed request object (RFC 9101, "JAR") carrying the
   authorization-request parameters as JWT claims, signed with ``key``, with
   ``iss`` = the client id, ``aud`` = the issuer, a 300-second lifetime and
   a ``jti``.

   OpenID Federation automatic registration needs this: pass the result as
   the ``request`` parameter via ``authorization_url(..., extra={"request":
   jar})``. ``key`` must be one of the RP's published client keys. ``redirect_uri`` overrides the client's value, as
   in :func:`authorization_url`.

   The keyword arguments ``claims`` (OIDC ``claims`` request), ``prompt``,
   ``ui_locales``, ``acr_values``, ``max_age`` and ``sign_request`` (sent as
   ``https://id.oidc.se/param/signRequest``, for Sweden Connect signature
   requests) are placed inside the signed payload and omitted when ``None``.
   ``claims`` and ``sign_request`` must be dicts (``TypeError`` otherwise) and
   keep their JSON types. :func:`begin` does not take them: build the request
   object yourself and pass it via ``extra={"request": jar}``.

   .. warning::

      RFC 9101 section 3 minimal-query rule: the query should carry only
      ``client_id``, ``response_type`` and ``request``. Do not repeat
      parameters that are inside the signed request object: an OP that reads
      the unsigned copy would apply a weaker value (for example ``max_age``,
      ``acr_values``, ``claims``, ``prompt``, ``ui_locales`` or
      ``signRequest``). :func:`authorization_url` and :func:`begin` currently
      still add the plain parameters to the query, so the OP must take them
      from the request object only. ``sign_request`` is attacker-influenced
      data for OP integrators that render it; the OP must cap its size.

   .. versionchanged:: 0.7.0
      Added ``claims``, ``prompt``, ``ui_locales``, ``acr_values``,
      ``max_age`` and ``sign_request``.

Discovery and keys
------------------

.. py:function:: discover(http: HttpClientProtocol | None, issuer: str) -> ProviderMetadata

   Discover provider metadata from ``issuer``
   (``<issuer>/.well-known/openid-configuration``).

   The issuer must be an ``https`` URL (plain ``http`` only for loopback
   hosts), and the ``issuer`` in the returned document must match the
   requested one exactly (OIDC Discovery section 4.3). Raises
   :class:`pygrindvakt.InternalError` on a transport failure or non-200,
   :class:`pygrindvakt.AuthnError` / :class:`pygrindvakt.BadRequestError`
   on an issuer mismatch or unusable document.

   The result's :attr:`~pygrindvakt.metadata.ProviderMetadata.raw` is the
   response body as fetched (parsed to a dict), obtained by recording the body
   handed to the upstream discovery routine; no validation is reimplemented.

.. py:function:: end_session_url(provider: ProviderInfo, *, id_token_hint: str | None = None, client: RpClient | None = None, post_logout_redirect_uri: str | None = None, state: str | None = None, logout_hint: str | None = None, ui_locales: str | None = None, extra: dict[str, str] | list[tuple[str, str]] | None = None) -> str

   Build the OIDC RP-Initiated Logout 1.0 URL to redirect the user to.
   Parameters are appended to ``provider.end_session_endpoint`` (an existing
   query is preserved) with proper percent-encoding. ``client`` adds
   ``client_id``. ``post_logout_redirect_uri`` is accepted **only** when
   ``client`` is given and the value exactly equals (string equality, as
   RP-Initiated Logout requires) one of ``client.post_logout_redirect_uris``;
   anything else, including an ``id_token_hint``-only call, raises
   :class:`pygrindvakt.BadRequestError`. Registration is structural so that a
   value taken from a request parameter cannot turn logout into an open
   redirect. It must also be registered at the OP. ``extra`` may not
   contain ``id_token_hint``, ``client_id``, ``post_logout_redirect_uri``,
   ``state``, ``logout_hint`` or ``ui_locales``, and neither may the endpoint's
   own query. ``id_token_hint`` is sent to the first hop, the host of
   ``provider.end_session_endpoint``. Raises :class:`pygrindvakt.ConfigError`
   when the provider's endpoint was missing, unsafe, or on a different origin
   than the issuer (so it is ``None``), or invalid, and
   :class:`pygrindvakt.BadRequestError` for unregistered or invalid
   caller-supplied values. ``state`` is echoed back to ``post_logout_redirect_uri``
   by the OP; generate it like the login ``state`` and verify it.

   .. versionadded:: 0.2.0

.. py:function:: fetch_jwks(http: HttpClientProtocol | None, jwks_uri: str, issuer: str) -> dict[str, Any]

   Fetch a JWKS document from ``jwks_uri`` for its associated ``issuer``
   and return it as a dict (``{"keys": [...]}``), ready for
   :func:`verify_id_token`. The issuer is mandatory so remote metadata cannot
   inherit the loopback HTTP development exception. This is a single
   uncached fetch; use :class:`JwksCache` to cache the key set and handle key
   rotation.

   A published JWK Set must not carry symmetric keys (OIDC Core 10.1). Every
   ``oct`` key is dropped from the returned dict and a ``UserWarning``
   ("published JWKS contains a symmetric (oct) key, ignored") is emitted once
   per call, so the result can never verify an ``HS256`` / ``HS384`` /
   ``HS512`` token. For MAC-signed ID tokens build the key set from the
   ``client_secret`` instead (see :func:`verify_id_token`).

   The drop is unconditional and fail-closed: it happens even when
   :mod:`warnings` is configured to raise (the warning can be suppressed, or
   turned into an error that is discarded, but the key is dropped regardless).
   The warning fires once per call; there is no global dedup. Python's
   warnings registry collapses identical messages per location by default,
   but under ``simplefilter("always")`` or ``"error"`` it fires on every
   call. The returned dict therefore may not equal the OP's published
   document: callers that cache or diff it should use a warnings filter or
   :class:`JwksCache`, which caches the filtered set.
   The filter covers key sets this library fetches from a ``jwks_uri``. A JWKS
   dict you fetched or assembled yourself is a caller-built key set by
   definition, and the library cannot tell it from one derived from a
   ``client_secret``: never feed a fetched set into an ``HS*`` allow-list.
   Inline JWKS in signed federation entity statements is handled by
   :func:`pygrindvakt.federation.entity_metadata_jwks`, which filters it the
   same way.

   .. versionchanged:: 0.3.0
      ``oct`` keys are dropped with a ``UserWarning``.

.. py:class:: JwksCache(http: HttpClientProtocol | None, jwks_uri: str, issuer: str, *, default_ttl: int = 3600, min_ttl: int = 60, max_ttl: int = 86400, min_refresh_interval: int = 30, fetch_timeout: float = 45.0)

   A thread-safe cache of one issuer's JWK Set (frozen; read-only
   ``jwks_uri`` and ``issuer`` properties). ``jwks_uri`` and ``issuer`` are
   validated at construction exactly as :func:`fetch_jwks` does, and so is
   ``http``; no request is made until first use. Pass the cache wherever a
   ``jwks`` dict is accepted: :func:`verify_id_token` and, for signed
   responses, :func:`fetch_userinfo`.

   **Shared secrets are refused.** The cache holds a *published* JWK Set, and
   an OP must not publish symmetric keys (OIDC Core 10.1): ``HS256`` /
   ``HS384`` / ``HS512`` ID tokens are MAC'd with a key derived from the
   ``client_secret``. So ``HS256``, ``HS384`` or ``HS512`` in
   ``allowed_algorithms`` of :meth:`verify_id_token` (or of
   :func:`verify_id_token` / :func:`fetch_userinfo` given the cache) raises
   :class:`pygrindvakt.ConfigError` with ``code == "shared_secret_algorithm"``,
   before any fetch and with no override. A fetched ``oct`` key is dropped
   from the cached set (and from :meth:`jwks`) with a ``UserWarning`` once per
   fetch. Verify such tokens with :func:`verify_id_token` and a key set you
   build from the client secret.

   .. versionchanged:: 0.3.0
      ``HS*`` algorithms are refused and fetched ``oct`` keys are ignored.

   **Lifetime.** The set lives for the response's ``Cache-Control: max-age``
   minus its ``Age`` header when present, otherwise ``default_ttl`` seconds,
   clamped to ``[min_ttl, max_ttl]``. ``no-store``, ``no-cache`` and
   ``max-age=0`` (and an ``Age`` that exhausts ``max-age``) give a lifetime of
   0, which ``min_ttl`` then raises: with the default ``min_ttl=60`` such a
   response is still reused for 60 seconds, protecting the OP from a refetch
   on every request. Pass ``min_ttl=0`` to honour those directives literally
   (every use refetches). ``min_ttl`` must not exceed ``max_ttl``; negative
   values raise :class:`~pygrindvakt.ConfigError` (also a ``ValueError``).

   .. note::

      ``Cache-Control`` and ``Age`` are honoured only when the HTTP client
      reports response headers. The built-in
      :class:`~pygrindvakt.http.ReqwestClient` (or ``None``) always does; a
      Python :class:`~pygrindvakt.http.HttpClientProtocol` must return them
      (a 4-tuple, or :class:`~pygrindvakt.http.HttpFetchResponse` with
      ``headers``). Otherwise the lifetime is ``default_ttl`` (clamped) and a
      ``UserWarning`` is emitted on the cache's first fetch, so a revoked key
      can stay trusted for up to ``default_ttl``: return headers, or lower
      ``default_ttl`` / ``max_ttl``. ``no-store``, ``no-cache`` and
      ``max-age=0`` are floored to ``min_ttl``; ``min_ttl=0`` makes them
      uncached.

   **Never stale.** An expired set is not served. If the refetch fails,
   :meth:`jwks` and the verification methods raise the fetch error (transport
   failures as :class:`pygrindvakt.InternalError` with ``code == "transport"``
   and the original exception as ``__cause__``; non-200 answers with
   ``upstream_status`` and ``code == "upstream_http"``). Failed fetches are
   not cached, so the next call tries again; a failure while refreshing for an
   unknown ``kid`` keeps the still-valid cached set.

   **Concurrency.** Callers share one in-flight fetch: sixteen threads that
   find the cache empty or expired cause a single request, and the others wait
   (with the GIL released) and reuse its result. The GIL is released during
   the fetch. Do not call a cache from inside its own HTTP client.

   ``fetch_timeout`` (seconds, finite and at least 1e-9, else :class:`~pygrindvakt.ConfigError`;
   default 45, the built-in client's 30 second timeout plus margin; also a
   read-only attribute) bounds how long a thread *waits* for another thread's in-flight
   fetch, in :meth:`jwks`, :meth:`refresh` and both verification paths
   (including the unknown-``kid`` refresh). On expiry the waiter raises
   :class:`pygrindvakt.InternalError` with ``code == "jwks_fetch_timeout"``
   (not ``UnknownKeyError``). It is real time, independent of the cache
   lifetime. It does **not** interrupt the thread running the fetch: that
   thread runs your HTTP client, which must set its own network timeouts (the
   built-in :class:`~pygrindvakt.http.ReqwestClient` has a 30 second request
   timeout). A Python adapter that stalls still stalls its own caller; the
   other threads give up after ``fetch_timeout``, and when the fetch finally
   ends its result is cached and later calls proceed normally.

   **Fork.** The cache is plain in-process memory, so a forked child keeps
   the cached set and its expiry (the clock is monotonic). As with the rest of
   the library, fork only while no other thread is inside a call.

   .. py:method:: jwks() -> dict[str, Any]

      The key set as a new dict, fetched first if none is cached or it has
      expired.

   .. py:method:: refresh() -> None

      Force a refetch. The very first fetch always goes through; after that a
      call within ``min_refresh_interval`` seconds of the previous fetch
      attempt (successful or not) returns without fetching. A failing fetch
      raises and leaves the cached set in place.

   .. py:method:: verify_id_token(id_token: str, client_id: str, expected_nonce: str | None, allowed_algorithms: list[str], *, trusted_additional_audiences: list[str] | None = None, unsafe_skip_nonce_check: bool = False, leeway: int | None = None, max_age: int | None = None, acr_values: list[str] | None = None, access_token: str | None = None, require_at_hash: bool = False, authorization_code: str | None = None, require_c_hash: bool = False, strict_hashes: bool = False) -> dict[str, Any]

      :func:`verify_id_token` against this cache's key set, with the cache's
      ``issuer`` as the expected issuer; the options are those of the
      function. Argument errors (missing nonce, bad algorithm name, ``leeway``
      above 300, ``require_at_hash`` without ``access_token``, an empty
      ``acr_values``) are raised before anything is fetched.

      The token's header is read without verification to find its ``kid``.
      If the cached set has keys with a ``kid`` and none equals the token's,
      the set is refetched once and the check repeated; if it still names no
      key, :class:`pygrindvakt.UnknownKeyError` (``code == "unknown_kid"``) is
      raised without verifying anything. That refetch happens at most once per
      ``min_refresh_interval`` seconds across all callers, counted from the
      previous fetch attempt, so a stream of tokens with random ``kid`` values
      cannot make the RP hammer the OP (they get ``UnknownKeyError`` without a
      fetch). A set whose keys have no ``kid``, and a token without one,
      behave as in :func:`verify_id_token`: no refresh, and the usual
      :class:`pygrindvakt.AuthnError`.

   .. versionadded:: 0.2.0

.. py:class:: DiscoveryCache(http: HttpClientProtocol | None, issuer: str, *, default_ttl: int = 3600, min_ttl: int = 60, max_ttl: int = 86400, failure_backoff: int = 10, stale_on_error: bool = True, max_stale: int = 86400, fetch_timeout: float = 45.0, allow_cross_origin_end_session: bool = False)

   A thread-safe cache of one issuer's discovery document (frozen; read-only
   ``issuer``, ``failure_backoff`` and ``fetch_timeout`` properties). ``issuer``
   is validated at construction exactly as :func:`discover` does (and a
   backslash is refused), and so is ``http``; negative ``default_ttl``,
   ``min_ttl``, ``max_ttl``, ``failure_backoff`` or ``max_stale``, a
   ``min_ttl`` above ``max_ttl`` and a ``fetch_timeout`` that is not finite or
   below 1e-9 raise :class:`~pygrindvakt.ConfigError`. A ``default_ttl``
   outside ``[min_ttl, max_ttl]`` is clamped, not rejected. No request is made
   until first use. The cache is the long-lived counterpart of
   :func:`discover`, which stays a one-shot primitive and is unchanged.

   .. versionadded:: 0.3.0

   **Lifetime.** The document lives for the response's
   ``Cache-Control: max-age`` minus its ``Age`` header when present, otherwise
   ``default_ttl`` seconds, clamped to ``[min_ttl, max_ttl]``. ``no-store``,
   ``no-cache`` and ``max-age=0`` give 0, which ``min_ttl`` raises (``min_ttl=0``
   leaves them uncached). As for :class:`JwksCache`, headers are honoured only
   when the HTTP client reports them; otherwise ``default_ttl`` applies and a
   ``UserWarning`` is emitted on the first fetch.

   **Issuer binding.** Every fetch goes through :func:`discover`, so a
   document whose ``issuer`` differs from the configured one raises
   (:class:`pygrindvakt.AuthnError`, the same error as :func:`discover`) and is
   never cached or served; the previous good document, if any, stays the only
   candidate for stale serving.

   **Failure policy.** After a failed fetch no network call is made for
   ``failure_backoff`` seconds. Inside that window, and when the refetch of an
   expired entry fails:

   * the previous document is served if ``stale_on_error`` is true **and** the
     entry expired less than ``max_stale`` seconds ago; a one-time
     ``UserWarning`` is emitted when stale metadata is first served after a
     failure (again after the next outage);
   * otherwise the call that hit the network raises the original error, and
     calls inside the window raise :class:`pygrindvakt.InternalError` with
     ``code == "discovery_backoff"`` and the original error as ``__cause__``
     (a copy without traceback). Its ``retryable`` is that of the cause:
     ``True`` for a transient failure (transport, upstream 5xx or 429),
     ``False`` for a permanent one (issuer mismatch, malformed document).

   With ``stale_on_error=False`` an expired document is never served. A
   document older than ``max_stale`` past its expiry is never served. An
   unexpired document is served regardless. This differs from
   :class:`JwksCache`, which never serves an expired key set: metadata changes
   rarely, and an outage of the well-known endpoint should not break login
   for a day. Keys stay never-stale because :meth:`jwks` returns a real
   :class:`JwksCache` with its own policy. See ADR 0008.

   **Concurrency.** Callers share one in-flight fetch. ``fetch_timeout``
   (seconds) bounds how long a thread *waits* for another thread's fetch; on
   expiry the waiter first applies the stale policy above: with
   ``stale_on_error`` true and a previous document that expired less than
   ``max_stale`` seconds ago it is served (with the one-time ``UserWarning``);
   otherwise the waiter raises :class:`pygrindvakt.InternalError` with
   ``code == "discovery_fetch_timeout"`` (``retryable`` is ``True``). The
   fetching thread is not interrupted (your HTTP client must set its own
   network timeouts) and its result is cached when it finishes.

   **Fork.** The cache is plain in-process memory, so a forked child keeps the
   cached document and its expiry (the clock is monotonic). As with the rest
   of the library, fork only while no other thread is inside a call.

   .. py:method:: metadata() -> ProviderMetadata

      The discovery document, fetched first if none is cached or it expired,
      subject to the failure policy above.

   .. py:method:: info() -> ProviderInfo

      ``ProviderInfo.from_metadata(metadata())``, built once per fetch, so the
      ``UserWarning`` of ``from_metadata`` (a dropped ``end_session_endpoint``)
      is emitted once per fetch and not on every call.
      ``allow_cross_origin_end_session`` is passed through.

   .. py:method:: jwks() -> JwksCache

      A :class:`JwksCache` bound to ``info().jwks_uri`` and ``info().issuer``,
      sharing this cache's HTTP client, clock and ``fetch_timeout`` and using
      the :class:`JwksCache` constructor defaults for the TTL parameters
      (``default_ttl=3600``, ``min_ttl=60``, ``max_ttl=86400``,
      ``min_refresh_interval=30``). The SAME object is
      returned across metadata refreshes, so the keys cached in it survive;
      it is replaced only when a new document advertises a different
      ``jwks_uri`` or issuer, and the old object is then never returned again
      (call ``jwks()`` each time instead of holding on to the result, since
      an old object keeps verifying against the old ``jwks_uri``). Under
      concurrency a caller that still holds an older metadata document than
      the one the installed cache was built for is given the installed
      (newer) cache; an older document never replaces a newer cache.

   .. py:method:: refresh() -> None

      Force a refetch of the document. A call within ``failure_backoff``
      seconds of a failed fetch returns without fetching. A failing fetch
      raises the original error and leaves the cached document in place.

The authorization response
--------------------------

.. py:function:: parse_authorization_response(params: HttpRequestData | Sequence[tuple[str, str]] | Mapping[str, Sequence[str]], *, response_mode: Literal["query", "fragment", "form_post"] | None = None, accept_jarm: bool = False) -> AuthorizationResponse

   Parse the authorization response (the callback) of an authorization
   request, failing closed. This is the RP-side counterpart of
   :class:`pygrindvakt.request.AuthorizationRequest`
   (`ADR 0007 <https://github.com/kushaldas/pygrindvakt/blob/main/docs/adr/0007-authorization-response-parsing.md>`_).

   ``params`` takes one of three shapes:

   * a :class:`pygrindvakt.http.HttpRequestData`: a ``GET`` is read from
     ``query_pairs`` (mode ``query``), a ``POST`` from ``form_pairs`` (mode
     ``form_post``). A response parameter (``code``, ``state``, ``error``,
     ``error_description``, ``error_uri``, ``iss``, ``response``) in the
     channel that is not read raises :class:`pygrindvakt.BadRequestError`
     for both methods (the query string of a ``POST``, the form body of a
     ``GET``), so a request cannot smuggle a second value past the one that
     is parsed. A ``POST`` without any form parameters raises too, saying
     that a ``form_post`` callback needs a form body: parse the form before
     building the ``HttpRequestData``. Any other method raises
     ``BadRequestError``. If the channel that is read (``query`` for a
     ``GET``, ``form`` for a ``POST``) is non-empty and was built from, or
     last assigned, a mapping (``query={...}``, ``req.query = {...}``), a
     :class:`TypeError` is raised: a mapping discards duplicate parameters.
     Build it from a list of pairs (``request.args.items(multi=True)``). An
     empty mapping is accepted.
   * an ordered list of ``(str, str)`` pairs, for example
     ``urllib.parse.parse_qsl(qs, keep_blank_values=True)``;
   * a multi-dict ``{name: [values]}``, the shape ``urllib.parse.parse_qs``
     returns, which is flattened into pairs with duplicates preserved;
   * an object with a ``lists()`` method yielding ``(name, [values])``, such
     as a werkzeug ``MultiDict`` (``request.args``), read by duck typing so
     duplicates are kept.

   Pass ``keep_blank_values=True`` to ``parse_qsl`` and ``parse_qs``. By
   default they drop blank values, so ``code=valid&code=&state=expected``
   reaches this function without its second ``code``: the duplicate is
   hidden and the fail-closed refusal never happens.

   A mapping with a non-list value, such as a plain ``dict[str, str]``,
   raises ``TypeError`` naming the offending key: a mapping discards
   duplicate parameters before this function can see them. For a dict
   subclass the message suggests ``request.args.items(multi=True)`` (a list
   of pairs) or ``request.args.lists()``.

   ``response_mode`` labels list and multi-dict input as ``"query"``
   (the default), ``"fragment"`` (the caller parsed ``location.hash``
   client-side and posted it) or ``"form_post"``; any other value raises
   :class:`pygrindvakt.ConfigError`. For an ``HttpRequestData`` it must be
   omitted or equal the mode implied by the method.

   Raises :class:`pygrindvakt.BadRequestError` (per-request input) when:

   * a parameter name or value in pairs, multi-dict or ``.lists()`` input is
     not valid Unicode (a lone surrogate, for example from a decoded
     ``\ud800``); the message names the parameter only when it is a known
     protocol parameter and never echoes the value. A name or value that is
     not a ``str`` at all is a programmer error and raises :class:`TypeError`,
     as does constructing ``HttpRequestData`` with a lone surrogate;
   * ``code``, ``state``, ``error``, ``error_description``, ``error_uri``,
     ``iss`` or ``response`` appears more than once;
   * ``code`` and ``error`` are both present, or neither is (unless
     ``response`` is present and ``accept_jarm=True``);
   * ``code``, ``state``, ``error`` or ``iss`` is the empty string;
   * ``response`` is the empty string;
   * ``code``, ``state`` or ``iss`` contains a control character (newline,
     NUL, tab, DEL, ...), a bidi or invisible formatting character, or a
     backslash. Otherwise they are kept verbatim, without trimming;
   * ``code``, ``state`` or ``iss`` is longer than 2048 characters (the
     message does not echo the value);
   * ``response`` (JARM) is longer than 32768 characters (the message does
     not echo the value);
   * ``error`` is longer than 64 characters or outside the RFC 6749
     section 5.2 character set (``%x20-21 / %x23-5B / %x5D-7E``);
   * ``response`` (JARM) is present and ``accept_jarm`` is false;
   * ``response`` (JARM) is present together with ``code``, ``state``,
     ``error``, ``error_description``, ``error_uri`` or ``iss``: a JARM
     response carries everything inside the JWT, and plaintext parameters
     next to it are a downgrade / confusion vector.

   Unknown ``error`` values are **kept**, never rejected, so a new or
   proprietary code does not break the login page; check
   :attr:`AuthorizationResponse.error_known`.

   .. warning::

      The result proves nothing by itself. Before using the code the caller
      MUST compare ``state`` with the value stored in the session (in
      constant time, for example ``mac.constant_time_eq`` on the UTF-8
      bytes), compare ``iss`` with
      :meth:`AuthorizationResponse.matches_iss`, and only then exchange the
      code with :func:`exchange_code`. Parsing does none of these.

   .. note::

      JARM (JWT Secured Authorization Response Mode) is parsed only as a
      stub. With ``accept_jarm=True`` the raw ``response`` JWT is exposed as
      :attr:`AuthorizationResponse.response` and is **UNVERIFIED and
      untrusted**: ``code``, ``state`` and ``error`` are ``None`` and
      ``matches_state`` / ``matches_iss`` return ``False``. Call
      :meth:`AuthorizationResponse.verify_jarm` to verify it and get the inner
      response. If you requested a JARM response mode, call ``verify_jarm``
      on every callback without checking :attr:`AuthorizationResponse.response`
      first: ``accept_jarm=True`` also accepts a plain code or error response,
      and ``verify_jarm`` rejects that with ``BadRequestError`` instead of
      letting unsigned parameters through.

   The shape rules (duplicates, blank values, character set and length caps,
   both / neither of ``code`` and ``error``) are enforced by the core
   library's callback parser
   (`ADR 0009 <https://github.com/kushaldas/pygrindvakt/blob/main/docs/adr/0009-core-callback-parser-and-jarm-verification.md>`_).

   .. versionadded:: 0.3.0

.. py:class:: AuthorizationResponse

   A parsed authorization response. Immutable, with no public constructor;
   build it with :func:`parse_authorization_response`. Every value comes from
   the OP (or from whoever crafted the callback URL) and is untrusted.
   ``repr()`` shows ``is_error``, ``error``, ``iss`` and ``response_mode``
   but only ``<set>`` / ``None`` for ``code`` and ``state``, never their
   values.

   .. py:property:: code
      :type: str | None

      The authorization code, verbatim, or ``None`` for an error response.
   .. py:property:: state
      :type: str | None

      The ``state`` echoed by the OP, verbatim.
   .. py:property:: error
      :type: str | None

      The OAuth error code, or ``None``.
   .. py:property:: error_description_safe
      :type: str | None

      ``error_description`` with control, bidi and invisible characters
      escaped (``\n``, ``\u{202e}``, ...) and capped at 256 characters
      (the escaper behind ``OAuthError.__str__``). The raw ``error_description`` is
      provider-controlled text and is **not available by design**: there is no
      ``error_description`` attribute. Even the safe form is for logs and
      plain-text display, not for HTML without escaping.
   .. py:property:: error_uri
      :type: str | None

      ``error_uri`` only if it is an absolute ``https`` URL (plain ``http``
      only for loopback hosts, the same transport rule as redirect URIs)
      with a host, at most 2048 characters, without whitespace, control
      characters, backslash, userinfo or fragment; otherwise ``None`` (no
      exception). The **normalised** URL is returned, so what you see is
      what was validated (``https:evil.example/x`` becomes
      ``https://evil.example/x``). It is untrusted: never
      follow it automatically and never render it as a link without your own
      validation. It is not bound to the issuer's origin (that would need an
      expected-issuer input and is out of scope).
   .. py:property:: iss
      :type: str | None

      The RFC 9207 ``iss`` parameter, verbatim. Compare it with
      :meth:`matches_iss`.
   .. py:property:: response
      :type: str | None

      The raw JARM ``response`` JWT, at most 32768 characters; only set with
      ``accept_jarm=True``. UNVERIFIED and untrusted. Verify it with
      :meth:`verify_jarm`.
   .. py:property:: jarm_verified
      :type: bool

      ``True`` only for the result of a successful :meth:`verify_jarm`.
   .. py:property:: response_mode
      :type: str

      ``"query"``, ``"fragment"`` or ``"form_post"``.
   .. py:property:: is_error
      :type: bool

      ``True`` when ``error`` is present.
   .. py:property:: error_known
      :type: bool

      ``True`` when ``error`` is a code the binding knows: RFC 6749
      sections 4.1.2.1 and 5.2, OIDC Core section 3.1.2.6, and the
      DPoP ``invalid_dpop_proof``. ``False`` for any other value
      (and when there is no error).

      .. warning::

         "Known" is **wider** than what :class:`pygrindvakt.OAuthError`
         accepts. ``OAuthError`` accepts 12 of them (plus ``unmet_authentication_requirements``,
         see below); the other 8 known codes
         (``interaction_required``, ``account_selection_required``,
         ``consent_required``, ``invalid_request_uri``,
         ``invalid_request_object``, ``request_not_supported``,
         ``request_uri_not_supported``, ``registration_not_supported``) make
         ``OAuthError(resp.error)`` raise :class:`ValueError`. Never build an
         ``OAuthError`` from a callback value without catching
         ``ValueError``; branch on the ``resp.error`` string instead.

         Conversely, ``unmet_authentication_requirements`` is accepted by
         ``OAuthError`` since 0.6.0 but is not in core's known list, so
         ``error_known`` is ``False`` for it.

   .. py:method:: matches_iss(expected: str, *, required: bool = True) -> bool

      RFC 9207 issuer check, fail closed: ``True`` when ``iss`` equals
      ``expected`` exactly (byte for byte; no case folding, no trailing-slash
      normalisation). When the response has no ``iss`` the result is
      ``not required``, so ``False`` by default. An empty ``expected`` is a
      configuration fault and always gives ``False``, regardless of
      ``required``; so does an unverified JARM stub
      (``response`` set, even with ``required=False``). Never raises. The caller
      MUST call it. Pass ``required=False`` **only** when the OP does not
      advertise ``authorization_response_iss_parameter_supported`` in its
      metadata (RFC 9207 section 2.4); otherwise a mix-up attacker's response
      without ``iss`` would be accepted.

   .. versionadded:: 0.3.0

   .. py:method:: matches_state(expected: str, *, required: bool = True) -> bool

      ``state`` check, fail closed: ``True`` when ``state`` equals ``expected``
      (the value stored in the session), compared in constant time over the
      UTF-8 bytes (RFC 6749 sections 4.1.2.3 and 10.12). When the response has
      no ``state`` the result is ``not required``, so ``False`` by default.
      An empty ``expected`` always gives ``False``, regardless of
      ``required``, as does an unverified JARM stub (``response`` set). Never raises for a mismatch; ``expected`` must be a ``str`` (``TypeError``
      otherwise). ``state`` in the response is conditional on the request
      carrying one; :func:`authorization_url` and :func:`begin` always send it,
      so keep ``required=True``. Pass ``required=False`` only for a request you
      deliberately built without ``state``. ALWAYS call it before exchanging
      the code: the parse result alone proves nothing.

   .. versionadded:: 0.3.0

   .. py:method:: verify_jarm(jwks: dict[str, Any] | JwksCache, *, issuer: str, client_id: str, allowed_algorithms: Sequence[str], trust: Literal["typed", "dedicated_keys", "untyped_shared_key_compat"] = "typed", typ: str | None = None, leeway: int | None = None) -> AuthorizationResponse

      Verify the JARM ``response`` JWT of a stub parsed with
      ``accept_jarm=True`` and return the inner authorization response (a new
      :class:`AuthorizationResponse` with :attr:`jarm_verified` ``True`` and
      the same ``response_mode``). Fails closed.

      ``jwks`` is a ``{"keys": [...]}`` dict or a :class:`JwksCache`. A
      ``JwksCache`` must belong to ``issuer`` and is refreshed once for an
      unknown ``kid``. ``allowed_algorithms`` is required; use
      :data:`JARM_ASYMMETRIC_ALGORITHMS`. ``HS*`` with a ``JwksCache`` raises
      :class:`pygrindvakt.ConfigError` (``code == "shared_secret_algorithm"``).
      ``issuer`` must be the JWT ``iss`` and ``client_id`` its ``aud``; ``exp``
      is required. ``leeway`` (seconds) is capped at
      :data:`MAX_ID_TOKEN_LEEWAY`.

      ``trust`` states how the JWT is proven to be a JARM response rather than
      an ID token signed with the same key (same vocabulary as
      :func:`fetch_userinfo`):

      * ``"typed"`` (default, safe): the JOSE ``typ`` header must equal
        ``typ`` (default :data:`JARM_TYP`, ``oauth-authz-resp+jwt``).
      * ``"dedicated_keys"``: you assert that ``jwks`` holds only keys the OP
        uses for JARM, never ID tokens. A missing ``typ`` or ``JWT`` is
        tolerated.
      * ``"untyped_shared_key_compat"`` (weakest): for OPs that sign JARM and
        ID tokens with the same keys and set no ``typ``. A missing ``typ`` or
        ``JWT`` is tolerated.

      Treat both opt-ins as weaker than ``"typed"``; this release does not
      distinguish them in behaviour. ``typ`` is only valid with
      ``"typed"``.

      Raises :class:`pygrindvakt.BadRequestError` when this is not an
      unverified JARM stub, the JWT is encrypted (a JWE) or the inner response
      has a bad shape; :class:`pygrindvakt.AuthnError` for a bad signature,
      ``typ``, ``kid``, ``iss``, ``aud`` or ``exp``. A ``kid`` that names no
      key in the issuer's JWK Set (after the cache's rate-limited refresh,
      which may have been skipped by the minimum refresh interval) raises
      :class:`pygrindvakt.AuthnError` with ``code == "unknown_kid"`` (401) and
      the original :class:`UnknownKeyError` as ``__cause__``. The response is
      rejected (fail closed); a key-rotation race therefore surfaces as
      ``AuthnError``.
      :class:`pygrindvakt.ConfigError` for bad arguments (empty
      ``allowed_algorithms``, ``issuer`` or ``client_id``, an issuer that
      differs from the cache, ``leeway`` out of range), before any fetch.

      ``error_description_safe`` of the result is escaped by this binding.
      The result is still untrusted until you call :meth:`matches_state`
      and :meth:`matches_iss` on it (not on the stub, which always gives
      ``False``). A verified response is valid until its ``exp``; there is no
      ``iat`` / max-age bound, so a captured one can be replayed until then.

   .. versionadded:: 0.3.0

Finishing the flow
------------------

.. py:function:: exchange_code(http: HttpClientProtocol | None, provider: ProviderInfo, client: RpClient, code: str, code_verifier: str | None = None, *, redirect_uri: str | None = None) -> TokenSet

   Exchange an authorization ``code`` for tokens at the provider's token
   endpoint, authenticating as configured on ``client``
   (``client_secret_basic`` via the ``Authorization`` header,
   ``client_secret_post`` in the form, ``private_key_jwt`` with a fresh
   assertion, or nothing). ``code_verifier`` is the PKCE verifier matching
   the challenge sent in :func:`authorization_url`. If the authorization
   request overrode ``redirect_uri``, pass the same ``redirect_uri`` here.

   A non-200 response raises :class:`pygrindvakt.AuthnError` with a generic
   message; ``exc.code`` / ``exc.upstream_error`` hold the upstream OAuth error
   (for example ``invalid_client`` or ``invalid_grant``) and ``exc.upstream_status``,
   ``exc.upstream_error_description`` and ``exc.upstream_body`` the sanitized
   details. The description and body may echo secrets: never log them
   verbatim or show them to users.

.. py:function:: verify_id_token(jwks: dict[str, Any] | JwksCache, id_token: str, issuer: str, client_id: str, expected_nonce: str | None, allowed_algorithms: list[str], trusted_additional_audiences: list[str] | None = None, unsafe_skip_nonce_check: bool = False, *, leeway: int | None = None, max_age: int | None = None, acr_values: list[str] | None = None, access_token: str | None = None, require_at_hash: bool = False, authorization_code: str | None = None, require_c_hash: bool = False, strict_hashes: bool = False) -> dict[str, Any]

   Verify an ``id_token`` against the provider JWKS (a dict
   ``{"keys": [...]}`` or a :class:`JwksCache`), the expected ``issuer``,
   audience ``client_id`` and
   ``expected_nonce``; ``sub``, ``exp`` and ``iat`` are required. The protected
   algorithm must be in ``allowed_algorithms``. Additional audiences are
   rejected unless explicitly listed in ``trusted_additional_audiences``;
   multi-audience tokens also require ``azp`` equal to ``client_id``. Returns the
   validated claims as a dict. Raises :class:`pygrindvakt.AuthnError` (or
   another :class:`pygrindvakt.GrindvaktError` subclass) on any failure:
   bad signature, unknown key, wrong issuer or audience, expired, nonce
   mismatch. When the key set has several keys the token must carry a ``kid``
   (OIDC Core 10.1).

   With none of the keyword options the behaviour is unchanged (a ``at_hash``
   or ``c_hash`` claim is ignored, as there is nothing to check it against).
   The options:

   ``leeway``
      Clock-skew tolerance in seconds for ``exp`` / ``nbf`` / ``iat`` and for
      the future-``auth_time`` check; default 60. Above 300 raises
      :class:`pygrindvakt.ConfigError` (it is for clock drift, not for
      reviving expired tokens); negative raises :class:`~pygrindvakt.ConfigError`. It is not
      added to ``max_age``.

   ``max_age``
      The OIDC ``max_age`` policy, in seconds. It is checked against the
      ``auth_time`` claim (never ``iat``): the token must carry a numeric
      ``auth_time`` (a fractional value is floored) with ``now <= auth_time +
      max_age``. A missing or non-numeric ``auth_time`` is an
      :class:`pygrindvakt.AuthnError`, as is an ``auth_time`` older than
      ``max_age`` or more than ``leeway`` in the future. Send ``max_age`` in
      the authorization request as well; this is the RP-side enforcement.

   ``acr_values``
      Allow-list: the ``acr`` claim must be a string in the list, else
      :class:`pygrindvakt.AuthnError`. An empty list is a
      :class:`pygrindvakt.ConfigError`.

   ``access_token``, ``require_at_hash``
      ``at_hash`` is compared with the hash of ``access_token`` (constant
      time) when the id_token carries one. Without ``require_at_hash`` a token
      lacking ``at_hash`` is accepted, so it is **not** bound to the access
      token; set ``require_at_hash=True`` when the binding must hold (implicit
      and hybrid flows, or an OP known to emit it). ``require_at_hash`` without
      ``access_token`` raises :class:`pygrindvakt.ConfigError`.

   ``authorization_code``, ``require_c_hash``
      The same for ``c_hash`` (hybrid flows need ``require_c_hash=True``).

   ``strict_hashes``
      By default an ``at_hash`` / ``c_hash`` claim is **ignored** when the
      matching ``access_token`` / ``authorization_code`` is not passed, and a
      missing claim is accepted. With ``strict_hashes=True`` the token is
      rejected with :class:`pygrindvakt.AuthnError` if it carries a hash claim
      that cannot be checked, and ``at_hash`` / ``c_hash`` is required whenever
      ``access_token`` / ``authorization_code`` is passed (as if
      ``require_at_hash`` / ``require_c_hash`` were set; no
      :class:`pygrindvakt.ConfigError` when the value is absent). With
      neither value passed and no hash claim, nothing is required. Code-flow
      callers who pass ``access_token`` but whose OP omits ``at_hash`` must
      leave ``strict_hashes`` off. An ``EdDSA`` token cannot satisfy the
      requirement (``AuthnError`` if the claim is absent, ``CryptoError`` if
      present).

   The hash is computed with the SHA-2 variant matching the token's ``alg``.
   ``EdDSA`` defines none: an ``EdDSA`` token that carries ``at_hash`` /
   ``c_hash`` while the matching value is supplied raises
   :class:`pygrindvakt.CryptoError`, and ``require_*_hash`` cannot be met by
   it in practice. An ``EdDSA`` token without the claim passes unless
   required. Supplying ``access_token`` or ``authorization_code`` to an OP
   that signs with ``EdDSA`` and emits hashes therefore fails; omit them there.

   ``expected_nonce`` is the nonce this RP sent in the authorization
   request. Passing ``None`` is refused with :class:`pygrindvakt.AuthnError`
   unless ``unsafe_skip_nonce_check=True`` is given as well, which disables
   the nonce check entirely and emits a ``UserWarning``. A nonce that is
   given is always enforced, flag or not.

   .. danger::

      Only skip the nonce check for flows that genuinely carry no nonce
      (e.g. a pure OAuth 2.0 flow that still returns an id_token). Skipping
      it for the standard code flow allows id_token replay.

   **HS256 / HS384 / HS512 and the client secret.** An OP MACs such an ID
   token with a key derived from the ``client_secret`` (OIDC Core 10.1), not
   with a key from its JWK Set, which must not contain one. Build the key set
   yourself and allow the algorithm explicitly::

      secret = client_secret.encode()
      jwks = {"keys": [{"kty": "oct", "k": base64.urlsafe_b64encode(secret).rstrip(b"=").decode()}]}
      claims = rp.verify_id_token(jwks, id_token, issuer, client_id, nonce, ["HS256"])

   This is not an unsafe option: it needs no flag and emits no warning. The
   secret must be at least as long as the hash output (32, 48 or 64 bytes for
   ``HS256``, ``HS384``, ``HS512``; RFC 7518 3.2); a shorter ``oct`` key raises
   :class:`pygrindvakt.ConfigError` with ``code == "weak_shared_secret"``
   (the message never contains the key). Only the key the token selects is
   checked: the one its ``kid`` names, or the only key of a one-key set. A
   ``kid`` naming another key (say the OP's EC key) is not a config fault even
   if a weak ``oct`` key sits in the set, but a weak key selected by its
   ``kid`` raises, so keep weak keys out of verifier sets. The key is checked
   only if it can verify with the token's algorithm (``alg`` absent or equal
   to it, ``use`` absent or ``sig``, ``key_ops`` absent or containing
   ``verify``); others are left untouched. ``k`` must be strict unpadded base64url (no
   ``=``, whitespace, ``+`` or ``/``), otherwise the same code is raised with
   the message "invalid oct key material". A :class:`JwksCache` with an ``HS*``
   algorithm raises :class:`~pygrindvakt.ConfigError` with ``code ==
   "shared_secret_algorithm"``, and an ``oct`` key in a dict from
   :func:`fetch_jwks` was already dropped. ``none`` is never accepted:
   it is an invalid algorithm name (:class:`~pygrindvakt.ConfigError`). The
   same rules apply to ``allowed_algorithms`` in :func:`fetch_userinfo`.

   .. versionchanged:: 0.2.0
      Added the keyword-only ``leeway``, ``max_age``, ``acr_values``,
      ``access_token`` / ``require_at_hash``, ``authorization_code`` /
      ``require_c_hash`` and ``strict_hashes`` options, and the requirement
      that the token carry a ``kid`` when the key set holds more than one key.
      ``jwks`` now also accepts a :class:`JwksCache`.

   .. versionchanged:: 0.3.0
      A :class:`JwksCache` with an ``HS*`` algorithm is refused
      (``shared_secret_algorithm``), and an ``oct`` key shorter than the hash
      output is refused (``weak_shared_secret``). Before, an ``HS384`` /
      ``HS512`` key of 33 bytes or more was accepted whatever its length, and
      a 32-byte ``HS256`` secret failed with a ``JoseError``.

.. py:function:: fetch_userinfo(http: HttpClientProtocol | None, userinfo_endpoint: str | None, access_token: str, expected_sub: str, issuer: str, *, method: Literal["POST", "GET"] = "POST", jwks: dict[str, Any] | JwksCache | None = None, client_id: str | None = None, allowed_algorithms: list[str] | None = None, trust: str | None = None, typ: str | None = None, max_age: int | None = 300, require_exp: bool = False) -> dict[str, Any]

   Fetch the UserInfo response with a Bearer ``access_token`` and return its
   claims as a dict. The ``sub`` must exactly equal ``expected_sub`` from the
   validated ID token. The associated ``issuer`` is mandatory to scope the
   loopback HTTP development exception. Raises :class:`pygrindvakt.AuthnError`
   on a non-200 or subject mismatch.

   ``userinfo_endpoint`` is ``None`` when the OP does not advertise one (see
   :attr:`ProviderInfo.userinfo_endpoint`); that raises
   :class:`pygrindvakt.ConfigError` (``provider does not advertise a
   userinfo_endpoint``).

   **Method.** ``method="POST"`` (the default) sends an empty form body with
   the token in the ``Authorization`` header and works with every HTTP client.
   ``method="GET"`` (OIDC Core 5.3.1 allows both) sends the token in the
   ``Authorization`` header of a GET and needs a client that supports request
   headers on GET: the built-in :class:`~pygrindvakt.http.ReqwestClient`, or a
   Python client with ``get(url, headers=...)`` or ``get_with_headers(url,
   headers)`` (see :doc:`http`). Otherwise :class:`pygrindvakt.ConfigError`.
   The built-in client never follows redirects, so the token is never sent to
   a redirect target; an injected client must do the same, or strip
   ``Authorization`` on a cross-origin redirect.

   **JSON responses** (any content type except ``application/jwt``) are parsed
   directly; none of the keyword arguments below is used.

   **Signed responses** (``application/jwt``) are verified, never trusted
   as-is, and fail closed: unless ``jwks``, ``client_id``,
   ``allowed_algorithms`` (non-empty) **and** ``trust`` are all given, an
   :class:`pygrindvakt.AuthnError` with ``code == "userinfo_unverifiable"`` is
   raised. ``jwks`` is a JWK Set dict or a :class:`JwksCache`, as for
   :func:`verify_id_token` (with a cache, an unknown ``kid`` in the response
   triggers the same single rate-limited refresh, else
   :class:`pygrindvakt.UnknownKeyError`). The JWS must be signed by a key in ``jwks`` with an
   allowed algorithm and carry a ``kid`` naming it, ``iss`` must equal
   ``issuer``, ``aud`` must be exactly ``client_id`` (multi-audience tokens are
   refused), and ``sub`` must equal ``expected_sub``. A token carrying
   ``nonce``, ``at_hash`` or ``c_hash``, or a ``typ`` of ``id_token+jwt`` /
   ``at+jwt``, is refused as an id_token or access token presented as
   UserInfo. ``exp`` is checked when present; ``require_exp=True`` demands it.

   ``trust`` states how the JWT is proven to be UserInfo rather than an
   id_token the OP signed with the same key and replayed here (the ``iss``,
   ``aud`` and ``sub`` of both are identical):

   * ``"typed"`` (safe): requires the exact JOSE ``typ`` header given as
     ``typ``. For OPs that type their UserInfo JWTs. ``typ`` must identify
     UserInfo specifically; ``JWT``, ``id_token+jwt`` and ``at+jwt`` are
     refused.
   * ``"dedicated_keys"`` (safe, as far as your attestation holds): you assert
     that ``jwks`` contains only keys the OP uses to sign UserInfo, never
     id_tokens, so a token that verifies cannot be an id_token. It does not
     prove the token is UserInfo rather than some other JWT signed by those
     keys.
   * ``"untyped_shared_key_compat"`` (**weakest**; compatibility only): for OPs
     that sign UserInfo and id_tokens with the same keys and set no ``typ``. A
     fresh id_token that omits ``nonce``, ``at_hash`` and ``c_hash`` is
     indistinguishable from UserInfo and **will be accepted** for up to
     ``max_age`` seconds. Prefer ``"typed"`` or ``"dedicated_keys"``.

   ``typ`` is only valid with ``trust="typed"``, and ``trust="typed"``
   requires it (:class:`~pygrindvakt.ConfigError` otherwise, as for an
   unknown ``trust`` or ``method``).

   ``max_age`` (default 300 seconds) requires an ``iat`` claim and rejects a
   token older than that (plus the library's 60 second clock-skew leeway), so
   a captured token cannot be replayed indefinitely even without ``exp``.

   .. warning::

      ``max_age=None`` removes both the ``iat`` requirement and the age bound.
      A token without ``exp`` can then be **replayed without limit**. Use it
      only for an OP that emits neither ``iat`` nor ``exp``.

   Encrypted (JWE) responses are not supported and raise
   :class:`pygrindvakt.AuthnError` with ``code == "userinfo_encrypted"``.

   **HS256 / HS384 / HS512.** A UserInfo JWT MACed with the ``client_secret``
   verifies against a caller-built ``jwks`` dict (an ``oct`` key from the
   secret, as described under :func:`verify_id_token`), with the same minimum
   key lengths (``ConfigError``, ``code == "weak_shared_secret"``). With a
   :class:`JwksCache` an ``HS*`` entry in ``allowed_algorithms`` raises
   :class:`~pygrindvakt.ConfigError` (``code == "shared_secret_algorithm"``)
   before the request is made.

   .. versionchanged:: 0.2.0
      ``userinfo_endpoint`` became ``str | None`` (a provider that does not
      advertise UserInfo yields ``None`` from ``ProviderInfo``, and passing it
      through raises :class:`pygrindvakt.ConfigError`), and the ``method``,
      ``jwks``, ``client_id``, ``allowed_algorithms``, ``trust``, ``typ``,
      ``max_age`` and ``require_exp`` options were added.

   .. versionchanged:: 0.3.0
      ``HS*`` with a :class:`JwksCache` is refused and ``oct`` keys shorter
      than the hash output are refused.

   .. code-block:: python

      profile = rp.fetch_userinfo(
          http_client, info.userinfo_endpoint, ts.access_token, claims["sub"],
          info.issuer,
          method="GET",
          jwks=jwks_cache,   # a JwksCache for this issuer, or a JWK Set dict
          client_id="demo", allowed_algorithms=["ES256"],
          trust="typed", typ="userinfo+jwt",   # only used if the OP signs it
      )

Client assertions and attribute mapping
---------------------------------------

.. py:function:: build_client_assertion(key: SigningKey, client_id: str, audience: str) -> str

   Build a ``private_key_jwt`` client assertion (RFC 7523) signed with
   ``key``: ``iss`` = ``sub`` = ``client_id``, ``aud`` = ``audience`` (the
   token endpoint URL), valid for 300 seconds, with a random ``jti``.
   :func:`exchange_code` calls this itself for a ``private_key_jwt`` client;
   use it directly for other endpoints that require client authentication.

.. py:function:: claims_to_attributes(claims: dict[str, Any]) -> dict[str, list[str]]

   Convert a userinfo or id_token claims dict into the attribute-map shape
   ``{name: [values]}`` used by identity proxies: strings become
   one-element lists, lists keep their string members, numbers and booleans
   are stringified, and anything else (nested objects, ``null``, empty
   lists) is dropped.

Validators and limits
---------------------

These check caller-supplied values. :func:`validate_issuer` and
:func:`validate_service_endpoint` validate integrator configuration or
provider metadata, so they raise :class:`pygrindvakt.ConfigError` (a
``ValueError``, ``status_hint`` 500). :func:`validate_redirect_uri_syntax` can
validate request input, so it raises :class:`pygrindvakt.BadRequestError` (also a ``ValueError``). None of
them establishes trust.

Which error class? Configuration values (issuer, service endpoints,
``auth_method``, TTLs, and the algorithm allow-lists passed to ``rp.*``) raise
:class:`pygrindvakt.ConfigError`. Per-request inputs (a redirect URI override,
:func:`validate_redirect_uri_syntax`, the OAuth error redirect base) raise
:class:`pygrindvakt.BadRequestError`. Algorithm names handed to the ``jwt.*``
primitives (``sign``, ``verify_*``, ``oidc_token_hash``) raise
:class:`pygrindvakt.CryptoError`. ``ConfigError`` and ``BadRequestError`` are
both ``ValueError``, so ``except ValueError`` catches either and hides the
distinction; branch on the class instead.

.. py:function:: validate_issuer(issuer: str) -> None

   Check the syntax of an issuer identifier: an absolute ``https`` URL
   (``http`` only for loopback hosts) with no userinfo, query, fragment,
   whitespace, control or invisible characters. Raises
   :class:`pygrindvakt.ConfigError` otherwise.

   It checks syntax only. It does **not** establish that the issuer is
   trusted, nor that it matches any discovery metadata. Backslashes are
   rejected: the URL parser would reinterpret them as ``/``, so the parsed
   authority would differ from the raw string. Compare issuers byte-for-byte
   (exact string match); never use suffix/substring checks.

   .. versionadded:: 0.3.0

.. py:function:: validate_redirect_uri_syntax(redirect_uri: str) -> None

   Check that ``redirect_uri`` is an absolute URL without a fragment
   (upstream's rule). This binding also rejects whitespace, control, bidi and
   invisible formatting characters and userinfo
   (``https://good.example@evil.example/cb``); this is binding-side hardening,
   stricter than core 0.10. Raises :class:`pygrindvakt.BadRequestError`
   otherwise (not ``ConfigError``: it can validate request input). The same
   check applies to ``RpClient`` ``redirect_uris`` and
   ``post_logout_redirect_uris`` (:class:`pygrindvakt.ConfigError`) and to
   per-request overrides (:class:`pygrindvakt.BadRequestError`).

   This checks syntax only. The scheme is **not** checked: custom native-app
   schemes such as ``com.example.app:/cb``, ``javascript:``, ``file:`` and
   ``http://attacker.example/cb`` all pass.

   It is the syntax step of :class:`RpClient`'s redirect URI handling, which
   also requires registration, exact-string comparison and a transport check
   (`ADR 0004 <https://github.com/kushaldas/pygrindvakt/blob/main/docs/adr/0004-redirect-registration-and-hash-binding.md>`_). It is
   **not** a registration policy and does **not** make a URI safe to register
   or redirect to. Do not use it to vet client registrations on an OP: this
   library provides no OP-side registration policy, so apply an https or
   scheme allow-list and compare redirect URIs by **exact match** yourself.

   Backslashes are rejected: the URL parser would reinterpret them as ``/``,
   making the parsed authority differ from the raw string.

   .. versionadded:: 0.3.0

.. py:function:: validate_service_endpoint(name: str, endpoint: str, issuer: str | None = None, *, allow_loopback_http: bool = False) -> None

   The loopback ``http`` exception is opt-in: pass ``allow_loopback_http=True``
   and an ``issuer`` that is the authenticated, locally configured issuer,
   never taken from the document being validated. A loopback-``http`` issuer
   then permits loopback ``http`` endpoints on **any** port.

   Check that a metadata endpoint is an absolute ``https`` URL; ``name`` is
   used in the error message. By default only ``https`` passes. If ``issuer``
   is given it is still validated first (as :func:`validate_issuer`; an
   invalid issuer raises :class:`pygrindvakt.ConfigError` whatever the
   endpoint) but it never enables loopback ``http``. With
   ``allow_loopback_http=True``, ``issuer`` is required (otherwise
   :class:`pygrindvakt.ConfigError`), and loopback ``http`` is also allowed
   when the issuer is itself a loopback ``http`` origin. A :class:`UserWarning`
   is emitted whenever a plain ``http`` endpoint is accepted that way. Raises
   :class:`pygrindvakt.ConfigError` otherwise.

   It checks shape and scheme only. It does **not** require the endpoint to
   be on the issuer's origin or establish trust. Validating the issuer's
   syntax does not stop an attacker-supplied ``http://localhost`` issuer, so
   never enable the opt-in with an issuer taken from an unauthenticated
   document.

   Backslashes in ``endpoint`` or ``issuer`` are rejected: the URL parser
   would reinterpret them as ``/``, making the parsed authority differ from
   the raw string. Compare issuers byte-for-byte (exact string match); never
   use suffix/substring checks.

   .. versionadded:: 0.3.0

.. py:data:: MAX_ID_TOKEN_LEEWAY
   :type: int

   The largest ``leeway`` in seconds that :func:`verify_id_token` accepts
   (300); a larger value raises :class:`pygrindvakt.ConfigError`. It is a cap
   enforced by the library, **not** a recommended value: keep ``leeway`` as
   small as your clock skew allows.

   .. versionadded:: 0.3.0

.. py:data:: JARM_ASYMMETRIC_ALGORITHMS
   :type: tuple[str, ...]

   The asymmetric JWS algorithms suitable for
   ``verify_jarm(allowed_algorithms=...)``.

   .. versionadded:: 0.3.0

.. py:data:: JARM_TYP
   :type: str

   The JARM response JWT ``typ`` header value, ``"oauth-authz-resp+jwt"``,
   the default for ``verify_jarm(trust="typed")``.

   .. versionadded:: 0.3.0

.. py:function:: asymmetric_algorithms() -> list[str]

   The classical asymmetric JWS algorithms from the core library's catalogue
   (``RS256``, ``RS384``, ``RS512``, ``PS256``, ``PS384``, ``PS512``,
   ``ES256``, ``ES384``, ``ES512``, ``EdDSA``, ``ES256K``). ``HS*`` and
   ``none`` are never included. Post-quantum names (ML-DSA, feature-gated in
   jose-rs) are **not** included, even if the build parses them.

   It is **not** what an OP advertises (see
   ``id_token_signing_alg_values_supported`` in its metadata) or what suits
   your deployment. Pass an explicit allowlist as ``allowed_algorithms``. It is
   a catalogue, not a recommended allowlist. It includes ``EdDSA``, for
   which :func:`pygrindvakt.jwt.supports_oidc_token_hash` is ``False``, so
   ``allowed_algorithms=rp.asymmetric_algorithms()`` together with
   ``strict_hashes=True`` on a flow that needs ``at_hash`` / ``c_hash`` is
   unsatisfiable for EdDSA tokens: filter with
   :func:`pygrindvakt.jwt.supports_oidc_token_hash` or pass an explicit
   allowlist.

   .. versionadded:: 0.3.0

   .. versionchanged:: 0.4.0
      The list comes from the core library's algorithm catalogue instead of a
      fixed probe list. The names are unchanged; the order now follows the
      catalogue (``ES512``, ``EdDSA``, ``ES256K``).

.. py:function:: claims_audiences(claims: Mapping[str, Any]) -> list[str]

   Normalise the ``aud`` claim of a claims dict to a **non-empty** list of
   non-empty strings: a string becomes ``[string]``, a list of strings is
   copied. The function returns a non-empty list or raises, so a caller's
   ``all(a in {CLIENT} for a in aud)`` or ``set(aud) <= {CLIENT}`` can never
   be vacuously true for a token without an audience binding. A missing
   ``aud``, ``aud: []``, ``aud: ""`` or an empty-string list member raises
   :class:`pygrindvakt.BadRequestError`, as does ``aud`` of any other type
   (including ``None``), a list member that is not a string, or a string that
   is not valid Unicode (a lone surrogate). The claims are per-request input;
   the message never echoes the value. A ``claims`` that is not a mapping
   raises :class:`TypeError`. The dict passed in is never modified.

   This is a convenience for application code only.
   :func:`verify_id_token` returns ``aud`` verbatim, and the ``aud`` and
   ``azp`` checks are made by the library inside it; do not re-implement them
   with this function.

   .. versionadded:: 0.3.0

Startup checks
--------------

.. py:function:: check_rp_compatibility(provider: ProviderInfo | ProviderMetadata, *, client: RpClient | None = None, pkce: bool | None = None, algorithms: Sequence[str] | None = None, scopes: Sequence[str] | None = None, acr_values: Sequence[str] | None = None, shared_secret_keys: bool = False) -> list[str]

   Compare what the RP intends to use with what the OP advertises in its
   discovery document, and return human-readable findings. An empty list means
   nothing contradicts the document. Pure: no I/O, nothing is enforced.

   ``provider`` is a :class:`ProviderInfo` that has :attr:`ProviderInfo.metadata`
   (build it with ``ProviderInfo.from_metadata(discover(...))``; one without
   raises :class:`pygrindvakt.ConfigError`) or the
   :class:`pygrindvakt.metadata.ProviderMetadata` returned by :func:`discover`
   directly. Checks exactly:

   * always: ``"code"`` is in ``response_types_supported``;
   * ``pkce=True`` (the RP sends an S256 challenge; ``None`` and ``False`` skip
     the check): ``"S256"`` is in ``code_challenge_methods_supported``;
   * ``algorithms`` (the id_token algorithms the RP allows; must not be empty):
     at least one is in ``id_token_signing_alg_values_supported``. Two rules
     mirror ADR 0006 and are real mismatches (no
     ``not advertised:`` prefix): ``none`` (any case) is always refused by this
     library, so the message says to fix the RP config, not the OP; and
     ``HS256``/``HS384``/``HS512`` are only usable with a key set derived from
     the ``client_secret`` (OpenID Connect Core 1.0 section 10.1) and are
     refused with ``JwksCache`` / published JWKS. Pass
     ``shared_secret_keys=True`` if you verify with such a caller-built key
     set; HS* is then not flagged and takes part in the normal intersection
     check. ``none`` is never counted as a match, and HS* is ignored by the
     intersection check unless ``shared_secret_keys=True``. The function
     cannot see your key source, so the default fails closed;
   * ``scopes``: every scope is in ``scopes_supported``;
   * ``acr_values``: every value is in ``acr_values_supported``;
   * ``client``: ``client.auth_method`` is in
     ``token_endpoint_auth_methods_supported``. If that member is absent or
     empty, the spec default ``["client_secret_basic"]`` (OpenID Connect
     Discovery 1.0 section 3, RFC 8414 section 2) is assumed: any other
     ``auth_method`` is then a real mismatch (the message says the list was
     absent and the default assumed), and ``client_secret_basic`` passes. An
     absent member and an explicit ``[]`` are indistinguishable after parsing
     and are treated the same.

   Not checked: ``grant_types_supported``, ``response_modes_supported``,
   ``pkce=False`` or ``None``, DPoP, request-object support, claims, or any
   other member of the document.

   Messages come in two kinds. A message starting with ``"not advertised:"``
   is **informational**: the OP lists nothing (absent or empty) for a check
   that was performed, so the support can be neither confirmed nor refuted
   (no default is assumed for these lists; in particular ``RS256`` is not
   assumed for ``id_token_signing_alg_values_supported``; the one exception
   is ``token_endpoint_auth_methods_supported`` above),
   for example ``not advertised: code_challenge_methods_supported (cannot
   confirm PKCE S256 support)`` for an OP such as ORCID that omits the member.
   It is only produced for checks that were requested (the ``code`` check is
   always requested). Every other message is a mismatch with a value the OP
   does advertise. Filter on the prefix to decide what is fatal:

   .. code-block:: python

      problems = rp.check_rp_compatibility(info, client=me, pkce=True, algorithms=["ES256"])
      mismatches = [p for p in problems if not p.startswith("not advertised:")]
      if mismatches:
          raise SystemExit("OP is not compatible: " + "; ".join(mismatches))

   .. warning::

      The metadata is untrusted, unauthenticated data from the OP (for
      example, ``scopes_supported`` is not required to be exhaustive). This
      function is advisory: it does not enforce anything and an empty result
      does not mean the OP will accept the request. Advertised values are
      escaped and truncated in the messages.

   .. versionadded:: 0.3.0

Example
-------

.. code-block:: python

   from pygrindvakt import AuthnError, http, rp

   http_client = http.ReqwestClient()
   info = rp.ProviderInfo.from_metadata(rp.discover(http_client, "https://op.example.com"))
   jwks_cache = rp.JwksCache(http_client, info.jwks_uri, info.issuer)   # once per process
   me = rp.RpClient("demo", "https://rp.example.com/cb", client_secret=os.environ["OIDC_SECRET"])

   # Login: keep state, nonce and verifier in the session.
   redirect_to, state, nonce, verifier = rp.begin(info, me)

   # Callback: check state, then exchange and verify.
   try:
       ts = rp.exchange_code(http_client, info, me, code, code_verifier=verifier)
       claims = rp.verify_id_token(jwks_cache, ts.id_token,
                                   info.issuer, me.client_id, nonce, ["ES256"])
       profile = rp.fetch_userinfo(http_client, info.userinfo_endpoint, ts.access_token,
                                   claims["sub"], info.issuer)
   except AuthnError:
       log.exception("login failed")            # never show str(e) to the user
       raise
   attributes = rp.claims_to_attributes(profile)   # {"email": ["alice@example.com"], ...}
