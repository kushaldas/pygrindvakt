pygrindvakt.provider
====================

.. py:module:: pygrindvakt.provider

The OpenID Provider engine.

A :class:`Provider` is constructed once at startup and shared across requests
and threads. Its endpoint methods take already-extracted inputs (query / form
dicts, header strings) and return :class:`pygrindvakt.http.Response` objects
or raise :class:`pygrindvakt.OAuthError`, so any web framework can drive it.
The framework guides (:doc:`../guides/op_flask`, :doc:`../guides/op_django`,
:doc:`../guides/op_fastapi`) show the five endpoints wired up.

One-time use of authorization codes, refresh tokens and ``private_key_jwt``
assertion ``jti`` values is enforced through a token-use store:
:class:`InMemoryTokenUseStore` (single process), :class:`RedisStore`
(shared), or any Python object satisfying :class:`TokenUseStoreProtocol`.

Constants
---------

.. py:data:: CLIENT_ASSERTION_TYPE
   :type: str
   :value: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

   The ``client_assertion_type`` form value for ``private_key_jwt`` (RFC
   7523).

.. py:data:: DEFAULT_CLIENT_ASSERTION_MAX_AGE
   :type: int

   The default maximum age (seconds) accepted for a client assertion's
   ``iat``.

.. py:data:: RESERVED_ID_TOKEN_CLAIMS
   :type: list[str]
   :value: ["iss", "sub", "aud", "exp", "iat", "nbf", "jti", "nonce", "auth_time", "acr", "azp", "at_hash", "c_hash"]

   Claim names that :meth:`Provider.authorization_redirect` refuses in
   ``extra_claims`` and :class:`AuthorizedClaims` refuses in either map.

AuthorizedClaims
----------------

.. py:class:: AuthorizedClaims(*, id_token: dict[str, Any], userinfo: dict[str, Any])

   Per-destination claim release decisions for
   :meth:`Provider.authorization_redirect_with_authorized_claims`. Both
   keywords are required; ``None`` raises ``TypeError``. Values keep their
   JSON types. Names in :data:`RESERVED_ID_TOKEN_CLAIMS` in either map raise
   ``ValueError``. The instance is immutable; ``id_token`` and ``userinfo``
   return fresh dicts, and ``repr()`` shows claim names only.

   Put a claim in both maps only if both destinations are authorized to
   receive it.

   .. versionadded:: 0.7.0

Provider
--------

.. py:class:: Provider(metadata: ProviderMetadata, signing_key: SigningKey, clients: InMemoryClientStore | ClientStoreProtocol, codec: TokenCodec, lifetimes: TokenLifetimes | None = None, token_use_store: InMemoryTokenUseStore | RedisStore | TokenUseStoreProtocol, client_assertion_max_age: int | None = None, authorization_response_iss: bool = False)

   The OpenID Provider engine. Build once, share across requests.

   * ``metadata``: the discovery document, mainly the issuer and endpoint
     URLs (:class:`pygrindvakt.metadata.ProviderMetadata`). It is copied.
   * ``signing_key``: an asymmetric key that signs id_tokens; its public
     half is published in the JWKS (:class:`pygrindvakt.keys.SigningKey`).
     Symmetric ``HS*`` keys are rejected because OIDC MAC ID tokens must use
     each client's own ``client_secret``, not one provider-wide secret.
   * ``clients``: an :class:`pygrindvakt.client.InMemoryClientStore` or any
     object implementing :class:`pygrindvakt.client.ClientStoreProtocol`
     (checked at construction; ``TypeError`` if ``get`` / ``put`` are
     missing).
   * ``codec``: seals codes and tokens (:class:`pygrindvakt.tokens.TokenCodec`).
   * ``lifetimes``: token lifetimes; defaults to :class:`TokenLifetimes`
     defaults.
   * ``token_use_store``: must be selected explicitly. Use
     :class:`InMemoryTokenUseStore` only for one process, or a shared
     :class:`RedisStore` / protocol implementation across workers. See
     :doc:`../guides/stores`.
   * ``client_assertion_max_age``: overrides
     :data:`DEFAULT_CLIENT_ASSERTION_MAX_AGE`.
   * ``authorization_response_iss``: opt in to RFC 9207. Authorization
     responses (success and error redirects, query or fragment) carry an
     ``iss`` parameter equal to the issuer, and the discovery document gains
     ``authorization_response_iss_parameter_supported: true``. A relying
     party checks it with :meth:`pygrindvakt.rp.AuthorizationResponse.matches_iss`
     after :func:`pygrindvakt.rp.parse_authorization_response`. Default
     ``False`` leaves behaviour unchanged. Advertising the discovery member
     in your own metadata without this flag emits a ``UserWarning``.

     .. versionadded:: 0.4.0

   .. py:property:: clients
      :type: InMemoryClientStore | ClientStoreProtocol

      The client store object passed at construction (the same Python
      object, so a Python store can be inspected or mutated by the app).

   .. py:property:: token_use_store
      :type: InMemoryTokenUseStore | RedisStore | TokenUseStoreProtocol

      The token-use store in effect.

   .. py:property:: metadata
      :type: ProviderMetadata
   .. py:property:: signing_key
      :type: SigningKey
   .. py:property:: lifetimes
      :type: TokenLifetimes
   .. py:property:: issuer
      :type: str

   .. py:method:: discovery_document() -> dict[str, Any]

      The ``/.well-known/openid-configuration`` document as a dict. Serve it
      with ``Response.json(op.discovery_document())``.

      It advertises ``subject_types_supported`` as ``["public"]`` only. The
      binding does not support pairwise subjects, so do not add ``"pairwise"``
      to your own metadata.

   .. py:method:: jwks_document() -> dict[str, Any]

      The JWKS document (``{"keys": [...]}``) as a dict: the public half of
      the signing key only.

      It never contains a symmetric (``oct``) key: the constructor refuses
      ``HS256`` / ``HS384`` / ``HS512`` signing keys with
      :class:`~pygrindvakt.ConfigError`, and a JWK of type ``oct`` cannot be
      loaded with any other algorithm. An OP must not publish symmetric keys
      (OIDC Core 10.1); see ADR 0006.

   .. py:method:: validate_authorization_request(request: AuthorizationRequest) -> Client

      Validate an authorization request against the registered client
      (known ``client_id``, exact ``redirect_uri`` match, allowed
      ``response_type``, ``nonce`` present for implicit / hybrid flows, and
      so on) and return that :class:`pygrindvakt.client.Client`.

      .. warning::

         On failure the ``redirect_uri`` is **not** trusted: render the raised
         :class:`pygrindvakt.OAuthError` with ``.to_response()``, never with
         ``.to_redirect()``. Redirecting an unvalidated URI makes the OP an
         open redirector.

   .. py:method:: authorization_redirect(request: AuthorizationRequest, sub: str, external_claims: dict[str, list[str]] | None = None, acr: str | None = None, extra_claims: dict[str, Any] | None = None) -> Response

      After the user has authenticated: mint the authorization code (or, for
      implicit / hybrid response types, the tokens) for ``sub`` and return
      the ``302`` redirect back to the client, with ``state`` echoed.

      The request is validated again immediately before minting, even if it
      was deserialized from a session. This prevents an application from
      turning stale or modified session data into tokens. ``sub`` must be
      non-empty. Standard OIDC profile claims are included only when their
      corresponding scopes were granted; application-specific claims remain
      available as custom claims.

      ``external_claims`` maps claim name to a **list of string values**, the
      shape an attribute-based identity backend produces. Multi-valued claims
      become JSON arrays; single values are coerced for the standard claims
      (``"true"`` becomes ``True`` for ``email_verified``), exactly as
      :func:`flatten_claims` does. ``acr`` sets the authentication context
      class reference. ``extra_claims`` are typed id_token claims (any JSON
      value); the reserved names in :data:`RESERVED_ID_TOKEN_CLAIMS` raise
      ``ValueError``. grindvakt would silently drop them, which could hide
      an attempt to override ``sub`` or ``nonce``.

      On :class:`pygrindvakt.OAuthError`, render the error using the request's
      response mode: ``"fragment"`` when ``request.use_fragment()`` is true,
      otherwise ``"query"``. The method itself revalidates the redirect URI
      before producing any artifact. With ``authorization_response_iss``
      enabled, render errors with :meth:`authorization_error_redirect`
      instead, so they carry ``iss`` too (``OAuthError.to_redirect`` never
      adds it). In query mode, a registered ``redirect_uri`` that already has
      an ``iss`` query parameter (percent-encoded spellings such as ``%69ss``
      included) raises ``OAuthError(server_error)``; the value is not echoed.
      Fragment mode is unaffected.

      .. versionchanged:: 0.4.0
         A ``redirect_uri`` that fails :func:`pygrindvakt.rp.validate_redirect_uri_syntax`
         (backslash, invisible or bidi characters, userinfo) raises
         ``OAuthError(invalid_request)`` before anything is minted, even when
         the client registered it; core alone accepted these.

   .. py:method:: authorization_redirect_with_authorized_claims(request: AuthorizationRequest, sub: str, claims: AuthorizedClaims, *, acr: str | None = None, auth_time: int | None = None) -> Response

      Like :meth:`authorization_redirect`, but the ID token and the UserInfo
      response receive separate claim sets from ``claims``. The request is
      revalidated and the ``redirect_uri`` checked as in
      :meth:`authorization_redirect`, and errors are rendered the same way.

      **No scope filter is applied**: ``claims`` is released as given, so
      apply the granted scopes and your release policy before building it. Put
      a claim in both maps only if both destinations are authorized to receive
      it. The code always seals the registration fingerprint and an explicit
      UserInfo claim set (``{}`` releases nothing there beyond ``sub``).
      Refresh keeps the split. If the client drops a previously granted scope
      at refresh, the matching standard claims are removed from both
      destinations.

      ``sub`` must be non-empty and the client's subject type must be
      ``public``; a pairwise client raises ``OAuthError(unauthorized_client)``.
      This is defence in depth: the binding never enables pairwise subjects,
      so core already refuses pairwise registrations at validation. Public
      subject identifiers only; pairwise subject support is not provided by
      this binding (see :doc:`../guides/security`).
      ``auth_time`` (Unix seconds) defaults to issuance time.

      .. versionadded:: 0.7.0

   .. py:method:: authorization_error_redirect(request: AuthorizationRequest, error: OAuthError) -> Response

      Render an authorization error redirect for ``request`` in its response
      mode. With ``authorization_response_iss=True`` it carries ``iss``
      (RFC 9207); without the flag it adds none and behaves like
      ``error.to_redirect(...)``. ``state`` comes from ``error``, as with
      ``to_redirect``: pass ``request.state`` yourself.

      The request is validated first, exactly as
      :meth:`validate_authorization_request` does, so a request rebuilt with
      :meth:`AuthorizationRequest.from_dict` cannot turn this into an open
      redirector. If validation fails that :class:`pygrindvakt.OAuthError` is
      raised; render it with ``.to_response()``, never as a redirect. With the
      flag on, query mode also raises ``OAuthError(server_error)`` when the
      registered ``redirect_uri`` already has an ``iss`` query parameter. A
      ``redirect_uri`` with a backslash, invisible or bidi characters or
      userinfo raises ``OAuthError(invalid_request)`` (the same rule as
      :meth:`authorization_redirect`).

      .. versionadded:: 0.4.0

   .. py:method:: handle_token_request(form: list[tuple[str, str]], token_url: str, auth_header: str | None = None, dpop: DpopProof | None = None) -> TokenResponse

      Handle a token-endpoint request for the ``authorization_code``,
      ``refresh_token`` and ``client_credentials`` grants, authenticating the
      client by ``client_secret_basic`` (``auth_header``),
      ``client_secret_post`` (form fields), ``private_key_jwt``
      (``client_assertion``) or ``none``, as registered.

      * ``form`` is the ordered parsed form body. Mappings are rejected because
        they may already have erased duplicate OAuth parameter names.
      * ``token_url`` is the absolute token endpoint URL **from
        configuration**. It is the audience a ``private_key_jwt`` assertion
        must name and the ``htu`` a DPoP proof must be bound to. Never derive
        it from the ``Host`` header.
      * ``auth_header`` is the raw ``Authorization`` header, if any.
      * ``dpop`` is an already-validated :class:`pygrindvakt.dpop.DpopProof`
        if the request carried a ``DPoP`` header (see :doc:`../guides/dpop`);
        the issued tokens are then bound to its key and ``token_type`` is
        ``DPoP``.

      Authorization codes and refresh tokens are single-use: a replay is
      ``invalid_grant``. Refresh tokens are rotated. Raises
      :class:`pygrindvakt.OAuthError`; render it with ``.to_response()``.
      An ID token is issued only when the original scope contained
      ``openid``. The ``client_credentials`` grant rejects ``openid`` because
      it has no authenticated end user.

   .. py:method:: userinfo(access_token: str, presented_jkt: str | None = None) -> dict[str, Any]

      Handle a userinfo request: validate ``access_token`` and return the
      claims (``sub`` plus the claims resolved at authorization time,
      filtered by scope). The token must carry the ``openid`` scope. For a
      DPoP-bound token, ``presented_jkt`` (the
      ``jkt`` of a proof validated with
      :func:`pygrindvakt.dpop.validate_resource_proof`) must match the
      token's ``cnf.jkt``; a bound token presented as plain Bearer is
      rejected. Raises :class:`pygrindvakt.OAuthError`.

   .. py:method:: signed_userinfo(access_token: str, presented_jkt: str | None = None) -> str

      Like :meth:`userinfo`, but return the response as a signed JWT: a
      compact JWS with ``typ`` ``userinfo+jwt``, ``iss``, ``aud`` set to the
      client id and ``exp`` at the earlier of the access token's expiry and
      five minutes from now. A client registered with
      ``userinfo_encrypted_response_alg`` (and optionally ``_enc``) receives
      a compact JWE of that JWS instead. Serve the result with
      ``content-type: application/jwt``. Relying parties verify it with
      :func:`pygrindvakt.rp.fetch_userinfo` using ``trust="typed"`` and
      ``typ="userinfo+jwt"``.

      Token, scope and DPoP failures raise :class:`pygrindvakt.OAuthError`
      with the same codes as :meth:`userinfo`. A client that is no longer
      registered, or unusable claims, raise ``invalid_grant``; a signing or
      encryption failure raises ``server_error``.

      .. versionadded:: 0.7.0

   .. py:method:: consume_request_id(client_id: str, jti: str, expiry: int) -> None

      Record a verified request object (RFC 9101) identifier for one-time
      use by ``client_id``: an OP-side JAR replay helper. The binding does
      not verify request objects; frontends must verify the signature and
      bind the object to the client themselves, then call this with the
      ``jti`` and the acceptance deadline ``expiry`` (Unix seconds).

      Returns ``None``. Raises :class:`pygrindvakt.OAuthError`:
      ``invalid_request`` for an empty or over-512-byte ``jti`` or an
      ``expiry`` that is not in the future or is more than 900 seconds
      ahead, ``invalid_grant`` on reuse, ``server_error`` on store failure.
      Replay state lives in the provider's ``token_use_store``; replicas need
      a shared one (for example :class:`RedisStore`) to enforce single use
      across processes.

      The marker is kept until ``expiry``, so the binding refuses an
      ``expiry`` beyond now + 900 s (nothing is recorded): otherwise a
      client could fill the shared store with permanent entries. Request
      objects with a longer lifetime are refused, and the integrator should
      reject request objects whose ``exp`` exceeds that bound anyway.

      .. versionadded:: 0.7.0

   .. py:method:: authenticate_client(form: list[tuple[str, str]], token_url: str, auth_header: str | None = None) -> Client

      Authenticate a client from a token-endpoint style request (form +
      ``Authorization`` header) and return the
      :class:`pygrindvakt.client.Client`, without processing a grant. Useful
      for custom endpoints (introspection, revocation, registration
      management) that need client authentication. A ``private_key_jwt``
      assertion's ``jti`` is consumed here too, so an assertion cannot be
      replayed against another endpoint. ``form`` must be ordered pairs;
      mappings are rejected because they erase duplicate names.

   .. code-block:: python

      from pygrindvakt import OAuthError, client, keys, metadata, provider, tokens
      from pygrindvakt.request import AuthorizationRequest

      ISSUER = "https://op.example.com"
      op = provider.Provider(
          metadata.ProviderMetadata(ISSUER),
          keys.signing_key_from_pem(open("op-key.pem", "rb").read(), kid="op-1"),
          client.InMemoryClientStore([client.Client("demo", client_secret="s3cret",
                                                    redirect_uris=["https://rp.example.com/cb"])]),
          tokens.TokenCodec(os.environ["OP_SECRET"]),
          token_use_store=provider.RedisStore(os.environ["REDIS_URL"]),   # after fork!
      )

      # Authorization endpoint, GET:
      req = AuthorizationRequest.from_params(query_pairs)
      op.validate_authorization_request(req)                # OAuthError -> e.to_response()
      # ... authenticate the user, then:
      resp = op.authorization_redirect(req, "alice", {"email": ["alice@example.com"]})

      # Token endpoint:
      try:
          resp = op.handle_token_request(form_pairs, f"{ISSUER}/token", auth_header=auth).to_response()
      except OAuthError as e:
          resp = e.to_response()

Token lifetimes and responses
-----------------------------

.. py:class:: TokenLifetimes(*, code_ttl: int = 600, access_token_ttl: int = 3600, id_token_ttl: int = 3600, refresh_token_ttl: int = 2592000)

   Lifetimes in seconds of issued artefacts. Immutable.

   .. py:property:: code_ttl
      :type: int
   .. py:property:: access_token_ttl
      :type: int
   .. py:property:: id_token_ttl
      :type: int
   .. py:property:: refresh_token_ttl
      :type: int

.. py:class:: TokenResponse

   A successful token-endpoint response.

   .. py:property:: access_token
      :type: str
   .. py:property:: token_type
      :type: str

      ``"Bearer"``, or ``"DPoP"`` for a sender-constrained token.

   .. py:property:: expires_in
      :type: int
   .. py:property:: id_token
      :type: str | None
   .. py:property:: scope
      :type: str | None
   .. py:property:: refresh_token
      :type: str | None

   .. py:method:: to_dict() -> dict[str, Any]

      Exactly the JSON body to send.

   .. py:method:: to_response() -> Response

      The complete HTTP response: ``200``, JSON body, ``cache-control:
      no-store``.

Token-use stores
----------------

.. py:class:: TokenUseStoreProtocol

   The duck-typed one-time-use store protocol accepted as ``token_use_store``.
   The object is checked for a callable ``consume`` when the ``Provider`` is
   built.

   .. py:method:: consume(token_hash: str, ttl_secs: int) -> bool

      Atomically record ``token_hash`` as used for ``ttl_secs`` seconds and
      return ``True`` iff it was **not** already recorded. ``token_hash`` is
      an opaque hash, never the token itself, so the store never sees
      credentials.

      **Fails closed:** an exception, or a non-``bool`` return value, is
      logged through ``sys.unraisablehook`` and reported to grindvakt as a
      store failure, which the client sees as ``server_error`` (HTTP 500).
      It is deliberately *not* treated as "already used": that would make a
      database outage look like an attack and would hide the outage from
      operators.

   The method runs on the thread driving the provider call, holding the GIL.
   It may call back into pygrindvakt; a nested call runs on a helper thread
   and costs one thread spawn.

   .. code-block:: python

      class RedisPyTokenUseStore:
          """The same SET NX EX pattern as RedisStore, over redis-py."""

          def __init__(self, r):
              self.r = r

          def consume(self, token_hash, ttl_secs):
              return bool(self.r.set(f"op:used:{token_hash}", 1, ex=ttl_secs, nx=True))

.. py:class:: InMemoryTokenUseStore()

   Process-local one-time-use store for codes, refresh tokens and assertion
   ``jti`` values, with TTL expiry and periodic purge. Fine for a single
   process, wrong across replicas: a code consumed in one worker is still
   fresh in another. Use :class:`RedisStore` or a Python-backed store there.

   .. py:method:: consume(token_hash: str, ttl_secs: int) -> bool

      Mark ``token_hash`` used; ``True`` iff it was not already used.

.. py:class:: RedisStore(redis_url: str, key_prefix: str | None = None)

   Redis-backed one-time-use store (``SET key 1 EX ttl NX``) for
   multi-process deployments. ``redis_url`` is a ``redis://`` or
   ``rediss://`` URL; ``key_prefix`` defaults to :attr:`DEFAULT_KEY_PREFIX`.
   Raises :class:`pygrindvakt.ConfigError` on a URL it cannot parse.

   .. warning::

      Construct it **after** ``fork``, for example in a gunicorn
      ``post_fork`` hook or lazily in the worker. The store's connection
      manager runs on the runtime of the process that created it; a store
      inherited across ``fork`` fails closed with a clear error
      (``server_error`` to the client) rather than hanging. See
      :doc:`../guides/stores`.

   .. py:attribute:: DEFAULT_KEY_PREFIX
      :type: str
      :value: "grindvakt:token-use:"

   .. py:method:: consume(token_hash: str, ttl_secs: int) -> bool

Helpers
-------

.. py:function:: flatten_claims(external: dict[str, list[str]]) -> dict[str, Any]

   Flatten ``{claim: [values]}`` into id_token / userinfo claim values the way
   the provider does: multi-valued claims stay lists, single values are
   unwrapped, and standard claims are coerced to their proper type
   (``email_verified`` to ``bool``).

   .. code-block:: python

      provider.flatten_claims({"email_verified": ["true"], "groups": ["a", "b"], "name": ["N"]})
      # {"email_verified": True, "groups": ["a", "b"], "name": "N"}
