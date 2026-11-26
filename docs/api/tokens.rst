pygrindvakt.tokens
==================

.. py:module:: pygrindvakt.tokens

The stateless token codec and its sealed payloads: authorization codes,
access tokens and refresh tokens.

grindvakt's OP keeps no token table. Each artefact is a JWE (``dir`` +
``A256GCM``) sealed under a key derived from the OP secret with HKDF, with a
type tag so a code cannot be presented as an access token. One-time use is
enforced separately by the provider's token-use store, which records a hash
of each consumed code / refresh token (see :doc:`provider`).

An application normally never touches these directly: the
:class:`pygrindvakt.provider.Provider` seals and opens them. They are exposed
for resource servers that validate access tokens locally, for tests, and for
custom grant handling.

Codec
-----

.. py:class:: TokenCodec(secret: str, previous_secrets: list[str] | None = None)

   Seals and opens authorization codes, access tokens and refresh tokens.

   ``previous_secrets`` are tried on open (after ``secret``) so tokens sealed
   under an old secret keep validating during key rotation: deploy with the
   new secret first and the old one in ``previous_secrets``, then drop the
   old one after the longest token lifetime has passed.

   .. warning::

      Secrets are Python ``str`` values and cannot be zeroized after use.
      Use a long random value (32 bytes or more of entropy) from a secret
      store; ``repr()`` never shows it.

   .. py:method:: seal_code(payload: AuthCodePayload) -> str

      Prefer :meth:`pygrindvakt.provider.Provider.authorization_redirect_with_authorized_claims`,
      which seals the registration fingerprint and UserInfo claim set for you.
      Sealing codes by hand is an advanced path. If you do, bind them to the
      registration:

      .. code-block:: python

         payload = AuthCodePayload(
             client_id=rp.client_id,
             redirect_uri=redirect_uri,
             scope="openid",
             sub="alice",
             auth_time=now,
             exp=now + 600,
             registration_digest=rp.registration_fingerprint(),
         )
         code = codec.seal_code(payload)

   .. py:method:: open_code(token: str) -> AuthCodePayload

      Open an authorization code (checks the type tag and expiry). Raises
      :class:`pygrindvakt.GrindvaktError` subclasses on a tampered, foreign
      or expired token.

   .. py:method:: seal_access_token(payload: AccessTokenPayload) -> str
   .. py:method:: open_access_token(token: str) -> AccessTokenPayload
   .. py:method:: seal_refresh_token(payload: RefreshTokenPayload) -> str
   .. py:method:: open_refresh_token(token: str) -> RefreshTokenPayload

   .. code-block:: python

      from pygrindvakt import tokens, util

      codec = tokens.TokenCodec(os.environ["OP_SECRET"], previous_secrets=[os.environ.get("OP_SECRET_OLD", "")] or None)

      # A resource server validating an access token issued by this OP:
      payload = codec.open_access_token(bearer)
      payload.sub, payload.scope.split(), payload.exp > util.now_secs()

Payloads
--------

All three payload classes are immutable, constructed with keyword-only
arguments, and round-trip through ``to_dict`` / ``from_dict``. Times are Unix
seconds. ``claims`` holds the resolved user claims (already flattened by
:func:`pygrindvakt.provider.flatten_claims`) that end up in the id_token and
userinfo response.

.. py:class:: AuthCodePayload(*, client_id: str, redirect_uri: str, scope: str, sub: str, auth_time: int, exp: int, nonce: str | None = None, code_challenge: str | None = None, code_challenge_method: str | None = None, claims: dict[str, Any] | None = None, acr: str | None = None, registration_digest: str | None = None, userinfo_claims: dict[str, Any] | None = None)

   Payload sealed into an authorization code. Carries everything the token
   endpoint needs to check the exchange (``redirect_uri``, the PKCE
   challenge) and to mint the tokens (``sub``, ``scope``, ``nonce``,
   ``claims``, ``acr``, ``auth_time``).

   .. py:staticmethod:: from_dict(d: dict[str, Any]) -> AuthCodePayload
   .. py:method:: to_dict() -> dict[str, Any]

   .. py:property:: client_id
      :type: str
   .. py:property:: redirect_uri
      :type: str
   .. py:property:: scope
      :type: str
   .. py:property:: sub
      :type: str
   .. py:property:: nonce
      :type: str | None
   .. py:property:: code_challenge
      :type: str | None
   .. py:property:: code_challenge_method
      :type: str | None
   .. py:property:: claims
      :type: dict[str, Any]
   .. py:property:: auth_time
      :type: int
   .. py:property:: exp
      :type: int
   .. py:property:: acr
      :type: str | None
   .. py:property:: registration_digest
      :type: str | None

      Fingerprint of the client registration the code was issued against.
      The token endpoint compares it with the current registration after
      client authentication and answers ``invalid_grant`` if it changed
      (including a key or secret rotation); the client then starts a new
      authorization. ``None`` for codes sealed before 0.6.0, which skip the
      check.

      .. warning::

         If ``None``, the binding check is **skipped silently**, also for
         codes you build by hand. Constructing an :class:`AuthCodePayload`
         with ``registration_digest=None`` emits a :class:`FutureWarning`
         (decoding a sealed code does not). Under ``-W error`` or
         ``filterwarnings = error::FutureWarning`` the constructor raises
         instead of warning. Prefer
         :meth:`Provider.authorization_redirect_with_authorized_claims
         <pygrindvakt.provider.Provider.authorization_redirect_with_authorized_claims>`,
         which seals it for you. An OP that hand-seals its codes (advanced)
         must pass ``client.registration_fingerprint()``, otherwise a rotated
         secret or key does not invalidate outstanding codes.

      .. versionadded:: 0.6.0

      .. versionchanged:: 0.7.0
         Building a payload with ``registration_digest=None`` emits a
         :class:`FutureWarning`. The argument will become required in a
         later release. Codes sealed before 0.6.0 still open without a digest
         and without a warning.

   .. py:property:: userinfo_claims
      :type: dict[str, Any] | None

      Claims destined for the UserInfo response. ``None`` means use
      ``claims`` for both destinations; ``{}`` releases no claims there.
      ``None`` and ``{}`` are kept distinct.

      .. warning::

         ``None`` and omitting the argument are identical: both release the
         full ``claims`` map at the UserInfo endpoint. To release no
         application claims there, pass ``{}``. Never forward a value that may
         be ``None`` when you mean "none"; that silently over-releases
         per-attribute personal data. Prefer
         :meth:`Provider.authorization_redirect_with_authorized_claims
         <pygrindvakt.provider.Provider.authorization_redirect_with_authorized_claims>`
         over hand-sealing: it always sets this explicitly.

      .. versionadded:: 0.6.0

   Authorization codes are bound to the client registration fingerprint: if
   the registration changes between authorization and the token request, the
   exchange fails with ``invalid_grant``. Unexpired 0.5.x codes and tokens
   still open with the same secret; they carry no digest and no separate
   UserInfo claims, so ``claims`` is used for both destinations.

   .. versionchanged:: 0.6.0
      Added ``registration_digest`` and ``userinfo_claims``.

   .. versionchanged:: 0.7.0
      Omitting ``registration_digest`` (or passing ``None``) emits a
      :class:`FutureWarning`; it will become required in a later release.

.. py:class:: AccessTokenPayload(*, client_id: str, sub: str, scope: str, exp: int, claims: dict[str, Any] | None = None, cnf_jkt: str | None = None)

   Payload sealed into an access token.

   .. py:staticmethod:: from_dict(d: dict[str, Any]) -> AccessTokenPayload
   .. py:method:: to_dict() -> dict[str, Any]

   .. py:property:: client_id
      :type: str
   .. py:property:: sub
      :type: str
   .. py:property:: scope
      :type: str
   .. py:property:: claims
      :type: dict[str, Any]
   .. py:property:: exp
      :type: int
   .. py:property:: cnf_jkt
      :type: str | None

      The DPoP key thumbprint the token is bound to (``cnf.jkt``), if any. A
      resource server must refuse a token with ``cnf_jkt`` set unless the
      request carries a valid DPoP proof from the same key; see
      :doc:`../guides/dpop`.

.. py:class:: RefreshTokenPayload(*, client_id: str, sub: str, scope: str, auth_time: int, exp: int, nonce: str | None = None, claims: dict[str, Any] | None = None, acr: str | None = None, cnf_jkt: str | None = None, userinfo_claims: dict[str, Any] | None = None)

   Payload sealed into a refresh token. Refresh tokens are rotated on use:
   each ``refresh_token`` grant returns a new one and records the old one as
   consumed.

   .. note::

      Refresh tokens are not bound to the client registration. Rotating a
      client's key or secret does not invalidate refresh tokens that were
      already issued; only client authentication (and DPoP binding, if used)
      protects them at redemption.

   .. py:staticmethod:: from_dict(d: dict[str, Any]) -> RefreshTokenPayload
   .. py:method:: to_dict() -> dict[str, Any]

   .. py:property:: client_id
      :type: str
   .. py:property:: sub
      :type: str
   .. py:property:: scope
      :type: str
   .. py:property:: nonce
      :type: str | None
   .. py:property:: claims
      :type: dict[str, Any]
   .. py:property:: auth_time
      :type: int
   .. py:property:: exp
      :type: int
   .. py:property:: acr
      :type: str | None
   .. py:property:: cnf_jkt
      :type: str | None
   .. py:property:: userinfo_claims
      :type: dict[str, Any] | None

      Claims destined for the UserInfo response. ``None`` means use
      ``claims`` for both destinations (always the case for 0.5.x tokens);
      ``{}`` releases none.

      .. warning::

         ``None`` and omitting the argument are identical: both release the
         full ``claims`` map at the UserInfo endpoint. To release no
         application claims there, pass ``{}``. Never forward a value that may
         be ``None`` when you mean "none"; that silently over-releases
         per-attribute personal data.

      .. versionadded:: 0.6.0

.. code-block:: python

   now = util.now_secs()
   at = tokens.AccessTokenPayload(client_id="demo", sub="alice", scope="openid", exp=now + 600,
                                  claims={"email": "alice@example.com"})
   sealed = codec.seal_access_token(at)
   assert codec.open_access_token(sealed).sub == "alice"
   with pytest.raises(pygrindvakt.GrindvaktError):
       codec.open_code(sealed)              # wrong type tag
