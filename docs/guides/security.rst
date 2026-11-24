Security guide
==============

OAuth 2.0 and OpenID Connect are security protocols whose value depends on a
handful of checks being exactly right. ``pygrindvakt`` is a thin binding: the
protocol logic, the JOSE cryptography and the validation rules live upstream in
``grindvakt``, ``jose-rs`` and ``kryptering``. This guide describes the
security properties the **binding** preserves, the guards it adds on top of
grindvakt, the escape hatches it deliberately leaves reachable, and the rules
an integrator must follow that no library can enforce.

Read this before wiring pygrindvakt into an authentication flow.

.. contents::
   :local:
   :depth: 1


Fail-closed hardening added by the binding
------------------------------------------

The binding bakes fail-closed policy into the Python boundary (ADR 0003), so
framework integrations cannot accidentally omit deployment-critical choices.

.. list-table::
   :header-rows: 1
   :widths: 34 40 26

   * - Guard
     - Security property
     - Escape hatch
   * - :func:`pygrindvakt.rp.verify_id_token` refuses ``expected_nonce=None``
       with :class:`pygrindvakt.AuthnError`.
     - Binds the ID token to the authorization request and prevents replay
       across login sessions.
     - ``unsafe_skip_nonce_check=True`` disables the check and emits a
       ``UserWarning``. Only for flows that genuinely carry no nonce.
   * - :class:`pygrindvakt.client.InMemoryClientStore` raises ``ValueError``
       on duplicate ``client_id`` values.
     - Keeps the last entry, so a copy-paste error silently changes which
       secret or redirect URI is live.
     - Use ``put()`` after construction if you really want to overwrite.
   * - :class:`pygrindvakt.client.Client` is keyword-only after ``client_id``
       and rejects unknown keywords (``TypeError``);
       :meth:`~pygrindvakt.client.Client.from_dict` rejects unknown keys
       (``ValueError``).
     - Ignores unknown fields, so ``redirect_uri`` (singular) yields a
       client with no redirect URIs that fails every authorization request.
     - None; fix the field name.
   * - :class:`pygrindvakt.client.Client` accepts a registered
       ``response_policy`` (also nested in
       :meth:`~pygrindvakt.client.Client.from_dict`); unknown keys and
       non-string values raise ``ValueError``.
     - The provider enforces the policy: the ``private_key_jwt`` algorithm
       pin (a ``kid`` is then required) and ID token encryption to the
       client's registered key. ``userinfo_encrypted_response_*`` is stored
       but **not applied**: :meth:`~pygrindvakt.provider.Provider.userinfo`
       returns JSON claims, and core's ``signed_userinfo`` (the only method
       that encrypts) is not bound yet. Do not rely on UserInfo encryption.
       Without the policy a client could sign assertions with any algorithm
       and receive plaintext-signed ID tokens.
     - None; register the policy on the client.
   * - :meth:`pygrindvakt.provider.Provider.authorization_redirect` raises
       ``ValueError`` for reserved id_token claim names in ``extra_claims``
       (:data:`pygrindvakt.provider.RESERVED_ID_TOKEN_CLAIMS`).
     - Silently drops ``iss``, ``sub``, ``aud``, ``exp``, ``iat``, ``nbf``,
       ``jti``, ``nonce``, ``auth_time`` and ``acr`` from ``extra_claims``,
       hiding an attempt to override the subject or nonce.
     - None; use ``sub`` and ``acr`` parameters for those, and
       ``external_claims`` for user attributes.
   * - Hand-sealed codes (:meth:`pygrindvakt.tokens.TokenCodec.seal_code`)
       skip the registration check when ``registration_digest`` is omitted,
       and release the full ``claims`` map at UserInfo when
       ``userinfo_claims=None``.
     - Without the digest a rotated secret or key does not invalidate
       outstanding codes; ``userinfo_claims=None`` over-releases personal
       data to UserInfo.
     - :meth:`pygrindvakt.provider.Provider.authorization_redirect_with_authorized_claims`
       seals the digest and an explicit UserInfo claim set itself.
   * - :class:`pygrindvakt.http.ReqwestClient` never follows redirects,
       enforces connect / read / total timeouts, and caps response bodies
       (streamed, so ``Content-Length`` cannot lie). Zero values are
       rejected.
     - grindvakt ships no HTTP client at all; a naive one would re-send
       token-endpoint bodies (``client_secret``, code) cross-origin on a
       307 / 308 and read unbounded responses.
     - Inject your own ``HttpClient``; then these become **your**
       responsibilities.
   * - DPoP validation requires an atomic replay store; the deprecated
       :class:`pygrindvakt.dpop.NoReplayStore` cannot be constructed.
     - A valid server nonce is replayed along with a captured proof and is
       therefore not a substitute for unique ``jti`` tracking.
     - None; use an in-memory store for one process or a shared store across
       workers.
   * - ``token_url`` / ``htu`` are explicit, documented as "from
       configuration, never from ``Host``".
     - Same requirement, but easy to miss.
     - None; see below.
   * - Python protocol adapters fail closed: an exception in a store or HTTP
       client is logged via ``sys.unraisablehook`` and reported as
       ``server_error`` / :class:`pygrindvakt.InternalError`.
     - Not applicable (Rust traits).
     - None.
   * - The per-call ``redirect_uri=`` override of
       :func:`~pygrindvakt.rp.authorization_url`,
       :func:`~pygrindvakt.rp.signed_request_object`,
       :func:`~pygrindvakt.rp.begin` and :func:`~pygrindvakt.rp.exchange_code`
       is accepted only if it equals the client's ``redirect_uri`` or an entry
       of :class:`RpClient(redirect_uris=[...]) <pygrindvakt.rp.RpClient>`
       (:class:`~pygrindvakt.BadRequestError` otherwise). Registered entries
       are checked at construction and may not be plain ``http`` to a
       non-loopback host; the client's own ``redirect_uri`` is not
       transport-checked.
     - The override is often derived from a request parameter. Accepting any
       valid URL lets an attacker send the authorization request with their own
       ``redirect_uri`` and receive the code.
     - ``RpClient(allow_unregistered_redirect_uri=True)`` skips the
       registration check (an override that differs from ``redirect_uri``
       must still be a valid URL and not plaintext http to a non-loopback
       host). It is set at construction, shows up in ``repr()``, and emits **no
       warning**: use it only for RFC 7591 dynamic registrations.
   * - :func:`~pygrindvakt.rp.end_session_url` accepts a
       ``post_logout_redirect_uri`` only when ``client=`` is passed and the
       value is registered on
       :class:`RpClient(post_logout_redirect_uris=[...]) <pygrindvakt.rp.RpClient>`,
       and :class:`~pygrindvakt.rp.ProviderInfo` binds ``end_session_endpoint``
       to the issuer's origin.
     - The logout URL carries ``id_token_hint`` (the whole ID token) to the
       OP only. An unregistered ``post_logout_redirect_uri`` turns a crafted
       logout link into an open redirect to an attacker-chosen host, unless
       the OP rejects it.
     - None for the registration check. ``allow_cross_origin_end_session=True``
       on ``ProviderInfo`` / ``from_metadata`` for OPs that legitimately log
       out on another origin.
   * - :class:`~pygrindvakt.metadata.ProviderMetadata` URL-validates the
       modelled endpoints, the extension ``*_endpoint`` members and the
       ``issuer`` on every write path (constructor, ``from_dict``, setters,
       ``set_extra_field``).
     - A document served under a trusted URL could otherwise point token,
       UserInfo or JWKS traffic at plaintext ``http``, a ``javascript:`` URL or
       a fragment-bearing URL.
     - None; fix the document. :func:`~pygrindvakt.rp.discover` deliberately
       does **not** apply the binding's own checks (extension members, the
       empty-string endpoint rule), so the binding adds no failures over a
       foreign document; upstream discovery still rejects malformed modelled
       endpoints. Re-validate before you act on what ``raw`` contains.

   * - ``HS256`` / ``HS384`` / ``HS512`` in ``allowed_algorithms`` with a
       :class:`~pygrindvakt.rp.JwksCache` (also via
       :func:`~pygrindvakt.rp.verify_id_token` or
       :func:`~pygrindvakt.rp.fetch_userinfo`) raise
       :class:`~pygrindvakt.ConfigError` (``code == "shared_secret_algorithm"``).
       An ``oct`` key in a JWK Set fetched from a ``jwks_uri``
       (:func:`~pygrindvakt.rp.fetch_jwks`, ``JwksCache``, the federation
       JWKS helpers, including inline ``jwks`` in entity metadata) is dropped
       with a ``UserWarning``. The drop is unconditional: it also happens when
       ``warnings`` is configured as errors (fail-closed). The same drop
       applies to every key set that enters federation verification: the
       ``jwks`` of :func:`~pygrindvakt.federation.verify` /
       ``verify_typed``, the ``trust_anchors`` map of
       :func:`~pygrindvakt.federation.resolve_via_trust_anchors`, the
       ``subject_fed_jwks`` of ``entity_metadata_jwks`` / ``fetch_signed_jwks``,
       and the getters ``EntityStatement.jwks()`` and
       ``ResolvedEntity.subject_jwks``. ``federation.verify``,
       ``verify_typed`` and ``verify_self_signed`` also refuse a token whose
       header ``alg`` is ``HS*`` or ``none`` with
       :class:`~pygrindvakt.AuthnError` (``code == "symmetric_algorithm"``).
     - OIDC Core 10.1 derives the MAC key from the ``client_secret``; an OP
       must not publish symmetric keys. Honouring a published ``oct`` key lets
       whoever controls the JWKS document (or its transport) mint tokens that
       pass an ``HS*`` allow-list. In a federation, an entity that publishes
       an ``oct`` key in its ``jwks`` would otherwise let anyone sign a
       ``jwk-set+jwt`` or entity statement with ``HS256`` and inject an
       attacker key as the OP's signing key. Federation entities sign with
       asymmetric keys; symmetric keys cannot be published.
     - None, by design (ADR 0006). Verify ``HS*`` tokens with
       :func:`~pygrindvakt.rp.verify_id_token` and a key set you build from
       the ``client_secret``; that path needs no flag. The filter covers key
       sets this library fetches; a JWKS dict you fetched or assembled
       yourself is a caller-built key set and cannot be told apart from a
       ``client_secret``-derived one, so never feed a fetched set into an
       ``HS*`` allow-list.
   * - An ``HS*`` ID token (or signed UserInfo), or a token passed to
       :func:`~pygrindvakt.jwt.verify_with_jwks` /
       :func:`~pygrindvakt.jwt.verify_with_jwk` (since 0.3.0; these were
       ungated before), verified against a caller-built key set whose ``oct`` key (the one the token
       selects by ``kid``, or the only key) is shorter than the hash output
       (32 / 48 / 64 bytes) raises :class:`~pygrindvakt.ConfigError`
       (``code == "weak_shared_secret"``).
     - RFC 7518 3.2 requires a key at least as long as the hash output; a short
       client secret is brute-forceable offline from one captured token.
     - None; use a longer ``client_secret``.
   * - :func:`pygrindvakt.rp.parse_authorization_response` raises
       :class:`~pygrindvakt.BadRequestError` for repeated parameters, both or
       neither of ``code`` and ``error``, a ``form_post`` response whose
       protocol parameters also appear in the query string (or a query
       response whose form body carries them), control, bidi or invisible
       characters, backslashes or more than 2048 characters in ``code`` /
       ``state`` / ``iss``, a malformed ``error``, a JARM ``response``, and
       plaintext parameters next to a JARM ``response``; a mapping with
       non-list values (a plain ``dict``) raises ``TypeError``. ``error_description`` is exposed only escaped and capped
       (``error_description_safe``); ``error_uri`` only when it is a safe
       absolute https URL (http only for loopback), normalised.
     - Callback parameters are attacker-influenced. A mapping or a repeated
       parameter lets a second value hide behind the first, and a provider
       description with ANSI, bidi or newline characters can forge log
       lines. The response proves nothing until ``state`` is compared and
       ``iss`` is checked (RFC 9207 mix-up defence).
     - ``accept_jarm=True`` exposes the raw, UNVERIFIED ``response`` JWT as a
       stub; verify it with
       :meth:`~pygrindvakt.rp.AuthorizationResponse.verify_jarm` (see
       :ref:`jarm-verification` below). ``matches_state`` and ``matches_iss``
       are the caller's job and cannot be forced; both fail closed
       (``matches_state`` on a missing ``state``, ``matches_iss`` on a missing
       ``iss`` unless you pass ``required=False`` for an
       OP that does not advertise
       ``authorization_response_iss_parameter_supported``).
   * - :class:`~pygrindvakt.rp.DiscoveryCache` serves an expired discovery
       document only after a failed refetch, only with ``stale_on_error=True``
       and only up to ``max_stale`` seconds past its expiry, and only for the
       configured issuer: a document whose ``issuer`` differs is never cached
       or served. Its ``jwks()`` returns a :class:`~pygrindvakt.rp.JwksCache`
       that is rebuilt (the old one never returned again) when ``jwks_uri`` or
       issuer change, and that never serves expired keys.
     - Unbounded stale metadata would be fail-open: an OP that moved its
       endpoints or retired a key location would be trusted indefinitely. The
       bound, the opt-out and the surfaced failure (a one-time
       ``UserWarning``, ``discovery_backoff`` with the original as
       ``__cause__``) keep it visible. Keys, the actual trust anchor of
       ID-token verification, stay never-stale, and keys cached for one
       ``jwks_uri`` cannot verify tokens after the OP moves it (ADR 0008).
     - ``stale_on_error=False`` to never serve expired metadata;
       ``max_stale`` to shorten the window. Raising ``max_stale`` widens it.

If grindvakt later adopts these guards upstream, the binding's checks become
redundant but harmless.


.. _jarm-verification:

Verifying a JARM response
-------------------------

:meth:`AuthorizationResponse.verify_jarm <pygrindvakt.rp.AuthorizationResponse.verify_jarm>`
verifies a signed authorization response (JARM) parsed with
``accept_jarm=True``. The signature is not the whole defence:

* **ID tokens are signed by the same OP.** An ID token has the same ``iss`` and
  ``aud`` as a JARM response and is signed by the same key. Where the keys are
  shared, a captured ID token could be presented as a JARM response. The default
  ``trust="typed"`` requires the JOSE ``typ`` ``oauth-authz-resp+jwt``
  (``rp.JARM_TYP``), which an ID token does not carry. Keep it unless the OP
  cannot type its responses.
* **The opt-in trust modes are caller attestations.** ``"dedicated_keys"``
  asserts that the key set holds only JARM signing keys.
  ``"untyped_shared_key_compat"`` is the weakest: with shared keys and no
  ``typ`` an ID token is indistinguishable from a JARM response. In this
  release the two behave the same (a missing ``typ`` or ``JWT`` is
  accepted), so do not rely on any difference. ``typ`` is only valid with
  ``"typed"``.
* **Pin the algorithms.** ``allowed_algorithms`` is required; pass
  ``rp.JARM_ASYMMETRIC_ALGORITHMS`` or the exact algorithm the OP announces. An
  ``HS*`` algorithm with a ``JwksCache`` raises ``ConfigError``
  (``shared_secret_algorithm``, ADR 0006); an ``HS*`` response with a
  caller-built key set needs a key at least as long as the hash output.
* **A verified response can be replayed until ``exp``.** There is no ``iat`` or
  max-age bound. Single use comes from consuming the session ``state`` once.
* **Always check ``state`` and ``iss`` on the verified result.** Verification
  does not know your session. Call ``matches_state`` and ``matches_iss`` on
  the result of ``verify_jarm``; on the unverified stub they always return
  ``False``. See ADR 0009.
* **Never fall back to plain parameters.** If you requested a JARM response
  mode, call ``verify_jarm`` on every callback without checking
  ``resp.response`` first. ``accept_jarm=True`` also accepts an ordinary code
  or error response; ``verify_jarm`` rejects that with ``BadRequestError``,
  whereas skipping it would accept unsigned ``code``, ``state`` and ``iss``.

``token_url`` comes from configuration, never from ``Host``
------------------------------------------------------------

:meth:`pygrindvakt.provider.Provider.handle_token_request`,
:meth:`~pygrindvakt.provider.Provider.authenticate_client`,
:func:`pygrindvakt.dpop.validate_proof` and
:func:`pygrindvakt.dpop.validate_resource_proof` all take the absolute URL of
the endpoint being served. That URL is compared against:

* the ``aud`` of a ``private_key_jwt`` client assertion, and
* the ``htu`` of a DPoP proof.

If you build it from the incoming request (``request.host``,
``request.url``, ``build_absolute_uri()``), an attacker who can influence the
``Host`` header, or who sits behind a misconfigured reverse proxy, chooses
what those checks compare against: an assertion or proof minted for
``https://attacker.example/token`` would validate on your OP. Derive the URL
from the same setting that produced
:class:`pygrindvakt.metadata.ProviderMetadata`:

.. code-block:: python

   ISSUER = os.environ["OP_ISSUER"]            # configuration
   TOKEN_URL = f"{ISSUER}/token"               # what clients are told in discovery

   op.handle_token_request(form_pairs, TOKEN_URL, auth_header=auth)      # correct
   op.handle_token_request(form_pairs, request.url, auth_header=auth)    # WRONG

The examples under ``examples/`` all follow this rule; the Flask, Django and
FastAPI guides call it out at the token endpoint.


Never send ``str(exc)`` to a client
-----------------------------------

The message of a :class:`pygrindvakt.GrindvaktError` is an operator-facing
diagnostic. It may quote an upstream error body, name an internal host, say
which key or algorithm was rejected, or describe why a signature failed. None
of that belongs in an HTTP response.

Exactly two things are client-safe:

* :meth:`pygrindvakt.OAuthError.to_response` for direct (JSON) errors at the
  token and userinfo endpoints, and for authorization-endpoint errors raised
  **before** the ``redirect_uri`` was validated.
* :meth:`pygrindvakt.OAuthError.to_redirect` for authorization-endpoint
  errors **after** validation succeeded.

Everything else should become a generic ``server_error``:

.. code-block:: python

   try:
       tr = op.handle_token_request(form_pairs, TOKEN_URL, auth_header=auth)
   except OAuthError as e:
       return to_flask(e.to_response())
   except GrindvaktError as e:
       log.error("token endpoint failure: %s", e.log_summary)   # log only, never the client
       return to_flask(OAuthError("server_error").to_response())

The structured attributes on upstream failures need the same care.
``exc.upstream_status`` and ``exc.upstream_error`` (the OAuth ``error`` code)
are fine to log or branch on, but ``exc.upstream_error_description`` and
``exc.upstream_body`` are free text from the upstream and may echo secrets or
personal data. Escaping makes them safe to print, not safe to disclose: do not
log them verbatim and never return them to end users.

On the RP side the same applies to :class:`pygrindvakt.AuthnError` raised by
:func:`~pygrindvakt.rp.exchange_code` or
:func:`~pygrindvakt.rp.verify_id_token`: log it
(``e.log_summary``), show the user a generic "login failed" page. Catch
:class:`pygrindvakt.ConfigError` first: it is a deployment fault (a bad
``auth_method``, algorithm list or ``JwksCache`` argument), not a failed login.
Log it and re-raise, never render it as "login failed" or as a 4xx/503, so a
broken configuration is noticed:

.. code-block:: python

   try:
       ts = rp.exchange_code(http, info, client, code, code_verifier=verifier)
       claims = rp.verify_id_token(jwks, ts.id_token, info.issuer, client.client_id, nonce, ["ES256"])
   except ConfigError as e:
       log.error("RP misconfigured: %s", e.log_summary)
       raise
   except GrindvaktError as e:
       log.warning("login failed: %s", e.log_summary)
       if e.retryable:                                   # OP or network trouble
           return render_template("login_unavailable.html"), 503
       return render_template("login_failed.html"), 401 if e.auth_failure else 400

``ConfigError`` is handled before the generic branch. There, ``retryable``
(OP or network trouble) gives 503, ``auth_failure`` gives 401 and anything
else gives 400. The status is for monitors and clients only; the body stays
generic and no error detail is sent to the browser.

``retryable`` does not make the callback safe to replay. Popping the pending
entry before the token exchange is not enough for strict single use: with
Flask's default signed-cookie session an older cookie can restore the entry,
and concurrent callbacks can each pass the state check. Keep the pending entry
server-side and consume it in one atomic step (for example a database
``DELETE ... RETURNING`` or a Redis ``GETDEL``). The OP rejects a code it has
already used, which is a separate protection. After a retryable failure, start
a new login instead of retrying the same callback.


The redirect policy
-------------------

Two different redirect rules matter.

**Inbound (authorization endpoint).** The ``redirect_uri`` in an authorization
request is attacker-controlled until
:meth:`~pygrindvakt.provider.Provider.validate_authorization_request` has
confirmed it exactly matches one registered for the client. Before that
point, render errors with ``to_response()``; after it, ``to_redirect()`` is
safe. The split is deliberate: an OP that redirects unvalidated URIs is an
open redirector and a phishing tool.

.. code-block:: python

   try:
       req = AuthorizationRequest.from_params(query_pairs)
       op.validate_authorization_request(req)
   except OAuthError as e:
       return e.to_response()                  # NOT to_redirect: redirect_uri is untrusted
   session["authz"] = req.to_dict()
   # ... later, after login ...
   except OAuthError as e:
       mode = "fragment" if req.use_fragment() else "query"
       return e.to_redirect(req.redirect_uri, mode)  # safe: validated above

Matching is exact, with no prefix or wildcard support, and there is no
``localhost`` exception.

As a last guard, ``to_redirect()`` raises ``BadRequestError`` if the base
contains whitespace, control, bidi or invisible characters or userinfo, is
unparsable, or has a fragment (``Location`` header injection). It does not
check registration; the exact match above remains your job.

**Outbound (HTTP client).** The built-in client refuses to follow redirects,
because a 307 / 308 from a token endpoint would re-send the form body
(``client_secret``, the authorization code, a ``client_assertion``) to
wherever the redirect points. The RP functions treat a ``3xx`` as a failed
request. If you inject your own ``HttpClient``, keep that property:
``follow_redirects=False`` in ``httpx``, ``allow_redirects=False`` in
``requests``.


TLS: rustls, not the system OpenSSL
-----------------------------------

Outbound HTTPS uses ``rustls`` compiled into the extension, with the bundled
Mozilla root store (``webpki-roots``). There is no OpenSSL dependency, no
environment variable that disables verification, and no ``verify=False``.
Two consequences:

* A private CA is not picked up from the system trust store,
  ``SSL_CERT_FILE`` or ``REQUESTS_CA_BUNDLE``. To talk to an OP with a
  private certificate,
  inject an ``HttpClient`` built on a Python library configured with that CA
  (see :doc:`rp`), keeping the no-redirect and size-cap rules.
* :func:`pygrindvakt.rp.discover` requires an ``https`` issuer. Plain ``http``
  is accepted only for loopback hosts, which is what the examples use on
  ``127.0.0.1``.


Secrets are Python strings
--------------------------

The token codec secret, client secrets, the DPoP nonce secret and a PKCS#11
PIN are passed as ``str``. A Python string is immutable and cannot be
zeroized: it stays in memory until the garbage collector reclaims it, and it
may be copied by string operations along the way. The Rust side copies the
value into its own buffers and never exposes it back (no getter, nothing in
``repr()``), but the original Python object is beyond the binding's control.

Practical rules:

* Read secrets from a secret store or the environment at startup, pass them
  straight into the constructor, and do not keep other references.
* Prefer :func:`pygrindvakt.keys.signing_key_from_pkcs11` for the OP signing
  key in production: the private key never leaves the token, so only the PIN
  is exposed to this problem.
* Rotate the codec secret with ``previous_secrets`` rather than restarting
  with a new one; see :class:`pygrindvakt.tokens.TokenCodec`.


Input hardening the binding inherits from grindvakt
---------------------------------------------------

* **JWT verification** rejects ``alg: none`` and symmetric algorithms against
  public keys, requires ``exp`` where the protocol does, and enforces
  ``typ`` where a type is defined (entity statements, resolve responses,
  signed JWK sets, DPoP proofs), so a token issued for one purpose cannot be
  presented for another.
* **Discovery** requires the ``issuer`` in the fetched document to equal the
  requested one exactly (OIDC Discovery section 4.3), which stops a
  compromised or mis-served document from redirecting the RP to another
  provider's endpoints.
* **PKCE** defaults to ``S256`` and the OP advertises only ``S256``.
* **Authorization codes, refresh tokens and assertion** ``jti`` **values are
  single-use**, enforced through the token-use store. Refresh tokens rotate.
* **Federation** verifies the whole trust chain: the trust anchor's entity
  configuration against the keys you configured, the resolve response's
  ``typ``, the chain's start (the subject) and end (the anchor), every
  subordinate statement's signature, and the ``sub`` you asked for.
* **Discovery-service URLs** (``initiate_login_uri``) must be ``https``
  without a fragment before a user is ever sent to them.


Footguns the API leaves reachable (and why)
-------------------------------------------

Each is named so it stands out in a code review.

``unsafe_skip_nonce_check=True``
   Disables the nonce check in :func:`pygrindvakt.rp.verify_id_token` and
   emits a ``UserWarning``. Exists for pure OAuth 2.0 flows that return an
   id_token without ever having sent a nonce. In the standard code flow it
   allows id_token replay. See :doc:`rp`.

``RpClient(allow_unregistered_redirect_uri=True)``
   Turns off the registration check on per-call ``redirect_uri`` overrides, so
   any syntactically valid URL that is not plaintext ``http`` to a non-loopback
   host is accepted. Unlike the ``unsafe_*`` arguments it warns nothing at call
   time; the flag is visible in ``repr()`` and in the constructor call. Legitimate only for RFC 7591 dynamic
   registrations, and never with a value that came from request data.

:func:`pygrindvakt.jwt.peek_claims_unverified` and :func:`pygrindvakt.federation.decode_unverified`
   Return claims without checking any signature. For inspection only (which
   key set to fetch, which authority to ask). Never make a decision on their
   output.

Python protocol adapters
   A ``ClientStore``, ``TokenUseStore``, ``ReplayStore`` or ``HttpClient``
   you write yourself is inside the trust boundary. The binding guarantees
   that an *exception* fails closed; it cannot guarantee that a ``consume``
   that always returns ``True`` is a bug. Test them.

``DiscoveryCache(stale_on_error=True, max_stale=...)``
   During an outage of the well-known endpoint the cache keeps serving the
   last discovery document, up to ``max_stale`` seconds (default 24 hours)
   past its expiry, with a one-time ``UserWarning``. The worst case is the
   document's lifetime plus ``max_stale``: with the defaults (``max_ttl`` 24
   hours, ``max_stale`` 24 hours) an endpoint change can go unnoticed for up
   to about two days of an outage. That keeps login working but means
   endpoint changes made by the OP are not seen meanwhile. Pass
   ``stale_on_error=False`` to fail instead, or lower ``max_stale``. Keys are
   unaffected: ``cache.jwks()`` never serves an expired key set. See ADR 0008.

In-memory stores
   :class:`~pygrindvakt.provider.InMemoryTokenUseStore`,
   :class:`~pygrindvakt.dpop.InMemoryReplayStore` and
   :class:`~pygrindvakt.client.InMemoryClientStore` are per process. Behind
   a multi-worker server, a code consumed by one worker is fresh in every
   other one. See :doc:`stores`.


Checklist for a production OP
-----------------------------

#. Derive the issuer and every endpoint URL, in particular ``token_url``,
   from configuration; never from ``Host``.
#. Use a shared, fail-closed token-use store
   (:class:`~pygrindvakt.provider.RedisStore`, constructed after fork, or a
   Python-backed one) whenever more than one process serves the token
   endpoint.
#. Render authorization-endpoint errors with ``to_response()`` until
   ``validate_authorization_request`` has succeeded, then with
   ``to_redirect()``.
#. Send only ``OAuthError.to_response()`` / ``to_redirect()`` output to
   clients; log everything else.
#. Keep the signing key on a PKCS#11 token where you can; otherwise load it
   from a file with restrictive permissions, never from source.
#. If you enable DPoP, use an atomic shared replay store across workers.
   A nonce is defense in depth, not a replacement for replay tracking.
#. Do not set any ``unsafe_*`` argument.

Checklist for a production RP
-----------------------------

#. Generate fresh ``state``, ``nonce`` and PKCE verifier per login, store
   them in the user's session, and check ``state`` on the callback before
   doing anything else.
#. Always pass the stored nonce to ``verify_id_token``; never
   ``unsafe_skip_nonce_check``.
#. Pass a non-empty allowlist of ID-token signing algorithms derived from
   trusted provider configuration, and opt in explicitly to any additional
   audience you trust.
#. Register every login redirect URI on the :class:`~pygrindvakt.rp.RpClient`
   (``redirect_uris=[...]``) instead of passing ``allow_unregistered_redirect_uri``,
   and register the ``post_logout_redirect_uris`` you use with
   :func:`~pygrindvakt.rp.end_session_url`.
#. In an implicit / hybrid flow, pass the ``access_token`` /
   ``authorization_code`` together with ``require_at_hash`` /
   ``require_c_hash`` or ``strict_hashes=True``, so an id_token carrying a hash
   claim that cannot be checked is refused instead of accepted.
#. Prefer ``private_key_jwt`` over shared secrets; the OP then holds only
   your public key.
#. Keep the built-in HTTP client, or make sure your own never follows
   redirects, enforces timeouts and caps bodies.
#. Treat ``AuthnError`` messages as log material.
#. Do not set ``unsafe_skip_nonce_check`` or
   ``allow_unregistered_redirect_uri``; register the redirect URIs instead.
