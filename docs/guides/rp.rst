Relying Party integration
=========================

A Relying Party (RP) sends the user to an OpenID Provider (OP), receives an
authorization code on its callback, exchanges it for tokens, verifies the
id_token, and optionally fetches userinfo. :mod:`pygrindvakt.rp` implements
each step; this guide strings them together. The runnable version is
``examples/flask-rp`` in the repository.

.. contents::
   :local:
   :depth: 1

Discovery
---------

Resolve the OP's metadata from its issuer URL. The issuer must be ``https``
(plain ``http`` only for loopback hosts), and the ``issuer`` in the returned
document must equal the requested one exactly, so a document served from the
wrong place cannot redirect you to someone else's endpoints.

.. code-block:: python

   from pygrindvakt import http, rp

   http_client = http.ReqwestClient()                     # never follows redirects, bounded body
   md = rp.discover(http_client, "https://op.example.com")
   info = rp.ProviderInfo.from_metadata(md)

Discovery is one HTTP round trip; keep ``info`` for the process lifetime and
refresh it on a timer. The provider's signing keys are cached by a
:class:`~pygrindvakt.rp.JwksCache` (see below).

``ProviderInfo.from_metadata(discover(...))`` keeps the discovery document as
``info.metadata``; ``discover`` itself returns a
:class:`~pygrindvakt.metadata.ProviderMetadata`, which has no ``.metadata``.

.. warning::

   Every endpoint on ``info.metadata`` (``userinfo_endpoint``,
   ``token_endpoint``, ``authorization_endpoint``, ``jwks_uri``,
   ``end_session_endpoint`` ...) is UNVALIDATED data from the OP. Never send
   credentials or tokens to them; use the validated properties on ``info``
   itself (``info.userinfo_endpoint``, ``info.token_endpoint`` ...). The raw
   ``end_session_endpoint`` is kept only to diagnose a rejection.

For a statically configured OP, build the
:class:`~pygrindvakt.rp.ProviderInfo` by hand instead:

.. code-block:: python

   info = rp.ProviderInfo(
       "https://op.example.com",
       "https://op.example.com/authorization",
       "https://op.example.com/token",
       userinfo_endpoint="https://op.example.com/userinfo",
       jwks_uri="https://op.example.com/jwks",
   )

The client
----------

An :class:`~pygrindvakt.rp.RpClient` carries the ``client_id``, the
``redirect_uri`` registered at the OP, the requested ``scope`` and how the
client authenticates at the token endpoint. The method defaults to
``client_secret_basic`` when a secret is given and ``none`` otherwise;
inconsistent combinations raise :class:`~pygrindvakt.ConfigError` (also a
``ValueError``) rather than being ignored.

.. code-block:: python

   me = rp.RpClient("demo", "https://rp.example.com/cb", client_secret=os.environ["OIDC_CLIENT_SECRET"])
   # or, for a public client (native app, SPA): rp.RpClient("spa", "https://rp.example.com/cb")

Startup checks
--------------

Two checks let a service fail at startup instead of on the first login.
:func:`~pygrindvakt.rp.check_rp_compatibility` compares your intent with what
the OP advertises, and :func:`pygrindvakt.http.supports_get_with_headers`
checks a custom HTTP client before you rely on ``fetch_userinfo(method="GET")``:

.. code-block:: python

   problems = rp.check_rp_compatibility(info, client=me, pkce=True, algorithms=["ES256"])
   hard = [p for p in problems if not p.startswith("not advertised:")]
   if hard:
       raise SystemExit("; ".join(hard))
   if not http.supports_get_with_headers(http_client):
       raise SystemExit("http_client cannot send headers on GET")

``check_rp_compatibility`` accepts the ``ProviderInfo`` or the
``ProviderMetadata`` from ``discover`` directly. It checks ``code`` in
``response_types_supported``, ``S256`` in ``code_challenge_methods_supported``
(only with ``pkce=True``), your ``algorithms``, ``scopes`` and ``acr_values``,
and the client's token endpoint auth method. Two ``algorithms`` rules mirror
ADR 0006: ``none`` is always reported (fix the RP config), and ``HS256``/
``HS384``/``HS512`` are reported unless you pass ``shared_secret_keys=True``
(you verify with a key set derived from the ``client_secret``). It remains
advisory. It does not check
``grant_types_supported``, ``response_modes_supported``, DPoP or anything else.

Messages starting with ``not advertised:`` are informational (the OP omits
that metadata member; no default is assumed, so ``RS256`` is not assumed for
``id_token_signing_alg_values_supported``). The one exception is
``token_endpoint_auth_methods_supported``: when absent or empty, the spec
default ``["client_secret_basic"]`` is assumed, so a ``client_secret_post``,
``private_key_jwt`` or ``none`` client is reported as a real mismatch. The
metadata is untrusted data from the OP, so treat the result as advice. If ``from_metadata`` dropped the OP's
``end_session_endpoint`` (it warns), compare ``info.end_session_endpoint``
with ``info.metadata.end_session_endpoint`` to see that it was rejected.

Starting the flow: PKCE, state and nonce in the session
-------------------------------------------------------

:func:`~pygrindvakt.rp.begin` generates three fresh random values per login
and builds the authorization URL; store the values in the user's session
before redirecting:

* ``state`` binds the callback to this browser session (CSRF protection on
  the callback).
* ``nonce`` binds the id_token to this authorization request (replay
  protection); it comes back inside the signed id_token.
* the PKCE ``verifier`` binds the code exchange to the party that started
  the flow; only its ``S256`` challenge leaves the RP.

.. code-block:: python

   @app.get("/login")
   def login():
       started = rp.begin(info, me)          # a rp.BeginResult (still a tuple)
       session["oidc"] = {
           "state": started.state,
           "nonce": started.nonce,
           "verifier": started.code_verifier,
       }
       return redirect(started.url)

The result is a named tuple, so ``url, state, nonce, verifier = rp.begin(info,
me)`` works too. Its ``repr()`` redacts the secrets, so it is safe in a debug
log.

``state`` and ``nonce`` are 32 random bytes each and the verifier is 48
(64 characters, within the RFC 7636 range). ``pkce=False`` is refused for
public clients.

Under the hood this is :func:`~pygrindvakt.rp.authorization_url` plus
:func:`pygrindvakt.util.random_token` and
:func:`pygrindvakt.pkce.s256_challenge`; call those directly if you need
full control.

Per-request redirect URI
~~~~~~~~~~~~~~~~~~~~~~~~

.. warning::

   Never take ``redirect_uri`` from request parameters (query string, form
   fields, headers such as ``Host`` or ``X-Forwarded-*``). An attacker-chosen
   value would send the authorization code to their site. The exact-match
   rule against ``redirect_uris`` exists for that reason: choose from your
   own registered list, never pass request data through.

``begin``, ``authorization_url`` and ``signed_request_object`` accept a
keyword-only ``redirect_uri`` that replaces the client's configured one for
that call. It must exactly equal the client's ``redirect_uri`` or one of
``RpClient(redirect_uris=[...])``, a fixed server-side list that you also
register at the OP (:class:`pygrindvakt.BadRequestError` otherwise). Entries
must be absolute, have no fragment and not be plain ``http`` to a non-loopback
host (``https``, loopback ``http`` and custom schemes for native apps are
fine). "Loopback" means exactly ``localhost``, ``127.0.0.0/8`` or ``::1``
(not ``foo.localhost`` or ``localhost.``). The client's own configured
``redirect_uri`` is not transport-checked (unchanged), so use ``https`` there
too. In the example, ``cb`` is one of those registered strings (for
instance chosen by which of your own hosts served the login page).
Pass the **same value** to ``exchange_code(..., redirect_uri=...)`` (RFC 6749
section 4.1.3), so keep it in the session with the other values:

.. code-block:: python

   url, state, nonce, verifier = rp.begin(info, me, redirect_uri=cb)
   session["oidc"] = {"state": state, "nonce": nonce, "verifier": verifier, "redirect_uri": cb}
   # callback:
   ts = rp.exchange_code(http_client, info, me, code,
                         code_verifier=pending["verifier"], redirect_uri=pending["redirect_uri"])

Register the alternatives on the client::

   me = rp.RpClient("demo", "https://rp.example.com/cb",
                    redirect_uris=["https://rp.example.com/alt"])

``RpClient(allow_unregistered_redirect_uri=True)`` disables the registration
check, for RPs that register redirect URIs dynamically (RFC 7591). The
override must still be a valid URL and not plain ``http`` to a non-loopback
host, but any attacker-influenced value is now accepted, so the warning above
applies with full force.

``authorization_url`` also accepts ``extra`` parameters (a dict or a list of
pairs, so names can repeat) for ``prompt``, ``acr_values``, ``login_hint`` or
a signed request object:

.. code-block:: python

   url = rp.authorization_url(info, me, state, nonce, code_challenge=challenge,
                              extra={"prompt": "login", "acr_values": "urn:mfa"})

Do not combine these with a request object: see the signed request object
section below.

The callback: exchange and verify
---------------------------------

On the callback, parse the response with
:func:`~pygrindvakt.rp.parse_authorization_response`, then check ``state``
against the session entry (popped first; see the warning below for what that
does and does not guarantee) with
:meth:`~pygrindvakt.rp.AuthorizationResponse.matches_state` and ``iss``
with :meth:`~pygrindvakt.rp.AuthorizationResponse.matches_iss`. Then exchange the code with the stored verifier and verify the
id_token against the issuer, your ``client_id`` and the stored nonce, using the
process-wide :class:`~pygrindvakt.rp.JwksCache`.

.. code-block:: python

   from pygrindvakt import AuthnError, BadRequestError, ConfigError, GrindvaktError

   # Created once at startup, next to `info`; thread-safe, shared by all requests.
   jwks_cache = rp.JwksCache(http_client, info.jwks_uri, info.issuer)

   @app.get("/callback")
   def callback():
       pending = session.pop("oidc", None)
       try:
           # items(multi=True) keeps duplicates; a plain dict would hide them.
           resp = rp.parse_authorization_response(list(request.args.items(multi=True)))
       except BadRequestError as e:
           log.warning("bad callback: %s", e.log_summary)
           abort(400)
       # The parse proves nothing: state and iss are still ours to check.
       if pending is None or not resp.matches_state(pending["state"]):
           abort(400)                                        # not our flow
       if not resp.matches_iss(info.issuer):
           abort(400)                                        # wrong OP or missing iss (RFC 9207)
       if resp.is_error:
           log.warning("OP returned %s: %s", resp.error, resp.error_description_safe)
           return render_template("login_failed.html")
       try:
           ts = rp.exchange_code(http_client, info, me, resp.code, code_verifier=pending["verifier"])
           claims = rp.verify_id_token(
               jwks_cache, ts.id_token, info.issuer, me.client_id,
               pending["nonce"], ["ES256"],
           )
       except ConfigError as e:
           log.error("RP misconfigured: %s", e.log_summary)  # deployment fault: log, alert, 500
           raise
       except GrindvaktError as e:
           log.warning("login failed: %s", e.log_summary)    # log_summary is for logs only
           if e.retryable:                                   # OP or network trouble
               return render_template("login_unavailable.html"), 503
           return render_template("login_failed.html"), 401 if e.auth_failure else 400
       session["user"] = {"sub": claims["sub"], "email": claims.get("email")}
       return redirect("/")

:func:`~pygrindvakt.rp.parse_authorization_response` replaces hand-written
``request.args`` handling. It refuses repeated parameters, a response with
both or neither of ``code`` and ``error``, control, bidi or invisible
characters and values over 2048 characters in ``code`` / ``state`` / ``iss``,
a malformed ``error`` and, unless ``accept_jarm=True``, a JARM ``response`` (see
`ADR 0007 <https://github.com/kushaldas/pygrindvakt/blob/main/docs/adr/0007-authorization-response-parsing.md>`_).
It proves nothing by itself: you still call ``matches_state`` (constant
time) and ``matches_iss``, always before exchanging the code. Both fail
closed. ``matches_state`` keeps ``required=True`` because ``rp.authorization_url``
and ``rp.begin`` always send ``state`` (RFC 6749 section 10.12); pass
``required=False`` only for a request you deliberately built without it. A
response without ``iss`` does not match. Only if the OP metadata does **not** advertise
``authorization_response_iss_parameter_supported`` (RFC 9207 section 2.4) may you
pass ``required=False`` so that a missing ``iss`` is tolerated; a present
``iss`` is always compared exactly. Log
``error_description_safe``, never the raw ``error_description`` (the binding
does not expose it: it is provider-controlled text). Treat ``error_uri`` as
untrusted: do not follow it or render it as a link (it is kept only as an
https URL, or plain http for loopback). Unknown error codes are
kept (``error_known`` is false) so they can be logged and shown as a generic
failure. ``error_known`` is wider than what
:class:`~pygrindvakt.OAuthError` accepts, so do not rebuild an ``OAuthError``
from ``resp.error``: ``OAuthError("consent_required")`` raises
``ValueError``. Branch on the string instead, for example
``if resp.error == "access_denied": ...`` (and ``login_required`` /
``interaction_required`` for a silent ``prompt=none`` attempt). For a ``response_mode=form_post`` callback pass the
:class:`~pygrindvakt.http.HttpRequestData` of the ``POST`` instead (with its
form already parsed). A werkzeug ``request.args`` can also be passed directly;
a plain ``dict`` is refused. When building an
:class:`~pygrindvakt.http.HttpRequestData` for the parser, pass ``query`` /
``form`` as a list of pairs (``request.args.items(multi=True)``), not a
``dict`` such as ``request.args.to_dict()``: a mapping-built channel raises
``TypeError`` because it has already dropped duplicate parameters.

For a signed JARM callback (``response_mode=jwt`` and friends) parse with
``accept_jarm=True``, which gives an unverified stub, then verify it. Check
``state`` and ``iss`` on the **verified** result; on the stub both checks
always fail:

.. code-block:: python

   resp = rp.parse_authorization_response(request.args, accept_jarm=True)
   resp = resp.verify_jarm(
       jwks_cache,
       issuer=info.issuer,
       client_id=me.client_id,
       allowed_algorithms=rp.JARM_ASYMMETRIC_ALGORITHMS,
   )  # AuthnError on a bad signature, typ, kid, iss, aud or exp
   if not resp.matches_state(pending["state"]):
       abort(400)
   if not resp.matches_iss(info.issuer):
       abort(400)
   if resp.is_error:
       ...  # the OP's error is inside the JWT: handle it before using resp.code

Call ``verify_jarm`` unconditionally, without checking ``resp.response`` first.
``accept_jarm=True`` also accepts an ordinary code or error response, and a
callback requested in a JARM response mode must never fall back to unsigned
parameters; ``verify_jarm`` raises ``BadRequestError`` for anything that is
not a JARM response. In that case the handler must reject the callback as a
possible downgrade attempt and never fall back to the plain parameters.

``trust`` defaults to ``"typed"``: the JWT must carry the JOSE ``typ``
``oauth-authz-resp+jwt`` (``rp.JARM_TYP``). Only pass ``trust="dedicated_keys"``
or ``"untyped_shared_key_compat"`` for an OP that does not type its JARM
responses (see :ref:`the security guide <jarm-verification>`).

:class:`~pygrindvakt.ConfigError` is handled before the generic branch, so a
broken deployment never looks like a failed login. In the generic branch the
status comes from the exception attributes: ``retryable`` (OP or network
trouble) gives 503, ``auth_failure`` gives 401, anything else gives 400. The
status is for monitors and clients only; the page body is generic and error
details never reach the browser.

.. warning:: ``retryable`` does not make the callback safe to replay.

   Pop the pending entry before the token exchange, but do not rely on the pop
   alone for single use. With Flask's default signed-cookie session the pending
   entry lives in the browser, so an older cookie can restore it, and
   concurrent callbacks can each pass the state check. For strict single use,
   keep the pending entry server-side and consume it in one atomic step (for
   example a database ``DELETE ... RETURNING`` or a Redis ``GETDEL``). The OP
   rejects a code it has already used, which is a separate protection.
   After a retryable failure, start a new login instead of retrying the same
   callback.

:func:`~pygrindvakt.rp.verify_id_token` checks the signature against the
JWKS, the explicit signing-algorithm allowlist, ``iss``, ``sub``, every
``aud`` value, ``azp`` when applicable, ``exp``, ``iat`` and the nonce, and
returns the claims as a dict. A non-200 from the token endpoint raises
:class:`pygrindvakt.AuthnError` (generic message; the upstream OAuth error is
in ``exc.code`` and the sanitized details in ``exc.upstream_*``). Treat
``upstream_error_description`` and ``upstream_body`` as secret-bearing: never
log them verbatim or show them to the user.

.. important:: The nonce is required.

   ``verify_id_token`` refuses ``expected_nonce=None`` with
   :class:`pygrindvakt.AuthnError`. Omitting the nonce in the code flow lets a
   captured id_token be replayed into a different session. The only way past
   the guard is
   ``unsafe_skip_nonce_check=True``, which emits a ``UserWarning`` and exists
   for flows that genuinely carry no nonce (a pure OAuth 2.0 flow whose
   token response happens to include an id_token). A nonce that *is* given
   is always enforced, flag or not.

OPs that sign ID tokens with HS256 (the client secret)
-------------------------------------------------------

An OP that registered ``id_token_signed_response_alg`` as ``HS256``,
``HS384`` or ``HS512`` MACs the ID token with a key derived from your
``client_secret`` (OIDC Core 10.1). It does not, and must not, publish that key
in its ``jwks_uri``. So these tokens are verified with a key set **you** build,
not with a fetched one:

.. code-block:: python

   import base64
   from pygrindvakt import rp

   secret = client_secret.encode()          # at least 32 bytes for HS256
   jwks = {"keys": [{"kty": "oct", "k": base64.urlsafe_b64encode(secret).rstrip(b"=").decode()}]}
   claims = rp.verify_id_token(jwks, ts.id_token, info.issuer, me.client_id, nonce, ["HS256"])

There is no flag and no warning for this: it is the specified way. Everything
else is refused. A :class:`~pygrindvakt.rp.JwksCache` with an ``HS*`` algorithm
raises :class:`~pygrindvakt.ConfigError` (``code == "shared_secret_algorithm"``),
and an ``oct`` key in a published JWK Set is dropped with a ``UserWarning`` by
:func:`~pygrindvakt.rp.fetch_jwks` and ``JwksCache``. A secret shorter than the
hash output (32, 48 or 64 bytes; RFC 7518 3.2) raises ``ConfigError`` with
``code == "weak_shared_secret"``: ask the OP for a longer client secret. See
ADR 0006.

.. versionchanged:: 0.3.0
   ``JwksCache`` with ``HS*`` raises, fetched ``oct`` keys are ignored and
   short secrets are refused.

Key caching and rotation
------------------------

Do not call :func:`~pygrindvakt.rp.fetch_jwks` per login: it costs a request
each time and gives no rotation handling. A
:class:`~pygrindvakt.rp.JwksCache` fetches the set on first use, reuses it for
the lifetime the OP advertises (``Cache-Control: max-age``, bounded by
``min_ttl`` / ``max_ttl``, else ``default_ttl``; ``no-store`` / ``no-cache`` are
floored to ``min_ttl``, and ``min_ttl=0`` leaves them uncached), and shares one fetch between
concurrent requests. When an id_token names a ``kid`` it does not have, it
refetches once (at most every ``min_refresh_interval`` seconds, so garbage
``kid`` values cannot flood the OP) and either verifies with the rotated key
or raises :class:`~pygrindvakt.UnknownKeyError`. It never serves an expired
set: if the OP is unreachable when the set expires, verification fails with an
:class:`~pygrindvakt.InternalError` (``code == "transport"``) instead of
trusting possibly revoked keys.

Concurrent callers share one fetch, and the others wait for it. That wait is
bounded by ``fetch_timeout`` (default 45 seconds: the built-in client's 30 second timeout plus margin): a waiter raises
:class:`~pygrindvakt.InternalError` with ``code == "jwks_fetch_timeout"``
instead of blocking forever. The bound covers only the waiting threads. The
thread that runs the fetch is not interrupted, so a Python ``HttpClient``
adapter must set its own network timeouts; a stalled adapter still stalls its
own caller. When it finally returns, its result is cached and later calls
work normally.

``Cache-Control`` is honoured only when the HTTP client reports response
headers. The built-in client (``http=None`` or a
:class:`~pygrindvakt.http.ReqwestClient`) always does; a Python adapter must
return them (a ``(status, body, content_type, headers)`` tuple or
:class:`~pygrindvakt.http.HttpFetchResponse` with ``headers``). Without them
``default_ttl`` applies and a ``UserWarning`` is emitted on the first fetch.

.. code-block:: python

   from pygrindvakt import UnknownKeyError

   try:
       claims = jwks_cache.verify_id_token(ts.id_token, me.client_id, nonce, ["ES256"])
   except UnknownKeyError:
       ...  # token signed by a key the issuer does not publish: reject

``rp.verify_id_token(jwks_cache, id_token, issuer, ...)`` is equivalent, but
``issuer`` must equal the cache's own issuer: a mismatch raises
:class:`pygrindvakt.ConfigError` before any fetch, so one provider's keys
can never vouch for another provider's ``iss``. The cache is accepted as ``jwks=`` by :func:`~pygrindvakt.rp.fetch_userinfo`
for signed UserInfo responses. Extra checks are keyword options on both:
``max_age`` (against ``auth_time``), ``acr_values``, ``access_token`` /
``require_at_hash``, ``authorization_code`` / ``require_c_hash``, ``leeway``
(see :func:`~pygrindvakt.rp.verify_id_token`).

.. warning::

   Implicit and hybrid flows (``code id_token``, ``code id_token token``) must
   pass ``access_token`` + ``require_at_hash=True`` and / or
   ``authorization_code`` + ``require_c_hash=True`` (or set
   ``strict_hashes=True``): ``verify_id_token`` does not notice a missing
   ``at_hash`` / ``c_hash`` binding otherwise, and by default ignores a hash
   claim when no value is given to check it against. ``strict_hashes=True``
   rejects hash claims it cannot check and requires ``at_hash`` / ``c_hash``
   whenever you pass ``access_token`` / ``authorization_code``. Code-flow
   callers who pass ``access_token`` but whose OP omits ``at_hash`` must leave
   it off.

.. code-block:: python

   claims = jwks_cache.verify_id_token(
       ts.id_token, me.client_id, nonce, ["ES256"],
       max_age=300, acr_values=["urn:mfa"],
       access_token=ts.access_token, require_at_hash=True,
   )

Long-lived RPs: discovery cache
-------------------------------

:func:`~pygrindvakt.rp.discover` is a one-shot primitive: one round trip, no
memory. A long-running RP wants the document refreshed on the OP's schedule,
without a refetch per login and without every login failing while the
well-known endpoint is briefly down. :class:`~pygrindvakt.rp.DiscoveryCache`
does that and hands out the objects the rest of the flow needs.

.. code-block:: python

   from pygrindvakt import http, rp

   # Created once per process, next to the RpClient; thread-safe.
   discovery = rp.DiscoveryCache(http.ReqwestClient(), "https://op.example.com")

   info = discovery.info()          # rp.ProviderInfo, rebuilt when the document is refetched
   jwks_cache = discovery.jwks()    # rp.JwksCache for info.jwks_uri; same object across refreshes
   claims = jwks_cache.verify_id_token(id_token, me.client_id, nonce, ["ES256"])

Call ``discovery.info()`` and ``discovery.jwks()`` per request instead of
keeping the results: the first is cheap while the document is fresh, and the
second hands you the right :class:`~pygrindvakt.rp.JwksCache` if the OP ever
moves its ``jwks_uri``. The ``JwksCache`` keeps its keys across metadata
refreshes as long as ``jwks_uri`` and issuer are unchanged, and is replaced
(never reused) when they change, so keys of one location cannot verify tokens
on behalf of another.

*Refresh.* The document lives for ``Cache-Control: max-age`` minus ``Age``,
else ``default_ttl``, clamped to ``[min_ttl, max_ttl]`` (same rules and the
same one-time warning for HTTP clients that report no headers as
:class:`~pygrindvakt.rp.JwksCache`). ``discovery.refresh()`` forces a refetch.
Concurrent callers share one fetch, and waiters give up after ``fetch_timeout``
with ``InternalError(code="discovery_fetch_timeout")``; the fetch finishes and
is cached.

*Failure and back-off.* After a failed fetch the cache makes no request for
``failure_backoff`` seconds (default 10), so a dead well-known endpoint is not
hammered by every login. In that window and when refetching an expired
document fails, the cache serves the previous document **if**
``stale_on_error`` is true (the default) and the document expired less than
``max_stale`` seconds ago (default one day); the first time this happens a
``UserWarning`` is emitted. Otherwise the failing call raises the original
error and calls inside the window raise
``InternalError(code="discovery_backoff")`` with the original as
``__cause__``; the latter is ``retryable`` exactly when the original was
(transient failures yes, an issuer mismatch or malformed document no). A
thread that times out waiting for another thread's fetch (``fetch_timeout``)
is served the stale document under the same rules instead of raising. Pass ``stale_on_error=False`` if you
would rather fail than log users in against metadata the OP has not
confirmed. This is deliberately more lenient than ``JwksCache``, which never
serves expired keys; the keys obtained through ``discovery.jwks()`` keep that
strict policy (ADR 0008).

*Fork.* The cache is plain in-process memory: a forked child keeps the cached
document and expiry. Fork only while no other thread is inside a call.

``rp.discover`` and ``ProviderInfo.from_metadata`` remain the primitives
underneath and are unchanged; use them directly for a short-lived script or
when you want to manage refresh yourself. Issuer binding is the same either
way: a document whose ``issuer`` differs from the configured one is rejected
and never cached.

Userinfo
--------

.. code-block:: python

   if info.userinfo_endpoint is not None:  # OPs may omit UserInfo
       profile = rp.fetch_userinfo(
           http_client, info.userinfo_endpoint, ts.access_token, claims["sub"], info.issuer
       )

By default the request is a POST with the token in the ``Authorization``
header, which OIDC Core permits and every OP built with pygrindvakt accepts. A
non-200 raises :class:`pygrindvakt.AuthnError`. The response must contain a
string ``sub`` exactly equal to the validated ID-token subject. The result is a
dict; :func:`~pygrindvakt.rp.claims_to_attributes` flattens it (or the id_token
claims) into the ``{name: [values]}`` shape an attribute-based backend or a
SAML proxy expects.

Some OPs only accept GET, or answer with a signed ``application/jwt`` response.
Pass ``method="GET"`` (the HTTP client must support request headers on GET; the
built-in one does and never follows redirects), and for a signed response also
say how to verify it:

.. code-block:: python

   if info.userinfo_endpoint is not None:
       profile = rp.fetch_userinfo(
           http_client, info.userinfo_endpoint, ts.access_token, claims["sub"],
           info.issuer,
           method="GET",
           # the process-wide cache from the id_token section above; the
           # OP's UserInfo JOSE ``typ`` (use trust="dedicated_keys" instead
           # if the OP signs UserInfo with keys that never sign id_tokens)
           jwks=jwks_cache, client_id=me.client_id, allowed_algorithms=["ES256"],
           trust="typed", typ="userinfo+jwt",
       )

A signed response is never accepted without ``jwks``, ``client_id``,
``allowed_algorithms`` and ``trust`` (``AuthnError``, ``code ==
"userinfo_unverifiable"``). ``trust`` matters because OPs often sign UserInfo
with the same key as id_tokens, so a replayed id_token could pass as UserInfo:
``"typed"`` (the OP sets a UserInfo-specific JOSE ``typ``; pass it as ``typ``)
and ``"dedicated_keys"`` (``jwks`` holds only UserInfo signing keys) are safe;
``"untyped_shared_key_compat"`` is the weakest and accepts a fresh id_token
that lacks ``nonce``, ``at_hash`` and ``c_hash``. The token must also be no
more than ``max_age`` (300) seconds old by ``iat``; ``max_age=None`` disables
that and makes replay unbounded. Encrypted (JWE) UserInfo is not supported. See
:func:`~pygrindvakt.rp.fetch_userinfo` for the full rules.

The rest of the token response (``refresh_token``, ``expires_in``,
``scope``) is available as ``ts.raw``.

Authenticating with ``private_key_jwt``
---------------------------------------

With ``private_key_jwt`` the RP proves possession of a private key instead
of sending a shared secret; the OP holds only the public JWKS. Register the
public key set at the OP and give the :class:`~pygrindvakt.rp.RpClient` the
signing key:

.. code-block:: python

   from pygrindvakt import keys

   rp_key = keys.signing_key_from_pem(open("rp-key.pem", "rb").read(), kid="rp-1")
   # The OP registers: client.Client("jwt-rp", redirect_uris=[...],
   #                    token_endpoint_auth_method="private_key_jwt", jwks=rp_key.to_public_jwks())
   me = rp.RpClient("jwt-rp", "https://rp.example.com/cb", auth_method="private_key_jwt", signing_key=rp_key)

:func:`~pygrindvakt.rp.exchange_code` then builds and sends the assertion
itself. For other endpoints that require client authentication (introspection,
revocation, a federation OP's token endpoint from custom code), build one
explicitly with :func:`~pygrindvakt.rp.build_client_assertion`. The audience
is the token endpoint URL:

.. code-block:: python

   assertion = rp.build_client_assertion(rp_key, "jwt-rp", info.token_endpoint)
   form = [
       ("grant_type", "authorization_code"), ("code", code), ("redirect_uri", me.redirect_uri),
       ("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
       ("client_assertion", assertion),
   ]
   status, body, _ = http_client.post_form(info.token_endpoint, form, [])

The assertion has ``iss`` = ``sub`` = ``client_id``, ``aud`` = the audience,
a 300-second lifetime and a random ``jti``; the OP consumes the ``jti`` so an
assertion cannot be replayed.

Signed request objects (JAR)
----------------------------

OpenID Federation automatic registration, and some OPs by policy, require the
authorization parameters to arrive as a signed JWT (RFC 9101).
:func:`~pygrindvakt.rp.signed_request_object` builds one from the same
inputs as ``authorization_url``; pass it as the ``request`` parameter
(RFC 9101 section 3 says the query should carry only ``client_id``,
``response_type`` and ``request``; the plain parameters that
``authorization_url`` adds are not authoritative, so an OP must read the signed
ones). The safe path is ``begin(request_object_key=..., ...)``: it signs the
generated state, nonce and PKCE challenge together with the optional
``claims``, ``prompt``, ``ui_locales``, ``acr_values``, ``max_age`` and
``sign_request``, and then sends only ``client_id``, ``response_type`` and
``request`` in the query (plus any ``extra``). ``authorization_url`` and
``begin`` refuse ``extra`` entries named ``claims``, ``prompt``,
``ui_locales``, ``acr_values``, ``max_age`` or ``signRequest`` when a request
object is attached (``ValueError``): put them in the signed object only. The
manual path below can leave
the unsigned query and the signed object out of step. Names are matched
case-insensitively with whitespace trimmed. Call shapes that worked in 0.6.0
(``extra={"request": jar, "acr_values": ...}``, ``request`` plus
``request_uri``, an endpoint query holding signed-parameter names) now raise;
move the parameter into ``signed_request_object(...)`` or use
``begin(request_object_key=..., acr_values=...)``:

.. code-block:: python

   jar = rp.signed_request_object(info, me, rp_key, state, nonce, code_challenge=challenge)
   url = rp.authorization_url(info, me, state, nonce, code_challenge=challenge, extra={"request": jar})

   # or, with generated state/nonce/verifier:
   url, state, nonce, verifier = rp.begin(
       info, me, request_object_key=rp_key, acr_values="urn:acr:2", max_age=300
   )

Using a custom HTTP client
--------------------------

Every networked function takes ``http`` first: ``None`` for the shared
built-in client, an explicit :class:`~pygrindvakt.http.ReqwestClient` with
your own limits, or any object implementing
:class:`~pygrindvakt.http.HttpClientProtocol`. Reasons to inject your own:
a private CA, an outbound proxy, per-host allowlists, or tests.

.. code-block:: python

   import httpx

   class HttpxClient:
       def __init__(self, **kw):
           self._c = httpx.Client(follow_redirects=False, timeout=httpx.Timeout(10.0), **kw)

       def get(self, url):
           r = self._c.get(url)
           return r.status_code, r.content, r.headers.get("content-type")

       def post_form(self, url, form, headers):
           r = self._c.post(url, data=dict(form), headers=dict(headers))
           return r.status_code, r.content, r.headers.get("content-type")

   http_client = HttpxClient(verify="/etc/ssl/private-ca.pem", proxy="http://proxy.internal:3128")
   md = rp.discover(http_client, "https://op.internal.example")

The contract: return ``(status, body: bytes, content_type)``, optionally with a
4th ``headers`` element, or an
:class:`~pygrindvakt.http.HttpFetchResponse`; **never follow redirects**;
enforce timeouts; bound the body size. An exception is logged through
``sys.unraisablehook`` and surfaces as :class:`pygrindvakt.InternalError`.
The methods run on the thread that called ``rp.discover`` (holding the GIL);
they may call back into pygrindvakt, at the cost of a helper thread per
nested call.

Deployment: threads and fork
----------------------------

One :class:`~pygrindvakt.http.ReqwestClient` (or the ``http=None`` default)
can be shared by every thread of a worker; the GIL is released during I/O, so
requests run in parallel. After ``fork`` (gunicorn ``--preload``,
``multiprocessing``) the child rebuilds the connection pool and the tokio
runtime lazily, so a client created in the master before the fork is fine.
Fork only while no other thread is inside a pygrindvakt call: a lock held by
another thread at fork time stays locked in the child and can deadlock it.
Forking while another master thread has a request in flight is not
supported. A custom Python client runs on the calling thread with the GIL held
and must be thread-safe if shared. Create a ``RedisStore`` *after* fork. See
:ref:`ReqwestClient <reqwest-client-fork>` and :doc:`stores`.

Testing without a network
-------------------------

Because the HTTP client is injectable, an RP can be tested end to end against
an in-process :class:`~pygrindvakt.provider.Provider`. The test-only module
:mod:`pygrindvakt.testing` ships the pieces: ``ProviderHttpClient`` answers
discovery and JWKS from ``op.discovery_document()`` / ``op.jwks_document()``
and forwards token and userinfo requests to ``op.handle_token_request`` /
``op.userinfo`` (``tests/test_rp.py`` is built on it); ``StaticHttpClient``
serves fixed responses and records the requests; ``mint_id_token`` signs an
ID Token with a key you hold. Import them explicitly
(``from pygrindvakt import testing``) and never ship them in your application.
Nested calls into pygrindvakt from inside such a client are supported; each
runs on a helper thread (see :doc:`stores`).

Logout
------

If the OP advertises an ``end_session_endpoint`` (OIDC RP-Initiated Logout
1.0), it is available as ``info.end_session_endpoint`` after discovery. Clear
your own session first, then redirect the browser to
:func:`~pygrindvakt.rp.end_session_url`:

.. code-block:: python

   if info.end_session_endpoint is not None:
       logout_url = rp.end_session_url(
           info,
           id_token_hint=session["id_token"],
           client=me,  # RpClient(..., post_logout_redirect_uris=["https://rp.example.com/logged-out"])
           post_logout_redirect_uri="https://rp.example.com/logged-out",
           state=util.random_token(24),
       )
       # redirect the browser to logout_url

``post_logout_redirect_uri`` must be registered with the OP and also on the
client, via ``RpClient(..., post_logout_redirect_uris=[...])``.
``end_session_url`` accepts it only when ``client`` is passed and the value
exactly equals a registered entry; anything else (including a value from
``request.args``, or an ``id_token_hint``-only call) raises
``BadRequestError``. This prevents logout from becoming an open redirect to a
host the attacker chose. A provider without an ``end_session_endpoint`` makes ``end_session_url`` raise
``ConfigError``; end only the local session in that case.

``id_token_hint`` carries the full ID token and goes to the first hop, the
host of the ``end_session_endpoint``. Therefore ``ProviderInfo`` requires that
endpoint to have the same origin as the issuer (scheme, host, effective port),
besides the https / no-credentials / no-fragment checks. ``ProviderInfo(...)``
raises ``ConfigError`` for a cross-origin endpoint, and
``ProviderInfo.from_metadata`` drops it, so ``info.end_session_endpoint`` is
``None`` and ``end_session_url`` raises ``ConfigError``. The message says
whether the provider does not advertise the endpoint or the advertised value
was rejected (cross-origin or unsafe). If the OP
legitimately logs out on another origin, opt in explicitly with
``allow_cross_origin_end_session=True`` on ``ProviderInfo(...)`` or
``ProviderInfo.from_metadata(...)``.

``ProviderMetadata`` itself only checks scheme, credentials, fragment and
control characters; it does not compare hosts with the issuer. An RP that gets
metadata from anything other than its own TLS discovery of the issuer (a
config service, a database row) must pin the host itself. The other metadata
endpoints (revocation, introspection, PAR, ``check_session_iframe``) are not
origin-checked.

Security notes
--------------

* Parse the callback with :func:`~pygrindvakt.rp.parse_authorization_response`,
  check ``state`` (constant time) before touching anything else, and pop the
  session entry so it cannot be reused. Compare ``iss`` with ``matches_iss``.
* Always pass the stored nonce; never ``unsafe_skip_nonce_check`` in a code
  flow.
* Prefer ``private_key_jwt``; load the key from a file or HSM, not source.
* Treat every :class:`pygrindvakt.AuthnError` as log material.
* Keep the built-in HTTP client unless you need a private CA or proxy, and
  then keep its three properties.

See :doc:`security` for the full list.
