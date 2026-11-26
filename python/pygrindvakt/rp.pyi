"""Type stubs for ``pygrindvakt.rp`` - the relying-party (client) side of OIDC."""

from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Literal, NamedTuple, Protocol, overload

from .http import HttpRequestData, _HttpArg, _HttpHeadersArg
from .keys import SigningKey
from .metadata import ProviderMetadata

MAX_ID_TOKEN_LEEWAY: int
"""Largest ``leeway`` (seconds) ``verify_id_token`` accepts (300).

A cap on skew tolerance, not a recommended value. A larger ``leeway`` raises
``ConfigError``.

.. versionadded:: 0.3.0
"""
JARM_ASYMMETRIC_ALGORITHMS: tuple[str, ...]
"""Asymmetric JWS algorithms suitable for ``verify_jarm(allowed_algorithms=...)``."""
JARM_TYP: str
"""The JARM response JWT ``typ`` header value (``oauth-authz-resp+jwt``)."""

class ProviderInfo:
    """Minimal upstream-provider information the RP needs.

    ``end_session_endpoint`` receives ``id_token_hint`` (the full ID token) in
    the query string, so it must have the same origin as ``issuer`` (scheme,
    host, effective port) unless ``allow_cross_origin_end_session=True``. The
    constructor raises ``ConfigError`` for a cross-origin endpoint without
    the opt-in; ``from_metadata`` drops it to ``None`` instead (so
    ``end_session_url`` raises ``ConfigError``). The opt-in still requires the
    scheme/userinfo/fragment checks to pass. Other metadata endpoints are not
    origin-checked.

    ``from_metadata`` also emits a ``UserWarning`` when it drops an
    ``end_session_endpoint``; compare ``end_session_endpoint`` with
    ``metadata.end_session_endpoint`` to tell "not advertised" from "rejected".
    A non-string advertised value is ignored with a ``UserWarning`` too.
    """

    def __init__(
        self,
        issuer: str,
        authorization_endpoint: str,
        token_endpoint: str,
        userinfo_endpoint: str | None = ...,
        jwks_uri: str | None = ...,
        *,
        end_session_endpoint: str | None = ...,
        allow_cross_origin_end_session: bool = ...,
    ) -> None: ...
    @staticmethod
    def from_metadata(metadata: ProviderMetadata, *, allow_cross_origin_end_session: bool = ...) -> ProviderInfo: ...
    @property
    def issuer(self) -> str: ...
    @property
    def authorization_endpoint(self) -> str: ...
    @property
    def token_endpoint(self) -> str: ...
    @property
    def userinfo_endpoint(self) -> str | None: ...
    @property
    def jwks_uri(self) -> str | None: ...
    @property
    def end_session_endpoint(self) -> str | None: ...
    @property
    def metadata(self) -> ProviderMetadata | None:
        """The discovery document this was built from (a copy), or ``None``.

        Set by ``from_metadata``, so ``ProviderInfo.from_metadata(discover(...))``
        has it; ``None`` for a hand-built ``ProviderInfo``. Not in ``repr()``.

        WARNING: EVERY endpoint on this document (``userinfo_endpoint``,
        ``token_endpoint``, ``authorization_endpoint``, ``jwks_uri``,
        ``end_session_endpoint`` ...) is UNVALIDATED data from the OP (ADR 0004
        section 3 exempts discovery). Never send credentials or tokens to
        them; use the validated properties on the ``ProviderInfo`` itself
        (``info.userinfo_endpoint``, ``info.token_endpoint`` ...). The raw
        ``end_session_endpoint`` is kept only so you can diagnose a rejection.

        .. versionadded:: 0.3.0
        """
    def __repr__(self) -> str: ...

class RpClient:
    """RP client configuration, including the token-endpoint auth method.

    ``auth_method`` is one of ``"none"``, ``"client_secret_basic"``,
    ``"client_secret_post"`` or ``"private_key_jwt"``; it defaults to
    ``client_secret_basic`` when ``client_secret`` is given, else ``none``.
    Inconsistent combinations raise :class:`ConfigError` (also a
    ``ValueError``).

    ``post_logout_redirect_uris`` registers the only values
    :func:`end_session_url` will accept as ``post_logout_redirect_uri`` (exact
    string match); each is syntax-validated here.

    ``redirect_uris`` registers the alternative login redirect URIs accepted
    as the per-call ``redirect_uri=`` override (exact string match; the
    configured ``redirect_uri`` is always accepted). Entries are
    syntax-validated here and must not be plain ``http`` to a non-loopback
    host (``https``, loopback ``http`` and custom/private-use schemes for
    native apps are allowed). ``allow_unregistered_redirect_uri=True`` accepts
    any valid override instead (RFC 7591 dynamic registrations only; never
    feed it request-supplied values).
    """

    def __init__(
        self,
        client_id: str,
        redirect_uri: str,
        *,
        scope: str = ...,
        client_secret: str | None = ...,
        auth_method: str | None = ...,
        signing_key: SigningKey | None = ...,
        post_logout_redirect_uris: list[str] | None = ...,
        redirect_uris: list[str] | None = ...,
        allow_unregistered_redirect_uri: bool = ...,
    ) -> None: ...
    @property
    def client_id(self) -> str: ...
    @property
    def redirect_uri(self) -> str: ...
    @property
    def scope(self) -> str: ...
    @property
    def auth_method(self) -> str: ...
    @property
    def post_logout_redirect_uris(self) -> tuple[str, ...]: ...
    @property
    def redirect_uris(self) -> tuple[str, ...]: ...
    @property
    def allow_unregistered_redirect_uri(self) -> bool: ...
    def __repr__(self) -> str: ...

class TokenSet:
    """The result of a successful code exchange.

    ``repr()`` never prints a token.
    """

    @property
    def access_token(self) -> str: ...
    @property
    def id_token(self) -> str: ...
    @property
    def token_type(self) -> str: ...
    @property
    def refresh_token(self) -> str | None:
        """``raw["refresh_token"]`` if it is a string, else ``None``.

        SECURITY: a long-lived credential; store it encrypted, never log it.

        .. versionadded:: 0.3.0
        """
    @property
    def expires_in(self) -> int | None:
        """``raw["expires_in"]`` in seconds, else ``None``.

        A non-negative JSON integer (or integral float) or a digits-only
        string, at most 10 years (315360000). ``None`` means "absent or not
        acceptable" (negative, non-integer, garbage, longer than 10 years),
        NEVER "no expiry": apply your own default lifetime when it is
        ``None`` and do not treat ``None`` as unbounded.

        .. versionadded:: 0.3.0
        """
    @property
    def scope(self) -> str | None:
        """``raw["scope"]`` if it is a string, else ``None``.

        .. versionadded:: 0.3.0
        """
    @property
    def raw(self) -> dict[str, Any]: ...
    def __repr__(self) -> str: ...

def authorization_url(
    provider: ProviderInfo,
    client: RpClient,
    state: str,
    nonce: str,
    code_challenge: str | None = ...,
    extra: dict[str, str] | list[tuple[str, str]] | None = ...,
    *,
    redirect_uri: str | None = ...,
) -> str: ...
def signed_request_object(
    provider: ProviderInfo,
    client: RpClient,
    key: SigningKey,
    state: str,
    nonce: str,
    code_challenge: str | None = ...,
    *,
    redirect_uri: str | None = ...,
    claims: dict[str, Any] | None = ...,
    prompt: str | None = ...,
    ui_locales: str | None = ...,
    acr_values: str | None = ...,
    max_age: int | None = ...,
    sign_request: dict[str, Any] | None = ...,
) -> str:
    """Build a signed Request Object (JAR) for ``client`` and ``provider``.

    The optional keyword arguments ``claims``, ``prompt``, ``ui_locales``,
    ``acr_values``, ``max_age`` and ``sign_request`` are included in the signed
    payload. ``claims`` and ``sign_request`` must be ``dict``; anything else
    raises ``TypeError``, and their JSON types are kept. ``sign_request`` is sent
    as ``https://id.oidc.se/param/signRequest``. A negative ``max_age`` raises
    ``OverflowError``.

    RFC 9101 section 3: the query should carry only ``client_id``,
    ``response_type`` and ``request``; do not repeat parameters that are inside
    the signed object, because an OP reading the unsigned copy would apply a
    weaker value. ``authorization_url`` and ``begin`` refuse these parameters in
    ``extra`` when a request object is attached, and refuse a second request
    object (``request`` and ``request_uri`` together, or either with
    ``request_object_key``) (``ValueError``); ``begin`` with
    these arguments and ``request_object_key`` sends the minimal query.
    ``sign_request`` is attacker-influenced data for an OP that renders it; the
    OP must cap its size.

    .. versionchanged:: 0.7.0
       Added ``claims``, ``prompt``, ``ui_locales``, ``acr_values``,
       ``max_age`` and ``sign_request``.
    """

class BeginResult(NamedTuple):
    """Result of ``begin``: a real ``tuple`` ``(url, state, nonce, code_verifier)``.

    ``state``, ``nonce`` and ``code_verifier`` are secrets: ``repr()`` redacts
    them and strips the query from ``url``.

    .. versionadded:: 0.3.0
    """

    url: str
    state: str
    nonce: str
    code_verifier: str | None
    def __repr__(self) -> str: ...

def begin(
    provider: ProviderInfo,
    client: RpClient,
    *,
    extra: dict[str, str] | list[tuple[str, str]] | None = ...,
    redirect_uri: str | None = ...,
    pkce: bool = ...,
    request_object_key: SigningKey | None = ...,
    claims: dict[str, Any] | None = ...,
    prompt: str | None = ...,
    ui_locales: str | None = ...,
    acr_values: str | None = ...,
    max_age: int | None = ...,
    sign_request: dict[str, Any] | None = ...,
) -> BeginResult:
    """Start an authorization-code flow: fresh ``state``, ``nonce`` and PKCE.

    With ``request_object_key`` a signed request object (RFC 9101) carrying the
    same ``state``, ``nonce`` and ``code_challenge`` is added as ``request``.

    The keyword arguments ``claims``, ``prompt``, ``ui_locales``,
    ``acr_values``, ``max_age`` and ``sign_request`` take the same values as
    for :func:`signed_request_object` (``claims`` and ``sign_request`` must be
    ``dict``, else ``TypeError``; a negative ``max_age`` raises
    ``OverflowError``). They need ``request_object_key``, else ``ValueError``.
    They are signed into the request object only. When any is given, the query
    is reduced to the RFC 9101 section 3 minimum: ``client_id``,
    ``response_type`` and ``request``, plus any ``extra`` entries and
    parameters already on the authorization endpoint. ``redirect_uri``,
    ``scope``, ``state``, ``nonce`` and the PKCE challenge are then only in the
    signed object. Without them the query is unchanged (full plain query plus
    ``request``).

    With a request object attached (``request_object_key``, or
    ``request`` / ``request_uri`` in ``extra``), ``extra`` must not contain
    ``claims``, ``prompt``, ``ui_locales``, ``acr_values``, ``max_age``,
    ``signRequest`` or ``https://id.oidc.se/param/signRequest``:
    ``ValueError`` naming the keys, because an OP could apply the unsigned
    copy (RFC 9101 section 3). Put them in the signed object only. The list
    is exact and case-sensitive and covers only the parameters this binding
    signs: ``claims_locales``, ``login_hint``, ``id_token_hint`` and
    ``display`` are not checked, so keep them out of the unsigned query
    yourself if you signed them.

    .. versionchanged:: 0.7.0
       Added ``claims``, ``prompt``, ``ui_locales``, ``acr_values``,
       ``max_age`` and ``sign_request``.
    """

def claims_audiences(claims: Mapping[str, Any]) -> list[str]:
    """Normalise ``claims["aud"]`` to a NON-EMPTY list of non-empty strings.

    Fails closed: a missing ``aud``, ``aud: []``, ``aud: ""`` or an
    empty-string member raises ``BadRequestError``, so ``all(a in {CLIENT} for
    a in aud)`` cannot be vacuously true. Also raises ``BadRequestError`` for
    a non-string/list ``aud``, a non-string member, or a string that is not
    valid Unicode (lone surrogate). ``claims`` is not modified;
    ``verify_id_token`` returns ``aud`` verbatim and performs the ``aud`` /
    ``azp`` checks itself.

    .. versionadded:: 0.3.0
    """

def check_rp_compatibility(
    provider: ProviderInfo | ProviderMetadata,
    *,
    client: RpClient | None = ...,
    pkce: bool | None = ...,
    algorithms: Sequence[str] | None = ...,
    scopes: Sequence[str] | None = ...,
    acr_values: Sequence[str] | None = ...,
    shared_secret_keys: bool = ...,
) -> list[str]:
    """Advisory comparison of the RP's intent with the OP's discovery document.

    ``provider`` is a ``ProviderInfo`` built with ``from_metadata`` (one
    without ``metadata`` raises ``ConfigError``) or the ``ProviderMetadata``
    returned by ``discover`` directly.

    Checks exactly: ``"code"`` in ``response_types_supported`` (always);
    ``"S256"`` in ``code_challenge_methods_supported`` when ``pkce=True``;
    ``algorithms`` intersects ``id_token_signing_alg_values_supported``;
    ``scopes`` are in ``scopes_supported``; ``acr_values`` are in
    ``acr_values_supported``; ``client.auth_method`` is in
    ``token_endpoint_auth_methods_supported``. Not checked:
    ``grant_types_supported``, ``response_modes_supported``,
    ``pkce=False``/``None``, DPoP, or any other member.

    Two ``algorithms`` rules mirror ADR 0006 (still advisory): ``none``
    (case-insensitive) is always a mismatch and never counts as a match;
    ``HS256``/``HS384``/``HS512`` are a mismatch unless
    ``shared_secret_keys=True`` (you verify with a key set derived from the
    ``client_secret``, OIDC Core 10.1; they are refused with ``JwksCache`` /
    published JWKS), and are ignored by the intersection check otherwise.

    Returns mismatch strings; ``[]`` means nothing contradicts the document.
    Strings starting with ``"not advertised:"`` are informational (the OP lists
    nothing for a check that was performed; no default is assumed, in
    particular not ``RS256`` for ``id_token_signing_alg_values_supported``).
    Exception: an absent or empty ``token_endpoint_auth_methods_supported``
    (indistinguishable after parsing) is treated as the spec default
    ``["client_secret_basic"]`` (OIDC Discovery 1.0 section 3, RFC 8414
    section 2), so any other ``client.auth_method`` is a real mismatch. Pure,
    no I/O, enforces nothing; the metadata is untrusted.

    .. versionadded:: 0.3.0
    """

def discover(http: _HttpArg, issuer: str) -> ProviderMetadata: ...
def end_session_url(
    provider: ProviderInfo,
    *,
    id_token_hint: str | None = ...,
    client: RpClient | None = ...,
    post_logout_redirect_uri: str | None = ...,
    state: str | None = ...,
    logout_hint: str | None = ...,
    ui_locales: str | None = ...,
    extra: dict[str, str] | list[tuple[str, str]] | None = ...,
) -> str:
    """OIDC RP-Initiated Logout 1.0 request URL.

    ``post_logout_redirect_uri`` is accepted only with ``client`` and when it
    exactly equals one of ``client.post_logout_redirect_uris``; otherwise
    ``BadRequestError``. This prevents an open redirect carrying
    ``id_token_hint`` when the value comes from a request parameter.
    """

def fetch_jwks(http: _HttpArg, jwks_uri: str, issuer: str) -> dict[str, Any]:
    """Fetch the JWK Set at ``jwks_uri`` and return it as a dict.

    A published JWK Set must not carry symmetric keys (OIDC Core section
    10.1). Every ``oct`` key is dropped from the result and a ``UserWarning``
    is emitted ("published JWKS contains a symmetric (oct) key, ignored"), so
    the returned set can never verify an ``HS256`` / ``HS384`` / ``HS512``
    token. Build the key set for MAC-signed ID tokens from the ``client_secret``
    instead; see :func:`verify_id_token`.

    The warning is emitted once per call (there is no global dedup). Python's
    warnings registry collapses identical messages per location by default,
    but under ``simplefilter("always")`` or ``"error"`` it fires on every
    call. The returned dict may therefore not equal the OP's published
    document; callers that cache or diff it should use a warnings filter or
    :class:`JwksCache`, which caches the filtered set.

    .. versionchanged:: 0.3.0
       ``oct`` keys are dropped with a ``UserWarning`` (once per call).
    """

def exchange_code(
    http: _HttpArg,
    provider: ProviderInfo,
    client: RpClient,
    code: str,
    code_verifier: str | None = ...,
    *,
    redirect_uri: str | None = ...,
) -> TokenSet: ...
def verify_id_token(
    jwks: dict[str, Any] | JwksCache,
    id_token: str,
    issuer: str,
    client_id: str,
    expected_nonce: str | None,
    allowed_algorithms: list[str],
    trusted_additional_audiences: list[str] | None = ...,
    unsafe_skip_nonce_check: bool = ...,
    *,
    leeway: int | None = ...,
    max_age: int | None = ...,
    acr_values: list[str] | None = ...,
    access_token: str | None = ...,
    require_at_hash: bool = ...,
    authorization_code: str | None = ...,
    require_c_hash: bool = ...,
    strict_hashes: bool = ...,
) -> dict[str, Any]:
    """Verify an id_token and return its claims.

    ``jwks`` is a key-set dict or a :class:`JwksCache`.

    ``HS256`` / ``HS384`` / ``HS512`` ID tokens are MAC'd with a key derived
    from the ``client_secret``, never from the OP's published JWK Set (OIDC
    Core section 10.1). Verify them with a key set you build yourself, for
    example ``{"keys": [{"kty": "oct", "k": <base64url(client_secret)>}]}``
    with ``allowed_algorithms=["HS256"]``. The secret must be at least as long
    as the hash output (32 / 48 / 64 bytes for ``HS256`` / ``HS384`` /
    ``HS512``, RFC 7518 section 3.2); a shorter ``oct`` key the token selects (by ``kid``) raises
    ``ConfigError`` with ``code == "weak_shared_secret"`` (the message never
    contains the key). A :class:`JwksCache` with an ``HS*`` algorithm raises
    ``ConfigError`` with ``code == "shared_secret_algorithm"``. ``none`` is
    never accepted (``ConfigError``, invalid algorithm).

    .. versionchanged:: 0.3.0
       A :class:`JwksCache` with ``HS*`` algorithms is refused, and a caller-built
       ``oct`` key shorter than the hash output is refused (``weak_shared_secret``;
       before, ``HS384`` / ``HS512`` keys of 33 bytes or more were accepted, and
       a 32-byte ``HS256`` secret failed with a confusing ``JoseError``).

    Optional checks, all off by default:

    * ``leeway``: clock-skew tolerance in seconds (default 60; above 300 raises
      ``ConfigError``).
    * ``max_age``: needs a numeric ``auth_time`` no older than ``max_age``
      seconds (``iat`` is not used; a missing or non-numeric ``auth_time`` is
      an ``AuthnError``; leeway is not added).
    * ``acr_values``: ``acr`` must be present and listed.
    * ``access_token`` / ``authorization_code``: check ``at_hash`` / ``c_hash``
      when present; ``require_at_hash`` / ``require_c_hash`` also reject
      tokens lacking the claim (and need the matching value, else
      ``ConfigError``). ``EdDSA`` tokens carrying a hash claim cannot be
      checked (``CryptoError``).
    * ``strict_hashes``: rejects (``AuthnError``) an id_token carrying
      ``at_hash`` / ``c_hash`` that cannot be checked (no matching
      ``access_token`` / ``authorization_code``), and requires ``at_hash`` /
      ``c_hash`` whenever ``access_token`` / ``authorization_code`` is passed,
      as if ``require_*`` were set. Code-flow callers who pass ``access_token``
      but whose OP omits ``at_hash`` must leave it off. ``EdDSA`` tokens cannot
      satisfy the requirement.
    """

class JwksCache:
    """Caching JWK Set fetcher for one issuer, with kid-rotation refresh.

    The set is refetched on expiry: ``Cache-Control: max-age`` minus ``Age``
    when present, else ``default_ttl``, clamped to ``[min_ttl, max_ttl]``
    (``no-store`` / ``no-cache`` / ``max-age=0`` are floored to ``min_ttl``;
    ``min_ttl=0`` leaves them uncached). ``Cache-Control`` is honoured only when
    the ``HttpClient`` reports response headers: the built-in client (``None`` /
    ``ReqwestClient``) always does, a Python adapter must return them (4-tuple
    or ``HttpFetchResponse(headers=...)``); otherwise ``default_ttl`` applies
    and a ``UserWarning`` is emitted on the first fetch. An expired set is never
    served: a failed refetch raises. Concurrent callers share one fetch.
    The cache is in-process memory; it stays valid after ``fork``.

    ``fetch_timeout`` (seconds, finite, at least 1e-9, default 45: the built-in client's 30s timeout plus margin) bounds how long a
    thread WAITS for another thread's in-flight fetch; on expiry the waiter
    raises ``InternalError`` with ``code == "jwks_fetch_timeout"``. It does not
    interrupt the thread running the fetch: a Python ``HttpClient`` adapter
    must set its own network timeouts, and a stalled adapter still stalls its
    own caller. The fetch carries on and its result is cached when it ends.

    Symmetric (``oct``) keys in the fetched document are dropped with a
    ``UserWarning`` (once per fetch): an OP must not publish them (OIDC Core
    section 10.1). ``HS256`` / ``HS384`` / ``HS512`` in ``allowed_algorithms``
    of :meth:`verify_id_token` raise ``ConfigError`` with
    ``code == "shared_secret_algorithm"``, with no override: MAC-signed ID
    tokens are verified with :func:`verify_id_token` and a key set built from
    the ``client_secret``.

    .. versionchanged:: 0.3.0
       ``oct`` keys are dropped with a warning and ``HS*`` algorithms are refused.
    """

    def __init__(
        self,
        http: _HttpArg,
        jwks_uri: str,
        issuer: str,
        *,
        default_ttl: int = 3600,
        min_ttl: int = 60,
        max_ttl: int = 86400,
        min_refresh_interval: int = 30,
        fetch_timeout: float = 45.0,
    ) -> None: ...
    @property
    def jwks_uri(self) -> str: ...
    @property
    def issuer(self) -> str: ...
    @property
    def fetch_timeout(self) -> float: ...
    def jwks(self) -> dict[str, Any]:
        """The cached key set, fetched first if absent or expired."""
    def refresh(self) -> None:
        """Force a refetch; a no-op within ``min_refresh_interval`` seconds of
        the previous attempt, except for the very first fetch."""
    def verify_id_token(
        self,
        id_token: str,
        client_id: str,
        expected_nonce: str | None,
        allowed_algorithms: list[str],
        *,
        trusted_additional_audiences: list[str] | None = ...,
        unsafe_skip_nonce_check: bool = ...,
        leeway: int | None = ...,
        max_age: int | None = ...,
        acr_values: list[str] | None = ...,
        access_token: str | None = ...,
        require_at_hash: bool = ...,
        authorization_code: str | None = ...,
        require_c_hash: bool = ...,
        strict_hashes: bool = ...,
    ) -> dict[str, Any]:
        """:func:`verify_id_token` against this cache's keys and issuer.

        If the token's ``kid`` is missing from a set whose keys have ``kid``s,
        the set is refreshed once (rate-limited by ``min_refresh_interval``)
        and a still-unknown ``kid`` raises ``UnknownKeyError``.

        ``HS256`` / ``HS384`` / ``HS512`` in ``allowed_algorithms`` raise
        ``ConfigError`` (``code == "shared_secret_algorithm"``) before any fetch.
        """
    def __repr__(self) -> str: ...

class DiscoveryCache:
    """Caching OpenID Provider discovery client for one issuer.

    :meth:`metadata` returns the discovery document, :meth:`info` the matching
    :class:`ProviderInfo` (built once per fetch, so the ``UserWarning`` of
    :meth:`ProviderInfo.from_metadata` fires once per fetch) and :meth:`jwks` a
    :class:`JwksCache` bound to the advertised ``jwks_uri``. The document is
    refetched on expiry: ``Cache-Control: max-age`` minus ``Age`` when present,
    else ``default_ttl``, clamped to ``[min_ttl, max_ttl]`` (``no-store`` /
    ``no-cache`` / ``max-age=0`` are floored to ``min_ttl``).
    ``Cache-Control`` is honoured only when the ``HttpClient`` reports response
    headers (see :class:`JwksCache`); otherwise ``default_ttl`` applies and a
    ``UserWarning`` is emitted on the first fetch. The ``issuer`` check of
    :func:`discover` applies on every fetch: a mismatching document raises and
    is neither cached nor served. Concurrent callers share one fetch.

    ``fetch_timeout`` (seconds, finite, at least 1e-9, default 45) bounds how
    long a thread WAITS for another thread's in-flight fetch; on expiry the
    waiter raises ``InternalError`` with ``code == "discovery_fetch_timeout"``.
    The fetch carries on and its result is cached when it ends.

    After a failed fetch no new network call is made for ``failure_backoff``
    seconds. In that window, and when the refetch of an expired entry fails,
    the previous document is served only if ``stale_on_error`` is true and the
    entry expired less than ``max_stale`` seconds ago (a one-time
    ``UserWarning`` is emitted when stale metadata is first served after a
    failure). Otherwise the original error is raised or, inside the window,
    ``InternalError`` with ``code == "discovery_backoff"`` and the original as
    ``__cause__`` (a traceback-free copy); its ``retryable`` is the cause's.
    A waiter that times out (``discovery_fetch_timeout``) is served the stale
    document under the same rules first. This differs from :class:`JwksCache`, which never serves an
    expired key set: keys stay never-stale through the :class:`JwksCache` that
    :meth:`jwks` returns.

    The cache is in-process memory; it stays valid after ``fork``, but fork
    only while no other thread is inside a cache call.

    .. versionadded:: 0.3.0
    """

    def __init__(
        self,
        http: _HttpArg,
        issuer: str,
        *,
        default_ttl: int = 3600,
        min_ttl: int = 60,
        max_ttl: int = 86400,
        failure_backoff: int = 10,
        stale_on_error: bool = True,
        max_stale: int = 86400,
        fetch_timeout: float = 45.0,
        allow_cross_origin_end_session: bool = False,
    ) -> None: ...
    @property
    def issuer(self) -> str: ...
    @property
    def failure_backoff(self) -> int: ...
    @property
    def fetch_timeout(self) -> float: ...
    def metadata(self) -> ProviderMetadata:
        """The discovery document, fetched first if absent or expired."""
    def info(self) -> ProviderInfo:
        """``ProviderInfo.from_metadata(metadata())``, built once per fetch."""
    def jwks(self) -> JwksCache:
        """A :class:`JwksCache` for the advertised ``jwks_uri`` and issuer.

        The same object is returned across metadata refreshes, so its keys
        survive; it is replaced (and the old object never returned again) only
        when the ``jwks_uri`` or issuer changes. The cache is built with the
        :class:`JwksCache` constructor defaults for the TTL parameters; a
        caller holding an older document is given the newer installed cache.
        Raises ``ConfigError`` if the provider advertises no ``jwks_uri``.
        """
    def refresh(self) -> None:
        """Force a refetch; a no-op within ``failure_backoff`` seconds of a
        failed fetch. A failed fetch raises and keeps the cached document."""
    def __repr__(self) -> str: ...

@overload
def fetch_userinfo(
    http: _HttpArg,
    userinfo_endpoint: str | None,
    access_token: str,
    expected_sub: str,
    issuer: str,
    *,
    method: Literal["POST"] = ...,
    jwks: dict[str, Any] | JwksCache | None = ...,
    client_id: str | None = ...,
    allowed_algorithms: list[str] | None = ...,
    trust: Literal["typed", "dedicated_keys", "untyped_shared_key_compat"] | None = ...,
    typ: str | None = ...,
    max_age: int | None = ...,
    require_exp: bool = ...,
) -> dict[str, Any]:
    """Fetch UserInfo with a Bearer ``access_token`` and return its claims.

    ``method="GET"`` needs an ``http`` client that supports request headers on
    GET (see ``pygrindvakt.http``); otherwise ``ConfigError``. ``userinfo_endpoint=None``
    (the OP advertises none) raises ``ConfigError``.

    A signed ``application/jwt`` response is verified only when ``jwks``,
    ``client_id``, ``allowed_algorithms`` and ``trust`` are all given;
    otherwise ``AuthnError`` with ``code == "userinfo_unverifiable"``.
    ``trust`` is how the JWT is proven to be UserInfo: ``"typed"`` (needs
    ``typ``; safe), ``"dedicated_keys"`` (safe if ``jwks`` holds only UserInfo
    signing keys) or ``"untyped_shared_key_compat"`` (weakest: a fresh
    id_token without nonce/at_hash/c_hash is accepted). ``max_age`` bounds the
    token age from ``iat`` (default 300 s); ``None`` removes the bound and
    replay becomes unbounded. Encrypted (JWE) responses are rejected
    (``code == "userinfo_encrypted"``).

    ``HS*`` in ``allowed_algorithms`` works with a caller-built ``jwks`` dict
    (an ``oct`` key from the ``client_secret``; shorter than 32 / 48 / 64 bytes
    raises ``ConfigError``, ``code == "weak_shared_secret"``). With a
    :class:`JwksCache` it raises ``ConfigError``
    (``code == "shared_secret_algorithm"``).
    """

@overload
def fetch_userinfo(
    http: _HttpHeadersArg,
    userinfo_endpoint: str | None,
    access_token: str,
    expected_sub: str,
    issuer: str,
    *,
    method: Literal["GET"],
    jwks: dict[str, Any] | JwksCache | None = ...,
    client_id: str | None = ...,
    allowed_algorithms: list[str] | None = ...,
    trust: Literal["typed", "dedicated_keys", "untyped_shared_key_compat"] | None = ...,
    typ: str | None = ...,
    max_age: int | None = ...,
    require_exp: bool = ...,
) -> dict[str, Any]: ...
def build_client_assertion(key: SigningKey, client_id: str, audience: str) -> str: ...
def claims_to_attributes(claims: dict[str, Any]) -> dict[str, list[str]]: ...
def validate_issuer(issuer: str) -> None:
    """Check the syntax of an issuer identifier.

    Requires an absolute ``https`` URL (``http`` only for loopback hosts) with
    no userinfo, query, fragment, whitespace, control or invisible characters;
    raises ``ConfigError`` otherwise (the issuer is integrator configuration
    or provider metadata, not request input). Syntax only: it does NOT
    establish that the issuer is trusted, nor that it matches any discovery
    metadata. Backslashes are rejected (the URL parser would reinterpret them
    as ``/``, making the parsed authority differ from the raw string). Compare
    issuers byte-for-byte (exact string match); never suffix/substring checks.

    .. versionadded:: 0.3.0
    """

def validate_redirect_uri_syntax(redirect_uri: str) -> None:
    """Check the syntax of a redirect URI.

    Requires an absolute URL without a fragment (upstream's rule). This
    binding also rejects whitespace, control, bidi and invisible formatting
    characters and userinfo (binding-side hardening, stricter than core 0.9).
    Raises ``BadRequestError`` otherwise (not ``ConfigError``: a redirect URI
    can come from a request). This checks syntax only. The scheme is NOT
    checked, so ``com.example.app:/cb``, ``javascript:`` and
    ``http://attacker.example/cb`` all pass. It is the syntax step of
    ``RpClient``'s redirect URI handling, which also requires registration,
    exact-string comparison and a transport check (ADR 0004); it is NOT a
    registration policy. Do not use it to vet client registrations on an OP:
    this library provides no OP-side registration policy, so apply an https or
    scheme allow-list and compare by EXACT match yourself. Backslashes are rejected (the URL
    parser would reinterpret them as ``/``, making the parsed authority differ
    from the raw string).

    .. versionadded:: 0.3.0
    """

def validate_service_endpoint(
    name: str, endpoint: str, issuer: str | None = ..., *, allow_loopback_http: bool = ...
) -> None:
    """The loopback ``http`` exception is opt-in (``allow_loopback_http=True``) and ``issuer`` must then be the authenticated, locally configured issuer, never taken from the document being validated.

    Checks that a metadata endpoint is an absolute ``https`` URL. ``name``
    appears in the error message. By default only ``https`` passes; if
    ``issuer`` is given it is still validated first (as
    :func:`validate_issuer`; an invalid issuer raises ``ConfigError``) but
    never enables loopback ``http``. With ``allow_loopback_http=True``,
    ``issuer`` is required (else ``ConfigError``) and loopback ``http`` is also
    allowed on ANY port when the issuer is itself a loopback ``http`` origin; a
    ``UserWarning`` is emitted whenever a plain ``http`` endpoint is accepted.
    Raises ``ConfigError`` otherwise (endpoints are integrator configuration or
    provider metadata, not request input). It does NOT check same-origin with
    the issuer or establish trust. Backslashes in ``endpoint`` or ``issuer``
    are rejected (the URL parser would reinterpret them as ``/``, making the
    parsed authority differ from the raw string). Compare issuers
    byte-for-byte (exact string match); never suffix/substring checks.

    .. versionadded:: 0.3.0
    """

def asymmetric_algorithms() -> list[str]:
    """The classical asymmetric JWS algorithms from the core library's catalogue.

    ``RS256/384/512``, ``PS256/384/512``, ``ES256/384/512``, ``EdDSA`` and
    ``ES256K``, in that order; never ``HS*`` or ``none``. Post-quantum names (ML-DSA,
    feature-gated in jose-rs) are NOT included even if the build parses them.
    This is a catalogue, not a recommended allowlist; it is not a list an
    OP advertises and not what suits your deployment. Pass an explicit
    allowlist to :func:`verify_id_token`. It includes ``EdDSA``, for which
    :func:`pygrindvakt.jwt.supports_oidc_token_hash` is ``False``, so
    ``allowed_algorithms=rp.asymmetric_algorithms()`` with
    ``strict_hashes=True`` on a flow that needs ``at_hash`` / ``c_hash`` is
    unsatisfiable for EdDSA tokens: filter with
    ``jwt.supports_oidc_token_hash`` or pass an explicit allowlist.

    .. versionadded:: 0.3.0
    .. versionchanged:: 0.4.0
       The list comes from the core library's algorithm catalogue instead of a
       fixed probe list. The names are unchanged; the order now follows the
       catalogue (``ES512``, ``EdDSA``, ``ES256K``).
    """

class MultiDictProtocol(Protocol):
    """A multi-dict exposing ``lists()`` -> ``(name, [values])`` (werkzeug ``MultiDict``)."""

    def lists(self) -> Iterable[tuple[str, list[str]]]: ...

class AuthorizationResponse:
    """A parsed, shape-checked authorization response (callback). Nothing in it is trusted.

    Built by :func:`parse_authorization_response`; there is no public
    constructor. The response proves nothing by itself: compare ``state``
    with the session (``mac.constant_time_eq`` on the UTF-8 bytes), compare
    ``iss`` with :meth:`matches_iss` (RFC 9207) and exchange the code. The raw
    ``error_description`` is not available by design; use
    ``error_description_safe``. ``repr()`` never prints ``code``, ``state`` or ``response``.

    .. versionadded:: 0.3.0
    """

    @property
    def code(self) -> str | None: ...
    @property
    def state(self) -> str | None: ...
    @property
    def error(self) -> str | None: ...
    @property
    def error_description_safe(self) -> str | None: ...
    @property
    def error_uri(self) -> str | None: ...
    @property
    def iss(self) -> str | None: ...
    @property
    def response(self) -> str | None: ...
    @property
    def response_mode(self) -> Literal["query", "fragment", "form_post"]: ...
    @property
    def jarm_verified(self) -> bool:
        """True only for the result of a successful :meth:`verify_jarm`."""
    @property
    def is_error(self) -> bool: ...
    @property
    def error_known(self) -> bool:
        """True when ``error`` is a code the binding knows (RFC 6749, OIDC Core, DPoP).

        "Known" is WIDER than what ``OAuthError`` accepts: 8 response-only
        codes (for example ``consent_required``) are known but
        ``OAuthError("consent_required")`` raises ``ValueError``. Never build
        ``OAuthError(resp.error)`` from a callback value without catching
        ``ValueError``; branch on the ``error`` string instead.
        """
    def matches_iss(self, expected: str, *, required: bool = True) -> bool:
        """Exact, byte-for-byte comparison of ``iss`` with ``expected`` (RFC 9207).

        Fails closed: an absent ``iss`` gives ``not required``, so ``False`` by
        default. Pass ``required=False`` ONLY when the OP does not advertise
        ``authorization_response_iss_parameter_supported`` (RFC 9207 section
        2.4). An empty ``expected`` is a configuration fault and always gives
        ``False``, regardless of ``required``, as does an unverified JARM stub
        (``response`` set). Never raises.
        """
    def matches_state(self, expected: str, *, required: bool = True) -> bool:
        """Constant-time comparison of ``state`` with ``expected`` (RFC 6749 4.1.2.3, 10.12).

        Compares the UTF-8 bytes. Fails closed: an absent ``state`` gives
        ``not required``, so ``False`` by default. ``rp.authorization_url`` and
        ``rp.begin`` always send ``state``, so keep ``required=True``; pass
        ``required=False`` only for a request deliberately built without
        ``state``. An empty ``expected`` always gives ``False``, regardless of
        ``required``, as does an unverified JARM stub (``response`` set). Never raises for a mismatch. ALWAYS call it before
        exchanging the code.
        """
    def verify_jarm(
        self,
        jwks: dict[str, Any] | JwksCache,
        *,
        issuer: str,
        client_id: str,
        allowed_algorithms: Sequence[str],
        trust: Literal["typed", "dedicated_keys", "untyped_shared_key_compat"] = ...,
        typ: str | None = ...,
        leeway: int | None = ...,
    ) -> AuthorizationResponse:
        """Verify the JARM ``response`` JWT and return the inner response.

        Fails closed. ``allowed_algorithms`` is required (use
        :data:`JARM_ASYMMETRIC_ALGORITHMS`); ``HS*`` with a ``JwksCache``
        raises ``ConfigError`` (``code == "shared_secret_algorithm"``). A
        ``JwksCache`` must belong to ``issuer`` and is refreshed once for an
        unknown ``kid``. ``trust`` is ``"typed"`` (default; the JOSE ``typ``
        must be ``typ``, default :data:`JARM_TYP`), ``"dedicated_keys"`` or
        ``"untyped_shared_key_compat"`` (a missing ``typ`` or ``JWT`` is
        tolerated; weakest). ``typ`` is only valid with ``"typed"``.
        ``leeway`` is capped at :data:`MAX_ID_TOKEN_LEEWAY`.

        Raises ``BadRequestError`` for a response that is not an unverified
        JARM stub (including a plain code/error callback), a JWE, or a bad
        inner shape; ``AuthnError`` for a bad signature, ``typ``, ``kid``,
        ``iss``, ``aud`` or ``exp``; ``ConfigError`` for bad arguments. A
        ``kid`` that names no key in the issuer's JWK Set (after the cache's
        rate-limited refresh, which may have been skipped by the minimum
        refresh interval) raises ``AuthnError`` with ``code == "unknown_kid"``
        (401) and the original ``UnknownKeyError`` as ``__cause__``. The
        response is rejected (fail closed); a key-rotation race therefore
        surfaces as ``AuthnError``.

        If you requested a JARM response mode, call this on every callback
        without checking ``response`` first. A ``BadRequestError`` for such a
        callback means a rejected response and a possible downgrade attempt:
        reject it, never fall back to plain parameters. The result keeps
        ``response_mode`
        and has ``jarm_verified`` True. The caller MUST still call
        :meth:`matches_state` and :meth:`matches_iss` (the JWT ``iss``).
        ``error_description_safe`` is escaped by this binding.
        """
    def __repr__(self) -> str: ...

def parse_authorization_response(
    params: HttpRequestData | Sequence[tuple[str, str]] | Mapping[str, list[str] | tuple[str, ...]] | MultiDictProtocol,
    *,
    response_mode: Literal["query", "fragment", "form_post"] | None = ...,
    accept_jarm: bool = ...,
) -> AuthorizationResponse:
    """Parse the authorization response (callback), failing closed.

    ``params`` is an ``http.HttpRequestData`` (GET uses ``query_pairs``, POST
    uses ``form_pairs`` with mode ``form_post``; a response parameter in the
    other channel, the query string of a POST or the body of a GET, raises),
    an ordered list of ``(str, str)`` pairs, a multi-dict
    ``{name: [values]}`` (``urllib.parse.parse_qs`` shape) or an object with a
    ``lists()`` method (werkzeug ``MultiDict``). A plain ``dict[str, str]`` raises ``TypeError`` because mappings
    discard duplicate parameters. Build pairs with
    ``parse_qsl(qs, keep_blank_values=True)``: by default ``parse_qsl`` and
    ``parse_qs`` drop blank values, which hides a duplicate such as
    ``code=valid&code=``. ``response_mode`` labels list and multi-dict
    input (default ``"query"``).

    Raises ``BadRequestError`` for a lone surrogate in a parameter name or
    value of pairs, multi-dict or ``lists()`` input (the message never echoes
    it; a non-``str`` name or value is a ``TypeError``, and so is a lone
    surrogate in ``HttpRequestData`` construction), a repeated parameter, both or neither of
    ``code`` and ``error``, an empty ``code`` / ``state`` / ``error`` / ``iss`` / ``response``, control,
    bidi or invisible characters or backslashes in ``code`` / ``state`` /
    ``iss``, a ``code`` / ``state`` / ``iss`` over 2048 characters, a JARM
    ``response`` over 32768 characters, an
    ``error`` outside RFC 6749 section 5.2 or over 64 characters, and a JARM
    ``response`` unless ``accept_jarm=True`` (then exposed raw and UNVERIFIED,
    and it must be the only protocol parameter; verify the JWT yourself). Unknown error codes are kept (``error_known`` is False).
    ``error_uri`` is kept only as a safe absolute https URL (plain http only for loopback hosts) with a host (at
    most 2048 characters, returned normalised), else ``None``.

    .. versionadded:: 0.3.0
    """
