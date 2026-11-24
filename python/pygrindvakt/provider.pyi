"""Type stubs for ``pygrindvakt.provider`` - the OpenID Provider engine.

A ``Provider`` is constructed once at startup and shared across requests. Its
endpoint methods take already-extracted inputs (query / form dicts, header
strings) and return ``Response`` objects or raise ``OAuthError``, so any web
framework can drive it.

One-time use of authorization codes / refresh tokens / ``private_key_jwt``
``jti``s is enforced through a token-use store: ``InMemoryTokenUseStore``
(single process), ``RedisStore`` (shared), or any Python object satisfying
``TokenUseStoreProtocol``.
"""

from typing import Any, Protocol

from .client import Client, ClientStoreProtocol, InMemoryClientStore
from .dpop import DpopProof
from .errors import OAuthError
from .http import Response
from .keys import SigningKey
from .metadata import ProviderMetadata
from .request import AuthorizationRequest
from .tokens import TokenCodec

CLIENT_ASSERTION_TYPE: str
DEFAULT_CLIENT_ASSERTION_MAX_AGE: int
RESERVED_ID_TOKEN_CLAIMS: list[str]

class TokenUseStoreProtocol(Protocol):
    """One-time-use store protocol: ``consume`` returns True iff
    ``token_hash`` was not already used. An exception is reported as a store
    failure, which grindvakt renders as ``server_error``."""

    def consume(self, token_hash: str, ttl_secs: int) -> bool: ...

class TokenLifetimes:
    """Lifetimes (seconds) of issued artefacts."""

    def __init__(
        self,
        *,
        code_ttl: int = ...,
        access_token_ttl: int = ...,
        id_token_ttl: int = ...,
        refresh_token_ttl: int = ...,
    ) -> None: ...
    @property
    def code_ttl(self) -> int: ...
    @property
    def access_token_ttl(self) -> int: ...
    @property
    def id_token_ttl(self) -> int: ...
    @property
    def refresh_token_ttl(self) -> int: ...
    def __repr__(self) -> str: ...

class AuthorizedClaims:
    """Per-destination claim release decisions for
    :meth:`Provider.authorization_redirect_with_authorized_claims`.

    ``id_token`` claims go into the ID token; ``userinfo`` claims are returned
    by UserInfo. Put a claim in both only when both destinations are
    authorized to receive it. Values keep their JSON types. Reserved claim
    names in ``RESERVED_ID_TOKEN_CLAIMS`` raise ``ValueError``; ``None`` for
    either map raises ``TypeError``.

    .. versionadded:: 0.7.0
    """

    def __init__(self, *, id_token: dict[str, Any], userinfo: dict[str, Any]) -> None: ...
    @property
    def id_token(self) -> dict[str, Any]: ...
    @property
    def userinfo(self) -> dict[str, Any]: ...
    def __repr__(self) -> str: ...

class TokenResponse:
    """A successful token-endpoint response. ``to_dict()`` is exactly the JSON
    body to send (with ``cache-control: no-store``)."""

    @property
    def access_token(self) -> str: ...
    @property
    def token_type(self) -> str: ...
    @property
    def expires_in(self) -> int: ...
    @property
    def id_token(self) -> str | None: ...
    @property
    def scope(self) -> str | None: ...
    @property
    def refresh_token(self) -> str | None: ...
    def to_dict(self) -> dict[str, Any]: ...
    def to_response(self) -> Response:
        """The complete HTTP response: 200, JSON body, ``cache-control: no-store``."""
    def __repr__(self) -> str: ...

class InMemoryTokenUseStore:
    """Process-local one-time-use store for codes, refresh tokens and
    assertion ``jti``s. Fine for a single process; use ``RedisStore`` or a
    Python-backed store across replicas."""

    def __init__(self) -> None: ...
    def consume(self, token_hash: str, ttl_secs: int) -> bool:
        """Mark ``token_hash`` used; True iff it was not already used."""
    def __repr__(self) -> str: ...

class RedisStore:
    """Redis-backed one-time-use store (``SET key 1 EX ttl NX``) for
    multi-process deployments. Construct it *after* fork (e.g. in a gunicorn
    ``post_fork`` hook or lazily in the worker)."""

    DEFAULT_KEY_PREFIX: str
    def __init__(self, redis_url: str, key_prefix: str | None = ...) -> None: ...
    def consume(self, token_hash: str, ttl_secs: int) -> bool: ...
    def __repr__(self) -> str: ...

class Provider:
    """The OpenID Provider engine. Build once, share across requests.

    ``clients`` is an ``InMemoryClientStore`` or any object implementing
    ``ClientStoreProtocol``; ``token_use_store`` must be selected explicitly.
    """

    def __init__(
        self,
        metadata: ProviderMetadata,
        signing_key: SigningKey,
        clients: InMemoryClientStore | ClientStoreProtocol,
        codec: TokenCodec,
        lifetimes: TokenLifetimes | None = ...,
        token_use_store: InMemoryTokenUseStore | RedisStore | TokenUseStoreProtocol = ...,
        client_assertion_max_age: int | None = ...,
        authorization_response_iss: bool = ...,
    ) -> None: ...
    @property
    def clients(self) -> InMemoryClientStore | ClientStoreProtocol:
        """The client store passed at construction."""
    @property
    def token_use_store(
        self,
    ) -> InMemoryTokenUseStore | RedisStore | TokenUseStoreProtocol:
        """The token-use store in effect."""
    @property
    def metadata(self) -> ProviderMetadata: ...
    @property
    def signing_key(self) -> SigningKey: ...
    @property
    def lifetimes(self) -> TokenLifetimes: ...
    @property
    def issuer(self) -> str: ...
    def discovery_document(self) -> dict[str, Any]:
        """The ``/.well-known/openid-configuration`` document as a dict."""
    def jwks_document(self) -> dict[str, Any]:
        """The JWKS document (``{"keys": [...]}``) as a dict.

        Never contains an ``oct`` key: the constructor refuses ``HS*`` signing
        keys (``ConfigError``) and an ``oct`` JWK cannot carry another algorithm.
        """
    def validate_authorization_request(self, request: AuthorizationRequest) -> Client:
        """Validate an authorization request against the registered client and
        return that ``Client``.

        On failure the ``redirect_uri`` is NOT trusted: render the raised
        ``OAuthError`` with ``.to_response()``, never ``.to_redirect()``.
        """
    def authorization_redirect(
        self,
        request: AuthorizationRequest,
        sub: str,
        external_claims: dict[str, list[str]] | None = ...,
        acr: str | None = ...,
        extra_claims: dict[str, Any] | None = ...,
    ) -> Response:
        """After the user authenticated: mint the code / tokens for ``sub`` and
        return the redirect ``Response`` back to the client.

        ``external_claims`` maps claim name -> list of string values.
        ``extra_claims`` are typed id_token claims; the reserved names in
        ``RESERVED_ID_TOKEN_CLAIMS`` raise ``ValueError``.

        The request is revalidated at this minting boundary. On ``OAuthError``,
        pass ``"fragment"`` to ``to_redirect`` when ``request.use_fragment()``
        is true, otherwise pass ``"query"``. With ``authorization_response_iss``
        on, use ``authorization_error_redirect`` instead so the error carries
        ``iss``; in query mode a registered ``redirect_uri`` that already has
        an ``iss`` query parameter raises ``OAuthError(server_error)``.

        For separate ID token and UserInfo release use
        ``authorization_redirect_with_authorized_claims``.
        """
    def authorization_redirect_with_authorized_claims(
        self,
        request: AuthorizationRequest,
        sub: str,
        claims: AuthorizedClaims,
        *,
        acr: str | None = ...,
        auth_time: int | None = ...,
    ) -> Response:
        """Like ``authorization_redirect``, with separate ID token and UserInfo
        release decisions.

        No scope filter is applied: ``claims`` is released as given, so apply
        scope and release policy first. Put a claim in both maps only if both
        destinations are authorized to receive it. The registration
        fingerprint and the UserInfo claim set are always sealed into the
        code. Refresh keeps the split; if the client drops a previously granted
        scope at refresh, the matching standard claims are removed from both
        destinations. ``sub`` must be a public subject: pairwise clients raise
        ``OAuthError(unauthorized_client)``. ``auth_time`` defaults to issuance
        time.

        .. versionadded:: 0.7.0
        """
    def authorization_error_redirect(self, request: AuthorizationRequest, error: OAuthError) -> Response:
        """Render an authorization error redirect for ``request`` in its
        response mode, adding ``iss`` (RFC 9207) when the Provider was built
        with ``authorization_response_iss=True`` and nothing otherwise.

        ``state`` comes from ``error`` (pass ``request.state`` yourself). The
        request is validated first, as in ``validate_authorization_request``;
        on failure that ``OAuthError`` is raised and must be rendered with
        ``.to_response()``. With the flag on, query mode also raises
        ``OAuthError(server_error)`` when the registered ``redirect_uri``
        already has an ``iss`` query parameter. A ``redirect_uri`` with a
        backslash, invisible or bidi characters or userinfo raises
        ``OAuthError(invalid_request)``, as in ``authorization_redirect``.
        """
    def handle_token_request(
        self,
        form: list[tuple[str, str]],
        token_url: str,
        auth_header: str | None = ...,
        dpop: DpopProof | None = ...,
    ) -> TokenResponse:
        """Handle a token-endpoint request.

        ``form`` is the ordered parsed form body. Mappings are rejected because
        they erase duplicate names. ``auth_header`` is the raw
        ``Authorization`` header, ``token_url`` the absolute token endpoint
        URL *from configuration* (it is the ``private_key_jwt`` audience and
        the DPoP ``htu``), and ``dpop`` an already-validated ``DpopProof`` if
        the request carried one. Raises ``OAuthError``; render it with
        ``.to_response()``.
        """
    def userinfo(self, access_token: str, presented_jkt: str | None = ...) -> dict[str, Any]:
        """Require an ``openid``-scoped access token, validate it (and any
        DPoP key binding), and return the subject and scope-filtered claims."""
    def signed_userinfo(self, access_token: str, presented_jkt: str | None = ...) -> str:
        """Like :meth:`userinfo`, but return a compact JWS (``typ`` ``userinfo+jwt``,
        ``iss``, ``aud`` = client_id, ``exp`` = min(access token exp, now + 300)),
        or a JWE when the client registered ``userinfo_encrypted_response_alg``.
        Serve it with ``content-type: application/jwt``. Raises ``OAuthError``:
        token, scope and DPoP failures as for ``userinfo``; ``invalid_grant`` if
        the client is gone; ``server_error`` on signing or encryption failure."""
    def authenticate_client(
        self,
        form: list[tuple[str, str]],
        token_url: str,
        auth_header: str | None = ...,
    ) -> Client:
        """Authenticate from ordered token-endpoint form pairs. Mappings are
        rejected because they erase duplicate parameter names."""
    def __repr__(self) -> str: ...

def flatten_claims(external: dict[str, list[str]]) -> dict[str, Any]:
    """Flatten ``{claim: [values]}`` into id_token / userinfo claim values the
    way the provider does (single values coerced for standard claims)."""
