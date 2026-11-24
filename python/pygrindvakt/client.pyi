"""Type stubs for ``pygrindvakt.client`` - registered relying parties and the
``ClientStore`` protocol (built-in in-memory store or any Python object with
``get(client_id)``, ``put(client)`` and optionally ``put_with_ttl(client, ttl)``).
"""

from typing import Any, Protocol

AUTH_NONE: str
AUTH_CLIENT_SECRET_BASIC: str
AUTH_CLIENT_SECRET_POST: str
AUTH_PRIVATE_KEY_JWT: str

class ClientStoreProtocol(Protocol):
    """Client store protocol accepted wherever ``clients=`` is taken.

    ``get`` may return a ``Client`` or a dict in ``Client.to_dict()`` shape.
    An optional ``put_with_ttl(client: Client, ttl_secs: int) -> None`` is
    used by federation auto-registration when present; otherwise ``put`` is
    called instead. The adapter fails closed: an exception in ``get`` means
    "unknown client" and is logged via ``sys.unraisablehook``.
    """

    def get(self, client_id: str) -> Client | dict[str, Any] | None: ...
    def put(self, client: Client) -> None: ...

class Client:
    """A registered relying party.

    Construct with keyword arguments (unknown keywords are rejected, so a typo
    such as ``redirect_uri=`` cannot silently produce an unusable client), or
    via ``Client.from_dict(...)``.
    """

    def __init__(
        self,
        client_id: str,
        *,
        client_secret: str | None = ...,
        redirect_uris: list[str] | None = ...,
        response_types: list[str] | None = ...,
        grant_types: list[str] | None = ...,
        token_endpoint_auth_method: str | None = ...,
        jwks: dict[str, Any] | None = ...,
        scope: str | None = ...,
        subject_type: str | None = ...,
        client_name: str | None = ...,
        response_policy: dict[str, str] | None = ...,
    ) -> None: ...
    @staticmethod
    def from_dict(d: dict[str, Any]) -> Client:
        """Build from a dict (the same shape as ``to_dict()`` / a JSON client
        registration). Unknown keys raise ``ValueError``."""
    def to_dict(self) -> dict[str, Any]:
        """The client as a dict."""
    def registration_fingerprint(self) -> str:
        """Unpadded base64url SHA-256 of the registration snapshot (credentials,
        keys and redirect URIs all contribute).

        Pass it as ``AuthCodePayload.registration_digest`` only when hand-sealing
        authorization codes (advanced);
        ``Provider.authorization_redirect_with_authorized_claims`` seals it itself. Changing the registration afterwards makes
        redemption fail with ``invalid_grant``."""
    @property
    def client_id(self) -> str: ...
    @property
    def client_secret(self) -> str | None: ...
    @property
    def redirect_uris(self) -> list[str]: ...
    @property
    def response_types(self) -> list[str]: ...
    @property
    def grant_types(self) -> list[str]: ...
    @property
    def token_endpoint_auth_method(self) -> str: ...
    @property
    def jwks(self) -> dict[str, Any] | None:
        """The client's JWKS (for ``private_key_jwt`` / request objects) as a dict."""
    @property
    def scope(self) -> str | None: ...
    @property
    def subject_type(self) -> str: ...
    @property
    def client_name(self) -> str | None: ...
    @property
    def response_policy(self) -> dict[str, str]:
        """The registered response policy: a fresh dict holding only the keys
        that are set (empty when none is). Keys:

        - ``sector_identifier_uri``: registered URI of the redirect-URI list
          that establishes a pairwise sector (the application validates the list).
        - ``request_object_signing_alg``: JWS algorithm the frontend must
          enforce on signed authorization requests.
        - ``token_endpoint_auth_signing_alg``: JWS algorithm pin for
          ``private_key_jwt`` assertions; the assertion must also carry a ``kid``.
        - ``id_token_encrypted_response_alg`` / ``id_token_encrypted_response_enc``:
          JWE key management / content encryption algorithms; the provider
          encrypts the signed ID token to the client's ``jwks``. ``enc``
          defaults to ``A128CBC-HS256``.
        - ``userinfo_encrypted_response_alg`` / ``userinfo_encrypted_response_enc``:
          the same for signed UserInfo responses. Stored but NOT applied:
          ``Provider.userinfo()`` returns JSON claims and core's
          ``signed_userinfo`` is not bound, so UserInfo is never encrypted.
        """
    def allows_redirect(self, uri: str) -> bool:
        """Whether ``uri`` exactly matches a registered redirect URI."""
    def allows_response_type(self, rt: str) -> bool:
        """Whether the client is allowed the given response type."""
    def __repr__(self) -> str: ...

class InMemoryClientStore:
    """In-memory client store with optional per-entry TTL (used by federation
    auto-registration). Process-local."""

    def __init__(self, clients: list[Client | dict[str, Any]] | None = ...) -> None:
        """Seed with static clients. Duplicate ``client_id``s raise ``ValueError``."""
    def get(self, client_id: str) -> Client | None:
        """Look up a client (expired TTL entries are removed on lookup)."""
    def put(self, client: Client | dict[str, Any]) -> None:
        """Insert or replace a client with no expiry."""
    def put_with_ttl(self, client: Client | dict[str, Any], ttl_secs: int) -> None:
        """Insert or replace a client that expires after ``ttl_secs``."""
    def __repr__(self) -> str: ...
