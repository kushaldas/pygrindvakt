"""Type stubs for ``pygrindvakt.tokens`` - the stateless token codec and its
sealed payloads (authorization codes, access tokens, refresh tokens)."""

from typing import Any

class AuthCodePayload:
    """Payload sealed into an authorization code."""

    def __init__(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        scope: str,
        sub: str,
        auth_time: int,
        exp: int,
        nonce: str | None = ...,
        code_challenge: str | None = ...,
        code_challenge_method: str | None = ...,
        claims: dict[str, Any] | None = ...,
        acr: str | None = ...,
        registration_digest: str | None = ...,
        userinfo_claims: dict[str, Any] | None = ...,
    ) -> None: ...
    @staticmethod
    def from_dict(d: dict[str, Any]) -> AuthCodePayload: ...
    def to_dict(self) -> dict[str, Any]: ...
    @property
    def client_id(self) -> str: ...
    @property
    def redirect_uri(self) -> str: ...
    @property
    def scope(self) -> str: ...
    @property
    def sub(self) -> str: ...
    @property
    def nonce(self) -> str | None: ...
    @property
    def code_challenge(self) -> str | None: ...
    @property
    def code_challenge_method(self) -> str | None: ...
    @property
    def claims(self) -> dict[str, Any]: ...
    @property
    def auth_time(self) -> int: ...
    @property
    def exp(self) -> int: ...
    @property
    def acr(self) -> str | None: ...
    @property
    def registration_digest(self) -> str | None:
        """Fingerprint of the client registration at authorization time.

        ``None`` for codes sealed before 0.6.0; the check is skipped for those.

        Security: if ``None``, the registration binding check is skipped
        silently, also for codes built by hand. An OP that seals its own codes
        must pass ``client.registration_fingerprint()``.
        """
    @property
    def userinfo_claims(self) -> dict[str, Any] | None:
        """Claims for the UserInfo response. ``None`` means use ``claims``;
        ``{}`` releases none.

        Warning: ``None`` and omitting the constructor argument both release
        the full ``claims`` map at UserInfo. Pass ``{}`` to release no
        application claims; never forward a possibly-``None`` value meaning
        "none".
        """
    def __repr__(self) -> str: ...

class AccessTokenPayload:
    """Payload sealed into an access token."""

    def __init__(
        self,
        *,
        client_id: str,
        sub: str,
        scope: str,
        exp: int,
        claims: dict[str, Any] | None = ...,
        cnf_jkt: str | None = ...,
    ) -> None: ...
    @staticmethod
    def from_dict(d: dict[str, Any]) -> AccessTokenPayload: ...
    def to_dict(self) -> dict[str, Any]: ...
    @property
    def client_id(self) -> str: ...
    @property
    def sub(self) -> str: ...
    @property
    def scope(self) -> str: ...
    @property
    def claims(self) -> dict[str, Any]: ...
    @property
    def exp(self) -> int: ...
    @property
    def cnf_jkt(self) -> str | None:
        """DPoP key thumbprint the token is bound to (``cnf.jkt``), if any."""
    def __repr__(self) -> str: ...

class RefreshTokenPayload:
    """Payload sealed into a refresh token."""

    def __init__(
        self,
        *,
        client_id: str,
        sub: str,
        scope: str,
        auth_time: int,
        exp: int,
        nonce: str | None = ...,
        claims: dict[str, Any] | None = ...,
        acr: str | None = ...,
        cnf_jkt: str | None = ...,
        userinfo_claims: dict[str, Any] | None = ...,
    ) -> None: ...
    @staticmethod
    def from_dict(d: dict[str, Any]) -> RefreshTokenPayload: ...
    def to_dict(self) -> dict[str, Any]: ...
    @property
    def client_id(self) -> str: ...
    @property
    def sub(self) -> str: ...
    @property
    def scope(self) -> str: ...
    @property
    def nonce(self) -> str | None: ...
    @property
    def claims(self) -> dict[str, Any]: ...
    @property
    def auth_time(self) -> int: ...
    @property
    def exp(self) -> int: ...
    @property
    def acr(self) -> str | None: ...
    @property
    def cnf_jkt(self) -> str | None: ...
    @property
    def userinfo_claims(self) -> dict[str, Any] | None:
        """Claims for the UserInfo response. ``None`` means use ``claims``;
        ``{}`` releases none.

        Warning: ``None`` and omitting the constructor argument both release
        the full ``claims`` map at UserInfo. Pass ``{}`` to release no
        application claims; never forward a possibly-``None`` value meaning
        "none".
        """
    def __repr__(self) -> str: ...

class TokenCodec:
    """Seals / opens authorization codes, access tokens and refresh tokens as
    JWE (``dir`` + ``A256GCM``) under keys derived from the OP secret via HKDF.

    ``previous_secrets`` are tried on open so tokens sealed under an old
    secret keep validating during key rotation.

    SECURITY: secrets are Python ``str``s and cannot be zeroized after use.
    """

    def __init__(self, secret: str, previous_secrets: list[str] | None = ...) -> None: ...
    def seal_code(self, payload: AuthCodePayload) -> str: ...
    def open_code(self, token: str) -> AuthCodePayload:
        """Open an authorization code (checks the type tag and expiry)."""
    def seal_access_token(self, payload: AccessTokenPayload) -> str: ...
    def open_access_token(self, token: str) -> AccessTokenPayload: ...
    def seal_refresh_token(self, payload: RefreshTokenPayload) -> str: ...
    def open_refresh_token(self, token: str) -> RefreshTokenPayload: ...
    def __repr__(self) -> str: ...
