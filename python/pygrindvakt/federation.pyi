from typing import Any

from .http import _HttpArg
from .keys import SigningKey

ENTITY_STATEMENT_TYP: str
RESOLVE_RESPONSE_TYP: str
JWK_SET_TYP: str

class EntityStatement:
    @property
    def claims(self) -> dict[str, Any]: ...
    def iss(self) -> str | None: ...
    def sub(self) -> str | None: ...
    def jwks(self) -> dict[str, Any]:
        """The statement's ``jwks``; symmetric (``oct``) keys are dropped with a ``UserWarning``."""
    def metadata(self, kind: str) -> dict[str, Any] | None: ...
    def authority_hints(self) -> list[str]: ...
    def __repr__(self) -> str: ...

class ResolvedEntity:
    @property
    def issuer(self) -> str: ...
    @property
    def subject(self) -> str: ...
    @property
    def metadata(self) -> dict[str, Any]: ...
    @property
    def subject_jwks(self) -> dict[str, Any]:
        """The subject's federation keys; symmetric (``oct``) keys are dropped with a ``UserWarning``."""
    @property
    def exp(self) -> int | None:
        """Earlier of the resolve response ``exp`` and the earliest expiry in its validated trust chain."""
    @property
    def trust_marks(self) -> list[Any]:
        """Raw trust mark entries from the anchor's resolve response (empty if absent). NOT verified."""
    def __repr__(self) -> str: ...

class CollectionEntity:
    def __init__(self, *, entity_id: str, display_name: str, logo_uri: str | None = ...) -> None: ...
    @property
    def entity_id(self) -> str: ...
    @property
    def display_name(self) -> str: ...
    @property
    def logo_uri(self) -> str | None: ...
    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __repr__(self) -> str: ...

def build_entity_configuration(
    key: SigningKey,
    entity_id: str,
    public_jwks: dict[str, Any],
    authority_hints: list[str],
    metadata: dict[str, Any],
    trust_marks: list[dict[str, Any]] | None = ...,
    lifetime: int = ...,
) -> str:
    """Build and sign a self-issued Entity Configuration JWT.

    An ``oct`` key in ``public_jwks`` emits a ``UserWarning`` and is still
    published (the call does not filter it); federation verifiers drop it.

    .. versionchanged:: 0.3.0
       Warns when ``public_jwks`` contains an ``oct`` key.
    """

def decode_unverified(token: str) -> EntityStatement: ...
def verify(token: str, jwks: dict[str, Any]) -> EntityStatement:
    """Verify an entity statement.

    Refuses ``alg`` ``HS*`` / ``none`` (``AuthnError``, ``code="symmetric_algorithm"``);
    ``oct`` keys in ``jwks`` are dropped with a ``UserWarning``.
    """

def verify_typed(token: str, jwks: dict[str, Any], typ: str) -> EntityStatement:
    """Like ``verify`` with a required ``typ``; same ``alg`` refusal and ``oct`` drop."""

def verify_self_signed(token: str) -> EntityStatement:
    """Verify a self-issued configuration; refuses ``alg`` ``HS*`` / ``none`` (``symmetric_algorithm``)."""

def fetch_entity_configuration(http: _HttpArg, entity_id: str) -> str: ...
def resolve_via_trust_anchors(http: _HttpArg, sub: str, trust_anchors: dict[str, dict[str, Any]]) -> ResolvedEntity:
    """Resolve ``sub`` via trust anchors; ``oct`` keys in ``trust_anchors`` are dropped with a ``UserWarning``."""

def entity_metadata_jwks(
    http: _HttpArg,
    metadata: dict[str, Any],
    subject_entity_id: str,
    subject_fed_jwks: dict[str, Any],
) -> dict[str, Any]:
    """Resolve an entity type's key set from its metadata (inline ``jwks``,
    ``signed_jwks_uri``, else ``jwks_uri``).

    Symmetric (``oct``) keys are dropped from the result with a ``UserWarning``
    (OIDC Core 10.1: published key sets must not carry them); this also filters
    inline ``jwks`` metadata. The drop is unconditional. ``oct`` keys in
    ``subject_fed_jwks`` are dropped too (with a ``UserWarning``), so an ``HS*``-signed
    ``signed_jwks_uri`` document is never accepted.
    """

def fetch_signed_jwks(
    http: _HttpArg,
    signed_jwks_uri: str,
    subject_entity_id: str,
    subject_fed_jwks: dict[str, Any],
) -> dict[str, Any]:
    """Fetch and verify a signed JWK Set (``typ = jwk-set+jwt``).

    Symmetric (``oct``) keys are dropped from the result with a ``UserWarning``
    (OIDC Core 10.1: published key sets must not carry them). ``oct`` keys in
    ``subject_fed_jwks`` are dropped too, so an ``HS*``-signed document fails verification.
    """

def fetch_collection(http: _HttpArg, collection_endpoint: str, entity_type: str) -> list[CollectionEntity]: ...
def parse_collection(body: dict[str, Any], entity_type: str) -> list[CollectionEntity]: ...
def apply_policy(metadata: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]: ...
